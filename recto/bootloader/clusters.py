"""Cluster registry — the registry-writer surface of the bootloader.

The fleet-registry substrate behind the ``/v0.5/clusters/*`` endpoints. A
bootloader deployment that sets ``clusters_registry_path`` (plus a write
token) in ``create_server`` gains the registry; deployments that leave it
unset keep every cluster endpoint 404 — the same config-presence gating
every other surface in this server uses. That is what makes the
two-deployment / one-codebase split real: one deployment configures the
registry and nothing else, while another configures the agent-facing
surfaces (pairing, capability) and no registry — from a single codebase.

Registry laws:

1. One WRITER. Runtime consumers never call the registry endpoints — they
   read the read-only PROJECTION this module exports to ``projection_path``
   on every mutation. A read path must never quietly become a write path.
2. Never trust the dying to report their death. Clusters heartbeat to
   renew a LEASE; an expired lease means PRESUMED DEAD, and the
   ``reap()`` sweep transitions the record to ``orphaned`` — clean
   retirement is a courtesy, not a dependency.
3. Records hold POINTERS, never secret values. The one credential this
   module touches — the per-cluster heartbeat token minted at
   register — is stored as a SHA-256 hash and returned exactly once.

Storage is a single JSON file written atomically (temp + os.replace),
matching the connections.json precedent. No background threads: status
is computed lazily from lease age at read time, and ``reap()`` persists
the transition when a caller invokes it (a scheduled sweep or an
operator tool).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

__all__ = [
    "ClusterRecord",
    "ClusterRegistry",
    "ClusterRegistryError",
]


class ClusterRegistryError(Exception):
    """Raised for invalid registry operations (bad id, bad token, ...)."""


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass
class ClusterRecord:
    """One spawned cluster. Pointers only — never secret values."""

    cluster_id: str
    region: str
    ordinal: str
    color: str
    status: str  # "active" | "retired" | "orphaned"
    created_at_unix: int
    endpoints: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, str] = field(default_factory=dict)
    lease_ttl_seconds: int = 180
    last_heartbeat_unix: int = 0
    retired_at_unix: int | None = None
    retired_reason: str | None = None
    heartbeat_token_sha256: str = ""

    def effective_status(self, now_unix: int | None = None) -> str:
        """Status with the lease applied — lazy orphan detection.

        A record persisted as ``active`` whose lease has lapsed reads as
        ``orphaned`` even before ``reap()`` persists the transition, so
        the projection never lies about liveness.
        """
        if self.status != "active":
            return self.status
        now = int(time.time()) if now_unix is None else now_unix
        if now - self.last_heartbeat_unix > self.lease_ttl_seconds:
            return "orphaned"
        return "active"

    def public_view(self, now_unix: int | None = None) -> dict[str, Any]:
        """Projection shape: everything EXCEPT the token hash."""
        d = asdict(self)
        d.pop("heartbeat_token_sha256", None)
        d["status"] = self.effective_status(now_unix)
        return d


class ClusterRegistry:
    """File-backed registry with lease-based orphan detection.

    Not thread-safe by itself; the bootloader's handler methods run on
    the ThreadingHTTPServer's per-request threads, so mutations funnel
    through a simple re-entrant load->mutate->persist under the module
    lock the caller holds (the server wiring serializes via
    ``threading.Lock`` — see server.py).
    """

    def __init__(
        self,
        registry_path: str | os.PathLike[str],
        *,
        projection_path: str | os.PathLike[str] | None = None,
        default_lease_ttl_seconds: int = 180,
    ) -> None:
        self.registry_path = Path(registry_path)
        self.projection_path = (
            Path(projection_path) if projection_path else None
        )
        self.default_lease_ttl_seconds = int(default_lease_ttl_seconds)
        self._records: dict[str, ClusterRecord] = {}
        self._load()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def _load(self) -> None:
        if not self.registry_path.exists():
            self._records = {}
            return
        raw = json.loads(self.registry_path.read_text(encoding="utf-8"))
        self._records = {
            rec["cluster_id"]: ClusterRecord(**rec)
            for rec in raw.get("clusters", [])
        }

    def _persist(self) -> None:
        payload = {
            "version": 1,
            "updated_at_unix": int(time.time()),
            "clusters": [asdict(r) for r in self._records.values()],
        }
        self._atomic_write(self.registry_path, payload)
        self.export_projection()

    @staticmethod
    def _atomic_write(path: Path, payload: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(
            dir=str(path.parent), prefix=path.name, suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, sort_keys=True)
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def export_projection(self) -> None:
        """Write the read-only projection (law #1). No token hashes."""
        if self.projection_path is None:
            return
        now = int(time.time())
        payload = {
            "version": 1,
            "generated_at_unix": now,
            "clusters": [
                r.public_view(now) for r in self._records.values()
            ],
        }
        self._atomic_write(self.projection_path, payload)

    # ------------------------------------------------------------------
    # Operations
    # ------------------------------------------------------------------
    def register(
        self,
        *,
        region: str,
        ordinal: str,
        color: str,
        endpoints: dict[str, str] | None = None,
        metadata: dict[str, str] | None = None,
        lease_ttl_seconds: int | None = None,
    ) -> tuple[ClusterRecord, str]:
        """Create a record; returns (record, heartbeat_token).

        The token is returned EXACTLY ONCE — only its hash persists
        (law #3). cluster_id is the regional identity ruled 2026-08-06:
        ``<region>-<ordinal>-<color>``, e.g. ``ncus-01-blue``.
        """
        for name, value in (("region", region), ("ordinal", ordinal), ("color", color)):
            if not value or not value.replace("-", "").isalnum():
                raise ClusterRegistryError(f"invalid {name}: {value!r}")
        cluster_id = f"{region}-{ordinal}-{color}".lower()
        if cluster_id in self._records and self._records[cluster_id].status == "active":
            raise ClusterRegistryError(f"cluster already active: {cluster_id}")
        token = secrets.token_urlsafe(32)
        now = int(time.time())
        rec = ClusterRecord(
            cluster_id=cluster_id,
            region=region.lower(),
            ordinal=ordinal.lower(),
            color=color.lower(),
            status="active",
            created_at_unix=now,
            endpoints=dict(endpoints or {}),
            metadata=dict(metadata or {}),
            lease_ttl_seconds=int(
                lease_ttl_seconds or self.default_lease_ttl_seconds
            ),
            last_heartbeat_unix=now,
            heartbeat_token_sha256=_sha256_hex(token),
        )
        self._records[cluster_id] = rec
        self._persist()
        return rec, token

    def _authenticated(self, cluster_id: str, token: str) -> ClusterRecord:
        rec = self._records.get(cluster_id)
        if rec is None:
            raise ClusterRegistryError(f"unknown cluster: {cluster_id}")
        if not hmac.compare_digest(
            rec.heartbeat_token_sha256, _sha256_hex(token or "")
        ):
            raise ClusterRegistryError("cluster token mismatch")
        return rec

    def heartbeat(
        self,
        cluster_id: str,
        token: str,
        *,
        endpoints: dict[str, str] | None = None,
        metadata: dict[str, str] | None = None,
    ) -> ClusterRecord:
        """Renew the lease. An orphaned record that heartbeats again
        RECOVERS to active — presumed dead is a presumption, and a
        cluster that comes back gets its lease back (the persisted
        transition is corrected on the next persist)."""
        rec = self._authenticated(cluster_id, token)
        if rec.status == "retired":
            raise ClusterRegistryError(
                f"cluster is retired: {cluster_id} — spawn a new one"
            )
        rec.status = "active"
        rec.last_heartbeat_unix = int(time.time())
        if endpoints:
            rec.endpoints.update(endpoints)
        if metadata:
            rec.metadata.update(metadata)
        self._persist()
        return rec

    def retire(
        self, cluster_id: str, token: str, *, reason: str = "retired"
    ) -> ClusterRecord:
        """Clean death — the courtesy path (law #2 makes it optional)."""
        rec = self._authenticated(cluster_id, token)
        rec.status = "retired"
        rec.retired_at_unix = int(time.time())
        rec.retired_reason = reason
        self._persist()
        return rec

    def reap(self, *, now_unix: int | None = None) -> list[str]:
        """Persist orphan transitions for every lapsed lease (law #2).

        Returns the cluster_ids newly marked orphaned. Idempotent."""
        now = int(time.time()) if now_unix is None else now_unix
        newly_orphaned: list[str] = []
        for rec in self._records.values():
            if rec.status == "active" and rec.effective_status(now) == "orphaned":
                rec.status = "orphaned"
                newly_orphaned.append(rec.cluster_id)
        if newly_orphaned:
            self._persist()
        return newly_orphaned

    def list_clusters(self, *, now_unix: int | None = None) -> list[dict[str, Any]]:
        now = int(time.time()) if now_unix is None else now_unix
        return [r.public_view(now) for r in self._records.values()]
