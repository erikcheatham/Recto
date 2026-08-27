"""
Connections substrate — data contract.

`ConnectionMeta` is the non-secret metadata record for one external
integration. `ConnectionStore` persists a collection of them to a sidecar
JSON in the bootloader state dir (sister of phones.json / sessions.json).

By construction NEITHER type carries a secret value — the API key/token
lives only in the dpapi-machine vault, keyed `conn.<key>` within the
consuming service's namespace. A `has_secret` boolean flags whether a value
has been set, so list/management surfaces can show "configured" vs "no key"
without ever touching the value. See `recto.connections.manage` for the
vault read/write primitives.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

# Connection keys map onto vault secret names as `conn.<key>` and onto the
# bootloader's wire surface as path segments, so they must be filesystem- and
# URL-safe and must NOT contain '.' (the single dot in `conn.<key>` is the
# reserved separator) or ':' (the DpapiMachineSource service-name separator).
_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


def normalize_connection_key(key: str) -> str:
    """Lowercase + validate a connection key. Returns the normalized key.

    Raises ValueError on anything that isn't a short alnum/`-`/`_` token —
    keys become vault secret names (`conn.<key>`) and URL path segments, so
    they have to be safe for both.
    """
    if not isinstance(key, str):
        raise ValueError(f"connection key must be a string (got {type(key)!r})")
    norm = key.strip().lower()
    if not _KEY_RE.match(norm):
        raise ValueError(
            "connection key must be 1-64 chars of [a-z0-9_-], starting "
            f"alphanumeric (got {key!r})"
        )
    return norm


def vault_secret_name(key: str) -> str:
    """The dpapi-machine secret name a connection's value is stored under.

    Centralized here so the manage layer and any future migration agree on
    the `conn.<key>` convention. Assumes `key` is already normalized.
    """
    return f"conn.{key}"


@dataclass(frozen=True)
class ConnectionMeta:
    """Non-secret metadata for one external-integration connection.

    Persisted in `connections.json`; round-tripped to the bootloader wire
    surface. Carries NO secret value — `has_secret` is the only signal about
    whether a value is configured.
    """

    service: str
    """Consuming application namespace (the dpapi-machine service), e.g.
    'ServiceA'. Same value as `metadata.name` in the consumer's service.yaml."""

    key: str
    """Normalized connection id, e.g. 'podcastindex'. Unique within a service."""

    display_name: str
    """Operator-facing label, e.g. 'Podcast Index API'."""

    category: str
    """Aggregation axis / substrate, e.g. 'podcasts' | 'streaming' | 'reviews'.
    Lets the operator console group connections by what they feed."""

    enabled: bool = True
    """Operator toggle. A disabled connection drops out of the consumer's
    fan-out even when a key is present."""

    config: dict[str, Any] = field(default_factory=dict)
    """Non-secret per-connection config: base_url, region, plan tier, rate
    caps, etc. NEVER put a secret here — secrets live in the vault."""

    health_url: str | None = None
    """Optional liveness-probe URL the consumer's health board can ping."""

    has_secret: bool = False
    """True when a value has been written to the vault for this connection.
    Set by the manage layer on write; cleared on delete. The value itself is
    never represented in this type."""

    created_at_unix: int = 0
    updated_at_unix: int = 0
    rotated_at_unix: int = 0
    """Last time the SECRET VALUE was set/rotated (distinct from metadata
    updates). 0 means never set."""

    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Serialize for the sidecar JSON + the bootloader wire surface.
        Secret-free by construction — safe to log/transmit."""
        return {
            "service": self.service,
            "key": self.key,
            "display_name": self.display_name,
            "category": self.category,
            "enabled": self.enabled,
            "config": dict(self.config),
            "health_url": self.health_url,
            "has_secret": self.has_secret,
            "created_at_unix": self.created_at_unix,
            "updated_at_unix": self.updated_at_unix,
            "rotated_at_unix": self.rotated_at_unix,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ConnectionMeta":
        return cls(
            service=raw["service"],
            key=normalize_connection_key(raw["key"]),
            display_name=raw.get("display_name", raw["key"]),
            category=raw.get("category", "uncategorized"),
            enabled=bool(raw.get("enabled", True)),
            config=dict(raw.get("config") or {}),
            health_url=raw.get("health_url"),
            has_secret=bool(raw.get("has_secret", False)),
            created_at_unix=int(raw.get("created_at_unix", 0)),
            updated_at_unix=int(raw.get("updated_at_unix", 0)),
            rotated_at_unix=int(raw.get("rotated_at_unix", 0)),
        )


class ConnectionStore:
    """Persists a collection of ConnectionMeta to a sidecar JSON file.

    Keyed by (service, key). Sister of the bootloader's StateStore file
    persistence — non-secret, plain JSON, atomic-ish write via temp+replace.
    The store holds metadata ONLY; the manage layer pairs it with the vault
    for the secret values.
    """

    SCHEMA_VERSION = 1

    def __init__(self, entries: dict[tuple[str, str], ConnectionMeta] | None = None):
        self._entries: dict[tuple[str, str], ConnectionMeta] = entries or {}

    # ---- queries -------------------------------------------------------

    def list(self, service: str | None = None) -> list[ConnectionMeta]:
        items = self._entries.values()
        if service is not None:
            items = [m for m in items if m.service == service]
        return sorted(items, key=lambda m: (m.service, m.category, m.key))

    def get(self, service: str, key: str) -> ConnectionMeta | None:
        return self._entries.get((service, normalize_connection_key(key)))

    # ---- mutations -----------------------------------------------------

    def upsert(self, meta: ConnectionMeta) -> ConnectionMeta:
        self._entries[(meta.service, meta.key)] = meta
        return meta

    def remove(self, service: str, key: str) -> ConnectionMeta | None:
        return self._entries.pop((service, normalize_connection_key(key)), None)

    # ---- persistence ---------------------------------------------------

    @classmethod
    def load(cls, path: Path) -> "ConnectionStore":
        if not path.exists():
            return cls()
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            # Corrupt or unreadable — start empty rather than crash the
            # bootloader. The operator can re-add connections; the vault
            # secrets survive a metadata-file loss independently.
            return cls()
        entries: dict[tuple[str, str], ConnectionMeta] = {}
        for row in raw.get("connections", []):
            try:
                meta = ConnectionMeta.from_dict(row)
            except (KeyError, ValueError):
                continue
            entries[(meta.service, meta.key)] = meta
        return cls(entries)

    def save(self, path: Path) -> None:
        payload = {
            "schema_version": self.SCHEMA_VERSION,
            "saved_at_unix": int(time.time()),
            "connections": [m.to_dict() for m in self.list()],
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(
            json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
        )
        tmp.replace(path)


__all__ = [
    "ConnectionMeta",
    "ConnectionStore",
    "normalize_connection_key",
    "vault_secret_name",
]
