"""
User Vault substrate — data contract.

`UserVaultEntryMeta` is the non-secret metadata record for one user-owned
provider key. `UserVaultStore` persists a collection of them to a sidecar
JSON in the bootloader state dir (sister of connections.json).

By construction NEITHER type carries a secret value — the key/token lives
only in the secret backend, named `uv.<user_id>.<key>` within the consuming
PLATFORM's namespace. A `has_secret` boolean flags whether a value has been
set, so list surfaces can show "configured" vs "no key" without ever
touching the value. See `recto.user_vault.manage` for the vault read/write
primitives.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..connections.types import normalize_connection_key

# User ids are the consuming platform's user identifiers. The canonical
# consumer emits GUIDs; we accept the RFC-4122 textual shape (lowercased on
# normalization) so ids are filesystem- and URL-safe by construction and a
# platform can never smuggle a path separator through the scoping claim.
_USER_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)


def normalize_user_id(user_id: str) -> str:
    """Lowercase + validate a user id (GUID textual form). Returns the
    normalized id; raises ValueError on anything else. Ids become vault
    secret-name components (`uv.<user_id>.<key>`) and JSON map keys, so
    the shape gate is a security boundary, not a formality."""
    if not isinstance(user_id, str):
        raise ValueError(f"user id must be a string (got {type(user_id)!r})")
    norm = user_id.strip().lower()
    if not _USER_ID_RE.match(norm):
        raise ValueError(
            "user id must be a GUID (8-4-4-4-12 lowercase hex) "
            f"(got {user_id!r})"
        )
    return norm


def normalize_user_vault_key(key: str) -> str:
    """User-vault entry keys share the connection-key grammar (1-64 chars
    of [a-z0-9_-], starting alphanumeric) — same reasons: they become
    vault secret-name components and wire-surface values."""
    return normalize_connection_key(key)


def user_vault_secret_name(user_id: str, key: str) -> str:
    """The secret name a user-vault value is stored under within the
    platform's namespace: `uv.<user_id>.<key>`. The `uv.` prefix keeps
    user entries disjoint from the platform tier's `conn.<key>` entries
    in the same service directory. Assumes both parts are normalized."""
    return f"uv.{user_id}.{key}"


@dataclass(frozen=True)
class UserVaultEntryMeta:
    """Non-secret metadata for one user-owned vault entry.

    Persisted in `user_vault.json`; round-tripped to the bootloader wire
    surface. Carries NO secret value — `has_secret` is the only signal
    about whether a value is configured.
    """

    platform: str
    """Consuming platform namespace (the secret-backend service), e.g. the
    same value the platform's agent is mapped to in the bootloader config."""

    user_id: str
    """Normalized (lowercase GUID) end-user id within the platform."""

    key: str
    """Normalized entry id, e.g. 'anthropic'. Unique within (platform, user)."""

    display_name: str
    """User-facing label, e.g. 'Anthropic API key'."""

    category: str
    """Grouping axis the platform's UI uses, e.g. 'ai-provider'."""

    has_secret: bool = False
    """True when a value has been written for this entry. Set by the manage
    layer on write; the value itself is never represented in this type."""

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
            "platform": self.platform,
            "user_id": self.user_id,
            "key": self.key,
            "display_name": self.display_name,
            "category": self.category,
            "has_secret": self.has_secret,
            "created_at_unix": self.created_at_unix,
            "updated_at_unix": self.updated_at_unix,
            "rotated_at_unix": self.rotated_at_unix,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "UserVaultEntryMeta":
        return cls(
            platform=raw["platform"],
            user_id=normalize_user_id(raw["user_id"]),
            key=normalize_user_vault_key(raw["key"]),
            display_name=raw.get("display_name", raw["key"]),
            category=raw.get("category", "uncategorized"),
            has_secret=bool(raw.get("has_secret", False)),
            created_at_unix=int(raw.get("created_at_unix", 0)),
            updated_at_unix=int(raw.get("updated_at_unix", 0)),
            rotated_at_unix=int(raw.get("rotated_at_unix", 0)),
        )


class UserVaultStore:
    """Persists a collection of UserVaultEntryMeta to a sidecar JSON file.

    Keyed by (platform, user_id, key). Sister of ConnectionStore — the
    store holds metadata ONLY; the manage layer pairs it with the secret
    backend for the values.
    """

    SCHEMA_VERSION = 1

    def __init__(
        self,
        entries: dict[tuple[str, str, str], UserVaultEntryMeta] | None = None,
    ):
        self._entries: dict[tuple[str, str, str], UserVaultEntryMeta] = (
            entries or {}
        )

    # ---- queries -------------------------------------------------------

    def list(self, platform: str, user_id: str) -> list[UserVaultEntryMeta]:
        """One user's entries within one platform — the ONLY list shape.
        There is deliberately no all-users enumeration on this class's
        public wire path; the sidecar is host-private."""
        user_id = normalize_user_id(user_id)
        return sorted(
            (
                m
                for m in self._entries.values()
                if m.platform == platform and m.user_id == user_id
            ),
            key=lambda m: (m.category, m.key),
        )

    def get(
        self, platform: str, user_id: str, key: str
    ) -> UserVaultEntryMeta | None:
        return self._entries.get(
            (platform, normalize_user_id(user_id), normalize_user_vault_key(key))
        )

    # ---- mutations -----------------------------------------------------

    def upsert(self, meta: UserVaultEntryMeta) -> UserVaultEntryMeta:
        self._entries[(meta.platform, meta.user_id, meta.key)] = meta
        return meta

    def remove(
        self, platform: str, user_id: str, key: str
    ) -> UserVaultEntryMeta | None:
        return self._entries.pop(
            (platform, normalize_user_id(user_id), normalize_user_vault_key(key)),
            None,
        )

    # ---- persistence ---------------------------------------------------

    @classmethod
    def load(cls, path: Path) -> "UserVaultStore":
        if not path.exists():
            return cls()
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            # Corrupt or unreadable — start empty rather than crash the
            # bootloader. Secret values survive a metadata-file loss
            # independently (same posture as ConnectionStore).
            return cls()
        entries: dict[tuple[str, str, str], UserVaultEntryMeta] = {}
        for row in raw.get("entries", []):
            try:
                meta = UserVaultEntryMeta.from_dict(row)
            except (KeyError, ValueError):
                continue
            entries[(meta.platform, meta.user_id, meta.key)] = meta
        return cls(entries)

    def save(self, path: Path) -> None:
        payload = {
            "schema_version": self.SCHEMA_VERSION,
            "saved_at_unix": int(time.time()),
            "entries": [
                m.to_dict()
                for m in sorted(
                    self._entries.values(),
                    key=lambda m: (m.platform, m.user_id, m.category, m.key),
                )
            ],
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(
            json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
        )
        tmp.replace(path)


__all__ = [
    "UserVaultEntryMeta",
    "UserVaultStore",
    "normalize_user_id",
    "normalize_user_vault_key",
    "user_vault_secret_name",
]
