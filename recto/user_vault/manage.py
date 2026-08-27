"""
User Vault substrate — management primitives.

Pairs the non-secret `UserVaultStore` (metadata sidecar JSON) with the
secret backend (dpapi-machine vault on a Windows host; file-backed store in
a container) for the values. Every function takes the sidecar path
explicitly and an injectable `secret_source_factory` so tests substitute an
in-memory vault for the Windows-only DpapiMachineSource — the exact seam
`recto.connections.manage` established.

The secret VALUE never appears in metadata, in return values of the list
path, or in any logging. Only `release_user_secret` returns a value, and it
is the agent-token-gated, user-scoped read path the bootloader fronts.

Semantics contract (mirrors the consuming platform's user-vault seam):
  * set: create on first call, rotate on subsequent calls with a non-empty
    secret; a None/empty secret updates metadata only, preserving the value.
  * delete: idempotent; removes metadata AND value.
  * release: returns the live value or None when unset — consumers treat
    None as "no key" (and, in the phone-approval future, as denial).
"""

from __future__ import annotations

import time
from pathlib import Path

from ..connections.manage import SecretSourceFactory, _default_secret_source
from ..secrets.base import SecretNotFoundError
from .types import (
    UserVaultEntryMeta,
    UserVaultStore,
    normalize_user_id,
    normalize_user_vault_key,
    user_vault_secret_name,
)

# ---------------------------------------------------------------------------
# Metadata queries (secret-free)
# ---------------------------------------------------------------------------


def list_user_entries(
    store_path: Path, platform: str, user_id: str
) -> list[UserVaultEntryMeta]:
    """One user's entry metadata within one platform. Never touches the
    secret backend — safe to call freely from list surfaces."""
    return UserVaultStore.load(store_path).list(platform, user_id)


# ---------------------------------------------------------------------------
# Secret release (the agent-token-gated, user-scoped runtime path)
# ---------------------------------------------------------------------------


def release_user_secret(
    platform: str,
    user_id: str,
    key: str,
    *,
    secret_source_factory: SecretSourceFactory = _default_secret_source,
) -> str | None:
    """Decrypt + return the user's secret value, or None if no value is
    set. Does NOT consult metadata — the consumer reads the live value at
    call time so a rotation takes effect on the next call with no restart.

    This is the seam the phone release-on-approval backend replaces: same
    signature, but the value comes back only after the paired device
    approves (None on denial). Callers must already tolerate None.
    """
    user_id = normalize_user_id(user_id)
    key = normalize_user_vault_key(key)
    source = secret_source_factory(platform)
    material = source.fetch(
        user_vault_secret_name(user_id, key), {"required": False}
    )
    value = material.value
    return value if value else None


# ---------------------------------------------------------------------------
# Mutations (agent-gated at the bootloader layer — the platform acts for
# its own user; the user-id scoping claim bounds the blast radius)
# ---------------------------------------------------------------------------


def set_user_entry(
    store_path: Path,
    *,
    platform: str,
    user_id: str,
    key: str,
    display_name: str | None = None,
    category: str | None = None,
    secret: str | None = None,
    secret_source_factory: SecretSourceFactory = _default_secret_source,
) -> UserVaultEntryMeta:
    """Upsert a user's entry: create on first call, update on subsequent.

    Rotation is the same call with a new `secret`. Passing `secret=None`
    OR `secret=""` leaves the existing value untouched (metadata-only
    edit) — to clear a value, use `delete_user_entry`. Matches the
    consuming platform's SetAsync semantics exactly.

    Timestamps: `created_at_unix` set once; `updated_at_unix` on every
    call; `rotated_at_unix` only when a new secret value is written.
    """
    if not platform:
        raise ValueError("platform must be non-empty")
    user_id = normalize_user_id(user_id)
    key = normalize_user_vault_key(key)
    now = int(time.time())

    store = UserVaultStore.load(store_path)
    existing = store.get(platform, user_id, key)

    wrote_secret = False
    if secret:  # non-empty string only
        source = secret_source_factory(platform)
        source.write(user_vault_secret_name(user_id, key), secret)
        wrote_secret = True

    has_secret = (existing.has_secret if existing else False) or wrote_secret

    meta = UserVaultEntryMeta(
        platform=platform,
        user_id=user_id,
        key=key,
        display_name=(
            display_name
            if display_name is not None
            else (existing.display_name if existing else key)
        ),
        category=(
            category
            if category is not None
            else (existing.category if existing else "uncategorized")
        ),
        has_secret=has_secret,
        created_at_unix=existing.created_at_unix if existing else now,
        updated_at_unix=now,
        rotated_at_unix=(
            now
            if wrote_secret
            else (existing.rotated_at_unix if existing else 0)
        ),
    )
    store.upsert(meta)
    store.save(store_path)
    return meta


def delete_user_entry(
    store_path: Path,
    *,
    platform: str,
    user_id: str,
    key: str,
    secret_source_factory: SecretSourceFactory = _default_secret_source,
) -> UserVaultEntryMeta | None:
    """Remove the metadata row AND the secret value. Idempotent — returns
    the removed metadata, or None if nothing was registered."""
    user_id = normalize_user_id(user_id)
    key = normalize_user_vault_key(key)
    store = UserVaultStore.load(store_path)
    removed = store.remove(platform, user_id, key)
    if removed is None:
        return None
    try:
        secret_source_factory(platform).delete(
            user_vault_secret_name(user_id, key)
        )
    except SecretNotFoundError:
        pass  # metadata existed without a value — fine.
    store.save(store_path)
    return removed


__all__ = [
    "list_user_entries",
    "release_user_secret",
    "set_user_entry",
    "delete_user_entry",
]
