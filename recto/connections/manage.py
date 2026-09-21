"""
Connections substrate — management primitives.

Pairs the non-secret `ConnectionStore` (metadata sidecar JSON) with the
dpapi-machine vault (secret values). Every function takes the connections
sidecar path explicitly (sister of `recto.profile.manage`'s state_dir
convention) and an injectable `secret_source_factory` so tests can
substitute an in-memory vault for the Windows-only DpapiMachineSource.

The secret VALUE never appears in metadata, in return values of the list
path, or in any logging. Only `get_connection_secret` returns a value, and
it's the agent-token-gated read path the bootloader fronts.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Callable, Protocol

from ..secrets.base import SecretMaterial, SecretNotFoundError
from .types import (
    ConnectionMeta,
    ConnectionStore,
    normalize_connection_key,
    vault_secret_name,
)


class WritableSecretSource(Protocol):
    """Structural contract the connections substrate needs from a backend:
    `fetch` (on the SecretSource ABC) plus `write` / `delete` (the
    file-storage backends DpapiMachineSource / CredManSource add). The base
    ABC mandates only `fetch`, so the connections layer is typed against this
    narrower-than-the-class, wider-than-the-ABC structural protocol — and
    tests substitute an in-memory double that satisfies it."""

    def fetch(self, secret_name: str, config: dict[str, Any]) -> SecretMaterial: ...
    def write(self, secret_name: str, value: str, comment: str = ...) -> None: ...
    def delete(self, secret_name: str) -> None: ...


# A factory: given a consuming service name, return a writable secret backend
# scoped to that service. Default constructs the production dpapi-machine backend.
SecretSourceFactory = Callable[[str], WritableSecretSource]


def _default_secret_source(service: str) -> WritableSecretSource:
    # Imported lazily so `import recto.connections.manage` doesn't trip the
    # Windows platform check on a non-Windows test box. Tests inject their own
    # factory and never reach this.
    from ..secrets.dpapi_machine import DpapiMachineSource

    return DpapiMachineSource(service)


# ---------------------------------------------------------------------------
# Metadata queries (secret-free)
# ---------------------------------------------------------------------------


def list_connections(
    connections_path: Path, service: str | None = None
) -> list[ConnectionMeta]:
    """All connection metadata, optionally filtered to one service. Never
    touches the vault — safe to call freely from the list/health surfaces."""
    return ConnectionStore.load(connections_path).list(service)


def get_connection_meta(
    connections_path: Path, service: str, key: str
) -> ConnectionMeta | None:
    return ConnectionStore.load(connections_path).get(service, key)


# ---------------------------------------------------------------------------
# Secret read (the agent-token-gated runtime path)
# ---------------------------------------------------------------------------


def get_connection_secret(
    service: str,
    key: str,
    *,
    secret_source_factory: SecretSourceFactory = _default_secret_source,
) -> str | None:
    """Decrypt + return the connection's secret value, or None if no value is
    set. Does NOT consult metadata — a consumer reads the live value directly
    so a rotation takes effect on the next call with no restart."""
    key = normalize_connection_key(key)
    source = secret_source_factory(service)
    material = source.fetch(vault_secret_name(key), {"required": False})
    value = material.value
    return value if value else None


# ---------------------------------------------------------------------------
# Operator mutations (gated at the bootloader layer)
# ---------------------------------------------------------------------------


def set_connection(
    connections_path: Path,
    *,
    service: str,
    key: str,
    display_name: str | None = None,
    category: str | None = None,
    secret: str | None = None,
    config: dict[str, Any] | None = None,
    enabled: bool | None = None,
    health_url: str | None = None,
    secret_source_factory: SecretSourceFactory = _default_secret_source,
) -> ConnectionMeta:
    """Upsert a connection: create on first call, update on subsequent calls.

    Rotation is the same call with a new `secret`. Passing `secret=None`
    leaves the existing vault value untouched (lets the operator edit
    metadata / toggle enabled / edit config without re-entering the key).
    Passing `secret=""` is treated the same as None (no clobber) — to clear a
    value, use `delete_connection`.

    Timestamps: `created_at_unix` set once; `updated_at_unix` on every call;
    `rotated_at_unix` only when a new secret value is written.
    """
    if not service:
        raise ValueError("service must be non-empty")
    key = normalize_connection_key(key)
    now = int(time.time())

    store = ConnectionStore.load(connections_path)
    existing = store.get(service, key)

    wrote_secret = False
    if secret:  # non-empty string only
        source = secret_source_factory(service)
        source.write(vault_secret_name(key), secret)
        wrote_secret = True

    has_secret = (existing.has_secret if existing else False) or wrote_secret

    meta = ConnectionMeta(
        service=service,
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
        enabled=(
            enabled
            if enabled is not None
            else (existing.enabled if existing else True)
        ),
        config=(
            dict(config)
            if config is not None
            else (dict(existing.config) if existing else {})
        ),
        health_url=(
            health_url
            if health_url is not None
            else (existing.health_url if existing else None)
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
    store.save(connections_path)
    return meta


def set_enabled(
    connections_path: Path, service: str, key: str, enabled: bool
) -> ConnectionMeta:
    """Toggle a connection's enabled flag without touching the vault."""
    return set_connection(
        connections_path,
        service=service,
        key=key,
        enabled=enabled,
    )


def delete_connection(
    connections_path: Path,
    *,
    service: str,
    key: str,
    secret_source_factory: SecretSourceFactory = _default_secret_source,
) -> ConnectionMeta | None:
    """Remove the metadata row AND the vault secret. Idempotent — returns the
    removed metadata, or None if nothing was registered."""
    key = normalize_connection_key(key)
    store = ConnectionStore.load(connections_path)
    removed = store.remove(service, key)
    if removed is None:
        return None
    try:
        secret_source_factory(service).delete(vault_secret_name(key))
    except SecretNotFoundError:
        pass  # metadata existed without a value — fine.
    store.save(connections_path)
    return removed


__all__ = [
    "SecretSourceFactory",
    "list_connections",
    "get_connection_meta",
    "get_connection_secret",
    "set_connection",
    "set_enabled",
    "delete_connection",
]
