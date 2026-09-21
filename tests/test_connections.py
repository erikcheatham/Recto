"""Tests for the connections substrate (recto.connections).

Uses an in-memory secret backend so the suite runs on any OS — the real
dpapi-machine backend is Windows-only. The double satisfies the
WritableSecretSource structural protocol (fetch / write / delete).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from recto.secrets.base import DirectSecret, SecretMaterial, SecretNotFoundError
from recto.connections import (
    ConnectionMeta,
    ConnectionStore,
    normalize_connection_key,
)
from recto.connections.manage import (
    delete_connection,
    get_connection_meta,
    get_connection_secret,
    list_connections,
    set_connection,
    set_enabled,
)


# ---------------------------------------------------------------------------
# In-memory secret backend double (per-service)
# ---------------------------------------------------------------------------


class _MemoryVault:
    """Single shared store keyed by (service, name) -> value."""

    def __init__(self) -> None:
        self.data: dict[tuple[str, str], str] = {}

    def factory(self, service: str) -> "_MemorySource":
        return _MemorySource(self, service)


class _MemorySource:
    def __init__(self, vault: _MemoryVault, service: str) -> None:
        self._vault = vault
        self._service = service

    def fetch(self, secret_name: str, config: dict[str, Any]) -> SecretMaterial:
        value = self._vault.data.get((self._service, secret_name))
        if value is None:
            if config.get("required", True):
                raise SecretNotFoundError(f"{self._service}/{secret_name}")
            return DirectSecret(value="")
        return DirectSecret(value=value)

    def write(self, secret_name: str, value: str, comment: str = "") -> None:
        self._vault.data[(self._service, secret_name)] = value

    def delete(self, secret_name: str) -> None:
        self._vault.data.pop((self._service, secret_name), None)


@pytest.fixture
def vault() -> _MemoryVault:
    return _MemoryVault()


@pytest.fixture
def conn_path(tmp_path: Path) -> Path:
    return tmp_path / "connections.json"


# ---------------------------------------------------------------------------
# Key normalization
# ---------------------------------------------------------------------------


def test_normalize_lowercases_and_validates():
    assert normalize_connection_key("PodcastIndex") == "podcastindex"
    assert normalize_connection_key("listen-notes_v2") == "listen-notes_v2"


@pytest.mark.parametrize("bad", ["", "has.dot", "has:colon", "has space", "-leads"])
def test_normalize_rejects_unsafe_keys(bad):
    with pytest.raises(ValueError):
        normalize_connection_key(bad)


# ---------------------------------------------------------------------------
# set / get metadata + secret
# ---------------------------------------------------------------------------


def test_set_creates_with_secret(vault, conn_path):
    meta = set_connection(
        conn_path,
        service="ServiceA",
        key="podcastindex",
        display_name="Podcast Index API",
        category="podcasts",
        secret="super-secret-key",
        config={"base_url": "https://api.podcastindex.org"},
        secret_source_factory=vault.factory,
    )
    assert meta.key == "podcastindex"
    assert meta.has_secret is True
    assert meta.category == "podcasts"
    assert meta.created_at_unix > 0
    assert meta.rotated_at_unix == meta.created_at_unix

    # value reads back from the vault, never from metadata
    assert get_connection_secret(
        "ServiceA", "podcastindex", secret_source_factory=vault.factory
    ) == "super-secret-key"

    # metadata carries no secret value anywhere in its dict
    as_dict = meta.to_dict()
    assert "super-secret-key" not in repr(as_dict)
    assert "secret" not in as_dict or as_dict.get("secret") is None


def test_metadata_persists_and_reloads(vault, conn_path):
    set_connection(
        conn_path,
        service="ServiceA",
        key="watchmode",
        display_name="Watchmode",
        category="streaming",
        secret="wm-key",
        secret_source_factory=vault.factory,
    )
    rows = list_connections(conn_path, service="ServiceA")
    assert len(rows) == 1
    assert rows[0].display_name == "Watchmode"
    assert rows[0].has_secret is True
    # fresh load (no cached store) still sees it
    reloaded = ConnectionStore.load(conn_path).get("ServiceA", "watchmode")
    assert reloaded is not None and reloaded.category == "streaming"


def test_get_secret_none_when_unset(vault):
    assert get_connection_secret(
        "ServiceA", "neverset", secret_source_factory=vault.factory
    ) is None


# ---------------------------------------------------------------------------
# rotation + metadata-only updates
# ---------------------------------------------------------------------------


def test_rotation_writes_new_value_and_bumps_rotated_at(vault, conn_path):
    first = set_connection(
        conn_path, service="ServiceA", key="taddy", secret="v1",
        secret_source_factory=vault.factory,
    )
    # force a later timestamp deterministically by re-saving with a new value
    import recto.connections.manage as m
    import time as _t

    orig = _t.time
    try:
        _t.time = lambda: orig() + 5  # type: ignore[assignment]
        second = set_connection(
            conn_path, service="ServiceA", key="taddy", secret="v2",
            secret_source_factory=vault.factory,
        )
    finally:
        _t.time = orig  # type: ignore[assignment]

    assert get_connection_secret(
        "ServiceA", "taddy", secret_source_factory=vault.factory
    ) == "v2"
    assert second.created_at_unix == first.created_at_unix  # created preserved
    assert second.rotated_at_unix > first.rotated_at_unix    # rotated bumped


def test_metadata_only_update_preserves_secret(vault, conn_path):
    set_connection(
        conn_path, service="ServiceA", key="listennotes", secret="ln-key",
        category="podcasts", secret_source_factory=vault.factory,
    )
    # update WITHOUT a secret — must not clobber the vault value
    updated = set_connection(
        conn_path, service="ServiceA", key="listennotes",
        display_name="Listen Notes (RapidAPI)", enabled=False,
        secret_source_factory=vault.factory,
    )
    assert updated.display_name == "Listen Notes (RapidAPI)"
    assert updated.enabled is False
    assert updated.has_secret is True
    assert get_connection_secret(
        "ServiceA", "listennotes", secret_source_factory=vault.factory
    ) == "ln-key"


def test_empty_secret_does_not_clobber(vault, conn_path):
    set_connection(
        conn_path, service="ServiceA", key="apple", secret="apple-key",
        secret_source_factory=vault.factory,
    )
    set_connection(
        conn_path, service="ServiceA", key="apple", secret="",  # empty = no-op
        category="podcasts", secret_source_factory=vault.factory,
    )
    assert get_connection_secret(
        "ServiceA", "apple", secret_source_factory=vault.factory
    ) == "apple-key"


def test_set_enabled_toggles_without_touching_vault(vault, conn_path):
    set_connection(
        conn_path, service="ServiceA", key="grok", secret="grok-key",
        secret_source_factory=vault.factory,
    )
    set_enabled(conn_path, "ServiceA", "grok", False)
    meta = get_connection_meta(conn_path, "ServiceA", "grok")
    assert meta is not None and meta.enabled is False
    assert get_connection_secret(
        "ServiceA", "grok", secret_source_factory=vault.factory
    ) == "grok-key"


# ---------------------------------------------------------------------------
# delete
# ---------------------------------------------------------------------------


def test_delete_removes_metadata_and_value(vault, conn_path):
    set_connection(
        conn_path, service="ServiceA", key="tmdb", secret="tmdb-key",
        secret_source_factory=vault.factory,
    )
    removed = delete_connection(
        conn_path, service="ServiceA", key="tmdb",
        secret_source_factory=vault.factory,
    )
    assert removed is not None and removed.key == "tmdb"
    assert get_connection_meta(conn_path, "ServiceA", "tmdb") is None
    assert get_connection_secret(
        "ServiceA", "tmdb", secret_source_factory=vault.factory
    ) is None


def test_delete_idempotent(vault, conn_path):
    assert delete_connection(
        conn_path, service="ServiceA", key="ghost",
        secret_source_factory=vault.factory,
    ) is None


# ---------------------------------------------------------------------------
# service isolation
# ---------------------------------------------------------------------------


def test_services_are_isolated(vault, conn_path):
    set_connection(
        conn_path, service="ServiceA", key="shared", secret="at-val",
        secret_source_factory=vault.factory,
    )
    set_connection(
        conn_path, service="ServiceB", key="shared", secret="serviceb-val",
        secret_source_factory=vault.factory,
    )
    assert get_connection_secret(
        "ServiceA", "shared", secret_source_factory=vault.factory
    ) == "at-val"
    assert get_connection_secret(
        "ServiceB", "shared", secret_source_factory=vault.factory
    ) == "serviceb-val"
    assert len(list_connections(conn_path, service="ServiceA")) == 1
    assert len(list_connections(conn_path)) == 2  # both services
