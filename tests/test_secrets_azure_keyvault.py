"""Tests for the azure-keyvault SecretSource backend.

Two arms:

- **Mocked** (default, runs in CI): a fake SecretClient injected through
  the constructor's ``secret_client`` seam, with the REAL
  ``azure.core.exceptions`` types so the error-mapping paths are
  exercised as production would hit them. Requires ``recto[azure]``
  installed (SDK import only -- no network, no vault).
- **Live** (env-gated, operator-side): set
  ``RECTO_TEST_AZURE_KEYVAULT_URL`` to a disposable vault the ambient
  credential can reach; a real set/get/delete round-trip runs. Skips
  cleanly otherwise.
"""

from __future__ import annotations

import os
import uuid

import pytest

pytest.importorskip(
    "azure.keyvault.secrets",
    reason="recto[azure] not installed -- azure-keyvault backend tests skipped",
)

from azure.core.exceptions import (  # noqa: E402
    ClientAuthenticationError,
    ResourceNotFoundError,
)

from recto.secrets import registered_sources, resolve_source  # noqa: E402
from recto.secrets.azure_keyvault import (  # noqa: E402
    VAULT_URL_ENV,
    AzureKeyVaultSource,
    normalize_kv_name,
)
from recto.secrets.base import (  # noqa: E402
    DirectSecret,
    SecretNotFoundError,
    SecretSourceError,
)

LIVE_URL = os.environ.get("RECTO_TEST_AZURE_KEYVAULT_URL")


# ----------------------------------------------------------------------
# Fake SecretClient (constructor-injection seam)
# ----------------------------------------------------------------------

class _FakeSecret:
    def __init__(self, value: str):
        self.value = value


class _FakePoller:
    def wait(self) -> None:
        pass


class _FakeSecretClient:
    def __init__(self):
        self.store: dict[str, str] = {}
        self.tags_seen: dict[str, dict | None] = {}
        self.auth_broken = False

    def get_secret(self, name: str) -> _FakeSecret:
        if self.auth_broken:
            raise ClientAuthenticationError(message="auth broken")
        if name not in self.store:
            raise ResourceNotFoundError(message=f"{name} not found")
        return _FakeSecret(self.store[name])

    def set_secret(self, name: str, value: str, tags=None) -> None:
        if self.auth_broken:
            raise ClientAuthenticationError(message="auth broken")
        self.store[name] = value
        self.tags_seen[name] = tags

    def begin_delete_secret(self, name: str) -> _FakePoller:
        if name not in self.store:
            raise ResourceNotFoundError(message=f"{name} not found")
        del self.store[name]
        return _FakePoller()


@pytest.fixture
def fake_client():
    return _FakeSecretClient()


@pytest.fixture
def source(fake_client):
    return AzureKeyVaultSource("MyService", secret_client=fake_client)


# ----------------------------------------------------------------------
# Name normalization
# ----------------------------------------------------------------------

def test_normalize_lowercases_and_maps_punctuation():
    assert (
        normalize_kv_name("MyService", "KEYCLOAK_WEB_SECRET")
        == "myservice--keycloak-web-secret"
    )
    assert (
        normalize_kv_name("MyService", "conn.cloudflare")
        == "myservice--conn-cloudflare"
    )


def test_normalize_is_one_to_one_per_character():
    # No collapsing: consecutive punctuation stays visible as
    # consecutive hyphens (fewer accidental collisions).
    assert normalize_kv_name("svc", "a._b") == "svc--a--b"
    assert normalize_kv_name("svc", "a.._b") == "svc--a---b"


def test_normalize_rejects_empty_parts():
    with pytest.raises(SecretSourceError):
        normalize_kv_name("", "x")
    with pytest.raises(SecretSourceError):
        normalize_kv_name("svc", "")


def test_normalize_rejects_overlong_names():
    with pytest.raises(SecretSourceError, match="127"):
        normalize_kv_name("svc", "x" * 130)


# ----------------------------------------------------------------------
# fetch
# ----------------------------------------------------------------------

def test_fetch_returns_direct_secret(source, fake_client):
    fake_client.store["myservice--api-key"] = "s3cret-value"
    material = source.fetch("API_KEY", {})
    assert isinstance(material, DirectSecret)
    assert material.value == "s3cret-value"
    # base.py hard rule 3: repr never leaks the value.
    assert "s3cret-value" not in repr(material)
    assert "s3cret-value" not in str(material)


def test_fetch_missing_raises_not_found(source):
    with pytest.raises(SecretNotFoundError):
        source.fetch("NOPE", {})


def test_fetch_auth_failure_maps_to_source_error(source, fake_client):
    fake_client.auth_broken = True
    with pytest.raises(SecretSourceError) as excinfo:
        source.fetch("ANY", {})
    # Generic message; provider detail rides in __cause__ (base.py rule 5).
    assert "authentication" in str(excinfo.value)
    assert isinstance(excinfo.value.__cause__, ClientAuthenticationError)
    assert not isinstance(excinfo.value, SecretNotFoundError)


# ----------------------------------------------------------------------
# write / delete (WritableSecretSource protocol)
# ----------------------------------------------------------------------

def test_write_then_fetch_roundtrip(source):
    source.write("conn.provider", "tok-123")
    assert source.fetch("conn.provider", {}).value == "tok-123"


def test_write_records_comment_as_tag(source, fake_client):
    source.write("conn.provider", "tok-123", comment="rotated by test")
    assert fake_client.tags_seen["myservice--conn-provider"] == {
        "recto-comment": "rotated by test"
    }
    source.write("conn.other", "tok-456")
    assert fake_client.tags_seen["myservice--conn-other"] is None


def test_write_refuses_empty_value(source):
    with pytest.raises(SecretSourceError):
        source.write("conn.provider", "")


def test_delete_removes_and_is_idempotent(source):
    source.write("conn.provider", "tok-123")
    source.delete("conn.provider")
    with pytest.raises(SecretNotFoundError):
        source.fetch("conn.provider", {})
    # Second delete: no-op, parity with the file-backed store.
    source.delete("conn.provider")


def test_service_scoping_prevents_cross_service_reads(fake_client):
    a = AzureKeyVaultSource("ServiceA", secret_client=fake_client)
    b = AzureKeyVaultSource("ServiceB", secret_client=fake_client)
    a.write("shared-name", "a-value")
    b.write("shared-name", "b-value")
    assert a.fetch("shared-name", {}).value == "a-value"
    assert b.fetch("shared-name", {}).value == "b-value"


def test_satisfies_writable_secret_source_shape(source):
    # The connections substrate duck-types the WritableSecretSource
    # protocol: fetch / write / delete.
    for attr in ("fetch", "write", "delete"):
        assert callable(getattr(source, attr))


# ----------------------------------------------------------------------
# Registry + construction
# ----------------------------------------------------------------------

def test_registered_in_source_registry():
    assert "azure-keyvault" in registered_sources()


def test_factory_fails_loud_without_vault_url(monkeypatch):
    monkeypatch.delenv(VAULT_URL_ENV, raising=False)
    with pytest.raises(SecretSourceError, match=VAULT_URL_ENV):
        resolve_source("azure-keyvault", "MyService")


def test_constructor_rejects_empty_service():
    with pytest.raises(SecretSourceError):
        AzureKeyVaultSource("", secret_client=_FakeSecretClient())


def test_backend_selector_name(source):
    assert source.name == "azure-keyvault"
    assert source.service == "MyService"


# ----------------------------------------------------------------------
# Live arm (env-gated, operator-side only)
# ----------------------------------------------------------------------

@pytest.mark.skipif(
    not LIVE_URL,
    reason="RECTO_TEST_AZURE_KEYVAULT_URL not set -- live vault arm skipped",
)
def test_live_vault_roundtrip():
    src = AzureKeyVaultSource("recto-test", vault_url=LIVE_URL)
    name = f"live-{uuid.uuid4().hex[:8]}"
    try:
        src.write(name, "live-value", comment="recto live test")
        assert src.fetch(name, {}).value == "live-value"
    finally:
        src.delete(name)
