"""Tests for the Recto User Vault Substrate bootloader endpoints
(2026-07-25).

Exercises the full /v0.4/user-vault/* HTTP surface against a live
BootloaderHandler with an in-memory secret backend injected via the
``user_vault_secret_source_factory`` config seam (the production
DpapiMachineSource is Windows-only).

Auth model under test (deliberate divergence from connections: ALL four
verbs are agent-gated — the platform acts for its own user at runtime):
  - Every verb: agent-token-gated AND platform-scoped via
    user_vault_agent_platforms, plus an X-Recto-Subject scoping claim
    (the platform's opaque subject handle, 43 base64url characters - never
    a user id, hard rule 15.o) the platform supplies per request.
  - Disabled-by-default: no user_vault_path -> all routes 404. No
    agent->platform mapping -> 403. Missing/invalid subject claim -> 400.

Release contract under test: `status` field is "released" | "unset"
(the phone release-on-approval seam adds "pending"/"denied" later with
no contract change).
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any
from urllib import request as urlrequest
from urllib.error import HTTPError

import pytest

from recto.bootloader.server import ChallengeStore, create_server
from recto.bootloader.state import StateStore
from recto.secrets.base import DirectSecret, SecretMaterial, SecretNotFoundError
from recto.subject_handle import normalize_subject, subject_storage_id
from recto.user_vault.types import user_vault_secret_name


# ---------------------------------------------------------------------------
# In-memory secret backend double (per-platform), satisfies WritableSecretSource
# ---------------------------------------------------------------------------


class _MemoryVault:
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


# ---------------------------------------------------------------------------
# Live HTTP fixtures
# ---------------------------------------------------------------------------

AGENT_TOKENS = {
    "platform-a-agent": "platform-a-secret",
    "platform-b-agent": "platform-b-secret",
}
AGENT_PLATFORMS = {
    "platform-a-agent": "PlatformA",
    "platform-b-agent": "PlatformB",
}

# Opaque subject handles (43 base64url characters = 32 bytes), as a platform mints them.
USER_1 = "ERERERERERERERERERERERERERERERERERERERERERE"
USER_2 = "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo"


def _hdrs(agent: str = "a", user_id: str | None = USER_1) -> dict[str, str]:
    agent_id = f"platform-{agent}-agent"
    h = {
        "X-Recto-Agent-Id": agent_id,
        "X-Recto-Agent-Token": AGENT_TOKENS[agent_id],
    }
    if user_id is not None:
        h["X-Recto-Subject"] = user_id
    return h


def _spawn(
    tmp_path: Path,
    *,
    user_vault_enabled: bool = True,
    agent_platforms: dict[str, str] | None = None,
    vault: _MemoryVault | None = None,
):
    """Spin a real bootloader. Returns (ctx, shutdown_fn)."""
    state = StateStore(state_dir=tmp_path)
    mem = vault or _MemoryVault()
    server = create_server(
        bind_host="127.0.0.1",
        bind_port=0,
        state=state,
        bootloader_id="test-uv-bootloader",
        challenges=ChallengeStore(),
        ssl_context=None,
        capability_agent_tokens=AGENT_TOKENS,
        user_vault_path=(
            str(tmp_path / "user_vault.json") if user_vault_enabled else None
        ),
        user_vault_agent_platforms=(
            AGENT_PLATFORMS if agent_platforms is None else agent_platforms
        ),
        user_vault_secret_source_factory=mem.factory,
    )
    host, port = server.server_address
    base_url = f"http://{host}:{port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def shutdown() -> None:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)

    return {"base_url": base_url, "vault": mem}, shutdown


@pytest.fixture
def server(tmp_path: Path):
    ctx, shutdown = _spawn(tmp_path)
    try:
        yield ctx
    finally:
        shutdown()


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def _get(url: str, headers: dict[str, str] | None = None) -> tuple[int, dict[str, Any]]:
    req = urlrequest.Request(url, headers=headers or {}, method="GET")
    try:
        with urlrequest.urlopen(req, timeout=5.0) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


def _post(
    url: str, body: dict[str, Any], headers: dict[str, str] | None = None
) -> tuple[int, dict[str, Any]]:
    data = json.dumps(body).encode("utf-8")
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    req = urlrequest.Request(url, data=data, headers=h, method="POST")
    try:
        with urlrequest.urlopen(req, timeout=5.0) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


def _set(base: str, headers: dict[str, str], **body) -> tuple[int, dict[str, Any]]:
    return _post(f"{base}/v0.4/user-vault/set", body, headers)


# ===========================================================================
# Types unit coverage
# ===========================================================================


class TestTypes:
    def test_subject_is_returned_unchanged(self):
        assert normalize_subject(f"  {USER_2} ") == USER_2

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "11111111-2222-3333-4444-555555555555",  # a GUID: a user id, never a handle
            "not-a-handle",
            "E" * 42,  # too short
            "E" * 44,  # too long
            "ERERERERERERERERERERERERERERERERERERERERERE=",  # padded
            "ERERERERERERERERERERERERERERERERERERERERER+",  # not url-safe
            "ERERERERERERERERERERERERERERERERERERERERERF",  # non-canonical last character
            "../../../etc/passwd",
        ],
    )
    def test_subject_rejects_bad_shapes(self, bad):
        with pytest.raises(ValueError):
            normalize_subject(bad)

    def test_secret_name_uses_the_case_safe_storage_id(self):
        assert subject_storage_id(USER_1) == "11" * 32
        assert (
            user_vault_secret_name(USER_1, "anthropic")
            == f"uv.{'11' * 32}.anthropic"
        )

    def test_handles_differing_in_case_never_share_a_secret_name(self):
        upper = "EpXZrhv5IxZUwhMMC2A1kzotNyKvXnbm91Oe-gkJ054"
        lower = "ePxzRHV5iXzuWHmmc2a1KZOTnYkVxNBM91oE-GKj054"  # the same text with its case swapped
        assert normalize_subject(upper) and normalize_subject(lower)
        assert user_vault_secret_name(upper, "k") != user_vault_secret_name(lower, "k")


# ===========================================================================
# Disabled-by-default
# ===========================================================================


class TestDisabled:
    def test_all_routes_404_when_disabled(self, tmp_path):
        ctx, shutdown = _spawn(tmp_path, user_vault_enabled=False)
        try:
            base = ctx["base_url"]
            status, body = _get(f"{base}/v0.4/user-vault", _hdrs())
            assert (status, body["error"]) == (404, "unknown_endpoint")
            status, body = _get(
                f"{base}/v0.4/user-vault/release?key=k", _hdrs()
            )
            assert (status, body["error"]) == (404, "unknown_endpoint")
            status, body = _set(base, _hdrs(), key="k", secret="v")
            assert (status, body["error"]) == (404, "unknown_endpoint")
            status, body = _post(
                f"{base}/v0.4/user-vault/delete", {"key": "k"}, _hdrs()
            )
            assert (status, body["error"]) == (404, "unknown_endpoint")
        finally:
            shutdown()


# ===========================================================================
# Auth: agent token, platform mapping, user-id claim
# ===========================================================================


class TestAuth:
    def test_401_missing_agent_headers(self, server):
        status, body = _get(f"{server['base_url']}/v0.4/user-vault")
        assert status == 401
        assert body["error"] == "agent_auth_required"

    def test_401_bad_token(self, server):
        status, body = _get(
            f"{server['base_url']}/v0.4/user-vault",
            {
                "X-Recto-Agent-Id": "platform-a-agent",
                "X-Recto-Agent-Token": "wrong",
                "X-Recto-Subject": USER_1,
            },
        )
        assert status == 401
        assert body["error"] == "agent_auth_invalid"

    def test_403_agent_not_mapped(self, tmp_path):
        ctx, shutdown = _spawn(tmp_path, agent_platforms={})
        try:
            status, body = _get(f"{ctx['base_url']}/v0.4/user-vault", _hdrs())
            assert status == 403
            assert body["error"] == "agent_not_mapped"
        finally:
            shutdown()

    def test_400_missing_subject_claim(self, server):
        status, body = _get(
            f"{server['base_url']}/v0.4/user-vault", _hdrs(user_id=None)
        )
        assert status == 400
        assert body["error"] == "subject_required"

    def test_400_a_user_id_shaped_claim_is_refused(self, server):
        status, body = _get(
            f"{server['base_url']}/v0.4/user-vault",
            _hdrs(user_id="11111111-2222-3333-4444-555555555555"),
        )
        assert status == 400
        assert body["error"] == "subject_invalid"

    def test_writes_also_require_subject_claim(self, server):
        status, body = _set(
            server["base_url"], _hdrs(user_id=None), key="k", secret="v"
        )
        assert status == 400
        assert body["error"] == "subject_required"


# ===========================================================================
# Set -> list -> release round-trip (the canonical BYOK flow)
# ===========================================================================


class TestRoundTrip:
    def test_set_then_list_then_release(self, server):
        base = server["base_url"]
        status, body = _set(
            base,
            _hdrs(),
            key="anthropic",
            display_name="Anthropic API key",
            category="ai-provider",
            secret="sk-ant-test-value",
        )
        assert status == 200
        entry = body["entry"]
        assert entry["platform"] == "PlatformA"
        assert entry["subject"] == USER_1
        assert entry["key"] == "anthropic"
        assert entry["has_secret"] is True
        # The secret VALUE must NEVER appear in the metadata.
        assert "sk-ant-test-value" not in json.dumps(entry)

        # List: metadata only, never values.
        status, body = _get(f"{base}/v0.4/user-vault", _hdrs())
        assert status == 200
        assert body["platform"] == "PlatformA"
        assert body["subject"] == USER_1
        rows = {e["key"]: e for e in body["entries"]}
        assert rows["anthropic"]["has_secret"] is True
        assert "sk-ant-test-value" not in json.dumps(body)

        # Release: the live value at call time.
        status, body = _get(
            f"{base}/v0.4/user-vault/release?key=anthropic", _hdrs()
        )
        assert status == 200
        assert body["status"] == "released"
        assert body["has_value"] is True
        assert body["value"] == "sk-ant-test-value"
        assert body["subject"] == USER_1

    def test_release_unset_entry_status_unset(self, server):
        base = server["base_url"]
        # Metadata-only entry (no secret yet).
        _set(base, _hdrs(), key="openai", category="ai-provider")
        status, body = _get(
            f"{base}/v0.4/user-vault/release?key=openai", _hdrs()
        )
        assert status == 200
        assert body["status"] == "unset"
        assert body["has_value"] is False
        assert body["value"] is None

    def test_release_missing_key_query_is_400(self, server):
        status, body = _get(
            f"{server['base_url']}/v0.4/user-vault/release", _hdrs()
        )
        assert status == 400
        assert body["error"] == "bootloader_error"

    def test_release_key_normalized(self, server):
        base = server["base_url"]
        _set(base, _hdrs(), key="Anthropic", secret="v")
        status, body = _get(
            f"{base}/v0.4/user-vault/release?key=ANTHROPIC", _hdrs()
        )
        assert status == 200
        assert body["key"] == "anthropic"
        assert body["value"] == "v"

    def test_subject_claim_is_case_sensitive(self, server):
        base = server["base_url"]
        other = USER_2[:-1].upper() + "A"  # same length, another handle
        _set(base, _hdrs(user_id=USER_2), key="k", secret="v")
        status, body = _get(
            f"{base}/v0.4/user-vault/release?key=k", _hdrs(user_id=other)
        )
        assert status == 200
        assert body["status"] == "unset"
        status, body = _get(
            f"{base}/v0.4/user-vault/release?key=k", _hdrs(user_id=USER_2)
        )
        assert body["subject"] == USER_2
        assert body["value"] == "v"

    def test_value_shell_unsafe_chars_survive(self, server):
        base = server["base_url"]
        gnarly = "jTY85zf$EL6YyAhHJ^myByU#NcMuHy5qXLWLK7pC"
        _set(base, _hdrs(), key="gnarly", secret=gnarly)
        _, body = _get(f"{base}/v0.4/user-vault/release?key=gnarly", _hdrs())
        assert body["value"] == gnarly
        assert len(body["value"]) == 40


# ===========================================================================
# Scoping: user-to-user and platform-to-platform isolation
# ===========================================================================


class TestScoping:
    def test_users_isolated_within_platform(self, server):
        base = server["base_url"]
        _set(base, _hdrs(user_id=USER_1), key="anthropic", secret="user1-key")
        _set(base, _hdrs(user_id=USER_2), key="xai", secret="user2-key")

        _, u1 = _get(f"{base}/v0.4/user-vault", _hdrs(user_id=USER_1))
        _, u2 = _get(f"{base}/v0.4/user-vault", _hdrs(user_id=USER_2))
        assert {e["key"] for e in u1["entries"]} == {"anthropic"}
        assert {e["key"] for e in u2["entries"]} == {"xai"}

        # User 2's claim can't release user 1's value.
        _, body = _get(
            f"{base}/v0.4/user-vault/release?key=anthropic",
            _hdrs(user_id=USER_2),
        )
        assert body["status"] == "unset"
        assert body["value"] is None

    def test_platforms_isolated(self, server):
        base = server["base_url"]
        _set(base, _hdrs("a"), key="anthropic", secret="platform-a-value")
        # Platform B's agent, same user id + key: separate namespace.
        _, body = _get(
            f"{base}/v0.4/user-vault/release?key=anthropic", _hdrs("b")
        )
        assert body["platform"] == "PlatformB"
        assert body["status"] == "unset"
        _, lst = _get(f"{base}/v0.4/user-vault", _hdrs("b"))
        assert lst["entries"] == []


# ===========================================================================
# Mutations: rotate, metadata-only edit, delete
# ===========================================================================


class TestMutations:
    def test_rotate_bumps_rotated_at_preserves_created(self, server):
        base = server["base_url"]
        _, first = _set(base, _hdrs(), key="k", secret="v1")
        created = first["entry"]["created_at_unix"]
        rotated1 = first["entry"]["rotated_at_unix"]
        import time as _t

        _t.sleep(1.1)
        _, second = _set(base, _hdrs(), key="k", secret="v2")
        assert second["entry"]["created_at_unix"] == created
        assert second["entry"]["rotated_at_unix"] > rotated1
        _, rel = _get(f"{base}/v0.4/user-vault/release?key=k", _hdrs())
        assert rel["value"] == "v2"

    def test_metadata_edit_without_secret_preserves_value(self, server):
        base = server["base_url"]
        _set(base, _hdrs(), key="k", secret="keepme")
        status, body = _set(base, _hdrs(), key="k", display_name="Renamed")
        assert status == 200
        assert body["entry"]["display_name"] == "Renamed"
        assert body["entry"]["has_secret"] is True
        _, rel = _get(f"{base}/v0.4/user-vault/release?key=k", _hdrs())
        assert rel["value"] == "keepme"

    def test_empty_secret_treated_as_no_clobber(self, server):
        base = server["base_url"]
        _set(base, _hdrs(), key="k", secret="keepme")
        _set(base, _hdrs(), key="k", secret="")
        _, rel = _get(f"{base}/v0.4/user-vault/release?key=k", _hdrs())
        assert rel["value"] == "keepme"

    def test_set_requires_key(self, server):
        status, body = _set(server["base_url"], _hdrs(), secret="v")
        assert status == 400

    def test_delete_removes_metadata_and_value(self, server):
        base = server["base_url"]
        _set(base, _hdrs(), key="k", secret="v")
        status, body = _post(
            f"{base}/v0.4/user-vault/delete", {"key": "k"}, _hdrs()
        )
        assert status == 200
        assert body["deleted"] is True
        _, lst = _get(f"{base}/v0.4/user-vault", _hdrs())
        assert lst["entries"] == []
        _, rel = _get(f"{base}/v0.4/user-vault/release?key=k", _hdrs())
        assert rel["status"] == "unset"
        # Backend truly empty for this entry.
        assert (
            "PlatformA",
            user_vault_secret_name(USER_1, "k"),
        ) not in server["vault"].data

    def test_delete_idempotent(self, server):
        status, body = _post(
            f"{server['base_url']}/v0.4/user-vault/delete",
            {"key": "never-existed"},
            _hdrs(),
        )
        assert status == 200
        assert body["deleted"] is False
        assert body["entry"] is None


# ===========================================================================
# Persistence: metadata survives a bootloader restart
# ===========================================================================


class TestPersistence:
    def test_entries_survive_restart(self, tmp_path):
        mem = _MemoryVault()
        ctx, shutdown = _spawn(tmp_path, vault=mem)
        _set(ctx["base_url"], _hdrs(), key="anthropic", secret="durable")
        shutdown()

        ctx, shutdown = _spawn(tmp_path, vault=mem)
        try:
            _, lst = _get(f"{ctx['base_url']}/v0.4/user-vault", _hdrs())
            assert {e["key"] for e in lst["entries"]} == {"anthropic"}
            _, rel = _get(
                f"{ctx['base_url']}/v0.4/user-vault/release?key=anthropic",
                _hdrs(),
            )
            assert rel["value"] == "durable"
        finally:
            shutdown()
