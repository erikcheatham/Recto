"""Tests for the Recto Connections Substrate bootloader endpoints
(2026-06-13).

Exercises the full /v0.4/connections/* HTTP surface against a live
BootloaderHandler with an in-memory secret backend injected via the
``connections_secret_source_factory`` config seam (the production
DpapiMachineSource is Windows-only).

Auth model under test:
  - READS  (GET /connections, GET /connections/secret): agent-token-gated
    AND service-scoped via connections_agent_services. A consumer reads
    only its own service's connections.
  - WRITES (POST /connections, /connections/enable, /connections/delete):
    operator-token-gated via capability_operator_token.

Disabled-by-default: no connections_path -> all routes 404. No operator
token -> write routes 404. No agent->service mapping -> reads 403.
"""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Any
from urllib import request as urlrequest
from urllib.error import HTTPError

import pytest

from recto.bootloader.server import (
    ChallengeStore,
    _connection_key_matches,
    create_server,
)
from recto.bootloader.state import StateStore
from recto.secrets.base import DirectSecret, SecretMaterial, SecretNotFoundError


# ---------------------------------------------------------------------------
# In-memory secret backend double (per-service), satisfies WritableSecretSource
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

AGENT_TOKENS = {"service-a-agent": "agent-secret", "service-b-agent": "serviceb-secret"}
AGENT_SERVICES = {"service-a-agent": "ServiceA", "service-b-agent": "ServiceB"}
OPERATOR_TOKEN = "op-root-token"

SVC_A_HDR = {
    "X-Recto-Agent-Id": "service-a-agent",
    "X-Recto-Agent-Token": "agent-secret",
}
SVC_B_HDR = {
    "X-Recto-Agent-Id": "service-b-agent",
    "X-Recto-Agent-Token": "serviceb-secret",
}
OP_HDR = {"X-Recto-Operator-Token": OPERATOR_TOKEN}


def _spawn(
    tmp_path: Path,
    *,
    connections_enabled: bool = True,
    operator_token: str | None = OPERATOR_TOKEN,
    vault: _MemoryVault | None = None,
    agent_keys: dict[str, list[str]] | None = None,
    enforce_key_acl: bool | None = None,
):
    """Spin a real bootloader. Returns (ctx, shutdown_fn).

    enforce_key_acl=None means DO NOT PASS IT -- the server's own default
    applies, so a test that says nothing exercises the SHIPPED posture.
    This used to default to False, mirroring the production default of the
    day; when production flipped to enforcing on 2026-08-09 that mirror
    would have quietly kept every unspecified test on the retired setting.
    A helper that restates a default is a second copy of it, and the two
    only agree until one moves.
    """
    state = StateStore(state_dir=tmp_path)
    mem = vault or _MemoryVault()
    server = create_server(
        bind_host="127.0.0.1",
        bind_port=0,
        state=state,
        bootloader_id="test-conn-bootloader",
        challenges=ChallengeStore(),
        ssl_context=None,
        capability_agent_tokens=AGENT_TOKENS,
        capability_operator_token=operator_token,
        connections_path=(
            str(tmp_path / "connections.json") if connections_enabled else None
        ),
        connections_agent_services=AGENT_SERVICES,
        connections_agent_keys=agent_keys,
        connections_secret_source_factory=mem.factory,
        **(
            {} if enforce_key_acl is None
            else {"connections_key_acl_enforce": enforce_key_acl}
        ),
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


# Keys the shared-fixture tests actually read. GRANTED EXPLICITLY, not
# wildcarded: these tests are about upsert/read/rotate/delete mechanics, not
# about the ACL -- but "not about the ACL" is a reason to grant the permission,
# never a reason to run without one.
#
# Until 2026-08-09 this fixture granted nothing and the tests passed anyway,
# because the ACL defaulted to AUDIT and served every unlisted key with a
# warning. So a whole class of round-trip tests had never once exercised an
# ALLOWED read -- they exercised an unallowlisted read that the gate declined
# to stop. Flipping the default to enforce turned 8 of them red, which is the
# gate reporting, on its first real execution, that the coverage it was
# credited with did not exist. That is the finding, not the breakage.
#
# '*' would have made them green in one character and taught the fixture to
# hand out the allow-all escape hatch. A test that adds a key now gets a 403
# and must name it here -- which is exactly what production would do.
FIXTURE_AGENT_KEYS = {
    # "definitely-not-registered" / "cloudflare" are allowlisted but never
    # upserted: the VAULT #11 404 tests need the ACL to pass so the
    # EXISTENCE gate (not the ACL) is what refuses. Gate order is
    # ACL -> existence, so a denied key discloses nothing, not even
    # whether it exists.
    "service-a-agent": [
        "podcastindex", "PodcastIndex", "watchmode", "alpaca", "k",
        "definitely-not-registered", "cloudflare",
    ],
    "service-b-agent": ["podcastindex", "PodcastIndex", "watchmode", "alpaca", "k"],
}


@pytest.fixture
def server(tmp_path: Path):
    ctx, shutdown = _spawn(tmp_path, agent_keys=FIXTURE_AGENT_KEYS)
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


def _upsert(base: str, **body) -> tuple[int, dict[str, Any]]:
    return _post(f"{base}/v0.4/connections", body, OP_HDR)


# ===========================================================================
# Disabled-by-default
# ===========================================================================


class TestDisabled:
    def test_list_404_when_connections_disabled(self, tmp_path):
        ctx, shutdown = _spawn(tmp_path, connections_enabled=False)
        try:
            status, body = _get(f"{ctx['base_url']}/v0.4/connections", SVC_A_HDR)
            assert status == 404
            assert body["error"] == "unknown_endpoint"
        finally:
            shutdown()

    def test_upsert_404_when_no_operator_token(self, tmp_path):
        ctx, shutdown = _spawn(tmp_path, operator_token=None)
        try:
            status, body = _post(
                f"{ctx['base_url']}/v0.4/connections",
                {"service": "ServiceA", "key": "podcastindex"},
                OP_HDR,
            )
            assert status == 404
            assert body["error"] == "unknown_endpoint"
        finally:
            shutdown()


# ===========================================================================
# Read auth (agent-token + service scoping)
# ===========================================================================


class TestReadAuth:
    def test_list_401_missing_headers(self, server):
        status, body = _get(f"{server['base_url']}/v0.4/connections")
        assert status == 401
        assert body["error"] == "agent_auth_required"

    def test_list_401_bad_token(self, server):
        status, body = _get(
            f"{server['base_url']}/v0.4/connections",
            {"X-Recto-Agent-Id": "service-a-agent", "X-Recto-Agent-Token": "wrong"},
        )
        assert status == 401
        assert body["error"] == "agent_auth_invalid"

    def test_list_403_agent_not_mapped(self, tmp_path):
        # Valid agent token but no connections_agent_services entry.
        state = StateStore(state_dir=tmp_path)
        server = create_server(
            bind_host="127.0.0.1",
            bind_port=0,
            state=state,
            bootloader_id="test",
            challenges=ChallengeStore(),
            ssl_context=None,
            capability_agent_tokens={"lonely-agent": "tok"},
            connections_path=str(tmp_path / "connections.json"),
            connections_agent_services={},  # nobody mapped
            connections_secret_source_factory=_MemoryVault().factory,
        )
        host, port = server.server_address
        base = f"http://{host}:{port}"
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            status, body = _get(
                f"{base}/v0.4/connections",
                {"X-Recto-Agent-Id": "lonely-agent", "X-Recto-Agent-Token": "tok"},
            )
            assert status == 403
            assert body["error"] == "agent_not_mapped"
        finally:
            server.shutdown()
            server.server_close()
            t.join(timeout=5.0)


# ===========================================================================
# Write auth (operator-token)
# ===========================================================================


class TestWriteAuth:
    def test_upsert_401_missing_operator_token(self, server):
        status, body = _post(
            f"{server['base_url']}/v0.4/connections",
            {"service": "ServiceA", "key": "podcastindex"},
        )
        assert status == 401
        assert body["error"] == "operator_token_required"

    def test_upsert_401_bad_operator_token(self, server):
        status, body = _post(
            f"{server['base_url']}/v0.4/connections",
            {"service": "ServiceA", "key": "podcastindex"},
            {"X-Recto-Operator-Token": "nope"},
        )
        assert status == 401
        assert body["error"] == "operator_token_invalid"


# ===========================================================================
# Upsert + read round-trip (the canonical flow)
# ===========================================================================


class TestUpsertReadRoundTrip:
    def test_create_then_list_then_read_secret(self, server):
        base = server["base_url"]
        # Operator creates the Podcast Index connection: apiKey in config
        # (cleartext HMAC identifier), secret in the vault.
        status, body = _upsert(
            base,
            service="ServiceA",
            key="podcastindex",
            display_name="Podcast Index",
            category="podcasts",
            secret="the-hmac-secret",
            config={"api_key": "PUBLIC_APIKEY_ID"},
            health_url="https://api.podcastindex.org/api/1.0/stats/current",
        )
        assert status == 200
        meta = body["connection"]
        assert meta["service"] == "ServiceA"
        assert meta["key"] == "podcastindex"
        assert meta["has_secret"] is True
        # The secret VALUE must NEVER appear in the metadata.
        assert "the-hmac-secret" not in json.dumps(meta)
        assert meta["config"]["api_key"] == "PUBLIC_APIKEY_ID"

        # Consumer lists its own service's connections (secret-free).
        status, body = _get(f"{base}/v0.4/connections", SVC_A_HDR)
        assert status == 200
        assert body["service"] == "ServiceA"
        rows = {c["key"]: c for c in body["connections"]}
        assert rows["podcastindex"]["has_secret"] is True
        assert rows["podcastindex"]["config"]["api_key"] == "PUBLIC_APIKEY_ID"
        assert "the-hmac-secret" not in json.dumps(body)

        # Consumer reads the live secret value at call-time.
        status, body = _get(
            f"{base}/v0.4/connections/secret?key=podcastindex", SVC_A_HDR
        )
        assert status == 200
        assert body["service"] == "ServiceA"
        assert body["key"] == "podcastindex"
        assert body["has_value"] is True
        assert body["value"] == "the-hmac-secret"

    def test_secret_read_preserves_shell_unsafe_chars(self, server):
        # The architectural reason keys go through the vault: $ ^ # survive
        # byte-exact because the value travels as a JSON string, never a
        # shell env var.
        base = server["base_url"]
        gnarly = "jTY85zf$EL6YyAhHJ^myByU#NcMuHy5qXLWLK7pC"
        _upsert(base, service="ServiceA", key="podcastindex", secret=gnarly)
        status, body = _get(
            f"{base}/v0.4/connections/secret?key=podcastindex", SVC_A_HDR
        )
        assert status == 200
        assert body["value"] == gnarly
        assert len(body["value"]) == 40

    def test_secret_read_key_normalized(self, server):
        base = server["base_url"]
        _upsert(base, service="ServiceA", key="PodcastIndex", secret="v")
        # Reader passes a differently-cased key; normalization lands it.
        status, body = _get(
            f"{base}/v0.4/connections/secret?key=PODCASTINDEX", SVC_A_HDR
        )
        assert status == 200
        assert body["key"] == "podcastindex"
        assert body["value"] == "v"

    def test_secret_read_missing_key_query_is_400(self, server):
        status, body = _get(f"{server['base_url']}/v0.4/connections/secret", SVC_A_HDR)
        assert status == 400
        assert body["error"] == "bootloader_error"

    def test_secret_read_unset_value_has_value_false(self, server):
        base = server["base_url"]
        # Register metadata WITHOUT a secret (operator just toggling config).
        # REGISTERED-but-unset is the one case that stays 200: it is an
        # honest "exists, no value yet" (rotation in flight). Contrast
        # test_secret_read_unknown_key_is_404 below.
        _upsert(base, service="ServiceA", key="watchmode", category="streaming")
        status, body = _get(
            f"{base}/v0.4/connections/secret?key=watchmode", SVC_A_HDR
        )
        assert status == 200
        assert body["has_value"] is False
        assert body["value"] is None

    def test_secret_read_unknown_key_is_404(self, server):
        """VAULT #11 red-build (2026-08-13): an UNREGISTERED key must 404,
        never 200+null. Before the existence gate, ANY key -- including
        against a completely empty store -- returned 200 with value:null,
        so vault reads lied: a consumer could not tell a missing key from
        an unset value, and an emptied store looked healthy to every
        caller. `required: False` guards absence of a VALUE, not nonsense.
        """
        base = server["base_url"]
        status, body = _get(
            f"{base}/v0.4/connections/secret?key=definitely-not-registered",
            SVC_A_HDR,
        )
        assert status == 404
        assert body["error"] == "unknown_connection"
        assert "value" not in body

    def test_secret_read_empty_store_is_404_for_every_key(self, server):
        """The empty-store half of the #11 falsifier: with ZERO entries
        registered, every key 404s -- the store being empty is LOUD at the
        read path instead of a silent 200+null costume."""
        base = server["base_url"]
        # No _upsert calls: the store in this fixture starts empty.
        _, listing = _get(f"{base}/v0.4/connections", SVC_A_HDR)
        assert listing["connections"] == []
        status, body = _get(
            f"{base}/v0.4/connections/secret?key=cloudflare", SVC_A_HDR
        )
        assert status == 404
        assert body["error"] == "unknown_connection"


# ===========================================================================
# Service scoping — a consumer never sees another service's connections
# ===========================================================================


class TestServiceScoping:
    def test_list_only_returns_own_service(self, server):
        base = server["base_url"]
        _upsert(base, service="ServiceA", key="podcastindex", secret="a")
        _upsert(base, service="ServiceB", key="alpaca", secret="b")

        _, servicea = _get(f"{base}/v0.4/connections", SVC_A_HDR)
        _, serviceb = _get(f"{base}/v0.4/connections", SVC_B_HDR)

        service_a_keys = {c["key"] for c in servicea["connections"]}
        service_b_keys = {c["key"] for c in serviceb["connections"]}
        assert service_a_keys == {"podcastindex"}
        assert service_b_keys == {"alpaca"}

    def test_secret_read_scoped_to_own_service(self, server):
        base = server["base_url"]
        _upsert(base, service="ServiceB", key="alpaca", secret="serviceb-secret-value")
        # ServiceA's agent tries to read a key that only exists under
        # ServiceB. It resolves in its OWN service namespace (ServiceA),
        # where the key is not registered -> 404 (was 200+null before the
        # 2026-08-13 existence gate; scoping is unchanged, only honesty).
        status, body = _get(
            f"{base}/v0.4/connections/secret?key=alpaca", SVC_A_HDR
        )
        assert status == 404
        assert body["error"] == "unknown_connection"
        # ServiceB's own agent reads it fine.
        status, body = _get(f"{base}/v0.4/connections/secret?key=alpaca", SVC_B_HDR)
        assert status == 200
        assert body["value"] == "serviceb-secret-value"


# ===========================================================================
# Rotate / metadata-edit / enable / delete
# ===========================================================================


class TestMutations:
    def test_rotate_bumps_rotated_at_preserves_created(self, server):
        base = server["base_url"]
        _, first = _upsert(base, service="ServiceA", key="k", secret="v1")
        created = first["connection"]["created_at_unix"]
        rotated1 = first["connection"]["rotated_at_unix"]
        import time as _t

        _t.sleep(1.1)
        _, second = _upsert(base, service="ServiceA", key="k", secret="v2")
        assert second["connection"]["created_at_unix"] == created
        assert second["connection"]["rotated_at_unix"] > rotated1
        # New value is live.
        _, sec = _get(f"{base}/v0.4/connections/secret?key=k", SVC_A_HDR)
        assert sec["value"] == "v2"

    def test_metadata_edit_without_secret_preserves_value(self, server):
        base = server["base_url"]
        _upsert(base, service="ServiceA", key="k", secret="keepme")
        # Edit display_name only; secret omitted -> value untouched.
        status, body = _upsert(
            base, service="ServiceA", key="k", display_name="Renamed"
        )
        assert status == 200
        assert body["connection"]["display_name"] == "Renamed"
        assert body["connection"]["has_secret"] is True
        _, sec = _get(f"{base}/v0.4/connections/secret?key=k", SVC_A_HDR)
        assert sec["value"] == "keepme"

    def test_enable_toggle(self, server):
        base = server["base_url"]
        _upsert(base, service="ServiceA", key="k", secret="v")
        status, body = _post(
            f"{base}/v0.4/connections/enable",
            {"service": "ServiceA", "key": "k", "enabled": False},
            OP_HDR,
        )
        assert status == 200
        assert body["connection"]["enabled"] is False
        # Re-enable.
        status, body = _post(
            f"{base}/v0.4/connections/enable",
            {"service": "ServiceA", "key": "k", "enabled": True},
            OP_HDR,
        )
        assert body["connection"]["enabled"] is True

    def test_enable_bad_body_is_400(self, server):
        status, body = _post(
            f"{server['base_url']}/v0.4/connections/enable",
            {"service": "ServiceA", "key": "k"},  # missing enabled
            OP_HDR,
        )
        assert status == 400

    def test_enable_requires_operator_token(self, server):
        status, body = _post(
            f"{server['base_url']}/v0.4/connections/enable",
            {"service": "ServiceA", "key": "k", "enabled": True},
        )
        assert status == 401

    def test_delete_removes_metadata_and_value(self, server):
        base = server["base_url"]
        _upsert(base, service="ServiceA", key="k", secret="v")
        status, body = _post(
            f"{base}/v0.4/connections/delete",
            {"service": "ServiceA", "key": "k"},
            OP_HDR,
        )
        assert status == 200
        assert body["deleted"] is True
        # Metadata gone.
        _, lst = _get(f"{base}/v0.4/connections", SVC_A_HDR)
        assert lst["connections"] == []
        # Value unreadable -- and since the 2026-08-13 existence gate, a
        # deleted connection 404s like any other unregistered key (it was
        # 200 has_value:false before, the fail-open #11 closed).
        status, sec = _get(f"{base}/v0.4/connections/secret?key=k", SVC_A_HDR)
        assert status == 404
        assert sec["error"] == "unknown_connection"

    def test_delete_idempotent(self, server):
        base = server["base_url"]
        status, body = _post(
            f"{base}/v0.4/connections/delete",
            {"service": "ServiceA", "key": "never-existed"},
            OP_HDR,
        )
        assert status == 200
        assert body["deleted"] is False
        assert body["connection"] is None

    def test_upsert_requires_service_and_key(self, server):
        status, body = _post(
            f"{server['base_url']}/v0.4/connections", {"key": "k"}, OP_HDR
        )
        assert status == 400


# ===========================================================================
# Per-key allowlist on the secret VALUE read (2026-07-28)
#
# The service map answers "whose keys?"; this gate answers "which of
# them?". Without it an agent token mapped to a service can read every
# secret in that service's namespace -- for a platform service, that is
# its AI-provider, payment, edge and push credentials at once.
#
# Two modes: AUDIT (default -- log the denial, allow the read, so an
# operator can discover the live key set) and ENFORCE (403).
# ===========================================================================


class TestKeyPatternMatching:
    """Unit-level: the pattern vocabulary is deliberately tiny."""

    @pytest.mark.parametrize(
        "pattern,key,expected",
        [
            ("anthropic", "anthropic", True),
            ("anthropic", "anthropic-2", False),
            ("anthropic", "xai", False),
            ("*", "anything-at-all", True),
            ("media-*", "media-spotify", True),
            ("media-*", "media-", True),
            ("media-*", "spotify", False),
            ("ANTHROPIC", "anthropic", True),   # patterns fold case
            ("  anthropic  ", "anthropic", True),  # and tolerate padding
            ("", "anthropic", False),
            ("   ", "anthropic", False),
        ],
    )
    def test_matches(self, pattern, key, expected):
        assert _connection_key_matches(pattern, key) is expected


class TestKeyAclDefaultPosture:
    """The VAULT crossing test, asserted against the SHIPPED default.

    Every test in TestKeyAclEnforcing passes enforce_key_acl=True explicitly,
    so between them they proved the gate WORKS and said nothing about whether
    it is ON. Until 2026-08-09 it was not: the default was audit, an unlisted
    key was served with a warning, and the suite was green throughout --
    because no test had ever asked the one question that mattered.

    A boundary is only enforced if it is enforced BY DEFAULT, so that is what
    this asserts, and it deliberately passes NO acl argument at all. If the
    default is ever flipped back, this reddens.
    """

    def test_default_config_refuses_an_unlisted_key(self, tmp_path):
        # No enforce flag, no allowlist -- the posture a fresh install gets.
        ctx, shutdown = _spawn(tmp_path)
        try:
            base = ctx["base_url"]
            _upsert(base, service="ServiceA", key="stripe", secret="sk-live-money")
            status, body = _get(
                f"{base}/v0.4/connections/secret?key=stripe", SVC_A_HDR
            )
            assert status == 403, (
                "the per-key ACL must ENFORCE by default; a valid token asking "
                "for an unlisted key has to be refused, not served"
            )
            assert body["error"] == "key_not_allowed"
            # The refusal must not leak what it refused to hand over.
            assert "sk-live-money" not in json.dumps(body)
        finally:
            shutdown()

    def test_default_config_allows_an_allowlisted_key(self, tmp_path):
        # The other half: enforcing-by-default must not mean refusing everything.
        # Without this, test_default_config_refuses_an_unlisted_key would still
        # pass against a bootloader that had simply broken secret reads.
        ctx, shutdown = _spawn(
            tmp_path, agent_keys={"service-a-agent": ["anthropic"]}
        )
        try:
            base = ctx["base_url"]
            _upsert(base, service="ServiceA", key="anthropic", secret="sk-real")
            status, body = _get(
                f"{base}/v0.4/connections/secret?key=anthropic", SVC_A_HDR
            )
            assert status == 200
            assert body["value"] == "sk-real"
        finally:
            shutdown()


class TestKeyAclEnforcing:
    def test_allowlisted_key_reads(self, tmp_path):
        ctx, shutdown = _spawn(
            tmp_path,
            agent_keys={"service-a-agent": ["anthropic"]},
            enforce_key_acl=True,
        )
        try:
            base = ctx["base_url"]
            _upsert(base, service="ServiceA", key="anthropic", secret="sk-real")
            status, body = _get(
                f"{base}/v0.4/connections/secret?key=anthropic", SVC_A_HDR
            )
            assert status == 200
            assert body["value"] == "sk-real"
        finally:
            shutdown()

    def test_non_allowlisted_key_403s(self, tmp_path):
        ctx, shutdown = _spawn(
            tmp_path,
            agent_keys={"service-a-agent": ["anthropic"]},
            enforce_key_acl=True,
        )
        try:
            base = ctx["base_url"]
            _upsert(base, service="ServiceA", key="stripe", secret="sk-live-money")
            status, body = _get(
                f"{base}/v0.4/connections/secret?key=stripe", SVC_A_HDR
            )
            assert status == 403
            assert body["error"] == "key_not_allowed"
            # The denial must not leak the value it refused to serve.
            assert "sk-live-money" not in json.dumps(body)
        finally:
            shutdown()

    def test_unmapped_agent_reads_nothing(self, tmp_path):
        """Default-deny: authenticated, service-mapped, but absent from the
        key map -> no secret at all."""
        ctx, shutdown = _spawn(tmp_path, agent_keys={}, enforce_key_acl=True)
        try:
            base = ctx["base_url"]
            _upsert(base, service="ServiceA", key="anthropic", secret="sk-real")
            status, body = _get(
                f"{base}/v0.4/connections/secret?key=anthropic", SVC_A_HDR
            )
            assert status == 403
            assert body["error"] == "key_not_allowed"
        finally:
            shutdown()

    def test_prefix_pattern_admits_family(self, tmp_path):
        ctx, shutdown = _spawn(
            tmp_path,
            agent_keys={"service-a-agent": ["media-*"]},
            enforce_key_acl=True,
        )
        try:
            base = ctx["base_url"]
            _upsert(base, service="ServiceA", key="media-spotify", secret="v1")
            _upsert(base, service="ServiceA", key="cloudflare", secret="v2")
            ok_status, ok_body = _get(
                f"{base}/v0.4/connections/secret?key=media-spotify", SVC_A_HDR
            )
            assert ok_status == 200
            assert ok_body["value"] == "v1"
            deny_status, _ = _get(
                f"{base}/v0.4/connections/secret?key=cloudflare", SVC_A_HDR
            )
            assert deny_status == 403
        finally:
            shutdown()

    def test_wildcard_escape_hatch_allows_all(self, tmp_path):
        ctx, shutdown = _spawn(
            tmp_path,
            agent_keys={"service-a-agent": ["*"]},
            enforce_key_acl=True,
        )
        try:
            base = ctx["base_url"]
            _upsert(base, service="ServiceA", key="stripe", secret="sk-live")
            status, body = _get(
                f"{base}/v0.4/connections/secret?key=stripe", SVC_A_HDR
            )
            assert status == 200
            assert body["value"] == "sk-live"
        finally:
            shutdown()

    def test_acl_does_not_cross_agents(self, tmp_path):
        """B's allowlist must not admit A. Guards against a check that
        reads the map by service (shared) rather than by agent."""
        ctx, shutdown = _spawn(
            tmp_path,
            agent_keys={"service-b-agent": ["anthropic"]},
            enforce_key_acl=True,
        )
        try:
            base = ctx["base_url"]
            _upsert(base, service="ServiceA", key="anthropic", secret="a-secret")
            status, _ = _get(
                f"{base}/v0.4/connections/secret?key=anthropic", SVC_A_HDR
            )
            assert status == 403
        finally:
            shutdown()

    def test_case_and_padding_normalized_before_the_gate(self, tmp_path):
        """The key normalizes BEFORE the allowlist check, so casing can't
        walk around a pattern."""
        ctx, shutdown = _spawn(
            tmp_path,
            agent_keys={"service-a-agent": ["anthropic"]},
            enforce_key_acl=True,
        )
        try:
            base = ctx["base_url"]
            _upsert(base, service="ServiceA", key="anthropic", secret="sk-real")
            status, body = _get(
                f"{base}/v0.4/connections/secret?key=ANTHROPIC", SVC_A_HDR
            )
            assert status == 200
            assert body["key"] == "anthropic"
        finally:
            shutdown()

    def test_list_metadata_is_not_filtered(self, tmp_path):
        """Deliberate scope line: the ACL gates VALUES, not discovery.
        Metadata is secret-free and stays whole."""
        ctx, shutdown = _spawn(
            tmp_path,
            agent_keys={"service-a-agent": ["anthropic"]},
            enforce_key_acl=True,
        )
        try:
            base = ctx["base_url"]
            _upsert(base, service="ServiceA", key="anthropic", secret="v1")
            _upsert(base, service="ServiceA", key="stripe", secret="v2")
            status, body = _get(f"{base}/v0.4/connections", SVC_A_HDR)
            assert status == 200
            keys = sorted(c["key"] for c in body["connections"])
            assert keys == ["anthropic", "stripe"]
        finally:
            shutdown()


class TestKeyAclAuditMode:
    """AUDIT MODE, EXPLICITLY ENABLED. Not the default -- see
    TestKeyAclDefaultPosture, which owns that question.

    The docstring on the first test here used to open with 'Default posture:'
    and then assert that an unlisted key comes back with its value. That made
    it a green test PINNING a crossed boundary: the suite passed *because* the
    gate was off, and read as though that were the intended shipped state.
    Audit mode is still a real, wanted capability -- it is how an operator
    discovers which keys a running system actually reads, including keys no
    static scan can enumerate. What it is not, and never should have been
    described as, is the default.
    """

    def test_audit_mode_allows_and_warns(self, tmp_path, caplog):
        """With audit EXPLICITLY enabled: the read succeeds, and the
        denial-that-would-have-been is on the record."""
        ctx, shutdown = _spawn(
            tmp_path,
            agent_keys={"service-a-agent": ["anthropic"]},
            enforce_key_acl=False,   # explicit opt-OUT of the enforcing default
        )
        try:
            base = ctx["base_url"]
            _upsert(base, service="ServiceA", key="stripe", secret="sk-live")
            with caplog.at_level(
                logging.WARNING, logger="recto.bootloader.connections"
            ):
                status, body = _get(
                    f"{base}/v0.4/connections/secret?key=stripe", SVC_A_HDR
                )
            assert status == 200
            assert body["value"] == "sk-live"
            assert any(
                "AUDIT" in r.getMessage() and "stripe" in r.getMessage()
                for r in caplog.records
            )
        finally:
            shutdown()

    def test_admitted_read_emits_an_info_line(self, tmp_path, caplog):
        """GATE 0b falsifier. An ADMITTED read must leave evidence.

        Until 2026-08-17 the allowed branch returned True with NO logging at
        all, while the denied branch warned. So the audit trail could show what
        was MISSING from an allowlist and never what was UNUSED in one -- and
        AN ALLOWLIST THAT CANNOT SHOW ITS OWN DEAD ENTRIES CAN ONLY EVER GROW.
        That is fatal to least-privilege, whose entire job is removal.

        It also made the enforcement rollout unverifiable. The plan was 'add
        the measured key set, observe one window, then enforce' -- but the
        moment a key is added its reads go silent, so the window reports
        nothing whether the set was right or wrong, and the only remaining
        feedback is breakage in production.

        INFO rather than DEBUG deliberately: this has to survive a default
        logging configuration or it is not evidence.
        """
        ctx, shutdown = _spawn(
            tmp_path, agent_keys={"service-a-agent": ["stripe"]},
        )
        try:
            base = ctx["base_url"]
            _upsert(base, service="ServiceA", key="stripe", secret="sk-live")
            with caplog.at_level(
                logging.INFO, logger="recto.bootloader.connections"
            ):
                status, body = _get(
                    f"{base}/v0.4/connections/secret?key=stripe", SVC_A_HDR
                )
            assert status == 200
            assert body["value"] == "sk-live"

            admitted = [
                r.getMessage() for r in caplog.records
                if r.levelno == logging.INFO
            ]
            assert admitted, "an admitted read produced no evidence at all"
            msg = " ".join(admitted)
            # agent, key AND service: an audit line missing any one of the
            # three cannot answer "who read what, where".
            assert "service-a-agent" in msg
            assert "stripe" in msg
            assert "ServiceA" in msg
        finally:
            shutdown()

    def test_admitted_read_does_not_log_the_secret_value(self, tmp_path, caplog):
        """The new INFO line is held to the same rule as the WARNING one.

        A log line added to improve auditability is a new place for a secret
        to escape; adding evidence must not cost confidentiality.
        """
        ctx, shutdown = _spawn(
            tmp_path, agent_keys={"service-a-agent": ["stripe"]},
        )
        try:
            base = ctx["base_url"]
            _upsert(base, service="ServiceA", key="stripe", secret="sk-live-XYZ")
            with caplog.at_level(
                logging.INFO, logger="recto.bootloader.connections"
            ):
                _get(f"{base}/v0.4/connections/secret?key=stripe", SVC_A_HDR)
            assert not any(
                "sk-live-XYZ" in r.getMessage() for r in caplog.records
            )
        finally:
            shutdown()

    def test_granted_traffic_is_distinguishable_from_no_traffic(
        self, tmp_path, caplog
    ):
        """The falsifier stated exactly: a window containing only GRANTED
        traffic must not look identical to a window containing NONE.

        This is the property the gate lacked, and it is the general rule the
        estate arrived at on 2026-08-17 after finding the same shape three
        times in a day: AN INSTRUMENT MUST REPORT THE BOUNDARY OF WHAT IT
        EXAMINED. Absence of a finding is evidence only when the instrument
        could have found one.
        """
        ctx, shutdown = _spawn(
            tmp_path, agent_keys={"service-a-agent": ["stripe"]},
        )
        try:
            base = ctx["base_url"]
            _upsert(base, service="ServiceA", key="stripe", secret="sk-live")

            # COUNT ONLY THIS LANE'S RECORDS. `caplog.at_level(..., logger=X)`
            # sets the LEVEL on X; it does NOT restrict what caplog COLLECTS --
            # caplog.records holds every record from every logger. Counting all
            # of them made this test measure the whole process's logging
            # surface while claiming, in its own docstring, to measure one lane.
            #
            # IT FAILED 2026-08-18 FOR EXACTLY THAT REASON: a startup line from
            # `recto.bootloader.identity` (GATE 5b) landed in `_spawn` above,
            # inflating the idle baseline to 1 and making `busy > quiet` read
            # `1 > 1`. The connections lane was working perfectly.
            #
            # **This test violated the rule it cites.** It did not report the
            # boundary of what it examined -- it examined everything and
            # reported as though it had examined one lane. Filtering by logger
            # name is what makes the count mean what the assertion says.
            LANE = "recto.bootloader.connections"

            def lane_records():
                return [r for r in caplog.records if r.name == LANE]

            # Window A: nothing happens.
            with caplog.at_level(logging.INFO, logger=LANE):
                pass
            quiet = len(lane_records())

            caplog.clear()

            # Window B: one perfectly ordinary, fully-authorised read.
            with caplog.at_level(logging.INFO, logger=LANE):
                _get(f"{base}/v0.4/connections/secret?key=stripe", SVC_A_HDR)
            busy = len(lane_records())

            assert busy > quiet, (
                "a window of granted traffic is indistinguishable from an idle "
                "one -- the lane cannot report success, only failure "
                f"(lane={LANE!r} quiet={quiet} busy={busy})"
            )
        finally:
            shutdown()

    def test_audit_mode_does_not_log_the_secret_value(self, tmp_path, caplog):
        ctx, shutdown = _spawn(
            tmp_path,
            agent_keys={},
            enforce_key_acl=False,
        )
        try:
            base = ctx["base_url"]
            _upsert(base, service="ServiceA", key="stripe", secret="sk-live-XYZ")
            with caplog.at_level(
                logging.WARNING, logger="recto.bootloader.connections"
            ):
                _get(f"{base}/v0.4/connections/secret?key=stripe", SVC_A_HDR)
            assert not any(
                "sk-live-XYZ" in r.getMessage() for r in caplog.records
            )
        finally:
            shutdown()


# --------------------------------------------------------------------------
# GATE 0c -- the emission itself, tested WITHOUT a logging harness.
#
# The three GATE 0b tests above use caplog. Caplog attaches its own handler and
# sets its own level, so it proves the line is LOGGED and says nothing about
# whether it is EMITTED. On 2026-08-17 that gap shipped: every logger.info in
# the substrate was discarded in production because nothing installed a root
# handler and logging.lastResort is fixed at WARNING.
#
# THIS TEST MUST NOT USE CAPLOG. It runs a subprocess with a virgin logging
# state and reads real stderr, because the only honest way to test "does output
# appear" is to look at the output.
# --------------------------------------------------------------------------

import subprocess  # noqa: E402
import sys as _sys  # noqa: E402
from pathlib import Path as _Path  # noqa: E402

_REPO_ROOT = _Path(__file__).resolve().parents[1]

_PROBE = r"""
import sys, logging
sys.path.insert(0, {root!r})
sys.path.insert(0, {examples!r})
from run_bootloader_consumer import _configure_logging
_configure_logging()
logging.getLogger("recto.bootloader.server").info("GATE0C_INFO_REACHED_A_HANDLER")
logging.getLogger("recto.bootloader.server").warning("GATE0C_WARNING_CONTROL")
"""


def _run_probe() -> subprocess.CompletedProcess:
    src = _PROBE.format(root=str(_REPO_ROOT), examples=str(_REPO_ROOT / "examples"))
    return subprocess.run(
        [_sys.executable, "-c", src], capture_output=True, text=True, timeout=60
    )


def test_info_records_reach_stderr_in_a_default_python_process():
    """The GATE 0b line must actually appear, not merely be logged.

    RED-BUILD: delete the _configure_logging() call from main(), or drop the
    basicConfig, and this fails while every caplog-based test still passes.
    """
    proc = _run_probe()
    assert proc.returncode == 0, f"probe failed: {proc.stderr}"
    assert "GATE0C_INFO_REACHED_A_HANDLER" in proc.stderr, (
        "INFO did not reach stderr. Python installs no root handler by default "
        "and logging.lastResort is WARNING, so every logger.info() in the "
        "substrate is discarded. This is the production condition measured "
        "2026-08-17, under which the connections-ACL audit line cannot appear "
        "and 'no traffic' is indistinguishable from 'no possible output'."
    )


def test_the_control_warning_proves_the_probe_can_see_output_at_all():
    """A negative result is only evidence if the probe can produce a positive one."""
    proc = _run_probe()
    assert "GATE0C_WARNING_CONTROL" in proc.stderr, (
        "the WARNING control did not appear either -- the probe cannot see "
        "stderr at all, so the INFO assertion above proves nothing."
    )
