"""A consumer's own actions and audiences, through the substrate (2026-10-04).

Recto names no consumer action and no audience. A consumer declares its
action keys in ITS manifest (``RECTO_CAPABILITY_MANIFEST_FILE``) and bounds,
per agent, what may be asked (``requestable_actions``) and where the grant
may be spent (``requestable_audiences``). The phone signs the bytes the
bootloader canonicalized. This file pins that contract with two generic
consumer actions that stand for "a push" and "an act":

1. A consumer-declared action loads and resolves. An undeclared one still
   refuses: ``resolve_actions`` raises, ``evaluate_scope`` fails closed,
   ``clause_weight_breakdown`` raises, and a policed agent cannot card it.
2. The two actions are never interchangeable. A clause allowing one does
   not satisfy the other, at the verifier's ``evaluate_scope`` and at the
   bootloader's pre-carding policy, and a signed grant for one evaluates
   False for the other. A deny never cancels its own allow into a pass:
   an agent barred from one action cannot card it as "allow, then deny".
3. The audience is configuration. A policed agent may card only for the
   audiences its operator listed, compared exactly. The substrate passes
   ``aud`` through the queue, the card-open re-stamp and the signature
   byte for byte, and ``verify_jws`` accepts the configured audience and
   refuses any other.
4. Single use is unchanged. ``max_uses`` 1 and the ``jti`` survive the
   queue and the re-stamp, and the assembled grant is handed out once.

As in ``test_bootloader_capability_requestable.py``, every refusal also
asserts the pending queue is EMPTY: the property bought is "a request
outside the policy never spends the operator's attention", not merely
"the status code is 403".
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
import sys
import threading
import time
from pathlib import Path
from typing import Any
from urllib import request as urlrequest
from urllib.error import HTTPError

import pytest

from recto.bootloader.server import ChallengeStore, create_server
from recto.bootloader.state import PhoneRegistration, StateStore
from recto.capability.jwt import verify_jws
from recto.capability.manifest import (
    clause_weight_breakdown,
    evaluate_scope,
    load_manifest,
    load_manifest_from_dict,
    resolve_actions,
)
from recto.capability.types import CapabilityClause

_EXAMPLES = pathlib.Path(__file__).resolve().parents[1] / "examples"
if str(_EXAMPLES) not in sys.path:
    sys.path.insert(0, str(_EXAMPLES))

from run_bootloader_consumer import _parse_agent_policy_list  # noqa: E402

# ---------------------------------------------------------------------------
# The consumer's manifest. Generic stand-ins: the real keys live in the
# consumer's own private file, never in this tree.
# ---------------------------------------------------------------------------

VERSION = "consumer-test-1"
PUSH = "example:push"
ACT = "example:act"
UNDECLARED = "example:undeclared"

CONSUMER_MANIFEST_RAW: dict[str, Any] = {
    "version": VERSION,
    "actions": {
        PUSH: {"count": 5, "description": "push one approved change"},
        ACT: {"count": 5, "description": "run one approved act"},
        "example:ask": {"count": 1, "description": "answer one question"},
    },
    "groups": {
        "operator:acts": {"actions": [ACT]},
        "operator:pushes": {"actions": [PUSH]},
    },
}
MANIFEST = load_manifest_from_dict(CONSUMER_MANIFEST_RAW)

# Audiences: configuration values a deployment chooses (one per cluster,
# per executor, per consumer). Generic here.
AUD_A = "executor:cluster-a"
AUD_B = "executor:cluster-b"
AUD_REPO = "repo:example/example"

PIN = "ab" * 32  # the payload fingerprint a consumer binds the grant to


def _clause(
    *,
    allow: list[str] | None = None,
    groups: list[str] | None = None,
    registry_version: str = VERSION,
) -> CapabilityClause:
    return CapabilityClause(
        tier=1,
        registry_version=registry_version,
        groups=list(groups or []),
        allow_actions=list(allow or []),
    )


# ---------------------------------------------------------------------------
# 1 + 2: the manifest and the verifier's scope evaluation
# ---------------------------------------------------------------------------


class TestConsumerManifest:
    def test_a_consumer_declared_act_action_loads(self) -> None:
        assert ACT in MANIFEST.actions
        assert MANIFEST.actions[ACT].count == 5
        assert MANIFEST.group_weight("operator:acts") == 5

    def test_the_manifest_ships_as_the_consumers_file(self, tmp_path: Path) -> None:
        """The deployment path: a JSON file the bootloader loads by path."""
        p = tmp_path / "capability-manifest.json"
        p.write_text(json.dumps(CONSUMER_MANIFEST_RAW), encoding="utf-8")
        loaded = load_manifest(p)
        assert loaded.version == VERSION
        assert set(loaded.actions) == set(MANIFEST.actions)

    def test_a_group_naming_an_undeclared_action_refuses_to_load(self) -> None:
        raw = json.loads(json.dumps(CONSUMER_MANIFEST_RAW))
        raw["groups"]["operator:acts"]["actions"].append(UNDECLARED)
        with pytest.raises(ValueError, match="unknown action"):
            load_manifest_from_dict(raw)

    def test_an_act_clause_permits_the_act_only(self) -> None:
        act = _clause(allow=[ACT])
        assert evaluate_scope(ACT, act, MANIFEST) is True
        assert evaluate_scope(PUSH, act, MANIFEST) is False

    def test_a_push_clause_permits_the_push_only(self) -> None:
        push = _clause(allow=[PUSH])
        assert evaluate_scope(PUSH, push, MANIFEST) is True
        assert evaluate_scope(ACT, push, MANIFEST) is False

    def test_group_expansion_keeps_the_two_apart(self) -> None:
        assert evaluate_scope(ACT, _clause(groups=["operator:acts"]), MANIFEST) is True
        assert evaluate_scope(PUSH, _clause(groups=["operator:acts"]), MANIFEST) is False
        assert evaluate_scope(ACT, _clause(groups=["operator:pushes"]), MANIFEST) is False

    def test_an_unknown_action_still_refuses(self) -> None:
        clause = _clause(allow=[UNDECLARED])
        with pytest.raises(ValueError, match="unknown action"):
            resolve_actions(clause, MANIFEST)
        assert evaluate_scope(UNDECLARED, clause, MANIFEST) is False
        with pytest.raises(ValueError, match="unknown action"):
            clause_weight_breakdown(clause, MANIFEST)

    def test_an_unknown_action_poisons_a_clause_that_also_names_a_known_one(self) -> None:
        """Fail closed on the whole clause, never a partial grant."""
        clause = _clause(allow=[ACT, UNDECLARED])
        assert evaluate_scope(ACT, clause, MANIFEST) is False

    def test_a_registry_version_the_manifest_does_not_carry_refuses(self) -> None:
        """A consumer that resolves through its manifest must stamp the
        manifest's version; any other version evaluates False."""
        clause = _clause(allow=[ACT], registry_version="v1")
        assert evaluate_scope(ACT, clause, MANIFEST) is False

    def test_the_public_sample_names_none_of_the_stand_ins(self) -> None:
        """The shipped sample is a template. A consumer's keys are added to
        the consumer's copy, never to this tree."""
        sample = load_manifest(
            pathlib.Path(__file__).resolve().parents[1]
            / "recto" / "capability" / "manifest_v1.json"
        )
        assert not {PUSH, ACT, UNDECLARED} & set(sample.actions)


# ---------------------------------------------------------------------------
# The launcher's policy reader (agents.json)
# ---------------------------------------------------------------------------


class TestAgentPolicyReader:
    def test_absent_is_no_policy(self) -> None:
        assert _parse_agent_policy_list("a", {}, "requestable_audiences", "audience") is None

    def test_present_is_read_stripped(self) -> None:
        got = _parse_agent_policy_list(
            "a", {"requestable_audiences": [f" {AUD_A} ", AUD_REPO]},
            "requestable_audiences", "audience",
        )
        assert got == [AUD_A, AUD_REPO]

    @pytest.mark.parametrize(
        "bad", [[], "", AUD_A, [""], ["  "], [1], [AUD_A, None], {"a": 1}],
        ids=["empty-list", "empty-string", "bare-string", "blank", "spaces",
             "int", "none-member", "object"],
    )
    def test_malformed_refuses_by_name(self, bad: Any) -> None:
        """A malformed policy must never read as "no policy": that fails open."""
        with pytest.raises(ValueError, match=r"agent 'a': requestable_audiences"):
            _parse_agent_policy_list(
                "a", {"requestable_audiences": bad}, "requestable_audiences", "audience",
            )

    def test_the_action_reader_keeps_its_message(self) -> None:
        with pytest.raises(ValueError) as exc:
            _parse_agent_policy_list("a", {"requestable_actions": []}, "requestable_actions", "action-key")
        assert str(exc.value) == (
            "agent 'a': requestable_actions must be a non-empty array of "
            "action-key strings when present."
        )

    def test_the_launcher_passes_the_audience_policy_to_create_server(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
    ) -> None:
        """The policy is only a policy if it reaches the server: the launcher's
        own main(), driven by an agents.json, hands it to create_server."""
        rc, kw = _launcher_kwargs(monkeypatch, tmp_path, [
            {"agent_id": "a", "token_env": "POLICY_TEST_TOKEN_A",
             "requestable_actions": [ACT], "requestable_audiences": [f" {AUD_A} "]},
            {"agent_id": "b", "token_env": "POLICY_TEST_TOKEN_B"},
        ])
        assert rc is None, "main() returned before create_server"
        assert kw["capability_agent_audiences"] == {"a": [AUD_A]}
        assert kw["capability_agent_requestable"] == {"a": [ACT]}

    def test_an_agents_file_without_the_audience_policy_starts_as_before(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
    ) -> None:
        """Today's agents.json (no requestable_audiences anywhere) starts
        unchanged: no audience policy reaches the server."""
        rc, kw = _launcher_kwargs(monkeypatch, tmp_path, [
            {"agent_id": "a", "token_env": "POLICY_TEST_TOKEN_A", "requestable_actions": [ACT]},
            {"agent_id": "b", "token_env": "POLICY_TEST_TOKEN_B"},
        ])
        assert rc is None, "main() returned before create_server"
        assert kw["capability_agent_audiences"] is None
        assert kw["capability_agent_requestable"] == {"a": [ACT]}

    def test_a_malformed_audience_policy_stops_startup(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str],
    ) -> None:
        rc, kw = _launcher_kwargs(monkeypatch, tmp_path, [
            {"agent_id": "a", "token_env": "POLICY_TEST_TOKEN_A", "requestable_audiences": AUD_A},
        ])
        assert rc == 2 and kw is None
        assert "agent 'a': requestable_audiences must be a non-empty array" in capsys.readouterr().err

    # THE AUTH-ONLY KIND (2026-10-17, hard rule 15.p): "capability_requests": false reaches the server as an auth-only
    # agent; a non-boolean, or a request policy beside it, stops startup by name.
    def test_an_auth_only_agent_reaches_the_server(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
    ) -> None:
        rc, kw = _launcher_kwargs(monkeypatch, tmp_path, [
            {"agent_id": "a", "token_env": "POLICY_TEST_TOKEN_A", "capability_requests": False},
            {"agent_id": "b", "token_env": "POLICY_TEST_TOKEN_B"},
        ])
        assert rc is None, "main() returned before create_server"
        assert set(kw["capability_agent_auth_only"]) == {"a"}

    def test_no_auth_only_agent_means_none_is_passed(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
    ) -> None:
        rc, kw = _launcher_kwargs(monkeypatch, tmp_path, [
            {"agent_id": "a", "token_env": "POLICY_TEST_TOKEN_A", "capability_requests": True},
        ])
        assert rc is None and kw["capability_agent_auth_only"] is None

    @pytest.mark.parametrize("bad", ["false", 0, None])
    def test_a_non_boolean_capability_requests_stops_startup(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str], bad: Any,
    ) -> None:
        rc, kw = _launcher_kwargs(monkeypatch, tmp_path, [
            {"agent_id": "a", "token_env": "POLICY_TEST_TOKEN_A", "capability_requests": bad},
        ])
        assert rc == 2 and kw is None
        assert "agent 'a': capability_requests must be true or false" in capsys.readouterr().err

    def test_an_auth_only_agent_with_a_request_policy_stops_startup(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str],
    ) -> None:
        rc, kw = _launcher_kwargs(monkeypatch, tmp_path, [
            {"agent_id": "a", "token_env": "POLICY_TEST_TOKEN_A", "capability_requests": False,
             "requestable_actions": [ACT]},
        ])
        assert rc == 2 and kw is None
        assert "an auth-only agent (capability_requests: false) carries no" in capsys.readouterr().err


class _CreateServerCalled(Exception):
    def __init__(self, kwargs: dict[str, Any]) -> None:
        super().__init__("create_server reached")
        self.kwargs = kwargs


def _launcher_kwargs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, agents: list[dict[str, Any]],
) -> tuple[int | None, dict[str, Any] | None]:
    """Run the launcher's main() up to create_server and return (rc, kwargs):
    (rc, None) when main() returned first, (None, kwargs) when it got there."""
    import run_bootloader_consumer as rbc

    agents_file = tmp_path / "agents.json"
    agents_file.write_text(json.dumps({"agents": agents}), encoding="utf-8")
    for name in [k for k in os.environ if k.startswith("RECTO_")]:
        monkeypatch.delenv(name)
    monkeypatch.setenv("RECTO_BOOTLOADER_ID", "policy-test")
    monkeypatch.setenv("RECTO_BIND_HOST", "127.0.0.1")
    monkeypatch.setenv("RECTO_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("RECTO_AGENTS_FILE", str(agents_file))
    monkeypatch.setenv("POLICY_TEST_TOKEN_A", "a" * 64)
    monkeypatch.setenv("POLICY_TEST_TOKEN_B", "b" * 64)
    # The launcher's logging setup is process-global; leave the test runner's alone.
    monkeypatch.setattr(rbc, "_configure_logging", lambda: 20)

    def _fake_create_server(**kwargs: Any) -> None:
        raise _CreateServerCalled(kwargs)

    monkeypatch.setattr(rbc, "create_server", _fake_create_server)
    try:
        return rbc.main(), None
    except _CreateServerCalled as reached:
        return None, reached.kwargs


# ---------------------------------------------------------------------------
# 2 + 3 + 4: the bootloader
# ---------------------------------------------------------------------------

ACT_AGENT, ACT_TOKEN = "act-agent", "act-agent-token-fixture-only"
PUSH_AGENT, PUSH_TOKEN = "push-agent", "push-agent-token-fixture-only"
BOTH_AGENT, BOTH_TOKEN = "both-agent", "both-agent-token-fixture-only"
FREE_AGENT, FREE_TOKEN = "free-agent", "free-agent-token-fixture-only"
TOKENS = {
    ACT_AGENT: ACT_TOKEN,
    PUSH_AGENT: PUSH_TOKEN,
    BOTH_AGENT: BOTH_TOKEN,
    FREE_AGENT: FREE_TOKEN,
}


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _make_operator_keypair() -> tuple[int, bytes]:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import ec

    priv = ec.generate_private_key(ec.SECP256K1(), default_backend())
    nums = priv.public_key().public_numbers()
    return priv.private_numbers().private_value, (
        nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")
    )


def _sign_cap(priv_int: int, header_b64: str, payload_b64: str) -> str:
    """ES256K over SHA-256(header.payload), low-s, raw r||s: what the phone posts."""
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    digest = hashlib.sha256(f"{header_b64}.{payload_b64}".encode("ascii")).digest()
    priv = ec.derive_private_key(priv_int, ec.SECP256K1(), default_backend())
    r, s = utils.decode_dss_signature(
        priv.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    )
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    if s > n // 2:
        s = n - s
    return _b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


@pytest.fixture
def live(tmp_path: Path):
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    phone_priv = Ed25519PrivateKey.generate()
    pub_b64u = _b64u(phone_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ))
    op_priv_int, op_pub = _make_operator_keypair()

    state = StateStore(state_dir=tmp_path)
    phone = PhoneRegistration.new(
        device_label="Consumer Actions Test Phone",
        public_key_b64u=pub_b64u,
        supported_algorithms=("ed25519",),
    )
    state.register_phone(phone)

    server = create_server(
        bind_host="127.0.0.1",
        bind_port=0,
        state=state,
        bootloader_id="consumer-actions-test",
        challenges=ChallengeStore(),
        ssl_context=None,
        capability_agent_tokens=dict(TOKENS),
        capability_agent_requestable={
            ACT_AGENT: [ACT],
            PUSH_AGENT: [PUSH],
            BOTH_AGENT: [PUSH, ACT],
        },
        capability_agent_audiences={
            ACT_AGENT: [AUD_A],
            PUSH_AGENT: [AUD_REPO],
            BOTH_AGENT: [AUD_A, AUD_REPO],
        },
        capability_manifest=MANIFEST,
        capability_operator_pubkey=op_pub,
    )
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {
            "base_url": f"http://{host}:{port}",
            "state": state,
            "phone_id": phone.phone_id,
            "phone_priv": phone_priv,
            "op_priv_int": op_priv_int,
            "op_pub": op_pub,
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)


def _http(method: str, url: str, body: dict[str, Any] | None = None,
          headers: dict[str, str] | None = None) -> tuple[int, dict[str, Any]]:
    h = {"Content-Type": "application/json"}
    h.update(headers or {})
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urlrequest.Request(url, data=data, headers=h, method=method)
    try:
        with urlrequest.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read() or b"{}")
    except HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def _agent_headers(agent: str) -> dict[str, str]:
    return {"X-Recto-Agent-Id": agent, "X-Recto-Agent-Token": TOKENS[agent]}


_JTI_SEQ = [0]


def _claims(
    *,
    action: str | None = ACT,
    aud: Any = None,
    groups: list[str] | None = None,
    jti: str | None = None,
) -> dict[str, Any]:
    now = int(time.time())
    _JTI_SEQ[0] += 1
    return {
        "iss": "phone:operator:enclave",
        "sub": "agent:consumer-test",
        "aud": [AUD_A] if aud is None else aud,
        "iat": now,
        "nbf": now,
        "exp": now + 600,
        "jti": jti or f"consumer-test-{now}-{_JTI_SEQ[0]}",
        "cap": {
            "tier": 1,
            "registry_version": VERSION,
            "groups": list(groups or []),
            "scope": {"env": [], "services": [], "repos": [],
                      "payload_sha256": PIN},
            "allow_actions": [action] if action else [],
            "deny_actions": [],
            "limits": {},
        },
        "purpose": "consumer actions test",
        "max_uses": 1,
    }


def _request(ctx, agent: str, claims: dict[str, Any], **extra: Any):
    body = {"phone_id": ctx["phone_id"], "claims": claims,
            "operation_description": "consumer actions test"}
    body.update(extra)
    return _http("POST", f"{ctx['base_url']}/v0.4/capability/request",
                 body, _agent_headers(agent))


def _pending(ctx) -> int:
    return len(ctx["state"].list_pending_for_phone(ctx["phone_id"]))


class TestActionPolicyKeepsTheTwoApart:
    def test_an_act_agent_cards_an_act(self, live) -> None:
        status, body = _request(live, ACT_AGENT, _claims(action=ACT))
        assert status == 201, body
        assert _pending(live) == 1

    def test_an_act_agent_cannot_card_a_push(self, live) -> None:
        status, body = _request(live, ACT_AGENT, _claims(action=PUSH))
        assert status == 403, body
        assert body["error"] == "action_not_requestable"
        assert body["disallowed_actions"] == [PUSH]
        assert _pending(live) == 0

    def test_a_push_agent_cannot_card_an_act(self, live) -> None:
        status, body = _request(live, PUSH_AGENT, _claims(action=ACT, aud=[AUD_REPO]))
        assert status == 403, body
        assert body["error"] == "action_not_requestable"
        assert body["disallowed_actions"] == [ACT]
        assert _pending(live) == 0

    def test_an_undeclared_action_is_not_requestable(self, live) -> None:
        status, body = _request(live, BOTH_AGENT, _claims(action=UNDECLARED))
        assert status == 403, body
        assert body["error"] == "action_not_requestable"
        assert body["disallowed_actions"] == [UNDECLARED]
        assert _pending(live) == 0

    @pytest.mark.parametrize(
        "agent, action, aud",
        [(ACT_AGENT, PUSH, AUD_A), (PUSH_AGENT, ACT, AUD_REPO)],
        ids=["act-agent-names-the-push", "push-agent-names-the-act"],
    )
    def test_an_action_allowed_and_denied_is_still_asked_for(
        self, live, agent, action, aud,
    ) -> None:
        """A deny never cancels its own allow into a pass. Under Recto's own
        verifier the clause allow [x], deny [x] allows nothing (evaluate_scope
        subtracts the deny), but a consumer verifier that reads allow_actions
        alone would grant x. So the policy judges what the clause NAMES, and
        an agent barred from the other lane's action cannot card it this way,
        in either direction. Refused, never queued."""
        claims = _claims(action=action, aud=[aud])
        claims["cap"]["deny_actions"] = [action]
        status, body = _request(live, agent, claims)
        assert status == 403, body
        assert body["error"] == "action_not_requestable"
        assert body["disallowed_actions"] == [action]
        assert _pending(live) == 0
        clause = CapabilityClause(
            tier=1, registry_version=VERSION,
            allow_actions=[action], deny_actions=[action],
        )
        assert evaluate_scope(action, clause, MANIFEST) is False

    def test_a_denied_group_member_is_still_asked_for(self, live) -> None:
        """The same rule for a group: naming the other lane's group and
        denying its one member still names that member."""
        claims = _claims(action=None, groups=["operator:pushes"])
        claims["cap"]["deny_actions"] = [PUSH]
        status, body = _request(live, ACT_AGENT, claims)
        assert status == 403, body
        assert body["error"] == "action_not_requestable"
        assert body["disallowed_actions"] == [PUSH]
        assert _pending(live) == 0

    def test_a_group_expands_through_the_consumers_manifest(self, live) -> None:
        status, body = _request(
            live, ACT_AGENT, _claims(action=None, groups=["operator:acts"]))
        assert status == 201, body
        status, body = _request(
            live, ACT_AGENT, _claims(action=None, groups=["operator:pushes"]))
        assert status == 403, body
        assert body["disallowed_actions"] == [PUSH]
        assert _pending(live) == 1


class TestAudiencePolicyIsConfiguration:
    def test_the_configured_audience_cards(self, live) -> None:
        status, body = _request(live, ACT_AGENT, _claims(aud=[AUD_A]))
        assert status == 201, body
        assert _pending(live) == 1

    def test_another_audience_is_refused_and_never_queued(self, live) -> None:
        status, body = _request(live, ACT_AGENT, _claims(aud=[AUD_B]))
        assert status == 403, body
        assert body["error"] == "audience_not_requestable"
        assert body["disallowed_audiences"] == [AUD_B]
        assert body["requestable_audiences"] == [AUD_A]
        assert _pending(live) == 0

    def test_one_foreign_audience_refuses_the_whole_request(self, live) -> None:
        status, body = _request(live, ACT_AGENT, _claims(aud=[AUD_A, AUD_B]))
        assert status == 403, body
        assert body["disallowed_audiences"] == [AUD_B]
        assert _pending(live) == 0

    def test_no_audience_is_refused(self, live) -> None:
        status, body = _request(live, ACT_AGENT, _claims(aud=[]))
        assert status == 403, body
        assert body["error"] == "audience_not_requestable"
        assert "no audience" in body["detail"]
        assert _pending(live) == 0

    @pytest.mark.parametrize("aud", [AUD_A, [AUD_A, 7], {"aud": AUD_A}],
                             ids=["bare-string", "non-string-member", "object"])
    def test_an_audience_that_is_not_an_array_of_strings_is_refused(self, live, aud) -> None:
        """A bare string would round-trip as a list of its characters."""
        status, body = _request(live, ACT_AGENT, _claims(aud=aud))
        assert status in (400, 403), body
        assert _pending(live) == 0

    def test_the_comparison_is_exact(self, live) -> None:
        status, body = _request(live, ACT_AGENT, _claims(aud=[AUD_A.upper()]))
        assert status == 403, body
        assert body["error"] == "audience_not_requestable"
        status, body = _request(live, ACT_AGENT, _claims(aud=[AUD_A + " "]))
        assert status == 403, body
        assert _pending(live) == 0

    def test_the_two_policies_are_independent(self, live) -> None:
        """An agent allowed both actions still cards only for its own audiences."""
        status, body = _request(live, BOTH_AGENT, _claims(action=PUSH, aud=[AUD_B]))
        assert status == 403, body
        assert body["error"] == "audience_not_requestable"
        status, body = _request(live, BOTH_AGENT, _claims(action=PUSH, aud=[AUD_REPO]))
        assert status == 201, body
        assert _pending(live) == 1

    def test_an_agent_without_an_audience_policy_is_unrestricted(self, live) -> None:
        """The legacy posture is unchanged: no policy, no check at this layer."""
        status, body = _request(live, FREE_AGENT, _claims(action=PUSH, aud=[AUD_B, "anything"]))
        assert status == 201, body
        assert _pending(live) == 1


def _approve_and_fetch(ctx, agent: str, request_id: str) -> tuple[dict[str, Any], str]:
    """The phone's half (fetch, sign, respond) and the agent's fetch. Returns
    (the card's wire context, the assembled JWS)."""
    status, pending = _http("GET", f"{ctx['base_url']}/v0.4/pending?phone_id={ctx['phone_id']}")
    assert status == 200, pending
    [card] = [r for r in pending["requests"] if r["request_id"] == request_id]
    wire = card["context"]
    hash_bytes = _b64u_decode(wire["payload_hash_b64u"])
    status, resp = _http(
        "POST", f"{ctx['base_url']}/v0.4/respond/{request_id}",
        {
            "decision": "approved",
            "signature_b64u": _b64u(ctx["phone_priv"].sign(hash_bytes)),
            "cap_signature_b64u": _sign_cap(
                ctx["op_priv_int"], wire["cap_header_b64"], wire["cap_payload_b64"]),
        },
    )
    assert status == 200, resp
    status, result = _http(
        "GET", f"{ctx['base_url']}/v0.4/capability/result/{request_id}",
        headers=_agent_headers(agent))
    assert status == 200, result
    assert result["status"] == "approved", result
    return wire, result["capability_jws"]


class TestTheSignedGrant:
    def test_the_card_carries_the_configured_audience_and_single_use_unchanged(self, live) -> None:
        claims = _claims(action=ACT, aud=[AUD_A], jti="consumer-test-restamp")
        status, queued = _request(live, ACT_AGENT, claims, grant_ttl_seconds=600)
        assert status == 201, queued
        status, pending = _http("GET", f"{live['base_url']}/v0.4/pending?phone_id={live['phone_id']}")
        assert status == 200, pending
        [card] = pending["requests"]
        signed = json.loads(_b64u_decode(card["context"]["cap_payload_b64"]))
        # The window was re-stamped at card-open...
        assert signed["exp"] - signed["nbf"] == 600
        # ...and nothing else moved: the substrate never rewrites these.
        assert signed["aud"] == [AUD_A]
        assert signed["jti"] == "consumer-test-restamp"
        assert signed["max_uses"] == 1
        assert signed["cap"]["allow_actions"] == [ACT]
        assert signed["cap"]["scope"]["payload_sha256"] == PIN

    @pytest.mark.parametrize(
        "agent,action,aud,other",
        [(ACT_AGENT, ACT, AUD_A, PUSH), (PUSH_AGENT, PUSH, AUD_REPO, ACT)],
        ids=["act-grant", "push-grant"],
    )
    def test_a_signed_grant_verifies_for_its_audience_and_its_action_only(
        self, live, agent: str, action: str, aud: str, other: str,
    ) -> None:
        jti = f"consumer-test-e2e-{action}"
        status, queued = _request(
            live, agent, _claims(action=action, aud=[aud], jti=jti), grant_ttl_seconds=600)
        assert status == 201, queued
        _wire, jws = _approve_and_fetch(live, agent, queued["request_id"])

        verified = verify_jws(jws, live["op_pub"], expected_aud=aud)
        assert verified.aud == [aud]
        assert verified.jti == jti
        assert verified.max_uses == 1
        assert verified.cap.scope.payload_sha256 == PIN
        # Its own action, and never the other one.
        assert evaluate_scope(action, verified.cap, MANIFEST) is True
        assert evaluate_scope(other, verified.cap, MANIFEST) is False
        # Any audience other than the configured one is refused.
        for wrong in (AUD_B if aud != AUD_B else AUD_A, aud.upper()):
            with pytest.raises(ValueError, match="claims: expected_aud"):
                verify_jws(jws, live["op_pub"], expected_aud=wrong)

    def test_the_grant_is_handed_out_once(self, live) -> None:
        status, queued = _request(live, ACT_AGENT, _claims(), grant_ttl_seconds=600)
        assert status == 201, queued
        _approve_and_fetch(live, ACT_AGENT, queued["request_id"])
        status, _ = _http(
            "GET", f"{live['base_url']}/v0.4/capability/result/{queued['request_id']}",
            headers=_agent_headers(ACT_AGENT))
        assert status == 404
