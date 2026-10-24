"""Hard rule 15 - the fail-closed shapes a review tried to call defects (2026-09-25).

The first whole-tree review of Recto (140 modules, an
independent refuter) raised 24 findings at or above high. Twenty-three were the
DESIGN, read back to the reader as a defect. Each accepted design is a decision
this tree stands on; this file pins the ones a unit test can hold, so a future
change that breaks the shape fails here, in the tree, before a reader has to
find it again. The acceptance ledger (operator-side, never in a public tree)
binds each acceptance to the quoted code; these tests bind the BEHAVIOUR.

Pinned elsewhere, named here so the map is whole:
  15.a operator pubkey None -> the bootloader REFUSES to mint / create a
       profile / add a device: test_bootloader_capability.py
       ::test_mint_refuses_when_no_operator_pubkey_is_configured (GATE 0)
  15.b the pending envelope is a read, never an approval:
       test_bootloader_pending_signed.py (tier 0, one action, single use,
       pinned to the wire bytes)
  15.e the export-mnemonic gate is the caller's, and there is ONE caller,
       biometric first: Recto.Shared (Settings.razor) - a source rule, see
       docs/hard-rules.md
  15.f the TOFU window is one host, one pairing operation:
       Recto.Shared.Tests/PinningServiceTests.cs
  15.m a subject is a handle - its user-vault and devices/pair halves:
       test_bootloader_user_vault.py::test_400_a_user_id_shaped_claim_is_refused,
       test_bootloader_devices_pair.py::TestRule15PairRecordCarriesAHandle
  15.p the auth-only kind reaches the server, and a malformed one stops startup:
       test_capability_consumer_actions.py::test_an_auth_only_agent_reaches_the_server (and its three siblings)
  15.w the grant store, both backends (one live grant per slot; an expired one dropped):
       test_state_postgres.py::test_a_grant_is_stored_found_and_listed and its two siblings
  15.q the relay log carries the status only:
       test_bootloader_devices_pair.py::TestRule15PairRecordCarriesAHandle
       ::test_the_relay_log_carries_the_status_only
"""
from __future__ import annotations

import time
import uuid
from pathlib import Path

import pytest

from recto.bootloader.server import ChallengeStore
from recto.capability.jwt import verify_jws
from recto.capability.pair_record import verify_pair_grant
from recto.capability.signing import mint_jws, public_key_hex
from recto.capability.types import CapabilityClaims, CapabilityClause, CapabilityScope
from recto.profile.manage import bootstrap_master, create_child_profile, mark_profile_revoked

_KEY = bytes.fromhex("7" * 64)


def _claims(*, now: int, nbf: int, exp: int) -> CapabilityClaims:
    return CapabilityClaims(
        iss="bootloader:rule15",
        sub="phone:rule15",
        aud=["recto-phone"],
        iat=now,
        nbf=nbf,
        exp=exp,
        jti=f"rule15-{uuid.uuid4().hex}",
        cap=CapabilityClause(tier=0, registry_version="0", scope=CapabilityScope(), allow_actions=["x:y"]),
        purpose="rule 15 fixture",
        max_uses=1,
    )


class TestRule15cTimeBoundsAreUpstream:
    """15.c - verify_pair_grant's window CEILING sits on top of verify_jws's
    standard bounds (nbf <= now < exp). A future nbf is refused BEFORE the
    grant is ever read; the grant check does not re-check what verify_jws
    already refused. (review finding: missing-nbf-check, pair_record.py:173)"""

    def test_verify_jws_refuses_a_future_nbf(self) -> None:
        now = int(time.time())
        token = mint_jws(_claims(now=now, nbf=now + 600, exp=now + 1200), _KEY)
        with pytest.raises(ValueError, match="nbf"):
            verify_jws(token, expected_pubkey=bytes.fromhex(public_key_hex(_KEY)), expected_aud="recto-phone", now=now)

    def test_verify_jws_accepts_the_same_token_once_nbf_has_passed(self) -> None:
        now = int(time.time())
        token = mint_jws(_claims(now=now, nbf=now + 600, exp=now + 1200), _KEY)
        claims = verify_jws(token, expected_pubkey=bytes.fromhex(public_key_hex(_KEY)),
                            expected_aud="recto-phone", now=now + 601)
        assert claims.nbf == now + 600

    def test_verify_pair_grant_documents_that_verify_jws_comes_first(self) -> None:
        # The contract is written where the reader looks: the docstring.
        assert "verify_jws" in (verify_pair_grant.__doc__ or "")


class TestRule15dMasterRevocation:
    """15.d - "while children exist" means ACTIVE children. A master whose
    children are all revoked has nothing left to orphan; revoking it then is
    the intended end state. (review finding: master-revocation-without-children-check)"""

    def test_master_refuses_while_an_active_child_exists(self, tmp_path: Path) -> None:
        mi = bootstrap_master(master_pubkey_hex=bytes(range(64)).hex(), display_name="m", state_dir=tmp_path)
        create_child_profile(kind="work", display_name="c", derived_pubkey_hex=bytes(range(1, 65)).hex(),
                             state_dir=tmp_path)
        with pytest.raises(ValueError, match="active child"):
            mark_profile_revoked(mi.master_profile_id, state_dir=tmp_path)

    def test_master_revokes_once_every_child_is_revoked(self, tmp_path: Path) -> None:
        mi = bootstrap_master(master_pubkey_hex=bytes(range(64)).hex(), display_name="m", state_dir=tmp_path)
        child = create_child_profile(kind="work", display_name="c", derived_pubkey_hex=bytes(range(1, 65)).hex(),
                                     state_dir=tmp_path)
        mark_profile_revoked(child.profile_id, state_dir=tmp_path)
        revoked = mark_profile_revoked(mi.master_profile_id, state_dir=tmp_path)
        assert revoked.revoked is True


class TestRule15gInMemoryChallengeStoreIsStillAGate:
    """15.g - ChallengeStore(state=None) is the legacy/test construction; what
    it loses without a store is cross-replica persistence, never single-use or
    the TTL. (review finding: fail-open-on-missing-state-store, server.py:632)"""

    def test_challenge_is_single_use(self) -> None:
        store = ChallengeStore()
        c, _exp = store.issue_challenge(ttl_seconds=60)
        assert store.consume_challenge(c) is True
        assert store.consume_challenge(c) is False
        assert store.consume_challenge("never-issued") is False

    def test_pairing_code_is_single_use_and_expires(self) -> None:
        store = ChallengeStore()
        code, _exp = store.issue_pairing_code(ttl_seconds=60)
        assert store.consume_pairing_code(code) is True
        assert store.consume_pairing_code(code) is False
        expired, _ = store.issue_pairing_code(ttl_seconds=0)
        time.sleep(0.01)
        assert store.consume_pairing_code(expired) is False


class TestRule15kSecretConfigIsTheOperators:
    """Hard rule 15.k: `config` is the operator's secret definition. EnvSource
    reads the operator's own environment under the operator's chosen name;
    nothing in a request shapes it - the backend takes no request at all."""

    def test_env_source_reads_only_the_name_the_operator_wrote(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import inspect

        from recto.secrets.env import EnvSource

        monkeypatch.setenv("OPERATOR_CHOSE_THIS", "v1")
        monkeypatch.delenv("db-password", raising=False)
        src = EnvSource()
        assert src.fetch("db-password", {"env_var": "OPERATOR_CHOSE_THIS"}).value == "v1"
        # the backend's contract carries no request: (secret_name, config) and nothing else
        params = list(inspect.signature(EnvSource.fetch).parameters)
        assert params == ["self", "secret_name", "config"]

    def test_no_secret_source_takes_a_request(self) -> None:
        import inspect

        from recto.secrets.base import SecretSource

        params = list(inspect.signature(SecretSource.fetch).parameters)
        assert params == ["self", "secret_name", "config"]
        assert not any(p in ("request", "headers", "payload", "handler") for p in params)



# ---------------------------------------------------------------------------
# 15.m - 15.r: the subject handle, the member binding, the auth-only agent, the label (2026-10-17)
# ---------------------------------------------------------------------------

_AGENT_ID = "rule15-consumer"
_AGENT_TOKEN = "rule15-consumer-token"
_UV_AGENT_ID = "rule15-user-vault"
_UV_AGENT_TOKEN = "rule15-user-vault-token"
_CONSUMER = "https://consumer.example"
_A_GUID = "11111111-2222-3333-4444-555555555555"


def _handle(name: str) -> str:
    """An opaque subject handle, minted the way a consumer would (a keyed hash; here a plain one)."""
    import base64
    import hashlib

    return base64.urlsafe_b64encode(hashlib.sha256(name.encode()).digest()).rstrip(b"=").decode("ascii")


@pytest.fixture
def rule15_ctx(tmp_path: Path):
    import threading

    from recto.bootloader.server import create_server
    from recto.bootloader.state import StateStore

    state = StateStore(state_dir=tmp_path)
    challenges = ChallengeStore(state=state)
    server = create_server(
        bind_host="127.0.0.1", bind_port=0, state=state, bootloader_id="rule15-test",
        challenges=challenges, ssl_context=None, signed_poll_mode="required",
        capability_agent_tokens={_AGENT_ID: _AGENT_TOKEN, _UV_AGENT_ID: _UV_AGENT_TOKEN},
        capability_agent_auth_only={_UV_AGENT_ID},
    )
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {"base_url": f"http://{host}:{port}", "state": state, "challenges": challenges, "dir": tmp_path}
    finally:
        server.shutdown()


def _mint_member(ctx, subject: object) -> tuple[int, dict]:
    from tests.test_bootloader_slots import _http

    return _http("POST", f"{ctx['base_url']}/v0.4/pairing/code",
                 {"member_of": {"consumer": _CONSUMER, "subject": subject}},
                 headers={"X-Recto-Agent-Id": _AGENT_ID, "X-Recto-Agent-Token": _AGENT_TOKEN})


def _member_challenge(ctx, subject: str) -> str:
    from tests.test_bootloader_slots import _http

    status, minted = _mint_member(ctx, subject)
    assert status == 200, minted
    status, chal = _http("GET", f"{ctx['base_url']}/v0.4/registration_challenge?code={minted['code']}")
    assert status == 200, chal
    return chal["challenge_b64u"]


def _register(ctx, phone, challenge: str, *, rebind_signer=None, rebind_ref: str | None = None,
              subject: str | None = None, label: object = "rule15 phone",
              rebind_challenge: str | None = None) -> tuple[int, dict]:
    """POST /v0.4/register for `phone` on `challenge`; optionally with a member_rebind_b64u signed by `rebind_signer`
    over `rebind_challenge` (default: the challenge being answered, the honest hand-over)."""
    from recto.bootloader.server import member_rebind_payload, poll_key_delegation_payload
    from tests.test_bootloader_slots import _b64u, _http

    body = {
        "public_key_b64u": phone.pub,
        "supported_algorithms": ["ed25519"],
        "v0_4_protocol": 1,
        "registration_proof": {"challenge": challenge,
                               "signature_b64u": _b64u(phone.identity.sign(challenge.encode("ascii")))},
        "poll_public_key_b64u": phone.poll_pub,
        "poll_key_delegation_b64u": _b64u(phone.identity.sign(
            poll_key_delegation_payload(phone.pub, phone.poll_pub))),
    }
    if label is not None:
        body["device_label"] = label
    if rebind_signer is not None:
        body["member_rebind_b64u"] = _b64u(rebind_signer.sign(
            member_rebind_payload(_CONSUMER, subject, rebind_ref, phone.pub, rebind_challenge or challenge)))
    return _http("POST", f"{ctx['base_url']}/v0.4/register", body)


class TestRule15mASubjectIsAHandle:
    """Hard rule 15.m: a subject is an opaque handle of 43 base64url characters. A value in any other shape - a
    GUID, an email, a short or padded token - is refused wherever a subject enters: the member code, the user vault's
    X-Recto-Subject claim (test_bootloader_user_vault.py::test_400_a_user_id_shaped_claim_is_refused) and the
    devices/pair record (test_bootloader_devices_pair.py::TestRule15PairRecordCarriesAHandle)."""

    @pytest.mark.parametrize("bad", [_A_GUID, "user@example.com", "E" * 42, "E" * 43 + "=", ""])
    def test_normalize_subject_refuses_anything_but_a_handle(self, bad: str) -> None:
        from recto.subject_handle import normalize_subject

        with pytest.raises(ValueError):
            normalize_subject(bad)

    def test_a_member_code_refuses_a_user_id(self, rule15_ctx) -> None:
        status, body = _mint_member(rule15_ctx, _A_GUID)
        assert status == 400 and body["error"] == "subject_invalid", body

    def test_a_member_code_naming_a_user_id_field_is_refused(self, rule15_ctx) -> None:
        from tests.test_bootloader_slots import _http

        status, body = _http("POST", f"{rule15_ctx['base_url']}/v0.4/pairing/code",
                             {"member_of": {"consumer": _CONSUMER, "user_id": _A_GUID}},
                             headers={"X-Recto-Agent-Id": _AGENT_ID, "X-Recto-Agent-Token": _AGENT_TOKEN})
        assert status == 400, body


class TestRule15nABoundSubjectRebindsOnlyByItsPhone:
    """Hard rule 15.n: one phone per (consumer, subject). A second key registering for a bound subject is refused
    with 409 member_subject_bound unless the BOUND phone's identity key signed the hand-over
    (recto-member-rebind-v1|consumer|subject|bound ref|incoming key|challenge) for the very challenge the incoming
    phone answers; with it, the binding moves and the old phone loses it. A signature over any other challenge - a
    replay - is refused. A phone holds one subject per consumer."""

    def test_the_first_phone_takes_the_binding(self, rule15_ctx) -> None:
        from tests.test_bootloader_slots import Phone

        a, s = Phone("a"), _handle("member-1")
        status, body = _register(rule15_ctx, a, _member_challenge(rule15_ctx, s))
        assert status in (200, 201), body
        assert rule15_ctx["state"].get_phone(a.ref).member_bindings == ((_CONSUMER, s),)

    def test_a_second_phone_without_the_bound_phones_signature_is_refused(self, rule15_ctx) -> None:
        from tests.test_bootloader_slots import Phone

        a, b, s = Phone("a"), Phone("b"), _handle("member-1")
        assert _register(rule15_ctx, a, _member_challenge(rule15_ctx, s))[0] in (200, 201)
        status, body = _register(rule15_ctx, b, _member_challenge(rule15_ctx, s))
        assert status == 409 and body["error"] == "member_subject_bound", body
        assert body["bound_phone_ref"] == a.ref
        assert rule15_ctx["state"].get_phone(b.ref) is None
        assert rule15_ctx["state"].get_phone(a.ref).member_bindings == ((_CONSUMER, s),)

    def test_a_hand_over_signed_by_the_incoming_key_is_refused(self, rule15_ctx) -> None:
        from tests.test_bootloader_slots import Phone

        a, b, s = Phone("a"), Phone("b"), _handle("member-1")
        assert _register(rule15_ctx, a, _member_challenge(rule15_ctx, s))[0] in (200, 201)
        status, body = _register(rule15_ctx, b, _member_challenge(rule15_ctx, s),
                                 rebind_signer=b.identity, rebind_ref=a.ref, subject=s)
        assert status == 409 and body["error"] == "member_subject_bound", body

    def test_the_bound_phones_signature_moves_the_binding(self, rule15_ctx) -> None:
        from tests.test_bootloader_slots import Phone

        a, b, s = Phone("a"), Phone("b"), _handle("member-1")
        assert _register(rule15_ctx, a, _member_challenge(rule15_ctx, s))[0] in (200, 201)
        status, body = _register(rule15_ctx, b, _member_challenge(rule15_ctx, s),
                                 rebind_signer=a.identity, rebind_ref=a.ref, subject=s)
        assert status in (200, 201), body
        assert rule15_ctx["state"].get_phone(b.ref).member_bindings == ((_CONSUMER, s),)
        assert rule15_ctx["state"].get_phone(a.ref).member_bindings == ()

    def test_a_hand_over_signed_for_another_challenge_is_refused(self, rule15_ctx) -> None:
        from tests.test_bootloader_slots import Phone

        a, b, s = Phone("a"), Phone("b"), _handle("member-1")
        assert _register(rule15_ctx, a, _member_challenge(rule15_ctx, s))[0] in (200, 201)
        stale = _member_challenge(rule15_ctx, s)  # a challenge A signed over, never the one B answers
        status, body = _register(rule15_ctx, b, _member_challenge(rule15_ctx, s),
                                 rebind_signer=a.identity, rebind_ref=a.ref, subject=s, rebind_challenge=stale)
        assert status == 409 and body["error"] == "member_subject_bound", body
        assert rule15_ctx["state"].get_phone(a.ref).member_bindings == ((_CONSUMER, s),)

    def test_a_replayed_hand_over_never_takes_the_binding_again(self, rule15_ctx) -> None:
        """The 6c32 scenario: A hands the binding to B, B hands it back to A; B's holder replays A's first signature
        with a fresh member code - refused, because that signature was for one spent challenge."""
        from recto.bootloader.server import member_rebind_payload
        from tests.test_bootloader_slots import Phone, _b64u

        a, b, s = Phone("a"), Phone("b"), _handle("member-1")
        assert _register(rule15_ctx, a, _member_challenge(rule15_ctx, s))[0] in (200, 201)
        c1 = _member_challenge(rule15_ctx, s)
        a_sig_for_b = _b64u(a.identity.sign(member_rebind_payload(_CONSUMER, s, a.ref, b.pub, c1)))
        assert _register(rule15_ctx, b, c1, rebind_signer=a.identity, rebind_ref=a.ref, subject=s)[0] in (200, 201)
        assert _register(rule15_ctx, a, _member_challenge(rule15_ctx, s),
                         rebind_signer=b.identity, rebind_ref=b.ref, subject=s)[0] in (200, 201)
        assert rule15_ctx["state"].get_phone(a.ref).member_bindings == ((_CONSUMER, s),)
        # the replay: B on a fresh challenge, carrying A's old signature verbatim
        from recto.bootloader.server import poll_key_delegation_payload
        from tests.test_bootloader_slots import _http

        c3 = _member_challenge(rule15_ctx, s)
        status, body = _http("POST", f"{rule15_ctx['base_url']}/v0.4/register", {
            "public_key_b64u": b.pub, "supported_algorithms": ["ed25519"], "v0_4_protocol": 1,
            "registration_proof": {"challenge": c3, "signature_b64u": _b64u(b.identity.sign(c3.encode("ascii")))},
            "poll_public_key_b64u": b.poll_pub,
            "poll_key_delegation_b64u": _b64u(b.identity.sign(poll_key_delegation_payload(b.pub, b.poll_pub))),
            "member_rebind_b64u": a_sig_for_b,
        })
        assert status == 409 and body["error"] == "member_subject_bound", body
        assert rule15_ctx["state"].get_phone(a.ref).member_bindings == ((_CONSUMER, s),)

    def test_a_phone_holds_one_subject_per_consumer(self, rule15_ctx) -> None:
        from tests.test_bootloader_slots import Phone

        a = Phone("a")
        assert _register(rule15_ctx, a, _member_challenge(rule15_ctx, _handle("member-1")))[0] in (200, 201)
        status, body = _register(rule15_ctx, a, _member_challenge(rule15_ctx, _handle("member-2")))
        assert status == 403 and body["error"] == "member_phone_bound_elsewhere", body


class TestRule15oTheBootloaderNeverStoresAPlatformUserId:
    """Hard rule 15.o: no state field, sidecar key or log line carries a platform's user id - only its opaque
    subject handle. Pinned on the stores here; the log half is a source rule: no print or logger line in
    recto/bootloader/server.py names a user id."""

    def test_a_member_registration_stores_the_handle_and_no_user_id(self, rule15_ctx) -> None:
        import re

        from tests.test_bootloader_slots import Phone

        s = _handle("member-1")
        assert _register(rule15_ctx, Phone("a"), _member_challenge(rule15_ctx, s))[0] in (200, 201)
        stored = "".join(p.read_text(encoding="utf-8") for p in rule15_ctx["dir"].glob("*.json"))
        assert s in stored
        assert '"user_id"' not in stored
        assert not re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", stored)

    def test_no_bootloader_log_line_names_a_user_id(self) -> None:
        import re

        src = (Path(__file__).resolve().parents[1] / "recto" / "bootloader" / "server.py").read_text(encoding="utf-8")
        offenders = [ln for ln in src.splitlines()
                     if re.search(r"\b(print|logger\.\w+|logging\.\w+)\(", ln) and "user_id" in ln]
        assert offenders == []


class TestRule15pAnAuthOnlyAgentRaisesNoCard:
    """Hard rule 15.p: an agent whose entry says "capability_requests": false authenticates to a substrate and
    raises NO capability card - refused by name before carding (an empty request policy stays a config error)."""

    def test_capability_request_from_an_auth_only_agent_is_refused(self, rule15_ctx) -> None:
        from tests.test_bootloader_slots import _http

        status, body = _http("POST", f"{rule15_ctx['base_url']}/v0.4/capability/request", {"phone_id": "pk_x"},
                             headers={"X-Recto-Agent-Id": _UV_AGENT_ID, "X-Recto-Agent-Token": _UV_AGENT_TOKEN})
        assert status == 403 and body["error"] == "agent_auth_only", body

    def test_a_request_kind_agent_is_not_refused_by_that_name(self, rule15_ctx) -> None:
        from tests.test_bootloader_slots import _http

        status, body = _http("POST", f"{rule15_ctx['base_url']}/v0.4/capability/request", {"phone_id": "pk_x"},
                             headers={"X-Recto-Agent-Id": _AGENT_ID, "X-Recto-Agent-Token": _AGENT_TOKEN})
        assert body.get("error") != "agent_auth_only", body


class TestRule15rADeviceLabelIsGenerated:
    """Hard rule 15.r: a phone that sends no label gets one derived from its own key (phone-<4 hex>); the registry
    never asks a person for a name."""

    @pytest.mark.parametrize("label", [None, "", "   "])
    def test_a_missing_label_is_generated_from_the_key(self, rule15_ctx, label) -> None:
        from recto.bootloader.server import generated_device_label
        from tests.test_bootloader_slots import Phone

        a = Phone("unused")
        status, body = _register(rule15_ctx, a, _member_challenge(rule15_ctx, _handle("m")), label=label)
        assert status in (200, 201), body
        assert rule15_ctx["state"].get_phone(a.ref).device_label == generated_device_label(a.ref)
        assert generated_device_label(a.ref).startswith("phone-") and len(generated_device_label(a.ref)) == 10


# ---------------------------------------------------------------------------
# 15.s - 15.w: the user-vault grant and its revocation (2026-10-17, R-series step 2)
# ---------------------------------------------------------------------------

_UVA_ID, _UVA_TOKEN = "rule15-uv-platform", "rule15-uv-platform-token"
_PLATFORM = "Rule15Platform"


@pytest.fixture
def uv_ctx(tmp_path: Path):
    """A bootloader with the user vault ON (in-memory values) and the member plane, so a phone can be bound to a
    subject and sign grants for it."""
    import threading

    from recto.bootloader.server import create_server
    from recto.bootloader.state import StateStore
    from tests.test_bootloader_user_vault import _MemoryVault

    state = StateStore(state_dir=tmp_path)
    challenges = ChallengeStore(state=state)
    vault = _MemoryVault()
    server = create_server(
        bind_host="127.0.0.1", bind_port=0, state=state, bootloader_id="rule15-test",
        challenges=challenges, ssl_context=None, signed_poll_mode="required",
        capability_agent_tokens={_AGENT_ID: _AGENT_TOKEN, _UVA_ID: _UVA_TOKEN},
        user_vault_path=str(tmp_path / "user_vault.json"),
        user_vault_agent_platforms={_UVA_ID: _PLATFORM},
        user_vault_secret_source_factory=vault.factory,
        user_vault_platform_consumers={_PLATFORM: _CONSUMER},
    )
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {"base_url": f"http://{host}:{port}", "state": state, "challenges": challenges, "dir": tmp_path}
    finally:
        server.shutdown()


def _bound(ctx, name: str = "a", member: str = "member-1"):
    """A phone registered on a member code for _handle(member) - bound to (_CONSUMER, that subject)."""
    from tests.test_bootloader_slots import Phone

    phone, subject = Phone(name), _handle(member)
    assert _register(ctx, phone, _member_challenge(ctx, subject))[0] in (200, 201)
    return phone, subject


def _grant_dict(subject: str, **over) -> dict:
    d = {"bootloader_id": "rule15-test", "consumer": _CONSUMER, "subject": subject,
         "agent_handle": _handle("agent-1"), "key": "user-ai-xai", "scope": "AgentChat",
         "not_after": int(time.time()) + 30 * 86400, "nonce": "nonce-" + uuid.uuid4().hex[:16]}
    d.update(over)
    return d


def _signed(phone, message: bytes) -> str:
    from tests.test_bootloader_slots import _b64u

    return _b64u(phone.identity.sign(message))


def _post(ctx, verb: str, record: dict, sig: str) -> tuple[int, dict]:
    from tests.test_bootloader_slots import _http

    return _http("POST", f"{ctx['base_url']}/v0.4/user-vault/{verb}", {"record": record, "signature_b64u": sig})


def _grant(ctx, phone, record: dict) -> tuple[int, dict]:
    from recto.user_vault.grant_record import GrantRecord

    return _post(ctx, "grant", record, _signed(phone, GrantRecord.from_dict(record).signed_message()))


def _revoke(ctx, phone, subject: str, grant_id: str) -> tuple[int, dict]:
    from recto.user_vault.grant_record import RevokeRecord

    rec = {"bootloader_id": "rule15-test", "consumer": _CONSUMER, "subject": subject, "grant_id": grant_id,
           "nonce": "revoke-" + uuid.uuid4().hex[:16]}
    return _post(ctx, "revoke", rec, _signed(phone, RevokeRecord.from_dict(rec).signed_message()))


class TestRule15sAGrantVerifiesOnlyAgainstTheBoundPhone:
    """Hard rule 15.s: a grant is admitted only under the signature of the phone its (consumer, subject) is bound
    to. Another registered phone's signature, a subject bound to no phone, or a signature over the bare record (no
    domain tag) is refused by name."""

    def test_the_bound_phone_admits_a_grant(self, uv_ctx) -> None:
        a, s = _bound(uv_ctx)
        status, body = _grant(uv_ctx, a, _grant_dict(s))
        assert status == 200 and body["status"] == "admitted", body
        stored = uv_ctx["state"].get_user_vault_grant(body["grant_id"])
        assert stored is not None and stored["signer_phone_ref"] == a.ref

    def test_another_phones_signature_is_refused(self, uv_ctx) -> None:
        _, s = _bound(uv_ctx, "a")
        b, _ = _bound(uv_ctx, "b", member="member-2")
        status, body = _grant(uv_ctx, b, _grant_dict(s))
        assert status == 403 and body["error"] == "grant_signature_invalid", body

    def test_a_subject_bound_to_no_phone_is_refused(self, uv_ctx) -> None:
        a, _ = _bound(uv_ctx)
        status, body = _grant(uv_ctx, a, _grant_dict(_handle("nobody")))
        assert status == 403 and body["error"] == "grant_subject_unbound", body

    def test_a_signature_without_the_domain_tag_is_refused(self, uv_ctx) -> None:
        from recto.user_vault.grant_record import GrantRecord

        a, s = _bound(uv_ctx)
        rec = _grant_dict(s)
        status, body = _post(uv_ctx, "grant", rec, _signed(a, GrantRecord.from_dict(rec).canonical_bytes()))
        assert status == 403 and body["error"] == "grant_signature_invalid", body


class TestRule15tAGrantPastOrTooLongIsRefused:
    """Hard rule 15.t: a grant already past its not_after, reaching further than GRANT_MAX_SECONDS, or naming
    another bootloader is refused at admission - the clock is the bootloader's."""

    def test_an_expired_grant_is_refused(self, uv_ctx) -> None:
        a, s = _bound(uv_ctx)
        status, body = _grant(uv_ctx, a, _grant_dict(s, not_after=int(time.time()) - 1))
        assert status == 403 and body["error"] == "grant_expired", body

    def test_a_grant_past_the_cap_is_refused(self, uv_ctx) -> None:
        from recto.user_vault.grant_record import GRANT_MAX_SECONDS

        a, s = _bound(uv_ctx)
        status, body = _grant(uv_ctx, a, _grant_dict(s, not_after=int(time.time()) + GRANT_MAX_SECONDS + 3600))
        assert status == 403 and body["error"] == "grant_too_long", body

    def test_a_grant_for_another_bootloader_is_refused(self, uv_ctx) -> None:
        a, s = _bound(uv_ctx)
        status, body = _grant(uv_ctx, a, _grant_dict(s, bootloader_id="another-bootloader"))
        assert status == 403 and body["error"] == "grant_bootloader_mismatch", body


class TestRule15uARevokedGrantNeverGrantsAgain:
    """Hard rule 15.u: the bound phone's revoke puts the grant on the revocation list at once; the same signed grant
    re-sent is refused. A grant REPLACED by a newer one for the same slot is revoked in the same step, so replaying
    it never displaces the newer one. Only the bound phone revokes; an unknown grant is refused by name."""

    def test_a_replaced_grant_replayed_is_refused_and_the_newer_stays(self, uv_ctx) -> None:
        """hecate 72fe: grant A (90 days), then grant B (7 days) for the same slot, then A re-sent - refused."""
        a, s = _bound(uv_ctx)
        rec_a = _grant_dict(s, not_after=int(time.time()) + 90 * 86400)
        status, body = _grant(uv_ctx, a, rec_a)
        assert status == 200, body
        id_a = body["grant_id"]
        status, body = _grant(uv_ctx, a, _grant_dict(s, not_after=int(time.time()) + 7 * 86400))
        assert status == 200, body
        id_b = body["grant_id"]
        assert uv_ctx["state"].is_revoked("uvgrant:" + id_a)
        status, body = _grant(uv_ctx, a, rec_a)  # the replay, signature verbatim
        assert status == 403 and body["error"] == "grant_revoked", body
        held = uv_ctx["state"].list_user_vault_grants(_CONSUMER, s)
        assert [g["grant_id"] for g in held] == [id_b]

    def test_the_same_grant_resent_is_not_a_replacement(self, uv_ctx) -> None:
        a, s = _bound(uv_ctx)
        rec = _grant_dict(s)
        gid = _grant(uv_ctx, a, rec)[1]["grant_id"]
        status, body = _grant(uv_ctx, a, rec)
        assert status == 200 and body["grant_id"] == gid, body
        assert not uv_ctx["state"].is_revoked("uvgrant:" + gid)

    def test_a_revoked_grant_resent_is_refused(self, uv_ctx) -> None:
        a, s = _bound(uv_ctx)
        rec = _grant_dict(s)
        status, body = _grant(uv_ctx, a, rec)
        assert status == 200, body
        gid = body["grant_id"]
        status, body = _revoke(uv_ctx, a, s, gid)
        assert status == 200 and body["revoked"] is True, body
        assert uv_ctx["state"].is_revoked("uvgrant:" + gid)
        status, body = _grant(uv_ctx, a, rec)
        assert status == 403 and body["error"] == "grant_revoked", body

    def test_only_the_bound_phone_revokes(self, uv_ctx) -> None:
        a, s = _bound(uv_ctx, "a")
        b, _ = _bound(uv_ctx, "b", member="member-2")
        gid = _grant(uv_ctx, a, _grant_dict(s))[1]["grant_id"]
        status, body = _revoke(uv_ctx, b, s, gid)
        assert status == 403 and body["error"] == "grant_signature_invalid", body
        assert not uv_ctx["state"].is_revoked("uvgrant:" + gid)

    def test_an_unknown_grant_is_refused(self, uv_ctx) -> None:
        a, s = _bound(uv_ctx)
        status, body = _revoke(uv_ctx, a, s, "0" * 64)
        assert status == 404 and body["error"] == "grant_unknown", body


class TestRule15vAGrantNamesOneAgent:
    """Hard rule 15.v: a grant names ONE agent by its opaque handle. A wildcard, an empty value or a raw id is
    refused before any signature is read ("all my agents" is not in v1)."""

    @pytest.mark.parametrize("bad", ["*", "", _A_GUID, "all"])
    def test_anything_but_one_agent_handle_is_refused(self, uv_ctx, bad: str) -> None:
        a, s = _bound(uv_ctx)
        status, body = _post(uv_ctx, "grant", _grant_dict(s, agent_handle=bad), "x")
        assert status == 400 and body["error"] in ("grant_agent_handle_invalid", "grant_record_invalid"), body


class TestRule15wAdmissionIsNotRelease:
    """Hard rule 15.w: storing or revoking a grant changes no release answer until step 4's switch turns the gate
    on - release does not read grants at all today."""

    def test_release_answers_the_same_with_and_without_a_grant(self, uv_ctx) -> None:
        from tests.test_bootloader_slots import _http

        a, s = _bound(uv_ctx)
        hdr = {"X-Recto-Agent-Id": _UVA_ID, "X-Recto-Agent-Token": _UVA_TOKEN, "X-Recto-Subject": s}
        status, _ = _http("POST", f"{uv_ctx['base_url']}/v0.4/user-vault/set",
                          {"key": "user-ai-xai", "secret": "v1"}, headers=hdr)
        assert status == 200
        before = _http("GET", f"{uv_ctx['base_url']}/v0.4/user-vault/release?key=user-ai-xai", headers=hdr)
        gid = _grant(uv_ctx, a, _grant_dict(s))[1]["grant_id"]
        during = _http("GET", f"{uv_ctx['base_url']}/v0.4/user-vault/release?key=user-ai-xai", headers=hdr)
        assert _revoke(uv_ctx, a, s, gid)[0] == 200
        after = _http("GET", f"{uv_ctx['base_url']}/v0.4/user-vault/release?key=user-ai-xai", headers=hdr)
        assert before == during == after
        assert before[1]["status"] == "released"

    def test_a_newer_grant_for_the_same_slot_replaces_the_older(self, uv_ctx) -> None:
        a, s = _bound(uv_ctx)
        first = _grant(uv_ctx, a, _grant_dict(s))[1]["grant_id"]
        second = _grant(uv_ctx, a, _grant_dict(s))[1]["grant_id"]
        held = uv_ctx["state"].list_user_vault_grants(_CONSUMER, s)
        assert [g["grant_id"] for g in held] == [second] and first != second


# ---------------------------------------------------------------------------
# 15.z - 15.aa: the grant request rings the bound phone; a revoke never needs the platform (R-series step 3)
# ---------------------------------------------------------------------------

def _uv_headers(subject: str) -> dict[str, str]:
    return {"X-Recto-Agent-Id": _UVA_ID, "X-Recto-Agent-Token": _UVA_TOKEN, "X-Recto-Subject": subject}


def _raise(ctx, subject: str, **over) -> tuple[int, dict]:
    from tests.test_bootloader_slots import _http

    body = {"action": "grant", "agent_handle": _handle("agent-1"), "key": "user-ai-xai", "scope": "AgentChat",
            "not_after": int(time.time()) + 90 * 86400}
    body.update(over)
    return _http("POST", f"{ctx['base_url']}/v0.4/user-vault/grant-request", body, headers=_uv_headers(subject))


def _status(ctx, subject: str, request_id: str) -> tuple[int, dict]:
    from tests.test_bootloader_slots import _http

    return _http("GET", f"{ctx['base_url']}/v0.4/user-vault/grant-request?request_id={request_id}",
                 headers=_uv_headers(subject))


def _uv_cards(ctx, phone) -> list[dict]:
    status, body = phone.read_pending(ctx)
    assert status == 200, body
    return [r for r in body["requests"] if r["kind"] in ("user_vault_grant", "user_vault_revoke")]


def _list_grants(ctx, phone, *, signer=None, issued_at: int | None = None) -> tuple[int, dict]:
    from recto.user_vault.grant_record import GrantsListRequest

    req = {"bootloader_id": "rule15-test", "phone_id": phone.ref,
           "issued_at": issued_at if issued_at is not None else int(time.time()),
           "nonce": "list-" + uuid.uuid4().hex[:16]}
    sig = _signed(signer or phone, GrantsListRequest.from_dict(req).signed_message())
    return _post_body(ctx, "grants", {"request": req, "signature_b64u": sig})


def _post_body(ctx, verb: str, body: dict) -> tuple[int, dict]:
    from tests.test_bootloader_slots import _http

    return _http("POST", f"{ctx['base_url']}/v0.4/user-vault/{verb}", body)


def _revoke_key(ctx, phone, subject: str, key: str = "user-ai-xai", *, window: int = 300) -> tuple[int, dict, dict]:
    from recto.user_vault.grant_record import RevokeKeyRecord

    rec = {"bootloader_id": "rule15-test", "consumer": _CONSUMER, "subject": subject, "key": key,
           "not_after": int(time.time()) + window, "nonce": "stopall-" + uuid.uuid4().hex[:16]}
    body = {"record": rec, "signature_b64u": _signed(phone, RevokeKeyRecord.from_dict(rec).signed_message())}
    status, out = _post_body(ctx, "revoke-key", body)
    return status, out, body


class TestRule15zAGrantRequestRingsOnlyTheBoundPhone:
    """Hard rule 15.z: a user-vault agent's grant request rings only the phone its subject is bound to, one open
    request per (agent, key), rate-limited per subject; its words - purpose and agent name - are held in memory, capped,
    refused with control or format characters, and never written to disk."""

    def test_the_bound_phone_sees_the_card_and_no_other_phone_does(self, uv_ctx) -> None:
        a, s = _bound(uv_ctx, "a")
        b, _ = _bound(uv_ctx, "b", member="member-2")
        status, body = _raise(uv_ctx, s, purpose="answers with your own key", agent_name="Agent One")
        assert status == 200, body
        cards = _uv_cards(uv_ctx, a)
        assert [c["request_id"] for c in cards] == [body["request_id"]]
        uv = cards[0]["context"]["user_vault_grant"]
        assert (uv["consumer"], uv["subject"], uv["key"], uv["scope"]) == (_CONSUMER, s, "user-ai-xai", "AgentChat")
        assert uv["bootloader_id"] == "rule15-test" and uv["agent_name"] == "Agent One"
        assert _uv_cards(uv_ctx, b) == []

    def test_an_unbound_subject_rings_nothing(self, uv_ctx) -> None:
        _bound(uv_ctx)
        status, body = _raise(uv_ctx, _handle("nobody"))
        assert status == 403 and body["error"] == "grant_subject_unbound", body

    def test_a_platform_with_no_consumer_mapped_rings_nothing(self, uv_ctx) -> None:
        from recto.bootloader.server import BootloaderHandler

        _, s = _bound(uv_ctx)
        saved = BootloaderHandler.config.user_vault_platform_consumers
        BootloaderHandler.config.user_vault_platform_consumers = {}
        try:
            status, body = _raise(uv_ctx, s)
        finally:
            BootloaderHandler.config.user_vault_platform_consumers = saved
        assert status == 403 and body["error"] == "grant_request_consumer_unmapped", body

    def test_the_words_never_touch_disk(self, uv_ctx) -> None:
        a, s = _bound(uv_ctx)
        purpose, name = "PURPOSE-" + uuid.uuid4().hex, "NAME-" + uuid.uuid4().hex[:12]
        assert _raise(uv_ctx, s, purpose=purpose, agent_name=name)[0] == 200
        assert _uv_cards(uv_ctx, a)[0]["context"]["user_vault_grant"]["purpose"] == purpose
        assert uv_ctx["state"].list_pending_for_phone(a.ref) == []
        for f in uv_ctx["dir"].rglob("*"):
            if f.is_file() and f.suffix != ".lock":  # the store lock is held open by the server
                raw = f.read_bytes()
                assert purpose.encode() not in raw and name.encode() not in raw, f

    def test_one_open_request_per_agent_and_key(self, uv_ctx) -> None:
        _, s = _bound(uv_ctx)
        assert _raise(uv_ctx, s)[0] == 200
        status, body = _raise(uv_ctx, s)
        assert status == 409 and body["error"] == "grant_request_open", body

    def test_raises_per_subject_are_rate_limited(self, uv_ctx) -> None:
        from recto.user_vault.grant_request import RAISES_PER_HOUR

        _, s = _bound(uv_ctx)
        for i in range(RAISES_PER_HOUR):
            assert _raise(uv_ctx, s, key=f"user-ai-k{i}")[0] == 200
        status, body = _raise(uv_ctx, s, key="user-ai-one-more")
        assert status == 429 and body["error"] == "grant_request_rate_limited", body

    @pytest.mark.parametrize("field,value", [
        ("purpose", "reads one way‮yaw rehtona"), ("purpose", "x" * 281),
        ("agent_name", "Agent\nOne"), ("agent_name", "n" * 65),
    ])
    def test_words_over_the_cap_or_with_control_characters_are_refused(self, uv_ctx, field, value) -> None:
        a, s = _bound(uv_ctx)
        status, body = _raise(uv_ctx, s, **{field: value})
        assert status == 400 and body["error"] == "grant_request_invalid", body
        assert _uv_cards(uv_ctx, a) == []

    def test_the_phones_grant_resolves_the_request_and_drops_its_words(self, uv_ctx) -> None:
        a, s = _bound(uv_ctx)
        rid = _raise(uv_ctx, s, purpose="p", agent_name="n")[1]["request_id"]
        shorter = int(time.time()) + 7 * 86400  # the person picked a shorter chip; the grant id differs from any proposal
        gid = _grant(uv_ctx, a, _grant_dict(s, not_after=shorter))[1]["grant_id"]
        status, body = _status(uv_ctx, s, rid)
        assert status == 200 and body["status"] == "admitted" and body["grant_id"] == gid, body
        assert body["not_after"] == shorter
        assert _uv_cards(uv_ctx, a) == []
        from recto.bootloader.server import BootloaderHandler
        r = BootloaderHandler.config.user_vault_grant_requests.get(rid)
        assert r.purpose is None and r.agent_name is None

    def test_deny_takes_the_card_off_the_phone(self, uv_ctx) -> None:
        a, s = _bound(uv_ctx)
        rid = _raise(uv_ctx, s)[1]["request_id"]
        assert _post_body(uv_ctx, "grant-request/deny", {"request_id": rid})[0] == 200
        assert _status(uv_ctx, s, rid)[1]["status"] == "denied"
        assert _uv_cards(uv_ctx, a) == []

    def test_another_subjects_request_reads_as_unknown(self, uv_ctx) -> None:
        _, s = _bound(uv_ctx, "a")
        _, s2 = _bound(uv_ctx, "b", member="member-2")
        rid = _raise(uv_ctx, s)[1]["request_id"]
        status, body = _status(uv_ctx, s2, rid)
        assert status == 404 and body["error"] == "grant_request_unknown", body


class TestRule15aaARevokeNeverNeedsThePlatform:
    """Hard rule 15.aa: the bound phone reads its subjects' live grants from the bootloader by its own signature and
    revokes one, or every grant of one key ("stop all"), straight to the bootloader - no platform call anywhere. A
    stop-all is used once: re-sent, it ends nothing granted since."""

    def test_the_phone_lists_its_live_grants_by_its_own_signature(self, uv_ctx) -> None:
        a, s = _bound(uv_ctx)
        gid = _grant(uv_ctx, a, _grant_dict(s))[1]["grant_id"]
        status, body = _list_grants(uv_ctx, a)
        assert status == 200, body
        assert [(g["grant_id"], g["subject"], g["key"]) for g in body["grants"]] == [(gid, s, "user-ai-xai")]
        assert "agent_name" not in body["grants"][0] and "purpose" not in body["grants"][0]

    def test_another_phones_signature_reads_nothing(self, uv_ctx) -> None:
        a, s = _bound(uv_ctx, "a")
        b, _ = _bound(uv_ctx, "b", member="member-2")
        _grant(uv_ctx, a, _grant_dict(s))
        status, body = _list_grants(uv_ctx, a, signer=b)
        assert status == 403 and body["error"] == "grant_signature_invalid", body

    def test_a_stale_list_request_is_refused(self, uv_ctx) -> None:
        a, _ = _bound(uv_ctx)
        status, body = _list_grants(uv_ctx, a, issued_at=int(time.time()) - 600)
        assert status == 403 and body["error"] == "grant_list_stale", body

    def test_a_revoke_from_the_list_needs_no_platform(self, uv_ctx) -> None:
        a, s = _bound(uv_ctx)
        _grant(uv_ctx, a, _grant_dict(s))
        listed = _list_grants(uv_ctx, a)[1]["grants"][0]
        status, body = _revoke(uv_ctx, a, listed["subject"], listed["grant_id"])
        assert status == 200 and body["revoked"] is True, body
        assert _list_grants(uv_ctx, a)[1]["grants"] == []

    def test_stop_all_ends_every_grant_of_the_key_and_only_that_key(self, uv_ctx) -> None:
        a, s = _bound(uv_ctx)
        g1 = _grant(uv_ctx, a, _grant_dict(s, agent_handle=_handle("agent-1")))[1]["grant_id"]
        g2 = _grant(uv_ctx, a, _grant_dict(s, agent_handle=_handle("agent-2")))[1]["grant_id"]
        other = _grant(uv_ctx, a, _grant_dict(s, key="user-ai-other"))[1]["grant_id"]
        status, body, _ = _revoke_key(uv_ctx, a, s)
        assert status == 200 and sorted(body["revoked"]) == sorted([g1, g2]), body
        assert [g["grant_id"] for g in _list_grants(uv_ctx, a)[1]["grants"]] == [other]

    def test_a_stop_all_re_sent_ends_nothing_granted_since(self, uv_ctx) -> None:
        a, s = _bound(uv_ctx)
        _grant(uv_ctx, a, _grant_dict(s))
        status, _, signed = _revoke_key(uv_ctx, a, s)
        assert status == 200
        fresh = _grant(uv_ctx, a, _grant_dict(s))[1]["grant_id"]
        status, body = _post_body(uv_ctx, "revoke-key", signed)  # the replay, signature verbatim
        assert status == 403 and body["error"] == "grant_act_used", body
        assert [g["grant_id"] for g in _list_grants(uv_ctx, a)[1]["grants"]] == [fresh]

    def test_a_stop_all_with_a_long_window_is_refused(self, uv_ctx) -> None:
        from recto.user_vault.grant_record import ACT_WINDOW_SECONDS

        a, s = _bound(uv_ctx)
        status, body, _ = _revoke_key(uv_ctx, a, s, window=ACT_WINDOW_SECONDS + 60)
        assert status == 403 and body["error"] == "grant_act_window_invalid", body

    def test_only_the_bound_phone_stops_all(self, uv_ctx) -> None:
        a, s = _bound(uv_ctx, "a")
        b, _ = _bound(uv_ctx, "b", member="member-2")
        _grant(uv_ctx, a, _grant_dict(s))
        status, body, _ = _revoke_key(uv_ctx, b, s)
        assert status == 403 and body["error"] == "grant_signature_invalid", body
        assert len(_list_grants(uv_ctx, a)[1]["grants"]) == 1

    def test_the_service_may_ask_for_a_revoke_and_the_phone_carries_it_out(self, uv_ctx) -> None:
        a, s = _bound(uv_ctx)
        gid = _grant(uv_ctx, a, _grant_dict(s))[1]["grant_id"]
        status, body = _raise(uv_ctx, s, action="revoke", grant_id=gid)
        assert status == 200, body
        card = _uv_cards(uv_ctx, a)[0]
        assert card["kind"] == "user_vault_revoke" and card["context"]["user_vault_grant"]["grant_id"] == gid
        assert _revoke(uv_ctx, a, s, gid)[0] == 200
        assert _status(uv_ctx, s, body["request_id"])[1]["status"] == "revoked"
