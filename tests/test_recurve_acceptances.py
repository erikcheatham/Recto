"""Hard rule 15 - the fail-closed shapes recurve tried to call defects (2026-09-25).

The first whole-tree recurve pass over Recto (run e410, 140 modules, an
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
    already refused. (recurve: missing-nbf-check, pair_record.py:173)"""

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
    the intended end state. (recurve: master-revocation-without-children-check)"""

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
    the TTL. (recurve: fail-open-on-missing-state-store, server.py:632)"""

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
