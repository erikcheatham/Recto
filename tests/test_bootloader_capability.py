"""Tests for the Phase 5 Wave B capability_request routing.

Covers three layers:

1. ``PendingRequest.new_capability_request`` construction + validation
   in ``recto.bootloader.state``: shape gates (non-empty cap_*_b64,
   valid base64url, payload decodes to JSON object with required JWT
   claims, exp not in past).
2. Server-level: ``_pending_to_wire`` emits ``cap_*`` fields when
   ``kind == "capability_request"`` and omits them otherwise; the new
   ``CapabilityResult`` dataclass round-trips through the StateStore.
3. End-to-end through the live HTTP ``BootloaderHandler``: an external
   agent POSTs a CapabilityClaims to ``/v0.4/capability/request``;
   the bootloader queues a PendingRequest visible via
   ``GET /v0.4/pending``; the phone resolves via
   ``POST /v0.4/respond/<id>`` with both the Ed25519 envelope AND the
   secp256k1 cap-signature; the bootloader assembles the JWS and the
   agent fetches it from ``GET /v0.4/capability/result/<id>``.

These tests require the ``[v0_4]`` extra (``cryptography``) for the
Ed25519 paired-phone fixture. The capability-side secp256k1 sign in
the round-trip uses BouncyCastle-shaped raw r||s sigs that the
bootloader treats as opaque (same opaque-forward pattern as
eth_signature_rsv); the test does NOT exercise full JWS verification
against an expected operator pubkey because the Python-side
secp256k1 sign primitive is still Wave A continuation.
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
from http.server import HTTPServer
from pathlib import Path
from typing import Any
from urllib import request as urlrequest
from urllib.error import HTTPError

import pytest

from recto.bootloader.server import (
    BootloaderConfig,
    BootloaderHandler,
    ChallengeStore,
    create_server,
)
from recto.bootloader.state import (
    CapabilityResult,
    PendingRequest,
    PhoneRegistration,
    StateStore,
)
from recto.capability.jwt import (
    _b64url_encode,
    _canonical_json,
    build_signing_input,
)
from recto.capability.types import (
    CapabilityClaims,
    CapabilityClause,
    CapabilityLimits,
    CapabilityScope,
)


def _b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------------------
# Fixtures: a known-good CapabilityClaims and its pre-encoded JWS segments
# ---------------------------------------------------------------------------


def _starter_claims(*, exp_offset_seconds: int = 86400) -> CapabilityClaims:
    """Darwin v1 starter capability — weight 18, Tier 1, 24h default."""
    now = int(time.time())
    return CapabilityClaims(
        iss="phone:operator:enclave",
        sub="agent:darwin@staging",
        aud=["consumer-app", "recto:vault"],
        iat=now,
        nbf=now,
        exp=now + exp_offset_seconds,
        jti=f"cap_test_{now}",
        cap=CapabilityClause(
            tier=1,
            registry_version="2026-05-05",
            groups=[
                "darwin:doc-edits",
                "darwin:staging-deploys",
                "darwin:secret-reads",
                "darwin:public-comms",
            ],
            scope=CapabilityScope(
                env=["staging"],
                services=["web", "darwin"],
                repos=["consumer-app", "recto"],
            ),
            allow_actions=[],
            deny_actions=["secret:rotate"],
            limits=CapabilityLimits(
                per_hour={},
                per_day={"deploy:staging": 5, "secret:read": 100},
                per_session={},
            ),
        ),
        purpose="Darwin v1 staging operations — Tier 0/1 autonomous",
    )


def _encode_claims(claims: CapabilityClaims) -> tuple[bytes, str, str]:
    """Build the JWS signing input from a CapabilityClaims."""
    return build_signing_input(claims)


# ---------------------------------------------------------------------------
# State-level: PendingRequest.new_capability_request construction
# ---------------------------------------------------------------------------


class TestNewCapabilityRequestConstruction:
    def _kwargs(self, **overrides: Any) -> dict[str, Any]:
        digest, header_b64, payload_b64 = _encode_claims(_starter_claims())
        base = dict(
            service="recto",
            secret="capability",
            phone_id="phone1",
            operation_description="Darwin staging-deploys capability",
            payload_hash_b64u=_b64u_encode(digest),
            child_pid=0,
            child_argv0="(external-agent)",
            cap_header_b64=header_b64,
            cap_payload_b64=payload_b64,
            cap_agent_id="darwin",
        )
        base.update(overrides)
        return base

    def test_happy_path(self) -> None:
        req = PendingRequest.new_capability_request(**self._kwargs())
        assert req.kind == "capability_request"
        assert req.cap_header_b64
        assert req.cap_payload_b64
        assert req.cap_agent_id == "darwin"
        assert req.eth_chain_id is None  # other-kind fields stay None
        assert req.btc_network is None
        assert req.ed_chain is None
        assert req.tron_network is None

    def test_default_ttl_is_one_hour(self) -> None:
        before = int(time.time())
        req = PendingRequest.new_capability_request(**self._kwargs())
        # Default ttl_seconds=3600 — capability requests are slower-rhythm
        # than per-sign flows.
        assert req.expires_at_unix - before >= 3590
        assert req.expires_at_unix - before <= 3610

    def test_explicit_ttl(self) -> None:
        req = PendingRequest.new_capability_request(
            **self._kwargs(ttl_seconds=600)
        )
        assert req.expires_at_unix - req.requested_at_unix == 600

    def test_empty_header_rejected(self) -> None:
        with pytest.raises(ValueError, match="cap_header_b64"):
            PendingRequest.new_capability_request(**self._kwargs(cap_header_b64=""))

    def test_empty_payload_rejected(self) -> None:
        with pytest.raises(ValueError, match="cap_payload_b64"):
            PendingRequest.new_capability_request(**self._kwargs(cap_payload_b64=""))

    def test_invalid_base64url_payload_rejected(self) -> None:
        # Square brackets are NOT in the base64url alphabet.
        with pytest.raises(ValueError, match="cap_payload_b64"):
            PendingRequest.new_capability_request(
                **self._kwargs(cap_payload_b64="[][][][")
            )

    def test_payload_must_decode_to_json_object(self) -> None:
        # Encode a JSON array, not an object.
        bad_payload = _b64u_encode(json.dumps([1, 2, 3]).encode("utf-8"))
        with pytest.raises(ValueError, match="JSON object"):
            PendingRequest.new_capability_request(
                **self._kwargs(cap_payload_b64=bad_payload)
            )

    def test_payload_missing_required_claim_rejected(self) -> None:
        # Drop the `cap` field.
        partial = {
            "iss": "x", "sub": "y", "aud": ["z"],
            "iat": 0, "nbf": 0, "exp": int(time.time()) + 3600,
            "jti": "j", "purpose": "p",
            # cap missing
        }
        bad_payload = _b64u_encode(_canonical_json(partial))
        with pytest.raises(ValueError, match="missing required claims"):
            PendingRequest.new_capability_request(
                **self._kwargs(cap_payload_b64=bad_payload)
            )

    def test_payload_with_past_exp_rejected(self) -> None:
        past_claims = _starter_claims(exp_offset_seconds=-3600)  # 1h ago
        digest, header_b64, payload_b64 = _encode_claims(past_claims)
        with pytest.raises(ValueError, match="exp.*in the past"):
            PendingRequest.new_capability_request(
                **self._kwargs(
                    cap_payload_b64=payload_b64,
                    cap_header_b64=header_b64,
                    payload_hash_b64u=_b64u_encode(digest),
                )
            )

    def test_empty_agent_id_normalized_to_none(self) -> None:
        req = PendingRequest.new_capability_request(**self._kwargs(cap_agent_id="   "))
        assert req.cap_agent_id is None

    def test_agent_id_optional(self) -> None:
        req = PendingRequest.new_capability_request(**self._kwargs(cap_agent_id=None))
        assert req.cap_agent_id is None


# ---------------------------------------------------------------------------
# State-level: round-trip through StateStore
# ---------------------------------------------------------------------------


class TestCapabilityRequestPersistence:
    @pytest.fixture
    def store(self, tmp_path: Path) -> StateStore:
        return StateStore(state_dir=tmp_path)

    def _build_req(self) -> PendingRequest:
        digest, header_b64, payload_b64 = _encode_claims(_starter_claims())
        return PendingRequest.new_capability_request(
            service="recto", secret="capability", phone_id="phone1",
            operation_description="x",
            payload_hash_b64u=_b64u_encode(digest),
            child_pid=0, child_argv0="(external-agent)",
            cap_header_b64=header_b64, cap_payload_b64=payload_b64,
            cap_agent_id="darwin",
        )

    def test_capability_request_round_trips_through_disk(
        self, store: StateStore
    ) -> None:
        req = self._build_req()
        store.add_pending(req)
        listed = store.list_pending_for_phone("phone1")
        assert len(listed) == 1
        loaded = listed[0]
        assert loaded.kind == "capability_request"
        assert loaded.cap_header_b64 == req.cap_header_b64
        assert loaded.cap_payload_b64 == req.cap_payload_b64
        assert loaded.cap_agent_id == "darwin"

    def test_take_pending_returns_full_request(
        self, store: StateStore
    ) -> None:
        req = self._build_req()
        store.add_pending(req)
        taken = store.take_pending(req.request_id)
        assert taken is not None
        assert taken.kind == "capability_request"
        assert taken.cap_payload_b64 == req.cap_payload_b64
        # Single-use semantics
        assert store.take_pending(req.request_id) is None

    def test_capability_result_store_round_trip(
        self, store: StateStore
    ) -> None:
        now = int(time.time())
        result = CapabilityResult(
            request_id="rid-1",
            status="approved",
            capability_jws="header.payload.signature",
            reason=None,
            agent_id="darwin",
            resolved_at_unix=now,
            expires_at_unix=now + 600,
        )
        store.put_capability_result(result)
        got = store.get_capability_result("rid-1")
        assert got is not None
        assert got.capability_jws == "header.payload.signature"
        # take is single-use
        taken = store.take_capability_result("rid-1")
        assert taken is not None
        assert store.get_capability_result("rid-1") is None

    def test_capability_result_purges_expired(
        self, store: StateStore
    ) -> None:
        now = int(time.time())
        result = CapabilityResult(
            request_id="rid-old",
            status="approved",
            capability_jws="x",
            reason=None,
            agent_id="darwin",
            resolved_at_unix=now - 7200,
            expires_at_unix=now - 3600,  # 1h ago
        )
        store.put_capability_result(result)
        # The put itself runs purge_expired before insert, so the just-
        # inserted-but-already-expired entry sticks for one read; the
        # next read sees it as expired and prunes.
        store.get_capability_result("rid-old")  # purge happens
        assert store.get_capability_result("rid-old") is None


# ---------------------------------------------------------------------------
# Server-level: _pending_to_wire emits cap_* fields
# ---------------------------------------------------------------------------


class TestCapabilityPendingToWire:
    def test_capability_context_fields_emitted(self) -> None:
        digest, header_b64, payload_b64 = _encode_claims(_starter_claims())
        req = PendingRequest.new_capability_request(
            service="recto", secret="capability", phone_id="phone1",
            operation_description="capability test",
            payload_hash_b64u=_b64u_encode(digest),
            child_pid=0, child_argv0="(external-agent)",
            cap_header_b64=header_b64, cap_payload_b64=payload_b64,
            cap_agent_id="darwin",
        )
        wire = BootloaderHandler._pending_to_wire(req)
        ctx = wire["context"]
        assert wire["kind"] == "capability_request"
        assert ctx["cap_header_b64"] == header_b64
        assert ctx["cap_payload_b64"] == payload_b64
        assert ctx["cap_agent_id"] == "darwin"
        # Other-kind fields are absent.
        assert "eth_chain_id" not in ctx
        assert "btc_network" not in ctx
        assert "ed_chain" not in ctx
        assert "tron_network" not in ctx

    def test_capability_agent_id_omitted_when_none(self) -> None:
        digest, header_b64, payload_b64 = _encode_claims(_starter_claims())
        req = PendingRequest.new_capability_request(
            service="recto", secret="capability", phone_id="phone1",
            operation_description="x",
            payload_hash_b64u=_b64u_encode(digest),
            child_pid=0, child_argv0="(external-agent)",
            cap_header_b64=header_b64, cap_payload_b64=payload_b64,
            cap_agent_id=None,
        )
        wire = BootloaderHandler._pending_to_wire(req)
        ctx = wire["context"]
        assert "cap_agent_id" not in ctx

    def test_non_capability_kind_omits_cap_fields(self) -> None:
        req = PendingRequest.new(
            kind="single_sign",
            service="svc", secret="KEY", phone_id="phone1",
            operation_description="x",
            payload_hash_b64u="aA",
            child_pid=1, child_argv0="x",
        )
        wire = BootloaderHandler._pending_to_wire(req)
        ctx = wire["context"]
        assert "cap_header_b64" not in ctx
        assert "cap_payload_b64" not in ctx
        assert "cap_agent_id" not in ctx


# ---------------------------------------------------------------------------
# End-to-end: live HTTP server, queue + GET /pending + POST /respond + result
# ---------------------------------------------------------------------------


@pytest.fixture
def signing_pair():
    """Returns (Ed25519PrivateKey, public_key_b64u). Mirrors the
    test_bootloader_eth pattern."""
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    priv = Ed25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv, _b64u_encode(pub_bytes)


@pytest.fixture(params=[True], ids=["operator-key"])
def live_server(tmp_path: Path, signing_pair, request):
    """Spin a real BootloaderHandler with capability_agent_tokens
    configured. Yields a context dict with base_url, state, phone_id,
    captured resolutions, and the agent token pair for use in test
    requests.

    Parametrised on WHETHER AN OPERATOR PUBKEY IS CONFIGURED so a single
    test can exercise the unconfigured bootloader without a second copy of
    this fixture -- a duplicated fixture is a second place for the shipped
    posture to be restated, and the two only agree until one moves.
    """
    priv, pub_b64u = signing_pair
    state = StateStore(state_dir=tmp_path)
    phone = PhoneRegistration.new(
        device_label="Test Phone",
        public_key_b64u=pub_b64u,
        supported_algorithms=("ed25519",),
    )
    state.register_phone(phone)

    captured: list[dict[str, Any]] = []

    def notify_fn(*, req, ok, signature_b64u, capability_jws=None,
                  eth_signature_rsv=None, btc_signature_base64=None,
                  ed_signature_base64=None, ed_pubkey_hex=None,
                  tron_signature_rsv=None, reason=None, **_extra):
        captured.append({
            "request_id": req.request_id,
            "kind": req.kind,
            "ok": ok,
            "signature_b64u": signature_b64u,
            "capability_jws": capability_jws,
            "reason": reason,
        })

    agent_id = "darwin"
    agent_token = "test-token-32-hex-chars-fixture-only"

    server = create_server(
        bind_host="127.0.0.1",
        bind_port=0,
        state=state,
        bootloader_id="test-bootloader",
        challenges=ChallengeStore(),
        notify_resolved_fn=notify_fn,
        ssl_context=None,
        capability_agent_tokens={agent_id: agent_token},
        # An operator pubkey is REQUIRED as of 2026-08-17: the mint path
        # fails closed when it is None, matching the four sibling sites
        # that always did.
        #
        # WHAT THIS FIXTURE USED TO SAY, and why it was wrong twice over:
        #   "Don't set capability_operator_pubkey - the round-trip test uses
        #    opaque-forward semantics. A full pubkey-recovery cross-check
        #    requires the deferred Python-side secp256k1 sign primitive."
        #
        # 1. THE PRIMITIVE WAS NO LONGER DEFERRED. `_mint_jws` in
        #    test_bootloader_capability_gate.py has signed ES256K with
        #    `cryptography` for some time. The comment described a
        #    limitation that had already been lifted one file away.
        # 2. WITHOUT A PUBKEY THE MINT SKIPPED VERIFICATION ENTIRELY, so the
        #    happy path posted `b"\x33" * 64` -- SIXTY-FOUR BYTES OF LITERAL
        #    0x33 -- and asserted the result was `approved`. That is not a
        #    weak signature; it is not a signature. The test was pinning
        #    "an arbitrary blob is minted as an approved capability."
        #
        # The tests now sign for real via `_sign_cap` below, so the round
        # trip exercises the crossing instead of routing around it.
        capability_operator_pubkey=(OPERATOR_PUBKEY if request.param else None),
    )
    host, port = server.server_address
    base_url = f"http://{host}:{port}"

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {
            "base_url": base_url,
            "state": state,
            "phone_id": phone.phone_id,
            "phone_priv": priv,
            "phone_pub_b64u": pub_b64u,
            "captured": captured,
            "agent_id": agent_id,
            "agent_token": agent_token,
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)


# ---------------------------------------------------------------------------
# Operator signing, test-only (2026-08-17)
#
# The bootloader now REFUSES to mint when no operator pubkey is configured, so
# these tests must produce a signature that actually recovers to one. Mirrors
# `_mint_jws` in test_bootloader_capability_gate.py: `cryptography` standing in
# for the Secure Enclave / StrongBox, over the same ES256K signing input the
# phone signs in production -- SHA-256(header_b64 + "." + payload_b64).
# ---------------------------------------------------------------------------

def _make_operator_keypair() -> tuple[int, bytes]:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import ec

    priv = ec.generate_private_key(ec.SECP256K1(), default_backend())
    nums = priv.public_key().public_numbers()
    # Uncompressed X||Y, no 0x04 prefix -- what capability_operator_pubkey wants.
    return priv.private_numbers().private_value, (
        nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")
    )


OPERATOR_PRIV_INT, OPERATOR_PUBKEY = _make_operator_keypair()


def _sign_cap(header_b64: str, payload_b64: str) -> str:
    """Sign a pending request's capability header+payload as the operator
    would, returning the b64url raw r||s the phone posts as
    ``cap_signature_b64u``."""
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    digest = hashlib.sha256(f"{header_b64}.{payload_b64}".encode("ascii")).digest()
    priv = ec.derive_private_key(OPERATOR_PRIV_INT, ec.SECP256K1(), default_backend())
    sig_der = priv.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    r, s = utils.decode_dss_signature(sig_der)
    # Low-s canonicalisation; some verifiers reject high-s. secp256k1 N:
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    if s > n // 2:
        s = n - s
    return _b64u_encode(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def _http_get_json(
    url: str, headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    req = urlrequest.Request(url, headers=headers or {}, method="GET")
    try:
        with urlrequest.urlopen(req, timeout=5.0) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


def _http_post_json(
    url: str, body: dict[str, Any],
    headers: dict[str, str] | None = None,
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


def _claims_dict() -> dict[str, Any]:
    """Serialize starter claims to dict shape for POST body."""
    from dataclasses import asdict
    return asdict(_starter_claims())


class TestCapabilityRequestEndpoint:
    def test_request_endpoint_queues_pending(
        self, live_server: dict[str, Any]
    ) -> None:
        ctx = live_server
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/capability/request",
            {
                "phone_id": ctx["phone_id"],
                "claims": _claims_dict(),
                "operation_description": "test capability",
            },
            headers={
                "X-Recto-Agent-Id": ctx["agent_id"],
                "X-Recto-Agent-Token": ctx["agent_token"],
            },
        )
        assert status == 201
        assert "request_id" in body
        assert "result_url" in body
        assert "expires_at_unix" in body

    def test_request_without_agent_headers_unauthorized(
        self, live_server: dict[str, Any]
    ) -> None:
        ctx = live_server
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/capability/request",
            {"phone_id": ctx["phone_id"], "claims": _claims_dict()},
        )
        assert status == 401
        assert body["error"] == "agent_auth_required"

    def test_request_with_wrong_token_unauthorized(
        self, live_server: dict[str, Any]
    ) -> None:
        ctx = live_server
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/capability/request",
            {"phone_id": ctx["phone_id"], "claims": _claims_dict()},
            headers={
                "X-Recto-Agent-Id": ctx["agent_id"],
                "X-Recto-Agent-Token": "wrong-token",
            },
        )
        assert status == 401
        assert body["error"] == "agent_auth_failed"

    def test_request_with_unknown_phone_400(
        self, live_server: dict[str, Any]
    ) -> None:
        ctx = live_server
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/capability/request",
            {"phone_id": "unknown-phone", "claims": _claims_dict()},
            headers={
                "X-Recto-Agent-Id": ctx["agent_id"],
                "X-Recto-Agent-Token": ctx["agent_token"],
            },
        )
        assert status == 400
        assert "not registered" in body["detail"]

    def test_request_with_invalid_claims_400(
        self, live_server: dict[str, Any]
    ) -> None:
        ctx = live_server
        bad_claims = {"iss": "x"}  # missing required fields
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/capability/request",
            {"phone_id": ctx["phone_id"], "claims": bad_claims},
            headers={
                "X-Recto-Agent-Id": ctx["agent_id"],
                "X-Recto-Agent-Token": ctx["agent_token"],
            },
        )
        assert status == 400
        assert "validation" in body["detail"].lower() or "missing" in body["detail"].lower()


class TestCapabilityRequestEndToEnd:
    def _queue(self, ctx: dict[str, Any]) -> dict[str, Any]:
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/capability/request",
            {"phone_id": ctx["phone_id"], "claims": _claims_dict()},
            headers={
                "X-Recto-Agent-Id": ctx["agent_id"],
                "X-Recto-Agent-Token": ctx["agent_token"],
            },
        )
        assert status == 201, body
        return body

    def test_pending_endpoint_shows_capability_request(
        self, live_server: dict[str, Any]
    ) -> None:
        ctx = live_server
        queued = self._queue(ctx)
        status, body = _http_get_json(
            f"{ctx['base_url']}/v0.4/pending?phone_id={ctx['phone_id']}"
        )
        assert status == 200
        assert len(body["requests"]) == 1
        wire = body["requests"][0]
        assert wire["request_id"] == queued["request_id"]
        assert wire["kind"] == "capability_request"
        assert "cap_header_b64" in wire["context"]
        assert "cap_payload_b64" in wire["context"]
        assert wire["context"]["cap_agent_id"] == ctx["agent_id"]

    def test_result_endpoint_returns_pending_before_respond(
        self, live_server: dict[str, Any]
    ) -> None:
        ctx = live_server
        queued = self._queue(ctx)
        status, body = _http_get_json(
            f"{ctx['base_url']}/v0.4/capability/result/{queued['request_id']}",
            headers={
                "X-Recto-Agent-Id": ctx["agent_id"],
                "X-Recto-Agent-Token": ctx["agent_token"],
            },
        )
        assert status == 200
        assert body["status"] == "pending"

    def test_full_round_trip_approved(
        self, live_server: dict[str, Any]
    ) -> None:
        ctx = live_server
        queued = self._queue(ctx)
        # Phone fetches the queued request to get the cap_*_b64 segments.
        _, pending_body = _http_get_json(
            f"{ctx['base_url']}/v0.4/pending?phone_id={ctx['phone_id']}"
        )
        wire = pending_body["requests"][0]
        cap_header_b64 = wire["context"]["cap_header_b64"]
        cap_payload_b64 = wire["context"]["cap_payload_b64"]
        # The phone signs SHA-256(signing_input). For this test we
        # use a fake-but-well-formed 64-byte signature; the bootloader
        # treats it as opaque (no verify_jws cross-check because the
        # config didn't pass capability_operator_pubkey).
        signing_input = f"{cap_header_b64}.{cap_payload_b64}".encode("ascii")
        # Ed25519 paired-phone envelope over payload_hash_b64u (which
        # IS the SHA-256 of the signing input — the bootloader pinned
        # them together at queue time).
        payload_hash_b64u = wire["context"]["payload_hash_b64u"]
        padding = "=" * (-len(payload_hash_b64u) % 4)
        hash_bytes = base64.urlsafe_b64decode(payload_hash_b64u + padding)
        # Verify the bootloader's hash matches the actual SHA-256.
        assert hash_bytes == hashlib.sha256(signing_input).digest()
        ed_sig = ctx["phone_priv"].sign(hash_bytes)
        # A REAL operator signature over the real signing input. This used to
        # be `b"\x11"*32 + b"\x22"*32` with the note "opaque to the bootloader
        # (no operator pubkey configured) — any 64 bytes pass structure-check."
        # That was accurate and that was the problem: the happy path asserted
        # `approved` for a constant. The mint now verifies, so the test signs.
        cap_sig_b64u = _sign_cap(cap_header_b64, cap_payload_b64)
        status, resp = _http_post_json(
            f"{ctx['base_url']}/v0.4/respond/{queued['request_id']}",
            {
                "decision": "approved",
                "signature_b64u": _b64u_encode(ed_sig),
                "cap_signature_b64u": cap_sig_b64u,
            },
        )
        assert status == 200, resp
        assert resp == {"resolved": True}
        # Resolver was called with capability_jws forwarded.
        assert len(ctx["captured"]) == 1
        cap = ctx["captured"][0]
        assert cap["ok"] is True
        assert cap["kind"] == "capability_request"
        assert cap["capability_jws"] is not None
        # The JWS is the 3-part header.payload.signature form.
        parts = cap["capability_jws"].split(".")
        assert len(parts) == 3
        assert parts[0] == cap_header_b64
        assert parts[1] == cap_payload_b64
        # Agent fetches the result.
        status, body = _http_get_json(
            f"{ctx['base_url']}/v0.4/capability/result/{queued['request_id']}",
            headers={
                "X-Recto-Agent-Id": ctx["agent_id"],
                "X-Recto-Agent-Token": ctx["agent_token"],
            },
        )
        assert status == 200
        assert body["status"] == "approved"
        assert body["capability_jws"] == cap["capability_jws"]

    @pytest.mark.parametrize("live_server", [False], indirect=True,
                             ids=["no-operator-key"])
    def test_mint_refuses_when_no_operator_pubkey_is_configured(
        self, live_server: dict[str, Any]
    ) -> None:
        """GATE 0 falsifier (2026-08-17). A bootloader that has never been
        told who the operator is must not mint.

        `capability_operator_pubkey` DEFAULTS TO None, and this site used to
        read `if ... is not None:` -- i.e. it SKIPPED verification whenever
        the key was absent and returned the assembled JWS anyway. The four
        sibling sites that consume the same field (:2013, :2221, :2417,
        :4978) all refused on None; this was the lone fail-open, on the mint
        path, under the default configuration.

        It is not the estate's only verification -- the consuming platform
        checks independently -- so this is defence in depth. It fails closed
        regardless, because A DEFENCE THAT SILENTLY DISABLES ITSELF IS NOT ONE.

        Note what this test could not have caught before: the old happy path
        posted sixty-four bytes of literal 0x33 and asserted `approved`.
        """
        ctx = live_server
        queued = self._queue(ctx)
        _, pending_body = _http_get_json(
            f"{ctx['base_url']}/v0.4/pending?phone_id={ctx['phone_id']}"
        )
        wire = pending_body["requests"][0]
        payload_hash_b64u = wire["context"]["payload_hash_b64u"]
        padding = "=" * (-len(payload_hash_b64u) % 4)
        hash_bytes = base64.urlsafe_b64decode(payload_hash_b64u + padding)
        ed_sig = ctx["phone_priv"].sign(hash_bytes)

        # A perfectly VALID operator signature. The point is that validity is
        # irrelevant when the bootloader holds no key to judge it against --
        # it must refuse rather than forward something it cannot check.
        cap_sig_b64u = _sign_cap(
            wire["context"]["cap_header_b64"], wire["context"]["cap_payload_b64"]
        )
        _http_post_json(
            f"{ctx['base_url']}/v0.4/respond/{queued['request_id']}",
            {
                "decision": "approved",
                "signature_b64u": _b64u_encode(ed_sig),
                "cap_signature_b64u": cap_sig_b64u,
            },
        )

        status, body = _http_get_json(
            f"{ctx['base_url']}/v0.4/capability/result/{queued['request_id']}",
            headers={
                "X-Recto-Agent-Id": ctx["agent_id"],
                "X-Recto-Agent-Token": ctx["agent_token"],
            },
        )
        assert status == 200
        assert body["status"] == "not_configured", body
        # And nothing mintable came back.
        assert not body.get("capability_jws")

    def test_result_is_single_use(
        self, live_server: dict[str, Any]
    ) -> None:
        ctx = live_server
        queued = self._queue(ctx)
        # Approve, fetch once.
        _, pending_body = _http_get_json(
            f"{ctx['base_url']}/v0.4/pending?phone_id={ctx['phone_id']}"
        )
        wire = pending_body["requests"][0]
        payload_hash_b64u = wire["context"]["payload_hash_b64u"]
        padding = "=" * (-len(payload_hash_b64u) % 4)
        hash_bytes = base64.urlsafe_b64decode(payload_hash_b64u + padding)
        ed_sig = ctx["phone_priv"].sign(hash_bytes)
        cap_sig_b64u = _sign_cap(
            wire["context"]["cap_header_b64"], wire["context"]["cap_payload_b64"]
        )
        _http_post_json(
            f"{ctx['base_url']}/v0.4/respond/{queued['request_id']}",
            {
                "decision": "approved",
                "signature_b64u": _b64u_encode(ed_sig),
                "cap_signature_b64u": cap_sig_b64u,
            },
        )
        # First fetch — approved.
        status1, body1 = _http_get_json(
            f"{ctx['base_url']}/v0.4/capability/result/{queued['request_id']}",
            headers={
                "X-Recto-Agent-Id": ctx["agent_id"],
                "X-Recto-Agent-Token": ctx["agent_token"],
            },
        )
        assert status1 == 200
        assert body1["status"] == "approved"
        # Second fetch — 404.
        status2, body2 = _http_get_json(
            f"{ctx['base_url']}/v0.4/capability/result/{queued['request_id']}",
            headers={
                "X-Recto-Agent-Id": ctx["agent_id"],
                "X-Recto-Agent-Token": ctx["agent_token"],
            },
        )
        assert status2 == 404

    def test_full_round_trip_denied(
        self, live_server: dict[str, Any]
    ) -> None:
        ctx = live_server
        queued = self._queue(ctx)
        status, resp = _http_post_json(
            f"{ctx['base_url']}/v0.4/respond/{queued['request_id']}",
            {
                "decision": "denied",
                "reason": "operator declined this scope",
            },
        )
        assert status == 200
        # Agent fetches result — sees denied.
        status, body = _http_get_json(
            f"{ctx['base_url']}/v0.4/capability/result/{queued['request_id']}",
            headers={
                "X-Recto-Agent-Id": ctx["agent_id"],
                "X-Recto-Agent-Token": ctx["agent_token"],
            },
        )
        assert status == 200
        assert body["status"] == "denied"
        assert body["reason"] == "operator declined this scope"
        assert "capability_jws" not in body

    def test_respond_missing_cap_signature_records_error(
        self, live_server: dict[str, Any]
    ) -> None:
        ctx = live_server
        queued = self._queue(ctx)
        _, pending_body = _http_get_json(
            f"{ctx['base_url']}/v0.4/pending?phone_id={ctx['phone_id']}"
        )
        wire = pending_body["requests"][0]
        payload_hash_b64u = wire["context"]["payload_hash_b64u"]
        padding = "=" * (-len(payload_hash_b64u) % 4)
        hash_bytes = base64.urlsafe_b64decode(payload_hash_b64u + padding)
        ed_sig = ctx["phone_priv"].sign(hash_bytes)
        # Approval without cap_signature_b64u — bootloader 400s.
        status, resp = _http_post_json(
            f"{ctx['base_url']}/v0.4/respond/{queued['request_id']}",
            {
                "decision": "approved",
                "signature_b64u": _b64u_encode(ed_sig),
                # cap_signature_b64u missing
            },
        )
        assert status == 400
        # Agent's poll sees signature_error.
        status, body = _http_get_json(
            f"{ctx['base_url']}/v0.4/capability/result/{queued['request_id']}",
            headers={
                "X-Recto-Agent-Id": ctx["agent_id"],
                "X-Recto-Agent-Token": ctx["agent_token"],
            },
        )
        assert status == 200
        assert body["status"] == "signature_error"
        assert "cap_signature_b64u missing" in body["reason"]

    def test_respond_wrong_length_cap_signature_records_error(
        self, live_server: dict[str, Any]
    ) -> None:
        ctx = live_server
        queued = self._queue(ctx)
        _, pending_body = _http_get_json(
            f"{ctx['base_url']}/v0.4/pending?phone_id={ctx['phone_id']}"
        )
        wire = pending_body["requests"][0]
        payload_hash_b64u = wire["context"]["payload_hash_b64u"]
        padding = "=" * (-len(payload_hash_b64u) % 4)
        hash_bytes = base64.urlsafe_b64decode(payload_hash_b64u + padding)
        ed_sig = ctx["phone_priv"].sign(hash_bytes)
        status, resp = _http_post_json(
            f"{ctx['base_url']}/v0.4/respond/{queued['request_id']}",
            {
                "decision": "approved",
                "signature_b64u": _b64u_encode(ed_sig),
                "cap_signature_b64u": _b64u_encode(b"\xab" * 32),  # 32 not 64
            },
        )
        assert status == 400
        assert "64 bytes" in resp["detail"]

    def test_result_endpoint_404_for_unknown_id(
        self, live_server: dict[str, Any]
    ) -> None:
        ctx = live_server
        status, body = _http_get_json(
            f"{ctx['base_url']}/v0.4/capability/result/nonexistent",
            headers={
                "X-Recto-Agent-Id": ctx["agent_id"],
                "X-Recto-Agent-Token": ctx["agent_token"],
            },
        )
        assert status == 404

    def test_result_endpoint_unauthorized_without_agent_headers(
        self, live_server: dict[str, Any]
    ) -> None:
        ctx = live_server
        queued = self._queue(ctx)
        status, body = _http_get_json(
            f"{ctx['base_url']}/v0.4/capability/result/{queued['request_id']}",
        )
        assert status == 401

    def test_result_endpoint_404_for_other_agent(
        self, live_server: dict[str, Any]
    ) -> None:
        """Agent A's request can't be fetched by agent B even with valid
        creds for B (cap_agent_id pinning)."""
        ctx = live_server
        # Reconfigure with a second agent token.
        BootloaderHandler.config.capability_agent_tokens["other-agent"] = "other-token"
        queued = self._queue(ctx)
        status, body = _http_get_json(
            f"{ctx['base_url']}/v0.4/capability/result/{queued['request_id']}",
            headers={
                "X-Recto-Agent-Id": "other-agent",
                "X-Recto-Agent-Token": "other-token",
            },
        )
        assert status == 404


# ---------------------------------------------------------------------------
# Endpoints disabled when capability_agent_tokens is empty
# ---------------------------------------------------------------------------


class TestCapabilityEndpointsDisabledWhenNoTokens:
    @pytest.fixture
    def disabled_server(self, tmp_path: Path, signing_pair):
        priv, pub_b64u = signing_pair
        state = StateStore(state_dir=tmp_path)
        phone = PhoneRegistration.new(
            device_label="x", public_key_b64u=pub_b64u,
            supported_algorithms=("ed25519",),
        )
        state.register_phone(phone)
        server = create_server(
            bind_host="127.0.0.1", bind_port=0, state=state,
            bootloader_id="test", challenges=ChallengeStore(),
            ssl_context=None,
            # capability_agent_tokens left at default (empty).
        )
        host, port = server.server_address
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield {"base_url": f"http://{host}:{port}"}
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5.0)

    def test_request_endpoint_404_when_disabled(
        self, disabled_server: dict[str, Any]
    ) -> None:
        ctx = disabled_server
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/capability/request",
            {"phone_id": "x", "claims": {}},
            headers={"X-Recto-Agent-Id": "a", "X-Recto-Agent-Token": "b"},
        )
        assert status == 404

    def test_result_endpoint_404_when_disabled(
        self, disabled_server: dict[str, Any]
    ) -> None:
        ctx = disabled_server
        status, body = _http_get_json(
            f"{ctx['base_url']}/v0.4/capability/result/x",
            headers={"X-Recto-Agent-Id": "a", "X-Recto-Agent-Token": "b"},
        )
        assert status == 404
