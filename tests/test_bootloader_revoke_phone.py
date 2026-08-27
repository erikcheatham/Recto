"""Tests for POST /v0.4/manage/phones/revoke (self-revoke + sibling-revoke).

Single endpoint handles both flows. Auth: signed-challenge from the
source phone, NOT capability-agent-token (the caller is a paired phone,
not an external agent). Mirrors the registration flow's challenge-
signature shape: phone fetches a challenge via the existing
``GET /v0.4/registration_challenge`` endpoint, signs the ASCII bytes
of ``f"{challenge_b64u}:{target_phone_id}"`` with its enclave key,
POSTs to this endpoint. The colon-binding in the payload prevents
replay -- a captured signature for one target can't be reused against
a different target.

Trust model for v1: any genuine paired phone has implicit authority
over its siblings (the "phones-as-master-quorum" model banked in
CLAUDE.md). Phase 5 v3 multi-device-per-user architecture will tighten
this with capability-JWT-gating; for v1 the signed-challenge from a
registered phone IS the authority.
"""

from __future__ import annotations

import base64
import json
import threading
from http import HTTPStatus
from pathlib import Path
from urllib import request as urlrequest
from urllib.error import HTTPError

import pytest

from recto.bootloader.server import ChallengeStore, create_server
from recto.bootloader.state import PhoneRegistration, StateStore


def _b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _http_post_json(url, body):
    data = json.dumps(body).encode("utf-8")
    req = urlrequest.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urlrequest.urlopen(req, timeout=5.0) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except HTTPError as e:
        body_bytes = e.read()
        try:
            return e.code, json.loads(body_bytes.decode("utf-8"))
        except json.JSONDecodeError:
            return e.code, {"_raw_body": body_bytes.decode("utf-8", errors="replace")}


def _generate_keypair():
    """Returns (Ed25519PrivateKey, public_key_b64u). Used by tests to
    seed phone registrations with valid signing keys."""
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv, _b64u_encode(pub_bytes)


def _sign(priv, payload: bytes) -> str:
    """Sign payload with an Ed25519PrivateKey, return base64url signature."""
    sig = priv.sign(payload)
    return _b64u_encode(sig)


@pytest.fixture
def two_phones_server(tmp_path: Path):
    """Live bootloader on a random port with TWO paired phones (an
    iPhone + a Pixel). Returns context with base_url, state, challenges,
    plus signing primitives for both phones."""
    iphone_priv, iphone_pub = _generate_keypair()
    pixel_priv, pixel_pub = _generate_keypair()
    state = StateStore(state_dir=tmp_path)
    iphone = PhoneRegistration.new(
        device_label="iPhone",
        public_key_b64u=iphone_pub,
        supported_algorithms=("ed25519",),
    )
    pixel = PhoneRegistration.new(
        device_label="Pixel",
        public_key_b64u=pixel_pub,
        supported_algorithms=("ed25519",),
    )
    state.register_phone(iphone)
    state.register_phone(pixel)
    challenges = ChallengeStore()
    server = create_server(
        bind_host="127.0.0.1",
        bind_port=0,
        state=state,
        bootloader_id="test-revoke",
        challenges=challenges,
        ssl_context=None,
    )
    host, port = server.server_address
    base_url = f"http://{host}:{port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {
            "base_url": base_url,
            "state": state,
            "challenges": challenges,
            "iphone": iphone,
            "iphone_priv": iphone_priv,
            "pixel": pixel,
            "pixel_priv": pixel_priv,
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)


def _build_revoke_body(*, revoker_id, target_id, challenge, revoker_priv):
    """Helper: construct a well-formed revoke body with valid sig."""
    payload = f"{challenge}:{target_id}".encode("ascii")
    return {
        "revoker_phone_id": revoker_id,
        "target_phone_id": target_id,
        "challenge_b64u": challenge,
        "signature_b64u": _sign(revoker_priv, payload),
    }


class TestRevokePhone:
    # ── Happy paths ────────────────────────────────────────────────────

    def test_self_revoke_happy_path(self, two_phones_server):
        """A phone removes itself (revoker_phone_id == target_phone_id)."""
        ctx = two_phones_server
        challenge, _ = ctx["challenges"].issue_challenge(ttl_seconds=60)
        body = _build_revoke_body(
            revoker_id=ctx["iphone"].phone_id,
            target_id=ctx["iphone"].phone_id,
            challenge=challenge,
            revoker_priv=ctx["iphone_priv"],
        )
        status, resp = _http_post_json(
            f"{ctx['base_url']}/v0.4/manage/phones/revoke", body)
        assert status == HTTPStatus.OK
        assert resp["revoked"] is True
        assert resp["revoked_phone_id"] == ctx["iphone"].phone_id
        assert resp["was_self_revoke"] is True
        assert resp["remaining_phones_count"] == 1
        # State actually updated
        assert ctx["state"].get_phone(ctx["iphone"].phone_id) is None
        assert ctx["state"].get_phone(ctx["pixel"].phone_id) is not None

    def test_sibling_revoke_happy_path(self, two_phones_server):
        """Pixel removes iPhone (revoker != target)."""
        ctx = two_phones_server
        challenge, _ = ctx["challenges"].issue_challenge(ttl_seconds=60)
        body = _build_revoke_body(
            revoker_id=ctx["pixel"].phone_id,
            target_id=ctx["iphone"].phone_id,
            challenge=challenge,
            revoker_priv=ctx["pixel_priv"],
        )
        status, resp = _http_post_json(
            f"{ctx['base_url']}/v0.4/manage/phones/revoke", body)
        assert status == HTTPStatus.OK
        assert resp["revoked"] is True
        assert resp["revoked_phone_id"] == ctx["iphone"].phone_id
        assert resp["was_self_revoke"] is False
        assert resp["remaining_phones_count"] == 1
        # iPhone removed; Pixel survives
        assert ctx["state"].get_phone(ctx["iphone"].phone_id) is None
        assert ctx["state"].get_phone(ctx["pixel"].phone_id) is not None

    # ── Body validation ────────────────────────────────────────────────

    def test_missing_revoker_id(self, two_phones_server):
        ctx = two_phones_server
        challenge, _ = ctx["challenges"].issue_challenge(ttl_seconds=60)
        body = _build_revoke_body(
            revoker_id=ctx["pixel"].phone_id,
            target_id=ctx["iphone"].phone_id,
            challenge=challenge,
            revoker_priv=ctx["pixel_priv"],
        )
        body["revoker_phone_id"] = ""
        status, resp = _http_post_json(
            f"{ctx['base_url']}/v0.4/manage/phones/revoke", body)
        assert status == HTTPStatus.BAD_REQUEST
        assert "revoker_phone_id" in resp["detail"]

    def test_missing_target_id(self, two_phones_server):
        ctx = two_phones_server
        challenge, _ = ctx["challenges"].issue_challenge(ttl_seconds=60)
        body = _build_revoke_body(
            revoker_id=ctx["pixel"].phone_id,
            target_id=ctx["iphone"].phone_id,
            challenge=challenge,
            revoker_priv=ctx["pixel_priv"],
        )
        body["target_phone_id"] = ""
        status, resp = _http_post_json(
            f"{ctx['base_url']}/v0.4/manage/phones/revoke", body)
        assert status == HTTPStatus.BAD_REQUEST
        assert "target_phone_id" in resp["detail"]

    def test_missing_challenge(self, two_phones_server):
        ctx = two_phones_server
        body = {
            "revoker_phone_id": ctx["pixel"].phone_id,
            "target_phone_id": ctx["iphone"].phone_id,
            "challenge_b64u": "",
            "signature_b64u": "x",
        }
        status, resp = _http_post_json(
            f"{ctx['base_url']}/v0.4/manage/phones/revoke", body)
        assert status == HTTPStatus.BAD_REQUEST
        assert "challenge_b64u" in resp["detail"]

    def test_missing_signature(self, two_phones_server):
        ctx = two_phones_server
        challenge, _ = ctx["challenges"].issue_challenge(ttl_seconds=60)
        body = {
            "revoker_phone_id": ctx["pixel"].phone_id,
            "target_phone_id": ctx["iphone"].phone_id,
            "challenge_b64u": challenge,
            "signature_b64u": "",
        }
        status, resp = _http_post_json(
            f"{ctx['base_url']}/v0.4/manage/phones/revoke", body)
        assert status == HTTPStatus.BAD_REQUEST
        assert "signature_b64u" in resp["detail"]

    # ── Phone-not-registered errors ────────────────────────────────────

    def test_unknown_revoker(self, two_phones_server):
        ctx = two_phones_server
        challenge, _ = ctx["challenges"].issue_challenge(ttl_seconds=60)
        body = _build_revoke_body(
            revoker_id="00000000-0000-0000-0000-000000000000",
            target_id=ctx["iphone"].phone_id,
            challenge=challenge,
            revoker_priv=ctx["pixel_priv"],
        )
        status, resp = _http_post_json(
            f"{ctx['base_url']}/v0.4/manage/phones/revoke", body)
        assert status == HTTPStatus.BAD_REQUEST
        assert "revoker" in resp["detail"]
        assert "not registered" in resp["detail"]

    def test_unknown_target(self, two_phones_server):
        ctx = two_phones_server
        challenge, _ = ctx["challenges"].issue_challenge(ttl_seconds=60)
        body = _build_revoke_body(
            revoker_id=ctx["pixel"].phone_id,
            target_id="00000000-0000-0000-0000-000000000000",
            challenge=challenge,
            revoker_priv=ctx["pixel_priv"],
        )
        status, resp = _http_post_json(
            f"{ctx['base_url']}/v0.4/manage/phones/revoke", body)
        assert status == HTTPStatus.BAD_REQUEST
        assert "target" in resp["detail"]
        assert "not registered" in resp["detail"]

    # ── Signature failures ─────────────────────────────────────────────

    def test_invalid_signature_rejected(self, two_phones_server):
        """Pixel claims to be revoking iPhone but signed with garbage sig."""
        ctx = two_phones_server
        challenge, _ = ctx["challenges"].issue_challenge(ttl_seconds=60)
        body = _build_revoke_body(
            revoker_id=ctx["pixel"].phone_id,
            target_id=ctx["iphone"].phone_id,
            challenge=challenge,
            revoker_priv=ctx["pixel_priv"],
        )
        # Tamper signature
        body["signature_b64u"] = _b64u_encode(b"\x00" * 64)
        status, resp = _http_post_json(
            f"{ctx['base_url']}/v0.4/manage/phones/revoke", body)
        assert status == HTTPStatus.UNAUTHORIZED
        assert resp["error"] == "revoke_signature_invalid"
        # State unchanged: both phones still registered
        assert ctx["state"].get_phone(ctx["iphone"].phone_id) is not None
        assert ctx["state"].get_phone(ctx["pixel"].phone_id) is not None

    def test_wrong_revoker_key_rejected(self, two_phones_server):
        """Body claims revoker=Pixel but the sig was made with iPhone's key."""
        ctx = two_phones_server
        challenge, _ = ctx["challenges"].issue_challenge(ttl_seconds=60)
        # Sig is from iphone_priv, but body claims revoker=pixel.
        body = _build_revoke_body(
            revoker_id=ctx["pixel"].phone_id,  # claim pixel
            target_id=ctx["iphone"].phone_id,
            challenge=challenge,
            revoker_priv=ctx["iphone_priv"],  # signed by iphone
        )
        status, resp = _http_post_json(
            f"{ctx['base_url']}/v0.4/manage/phones/revoke", body)
        assert status == HTTPStatus.UNAUTHORIZED
        assert resp["error"] == "revoke_signature_invalid"

    def test_replay_sig_against_different_target_rejected(self, two_phones_server):
        """A signature constructed for target=A can't be replayed for target=B
        because the colon-bound payload differs. Concrete attack scenario:
        attacker captures a valid sibling-revoke sig from a network log,
        then tries to use it to revoke a DIFFERENT phone."""
        ctx = two_phones_server
        challenge, _ = ctx["challenges"].issue_challenge(ttl_seconds=60)
        # Pixel signed payload binding to iphone's id
        signed_for_iphone = _build_revoke_body(
            revoker_id=ctx["pixel"].phone_id,
            target_id=ctx["iphone"].phone_id,
            challenge=challenge,
            revoker_priv=ctx["pixel_priv"],
        )
        # Attacker re-targets to pixel itself (or any other phone) using
        # the iphone-bound sig.
        replayed = dict(signed_for_iphone)
        replayed["target_phone_id"] = ctx["pixel"].phone_id
        status, resp = _http_post_json(
            f"{ctx['base_url']}/v0.4/manage/phones/revoke", replayed)
        # Should fail at challenge-consume step because the sig was
        # built for target=iphone and the challenge was already consumed
        # by no one yet... actually let me think. The challenge is
        # consumed inside the handler AFTER body validation but BEFORE
        # sig verify. So the replayed body's challenge gets consumed,
        # then sig verify fails because the payload (challenge:pixel)
        # doesn't match what was signed (challenge:iphone). 401.
        assert status == HTTPStatus.UNAUTHORIZED
        assert resp["error"] == "revoke_signature_invalid"
        # State unchanged
        assert ctx["state"].get_phone(ctx["iphone"].phone_id) is not None
        assert ctx["state"].get_phone(ctx["pixel"].phone_id) is not None

    # ── Challenge lifecycle ────────────────────────────────────────────

    def test_expired_challenge_rejected(self, two_phones_server):
        ctx = two_phones_server
        # Issue a challenge that expires immediately
        challenge, _ = ctx["challenges"].issue_challenge(ttl_seconds=0)
        # Sleep a hair to ensure clock advances past the 0-ttl
        import time as _time
        _time.sleep(0.05)
        body = _build_revoke_body(
            revoker_id=ctx["pixel"].phone_id,
            target_id=ctx["iphone"].phone_id,
            challenge=challenge,
            revoker_priv=ctx["pixel_priv"],
        )
        status, resp = _http_post_json(
            f"{ctx['base_url']}/v0.4/manage/phones/revoke", body)
        assert status == HTTPStatus.BAD_REQUEST
        assert "challenge" in resp["detail"]

    def test_challenge_is_single_use(self, two_phones_server):
        """Same challenge cannot be used to revoke twice (single-use semantics
        prevent any bulk-attack via one captured challenge)."""
        ctx = two_phones_server
        challenge, _ = ctx["challenges"].issue_challenge(ttl_seconds=60)
        # First revoke (iphone removes itself) -- should succeed
        body1 = _build_revoke_body(
            revoker_id=ctx["iphone"].phone_id,
            target_id=ctx["iphone"].phone_id,
            challenge=challenge,
            revoker_priv=ctx["iphone_priv"],
        )
        status1, _ = _http_post_json(
            f"{ctx['base_url']}/v0.4/manage/phones/revoke", body1)
        assert status1 == HTTPStatus.OK
        # Second attempt with the SAME challenge (pixel removes itself
        # this time) -- should fail at challenge-consume
        body2 = _build_revoke_body(
            revoker_id=ctx["pixel"].phone_id,
            target_id=ctx["pixel"].phone_id,
            challenge=challenge,  # reuse
            revoker_priv=ctx["pixel_priv"],
        )
        status2, resp2 = _http_post_json(
            f"{ctx['base_url']}/v0.4/manage/phones/revoke", body2)
        assert status2 == HTTPStatus.BAD_REQUEST
        assert "challenge" in resp2["detail"]
        # Pixel still registered (revoke didn't fire)
        assert ctx["state"].get_phone(ctx["pixel"].phone_id) is not None
