"""GET /v0.4/pending carries a bootloader signature over the envelope (2026-09-16).

The phone dropped its TLS leaf pin for the bootloader's own key. Attest proves
who the server is but binds no channel; an interposer with a CA-issued cert could
relay attest and inject a card. This signature makes a card that did not come
from the pinned key impossible to RENDER: the phone verifies before any card.

Coverage: the envelope verifies against the published key · the digest is over
the exact `requests` bytes on the wire · sub names the polling phone · an
unsigned bootloader sends no envelope (the phone's legacy path).
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import threading
from pathlib import Path
from urllib import request as urlrequest
from urllib.error import HTTPError

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from recto.bootloader.server import ChallengeStore, create_server, poll_key_delegation_payload
from recto.bootloader.state import StateStore
from recto.capability.jwt import verify_jws
from recto.capability.pair_record import CLOCK_SKEW_SECONDS, PENDING_ACTION, PENDING_WINDOW_SECONDS
from recto.capability.signing import public_key_hex

_KEY = bytes.fromhex("7" * 64)


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _post(url, body):
    req = urlrequest.Request(url, data=json.dumps(body).encode(), method="POST",
                             headers={"Content-Type": "application/json"})
    try:
        with urlrequest.urlopen(req, timeout=5.0) as r:
            return r.status, json.loads(r.read().decode())
    except HTTPError as e:
        return e.code, json.loads(e.read().decode())


def _get_raw(url) -> tuple[int, str]:
    try:
        with urlrequest.urlopen(url, timeout=5.0) as r:
            return r.status, r.read().decode("utf-8")
    except HTTPError as e:
        return e.code, e.read().decode("utf-8")


@pytest.fixture
def bootloader(tmp_path: Path):
    made = []

    def _make(signing_key: bytes | None):
        challenges = ChallengeStore()
        state_dir = tmp_path / ("signed" if signing_key else "unsigned")
        state_dir.mkdir(parents=True, exist_ok=True)
        server = create_server(
            bind_host="127.0.0.1", bind_port=0, state=StateStore(state_dir=state_dir),
            bootloader_id="pending-signed-test", challenges=challenges, ssl_context=None,
            capability_agent_tokens={"agent-1": "tok-agent-1"},
            devices_pair_signing_key=signing_key,
        )
        host, port = server.server_address
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        ctx = {"base_url": f"http://{host}:{port}", "challenges": challenges, "server": server, "thread": t}
        made.append(ctx)
        return ctx

    try:
        yield _make
    finally:
        for ctx in made:
            ctx["server"].shutdown()
            ctx["server"].server_close()
            ctx["thread"].join(timeout=5.0)


def _register(ctx) -> str:
    code, _ = ctx["challenges"].issue_pairing_code()
    _, ch_raw = _get_raw(f"{ctx['base_url']}/v0.4/registration_challenge?code={code}")
    ch = json.loads(ch_raw)
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    sig = key.sign(ch["challenge_b64u"].encode("ascii"))
    poll_pub = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    status, body = _post(f"{ctx['base_url']}/v0.4/register", {
        "phone_id": "ignored", "device_label": "signed-pending-phone",
        "public_key_b64u": _b64u(pub), "supported_algorithms": ["ed25519"], "v0_4_protocol": 1,
        "registration_proof": {"challenge": ch["challenge_b64u"], "signature_b64u": _b64u(sig)},
        # rule 14.2: a registration delegates a poll key or it is refused
        "poll_public_key_b64u": _b64u(poll_pub),
        "poll_key_delegation_b64u": _b64u(key.sign(poll_key_delegation_payload(_b64u(pub), _b64u(poll_pub)))),
    })
    assert status == 201, body
    return body["phone_id"]


def _queue_card(ctx, phone_id: str):
    status, body = _post(f"{ctx['base_url']}/v0.4/capability/request", {
        "agent_id": "agent-1", "agent_token": "tok-agent-1", "phone_id": phone_id,
        "claims": {"sub": "agent:test", "aud": ["consumer"], "purpose": "signed pending test",
                   "cap": {"tier": 0, "registry_version": "0", "scope": {}, "allow_actions": ["x:y"]}},
        "context": {"summary": "a card"},
    })
    return status, body


class TestSignedPendingEnvelope:
    def test_envelope_verifies_and_binds_the_wire_bytes_and_the_phone(self, bootloader):
        ctx = bootloader(_KEY)
        phone_id = _register(ctx)
        _queue_card(ctx, phone_id)  # whatever the request shape yields, the envelope must still bind
        status, raw = _get_raw(f"{ctx['base_url']}/v0.4/pending?phone_id={phone_id}")
        assert status == 200
        body = json.loads(raw)
        assert "pending_jws" in body
        claims = verify_jws(body["pending_jws"], expected_pubkey=bytes.fromhex(public_key_hex(_KEY)),
                            expected_aud="recto-phone")
        assert claims.iss == "bootloader:pending-signed-test"
        assert claims.sub == f"phone:{phone_id}"
        assert claims.cap.allow_actions == [PENDING_ACTION]
        assert claims.exp - claims.nbf == PENDING_WINDOW_SECONDS + CLOCK_SKEW_SECONDS
        assert claims.nbf == claims.iat - CLOCK_SKEW_SECONDS   # a phone a minute behind still verifies
        # The digest is over the exact `requests` text as it sits on the wire
        # (the phone hashes JsonElement.GetRawText(); dumps is compositional).
        m = re.search(r'"requests": (\[.*\])(?=, "pending_jws"|\})', raw, re.S)
        assert m, raw[:200]
        wire_requests = m.group(1)
        assert json.loads(wire_requests) == body["requests"]
        assert claims.cap.scope.payload_sha256 == hashlib.sha256(wire_requests.encode("utf-8")).hexdigest()

    def test_the_digest_equals_dumps_of_the_list(self, bootloader):
        ctx = bootloader(_KEY)
        phone_id = _register(ctx)
        _, raw = _get_raw(f"{ctx['base_url']}/v0.4/pending?phone_id={phone_id}")
        body = json.loads(raw)
        claims = verify_jws(body["pending_jws"], expected_pubkey=bytes.fromhex(public_key_hex(_KEY)),
                            expected_aud="recto-phone")
        expected = hashlib.sha256(json.dumps(body["requests"], sort_keys=True).encode("utf-8")).hexdigest()
        assert claims.cap.scope.payload_sha256 == expected

    def test_an_unsigned_bootloader_sends_no_envelope(self, bootloader):
        ctx = bootloader(None)
        phone_id = _register(ctx)
        status, raw = _get_raw(f"{ctx['base_url']}/v0.4/pending?phone_id={phone_id}")
        assert status == 200
        assert "pending_jws" not in json.loads(raw)
