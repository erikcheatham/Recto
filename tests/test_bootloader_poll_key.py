"""THE POLL KEY (2026-09-21, hard rule 14.2) -- the device signs its reads.

THE PROBLEM. The identity key is per-use biometric-gated on both shipped platforms, so it
cannot sign a poll tick without a face prompt per tick; that is why the phone's PollSigning
helper shipped in 1.1.0 with no caller, and why the evidence window would read `unsigned` on
every poll. THE DESIGN: a second, enclave-resident, NON-gated key, delegated once at
registration by an identity-key signature over

    recto-poll-key-v1|{identity pubkey}|{poll pubkey}

so that "every crossing is a signature by THAT key" holds by a signed claim: the identity
key named the poll key, once, under biometrics. REQUIRED (pre-launch: no compatibility window):
a registration without a delegated poll key does not enroll, and there is exactly one key a
read verifies against.

THREE THINGS, EACH WITH A TEST:
  1. registration carries the poll key + delegation, or is REFUSED; an undelegated or
     mis-delegated poll key is refused, never silently dropped;
  2. reads verify against the POLL key, and the identity key is never accepted for a read;
  3. a directly-seeded record with no poll key can verify no read at all.
"""

from __future__ import annotations

import base64
import json
import threading
import time
from pathlib import Path
from typing import Any
from urllib import request as urlrequest
from urllib.error import HTTPError

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from recto.bootloader.server import (
    POLL_SIG_HEADER,
    POLL_SIG_PREFIX,
    POLL_SIG_TS_HEADER,
    ChallengeStore,
    create_server,
    poll_key_delegation_payload,
)
from recto.bootloader.state import PhoneRegistration, StateStore


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _key() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return key, _b64u(pub)


def _http(method: str, url: str, body: dict[str, Any] | None = None,
          headers: dict[str, str] | None = None) -> tuple[int, dict[str, Any]]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    h = {"Content-Type": "application/json", **(headers or {})}
    req = urlrequest.Request(url, data=data, headers=h, method=method)
    try:
        with urlrequest.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8") or "{}")
    except HTTPError as exc:
        raw = exc.read().decode("utf-8")
        try:
            return exc.code, json.loads(raw or "{}")
        except json.JSONDecodeError:
            return exc.code, {"raw": raw}


def _spawn(tmp_path: Path, mode: str):
    state = StateStore(state_dir=tmp_path)
    challenges = ChallengeStore(state=state)
    server = create_server(
        bind_host="127.0.0.1", bind_port=0, state=state, bootloader_id="poll-key-test",
        challenges=challenges, ssl_context=None, signed_poll_mode=mode,
    )
    host, port = server.server_address
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return {"base_url": f"http://{host}:{port}", "state": state, "challenges": challenges,
            "server": server, "state_dir": tmp_path}


@pytest.fixture
def required(tmp_path: Path):
    ctx = _spawn(tmp_path, "required")
    yield ctx
    ctx["server"].shutdown()


def _register(ctx, identity: Ed25519PrivateKey, identity_pub: str, *,
              poll_pub: str | None = None, delegation: str | None = None,
              extra: dict[str, Any] | None = None) -> tuple[int, dict[str, Any]]:
    code, _ = ctx["challenges"].issue_pairing_code()
    status, chal = _http("GET", f"{ctx['base_url']}/v0.4/registration_challenge?code={code}")
    assert status == 200, chal
    challenge = chal["challenge_b64u"]
    body: dict[str, Any] = {
        "device_label": "poll-key phone",
        "public_key_b64u": identity_pub,
        "supported_algorithms": ["ed25519"],
        "v0_4_protocol": 1,
        "registration_proof": {
            "challenge": challenge,
            "signature_b64u": _b64u(identity.sign(challenge.encode("ascii"))),
        },
    }
    if poll_pub is not None:
        body["poll_public_key_b64u"] = poll_pub
    if delegation is not None:
        body["poll_key_delegation_b64u"] = delegation
    body.update(extra or {})
    return _http("POST", f"{ctx['base_url']}/v0.4/register", body)


def _delegate(identity: Ed25519PrivateKey, identity_pub: str, poll_pub: str) -> str:
    return _b64u(identity.sign(poll_key_delegation_payload(identity_pub, poll_pub)))


def _poll_headers(signer: Ed25519PrivateKey, phone_id: str, path: str) -> dict[str, str]:
    ts = int(time.time())
    sig = signer.sign(f"{POLL_SIG_PREFIX}|{phone_id}|{ts}|{path}".encode("ascii"))
    return {POLL_SIG_HEADER: _b64u(sig), POLL_SIG_TS_HEADER: str(ts)}


# --------------------------------------------------------------------------
# 1. registration carries the delegation
# --------------------------------------------------------------------------

def test_a_delegated_poll_key_is_recorded(required):
    identity, ipub = _key()
    _, ppub = _key()
    status, body = _register(required, identity, ipub, poll_pub=ppub,
                             delegation=_delegate(identity, ipub, ppub))
    assert status == 201, body
    assert body["poll_public_key_b64u"] == ppub
    assert required["state"].get_phone(body["phone_id"]).poll_public_key_b64u == ppub


def test_an_undelegated_poll_key_is_refused_not_dropped(required):
    """RED-BUILD: make the handler ignore a missing delegation and this enrolls a
    poll key nobody signed for."""
    identity, ipub = _key()
    _, ppub = _key()
    status, body = _register(required, identity, ipub, poll_pub=ppub)
    assert status >= 400, body
    assert not required["state"].list_phones(), "refused, but persisted"


def test_a_registration_without_a_poll_key_does_not_enroll(required):
    """No back-compat: there is one way to read from this registry."""
    identity, ipub = _key()
    status, body = _register(required, identity, ipub)
    assert status >= 400, body
    assert not required["state"].list_phones()


def test_a_delegation_by_the_wrong_key_is_refused(required):
    identity, ipub = _key()
    _, ppub = _key()
    stranger, _ = _key()
    status, body = _register(required, identity, ipub, poll_pub=ppub,
                             delegation=_delegate(stranger, ipub, ppub))
    assert status >= 400, body
    assert not required["state"].list_phones()


def test_a_delegation_over_a_different_poll_key_is_refused(required):
    identity, ipub = _key()
    _, ppub = _key()
    _, other = _key()
    status, body = _register(required, identity, ipub, poll_pub=ppub,
                             delegation=_delegate(identity, ipub, other))
    assert status >= 400, body


def test_the_poll_key_must_not_be_the_identity_key(required):
    identity, ipub = _key()
    status, body = _register(required, identity, ipub, poll_pub=ipub,
                             delegation=_delegate(identity, ipub, ipub))
    assert status >= 400, body


# --------------------------------------------------------------------------
# 2. reads verify against the poll key, and only the poll key
# --------------------------------------------------------------------------

@pytest.fixture
def delegated(required):
    identity, ipub = _key()
    poll, ppub = _key()
    status, body = _register(required, identity, ipub, poll_pub=ppub,
                             delegation=_delegate(identity, ipub, ppub))
    assert status == 201, body
    return {**required, "identity": identity, "poll": poll, "phone_id": body["phone_id"]}


@pytest.mark.parametrize("path", ["/v0.4/pending", "/v0.4/manage/phones"])
def test_a_read_signed_by_the_poll_key_is_admitted_under_required(delegated, path):
    status, body = _http(
        "GET", f"{delegated['base_url']}{path}?phone_id={delegated['phone_id']}",
        headers=_poll_headers(delegated["poll"], delegated["phone_id"], path),
    )
    assert status == 200, body


def test_a_read_signed_by_the_identity_key_is_refused(delegated):
    """The identity key signs approvals; the poll key signs reads. A poll signed by the
    identity key is what a replayed or coerced identity signature would look like."""
    path = "/v0.4/pending"
    status, body = _http(
        "GET", f"{delegated['base_url']}{path}?phone_id={delegated['phone_id']}",
        headers=_poll_headers(delegated["identity"], delegated["phone_id"], path),
    )
    assert status == 401, body
    assert body["error"] == "poll_signature_invalid"


def test_a_bare_read_is_still_refused_under_required(delegated):
    status, body = _http("GET", f"{delegated['base_url']}/v0.4/pending?phone_id={delegated['phone_id']}")
    assert status == 401, body


# --------------------------------------------------------------------------
# 3. a record with no poll key verifies nothing
# --------------------------------------------------------------------------

def test_a_seeded_record_without_a_poll_key_can_verify_no_read(required):
    """Only reachable by seeding the store directly (the wire refuses it). Even a
    valid identity-key signature is a verdict of invalid: there is no fallback key."""
    identity, ipub = _key()
    phone = PhoneRegistration.new(device_label="seeded", public_key_b64u=ipub,
                                  supported_algorithms=("ed25519",))
    phone = required["state"].register_phone(phone)
    path = "/v0.4/pending"
    status, body = _http(
        "GET", f"{required['base_url']}{path}?phone_id={phone.phone_id}",
        headers=_poll_headers(identity, phone.phone_id, path),
    )
    assert status == 401, body
    assert body["error"] == "poll_signature_invalid"
