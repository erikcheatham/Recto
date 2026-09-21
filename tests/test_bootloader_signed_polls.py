"""Tests for the signed-poll gate (2026-08-13 phone_id split).

phone_id used to carry two jobs: registry REFERENCE and bearer
READ-CREDENTIAL (possession of the string read /v0.4/pending and drove
the manage surfaces). The split makes authority a SIGNATURE and the
name a pure reference:

- The phone signs the ASCII string
  ``recto-poll-v1|{phone_id}|{ts}|{path}`` with its enclave key and
  sends ``X-Recto-Phone-Sig`` (b64u) + ``X-Recto-Phone-Ts`` headers.
- ``signed_poll_mode``: "off" | "advisory" (default) | "required".
  Advisory allows every poll and logs verdicts; required refuses
  unsigned (401 poll_signature_required) and bad/stale/wrong-key
  (401 poll_signature_invalid).
- ``phone_ref`` ("pk_" + first 16 hex of sha256(raw pubkey bytes)) is
  the additive, never-auth reference half, returned at registration
  and in manage/phones rows.

The required-mode unsigned-401 test is the RED-BUILD for the split
(bet 3: every crossing gets a test that red-builds the violation) --
if possession of a bare phone_id ever reads the pending queue again
under required mode, this file goes red.
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
from http import HTTPStatus
from pathlib import Path
from urllib import request as urlrequest
from urllib.error import HTTPError

import pytest

from recto.bootloader.server import (
    POLL_SIG_FRESHNESS_SECONDS,
    POLL_SIG_HEADER,
    POLL_SIG_PREFIX,
    POLL_SIG_TS_HEADER,
    ChallengeStore,
    _phone_ref,
    create_server,
)
from recto.bootloader.state import PhoneRegistration, StateStore


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _make_keypair():
    """Real Ed25519 keypair; returns (private_key, public_key_b64u)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )

    priv = Ed25519PrivateKey.generate()
    raw_pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return priv, _b64u(raw_pub)


def _sign_poll(priv, phone_id: str, ts: int, path: str) -> str:
    payload = f"{POLL_SIG_PREFIX}|{phone_id}|{ts}|{path}".encode("ascii")
    return _b64u(priv.sign(payload))


def _http(url: str, *, method: str = "GET", headers: dict | None = None,
          body: dict | None = None):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urlrequest.Request(url, method=method, data=data)
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urlrequest.urlopen(req, timeout=5.0) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except HTTPError as e:
        raw = e.read().decode("utf-8")
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, {"_raw_body": raw}


def _spawn(tmp_path: Path, mode: str):
    """Live bootloader in `mode` with one real-keyed phone registered.

    Returns dict with base_url / phone (registration) / priv (its
    signing key) / server (for shutdown).
    """
    state = StateStore(state_dir=tmp_path)
    priv, pub_b64u = _make_keypair()
    phone = PhoneRegistration.new(
        device_label="Signed-Poll Test Phone",
        public_key_b64u=pub_b64u,
        supported_algorithms=("ed25519",),
    )
    state.register_phone(phone)
    server = create_server(
        bind_host="127.0.0.1",
        bind_port=0,
        state=state,
        bootloader_id="test-bootloader",
        challenges=ChallengeStore(state=state),
        ssl_context=None,
        signed_poll_mode=mode,
    )
    host, port = server.server_address
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return {
        "base_url": f"http://{host}:{port}",
        "state": state,
        "phone": phone,
        "priv": priv,
        "server": server,
    }


@pytest.fixture
def required(tmp_path: Path):
    ctx = _spawn(tmp_path, "required")
    yield ctx
    ctx["server"].shutdown()


@pytest.fixture
def advisory(tmp_path: Path):
    ctx = _spawn(tmp_path, "advisory")
    yield ctx
    ctx["server"].shutdown()


@pytest.fixture
def off(tmp_path: Path):
    ctx = _spawn(tmp_path, "off")
    yield ctx
    ctx["server"].shutdown()


def _signed_headers(ctx, path: str, *, ts: int | None = None,
                    priv=None, sig: str | None = None) -> dict:
    ts = int(time.time()) if ts is None else ts
    priv = ctx["priv"] if priv is None else priv
    if sig is None:
        sig = _sign_poll(priv, ctx["phone"].phone_id, ts, path)
    return {POLL_SIG_HEADER: sig, POLL_SIG_TS_HEADER: str(ts)}


# ----------------------------------------------------------------------
# RED-BUILD: possession of a bare phone_id must not read under required
# ----------------------------------------------------------------------


def test_unsigned_pending_poll_under_required_is_401(required):
    status, body = _http(
        f"{required['base_url']}/v0.4/pending"
        f"?phone_id={required['phone'].phone_id}"
    )
    assert status == HTTPStatus.UNAUTHORIZED
    assert body["error"] == "poll_signature_required"


def test_unsigned_manage_phones_under_required_is_401(required):
    status, body = _http(
        f"{required['base_url']}/v0.4/manage/phones"
        f"?phone_id={required['phone'].phone_id}"
    )
    assert status == HTTPStatus.UNAUTHORIZED
    assert body["error"] == "poll_signature_required"


def test_unsigned_push_token_update_under_required_is_401(required):
    status, body = _http(
        f"{required['base_url']}/v0.4/manage/push_token",
        method="POST",
        body={
            "phone_id": required["phone"].phone_id,
            "push_token": "tok-1",
            "push_platform": "fcm",
        },
    )
    assert status == HTTPStatus.UNAUTHORIZED
    assert body["error"] == "poll_signature_required"


# ----------------------------------------------------------------------
# Advisory (the shipped default): everything still reads
# ----------------------------------------------------------------------


def test_unsigned_poll_under_advisory_is_200(advisory):
    status, body = _http(
        f"{advisory['base_url']}/v0.4/pending"
        f"?phone_id={advisory['phone'].phone_id}"
    )
    assert status == HTTPStatus.OK
    assert body["requests"] == []


def test_bad_signature_under_advisory_still_reads(advisory):
    headers = _signed_headers(
        advisory, "/v0.4/pending", sig=_b64u(b"\x00" * 64))
    status, body = _http(
        f"{advisory['base_url']}/v0.4/pending"
        f"?phone_id={advisory['phone'].phone_id}",
        headers=headers,
    )
    assert status == HTTPStatus.OK
    assert body["requests"] == []


def test_valid_signature_under_advisory_is_200(advisory):
    headers = _signed_headers(advisory, "/v0.4/pending")
    status, body = _http(
        f"{advisory['base_url']}/v0.4/pending"
        f"?phone_id={advisory['phone'].phone_id}",
        headers=headers,
    )
    assert status == HTTPStatus.OK
    assert body["requests"] == []


# ----------------------------------------------------------------------
# Required + a valid signature: every surface reads
# ----------------------------------------------------------------------


def test_valid_signature_under_required_reads_pending(required):
    headers = _signed_headers(required, "/v0.4/pending")
    status, body = _http(
        f"{required['base_url']}/v0.4/pending"
        f"?phone_id={required['phone'].phone_id}",
        headers=headers,
    )
    assert status == HTTPStatus.OK
    assert body["requests"] == []


def test_valid_signature_under_required_reads_manage_phones(required):
    headers = _signed_headers(required, "/v0.4/manage/phones")
    status, body = _http(
        f"{required['base_url']}/v0.4/manage/phones"
        f"?phone_id={required['phone'].phone_id}",
        headers=headers,
    )
    assert status == HTTPStatus.OK
    assert body["phones"] == []  # only itself is paired; list excludes self


def test_valid_signature_under_required_updates_push_token(required):
    headers = _signed_headers(required, "/v0.4/manage/push_token")
    status, body = _http(
        f"{required['base_url']}/v0.4/manage/push_token",
        method="POST",
        headers=headers,
        body={
            "phone_id": required["phone"].phone_id,
            "push_token": "tok-2",
            "push_platform": "apns",
        },
    )
    assert status == HTTPStatus.OK
    assert body["updated"] is True


# ----------------------------------------------------------------------
# Required + defective signatures: refused with poll_signature_invalid
# ----------------------------------------------------------------------


def test_garbage_signature_under_required_is_401(required):
    headers = _signed_headers(
        required, "/v0.4/pending", sig=_b64u(b"\xff" * 64))
    status, body = _http(
        f"{required['base_url']}/v0.4/pending"
        f"?phone_id={required['phone'].phone_id}",
        headers=headers,
    )
    assert status == HTTPStatus.UNAUTHORIZED
    assert body["error"] == "poll_signature_invalid"


@pytest.mark.parametrize("skew", [
    POLL_SIG_FRESHNESS_SECONDS + 1,      # just past the window, future
    -(POLL_SIG_FRESHNESS_SECONDS + 1),   # just past the window, past
    -3600,                                # long stale
])
def test_stale_timestamp_under_required_is_401(required, skew):
    ts = int(time.time()) + skew
    headers = _signed_headers(required, "/v0.4/pending", ts=ts)
    status, body = _http(
        f"{required['base_url']}/v0.4/pending"
        f"?phone_id={required['phone'].phone_id}",
        headers=headers,
    )
    assert status == HTTPStatus.UNAUTHORIZED
    assert body["error"] == "poll_signature_invalid"


def test_within_freshness_window_is_accepted(required):
    # A signature a minute old is still inside +/-120s.
    ts = int(time.time()) - 60
    headers = _signed_headers(required, "/v0.4/pending", ts=ts)
    status, _ = _http(
        f"{required['base_url']}/v0.4/pending"
        f"?phone_id={required['phone'].phone_id}",
        headers=headers,
    )
    assert status == HTTPStatus.OK


def test_wrong_key_under_required_is_401(required):
    stranger_priv, _ = _make_keypair()
    headers = _signed_headers(required, "/v0.4/pending", priv=stranger_priv)
    status, body = _http(
        f"{required['base_url']}/v0.4/pending"
        f"?phone_id={required['phone'].phone_id}",
        headers=headers,
    )
    assert status == HTTPStatus.UNAUTHORIZED
    assert body["error"] == "poll_signature_invalid"


def test_signature_over_wrong_path_under_required_is_401(required):
    # Path binding: a valid signature for /v0.4/pending must not open
    # /v0.4/manage/phones.
    headers = _signed_headers(required, "/v0.4/pending")
    status, body = _http(
        f"{required['base_url']}/v0.4/manage/phones"
        f"?phone_id={required['phone'].phone_id}",
        headers=headers,
    )
    assert status == HTTPStatus.UNAUTHORIZED
    assert body["error"] == "poll_signature_invalid"


def test_half_supplied_headers_under_required_is_401(required):
    ts = int(time.time())
    status, body = _http(
        f"{required['base_url']}/v0.4/pending"
        f"?phone_id={required['phone'].phone_id}",
        headers={POLL_SIG_TS_HEADER: str(ts)},  # ts without sig
    )
    assert status == HTTPStatus.UNAUTHORIZED
    assert body["error"] == "poll_signature_invalid"


def test_unknown_phone_stays_unknown_phone_error(required):
    # Unknown phone_id keeps the existing 400 shape in every mode; the
    # signature gate sits BEHIND the registration lookup.
    status, body = _http(
        f"{required['base_url']}/v0.4/pending?phone_id=no-such-phone"
    )
    assert status == HTTPStatus.BAD_REQUEST
    assert body["error"] == "bootloader_error"
    assert "not registered" in body["detail"]


# ----------------------------------------------------------------------
# Mode plumbing
# ----------------------------------------------------------------------


def test_mode_off_unsigned_poll_is_200(off):
    status, body = _http(
        f"{off['base_url']}/v0.4/pending"
        f"?phone_id={off['phone'].phone_id}"
    )
    assert status == HTTPStatus.OK
    assert body["requests"] == []


def test_invalid_mode_refused_at_startup(tmp_path: Path):
    state = StateStore(state_dir=tmp_path)
    with pytest.raises(ValueError, match="signed_poll_mode"):
        create_server(
            bind_host="127.0.0.1",
            bind_port=0,
            state=state,
            bootloader_id="test-bootloader",
            challenges=ChallengeStore(state=state),
            ssl_context=None,
            signed_poll_mode="enforced",  # not a legal mode name
        )


# ----------------------------------------------------------------------
# phone_ref: the pure-reference half
# ----------------------------------------------------------------------


def test_phone_ref_derivation_shape():
    _, pub_b64u = _make_keypair()
    ref = _phone_ref(pub_b64u)
    padding = "=" * (-len(pub_b64u) % 4)
    raw = base64.urlsafe_b64decode(pub_b64u + padding)
    assert ref == "pk_" + hashlib.sha256(raw).hexdigest()[:16]
    assert len(ref) == 3 + 16


def test_register_response_carries_phone_ref(advisory):
    priv, pub_b64u = _make_keypair()
    status, chal = _http(
        f"{advisory['base_url']}/v0.4/registration_challenge")
    assert status == HTTPStatus.OK
    challenge = chal["challenge_b64u"]
    sig = _b64u(priv.sign(challenge.encode("ascii")))
    status, body = _http(
        f"{advisory['base_url']}/v0.4/register",
        method="POST",
        body={
            "v0_4_protocol": 1,
            "public_key_b64u": pub_b64u,
            "device_label": "phone-ref-test",
            "supported_algorithms": ["ed25519"],
            "registration_proof": {
                "challenge": challenge,
                "signature_b64u": sig,
            },
        },
    )
    assert status == HTTPStatus.CREATED
    assert body["phone_ref"] == _phone_ref(pub_b64u)


def test_manage_phones_rows_carry_phone_ref(advisory):
    # Pair a second phone directly in state; the requester's
    # manage/phones view of it must carry the derived phone_ref.
    _, other_pub = _make_keypair()
    other = PhoneRegistration.new(
        device_label="Other Phone",
        public_key_b64u=other_pub,
        supported_algorithms=("ed25519",),
    )
    advisory["state"].register_phone(other)
    status, body = _http(
        f"{advisory['base_url']}/v0.4/manage/phones"
        f"?phone_id={advisory['phone'].phone_id}"
    )
    assert status == HTTPStatus.OK
    assert len(body["phones"]) == 1
    row = body["phones"][0]
    assert row["phone_id"] == other.phone_id
    assert row["phone_ref"] == _phone_ref(other_pub)
