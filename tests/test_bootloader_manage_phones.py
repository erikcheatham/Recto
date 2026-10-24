"""Tests for GET /v0.4/manage/phones?phone_id=<self>.

Endpoint contract (per
``phone/Recto/Recto.Shared/Protocol/V04/RegisteredPhonesResponse.cs``):
the MAUI client passes its own phone_id and gets back every other paired
phone, projected as ``{phone_id, device_label, algorithm, paired_at}``.
The "Registered phones" pane in the app then uses the list to show what
other devices share the bootloader so the operator can see + revoke any
that have been lost.

The list answers only a read signed by the requester's delegated poll key,
in every signed_poll_mode (hard rule 14.2): these tests run in mode "off"
and sign every read, and an unsigned read is refused even there.

Single-user-operator scoping today (Recto's current model: one operator,
N paired devices). Multi-tenant scoping (per-user filter) is a future v3
concern that adds a ``user_id`` filter clause without changing the wire
contract.
"""

from __future__ import annotations

import base64
import json
import threading
import time
from datetime import datetime, timezone
from http import HTTPStatus
from pathlib import Path
from urllib import request as urlrequest
from urllib.error import HTTPError

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from recto.bootloader.server import (
    POLL_SIG_HEADER,
    POLL_SIG_PREFIX,
    POLL_SIG_TS_HEADER,
    ChallengeStore,
    create_server,
)
from recto.bootloader.state import PhoneRegistration, StateStore

PATH = "/v0.4/manage/phones"


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class _PollKey:
    """A delegated poll key in the requester's own algorithm (the server verifies a read with it)."""

    def __init__(self, algorithm: str) -> None:
        self.algorithm = algorithm
        if algorithm == "ed25519":
            self._key = Ed25519PrivateKey.generate()
            self.pub = _b64u(self._key.public_key().public_bytes(serialization.Encoding.Raw,
                                                                 serialization.PublicFormat.Raw))
        else:
            self._key = ec.generate_private_key(ec.SECP256R1())
            n = self._key.public_key().public_numbers()
            self.pub = _b64u(n.x.to_bytes(32, "big") + n.y.to_bytes(32, "big"))

    def sign(self, data: bytes) -> bytes:
        if self.algorithm == "ed25519":
            return self._key.sign(data)
        r, s = decode_dss_signature(self._key.sign(data, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _phone(label: str, pubkey: str, algorithm: str) -> tuple[PhoneRegistration, _PollKey]:
    poll = _PollKey(algorithm)
    reg = PhoneRegistration.new(device_label=label, public_key_b64u=pubkey, supported_algorithms=(algorithm,),
                                poll_public_key_b64u=poll.pub)
    return reg, poll


def _http_get(url: str, headers: dict[str, str] | None = None):
    req = urlrequest.Request(url, method="GET", headers=headers or {})
    try:
        with urlrequest.urlopen(req, timeout=5.0) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            return e.code, json.loads(body)
        except json.JSONDecodeError:
            return e.code, {"_raw_body": body}


def _signed_list(base_url: str, phone: PhoneRegistration, poll: _PollKey):
    ts = int(time.time())
    sig = poll.sign(f"{POLL_SIG_PREFIX}|{phone.phone_id}|{ts}|{PATH}".encode("ascii"))
    return _http_get(f"{base_url}{PATH}?phone_id={phone.phone_id}",
                     headers={POLL_SIG_HEADER: _b64u(sig), POLL_SIG_TS_HEADER: str(ts)})


def _serve(state: StateStore):
    server = create_server(
        bind_host="127.0.0.1",
        bind_port=0,
        state=state,
        bootloader_id="test-bootloader",
        challenges=ChallengeStore(),
        ssl_context=None,
        signed_poll_mode="off",
    )
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, f"http://{host}:{port}"


def _stop(server, thread) -> None:
    server.shutdown()
    server.server_close()
    thread.join(timeout=5.0)


@pytest.fixture
def server_with_phones(tmp_path: Path):
    """Live bootloader on a random port with two paired phones (an
    iPhone and a Pixel) seeded into the state store."""
    state = StateStore(state_dir=tmp_path)
    iphone, iphone_poll = _phone("iPhone", "iphone-pubkey-b64u", "ecdsa-p256")
    pixel, pixel_poll = _phone("Pixel 10 Pro Fold", "pixel-pubkey-b64u", "ecdsa-p256")
    state.register_phone(iphone)
    state.register_phone(pixel)
    server, thread, base_url = _serve(state)
    try:
        yield {
            "base_url": base_url,
            "state": state,
            "iphone": iphone,
            "iphone_poll": iphone_poll,
            "pixel": pixel,
            "pixel_poll": pixel_poll,
        }
    finally:
        _stop(server, thread)


class TestManagePhones:
    def test_returns_other_phones_excluding_self(self, server_with_phones):
        """Pixel asks; gets back the iPhone (not itself)."""
        ctx = server_with_phones
        status, body = _signed_list(ctx["base_url"], ctx["pixel"], ctx["pixel_poll"])
        assert status == HTTPStatus.OK
        assert "phones" in body
        assert len(body["phones"]) == 1
        other = body["phones"][0]
        assert other["phone_id"] == ctx["iphone"].phone_id
        assert other["device_label"] == "iPhone"
        assert other["algorithm"] == "ecdsa-p256"
        # paired_at is ISO 8601 UTC; sanity-check it parses round-trip.
        parsed = datetime.fromisoformat(other["paired_at"])
        assert parsed.tzinfo is not None
        # And matches the unix timestamp on the registration.
        expected = datetime.fromtimestamp(
            ctx["iphone"].registered_at_unix, tz=timezone.utc
        )
        assert parsed == expected

    def test_iphone_perspective_returns_pixel(self, server_with_phones):
        """Symmetric: iPhone asks; gets back the Pixel."""
        ctx = server_with_phones
        status, body = _signed_list(ctx["base_url"], ctx["iphone"], ctx["iphone_poll"])
        assert status == HTTPStatus.OK
        assert len(body["phones"]) == 1
        other = body["phones"][0]
        assert other["phone_id"] == ctx["pixel"].phone_id
        assert other["device_label"] == "Pixel 10 Pro Fold"

    def test_an_unsigned_read_is_refused_even_in_mode_off(self, server_with_phones):
        """Hard rule 14.2: the list answers only a signed read, in every signed_poll_mode."""
        ctx = server_with_phones
        status, body = _http_get(f"{ctx['base_url']}{PATH}?phone_id={ctx['pixel'].phone_id}")
        assert status == HTTPStatus.UNAUTHORIZED, body
        assert body["error"] == "poll_signature_required"

    def test_returns_empty_when_only_self_paired(self, tmp_path: Path):
        """Single-phone case: the requesting phone is the only one
        registered; response is an empty list (not the self-entry)."""
        state = StateStore(state_dir=tmp_path)
        only, only_poll = _phone("Only Phone", "only-pubkey", "ed25519")
        state.register_phone(only)
        server, thread, base_url = _serve(state)
        try:
            status, body = _signed_list(base_url, only, only_poll)
            assert status == HTTPStatus.OK
            assert body == {"phones": []}
        finally:
            _stop(server, thread)

    def test_missing_phone_id_returns_400(self, server_with_phones):
        """No phone_id query param == BootloaderError == HTTP 400."""
        ctx = server_with_phones
        url = f"{ctx['base_url']}{PATH}"
        status, body = _http_get(url)
        assert status == HTTPStatus.BAD_REQUEST
        assert body["error"] == "bootloader_error"
        assert "phone_id" in body["detail"]

    def test_unknown_phone_id_returns_400(self, server_with_phones):
        """Caller asserting an unregistered phone_id is rejected (matches
        /v0.4/pending's strict posture: only paired phones can ask)."""
        ctx = server_with_phones
        url = f"{ctx['base_url']}{PATH}?phone_id=00000000-0000-0000-0000-000000000000"
        status, body = _http_get(url)
        assert status == HTTPStatus.BAD_REQUEST
        assert body["error"] == "bootloader_error"
        assert "not registered" in body["detail"]

    def test_returns_n_minus_1_when_three_paired(self, tmp_path: Path):
        """N-paired case: requester gets back N-1 entries (every
        other phone, excluding itself)."""
        state = StateStore(state_dir=tmp_path)
        a, a_poll = _phone("Phone A", "a-pubkey", "ecdsa-p256")
        b, _ = _phone("Phone B", "b-pubkey", "ecdsa-p256")
        c, _ = _phone("Phone C", "c-pubkey", "ed25519")
        for p in (a, b, c):
            state.register_phone(p)
        server, thread, base_url = _serve(state)
        try:
            status, body = _signed_list(base_url, a, a_poll)
            assert status == HTTPStatus.OK
            assert len(body["phones"]) == 2
            labels = sorted(p["device_label"] for p in body["phones"])
            assert labels == ["Phone B", "Phone C"]
            # Algorithm projection from supported_algorithms[0].
            algo_by_label = {p["device_label"]: p["algorithm"] for p in body["phones"]}
            assert algo_by_label["Phone B"] == "ecdsa-p256"
            assert algo_by_label["Phone C"] == "ed25519"
        finally:
            _stop(server, thread)
