"""Tests for GET /v0.4/manage/phones?phone_id=<self>.

Endpoint contract (per
``phone/RectoMAUIBlazor/Recto/Recto.Shared/Protocol/V04/RegisteredPhonesResponse.cs``):
the MAUI client passes its own phone_id and gets back every other paired
phone, projected as ``{phone_id, device_label, algorithm, paired_at}``.
The "Registered phones" pane in the app then uses the list to show what
other devices share the bootloader so the operator can see + revoke any
that have been lost.

Single-user-operator scoping today (Recto's current model: one operator,
N paired devices). Multi-tenant scoping (per-user filter) is a future v3
concern that adds a ``user_id`` filter clause without changing the wire
contract.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from http import HTTPStatus
from pathlib import Path
from urllib import request as urlrequest
from urllib.error import HTTPError

import pytest

from recto.bootloader.server import ChallengeStore, create_server
from recto.bootloader.state import PhoneRegistration, StateStore


def _http_get(url: str):
    req = urlrequest.Request(url, method="GET")
    try:
        with urlrequest.urlopen(req, timeout=5.0) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            return e.code, json.loads(body)
        except json.JSONDecodeError:
            return e.code, {"_raw_body": body}


@pytest.fixture
def server_with_phones(tmp_path: Path):
    """Live bootloader on a random port with two paired phones (an
    iPhone and a Pixel) seeded into the state store."""
    state = StateStore(state_dir=tmp_path)
    iphone = PhoneRegistration.new(
        device_label="iPhone",
        public_key_b64u="iphone-pubkey-b64u",
        supported_algorithms=("ecdsa-p256",),
    )
    pixel = PhoneRegistration.new(
        device_label="Pixel 10 Pro Fold",
        public_key_b64u="pixel-pubkey-b64u",
        supported_algorithms=("ecdsa-p256",),
    )
    state.register_phone(iphone)
    state.register_phone(pixel)
    server = create_server(
        bind_host="127.0.0.1",
        bind_port=0,
        state=state,
        bootloader_id="test-bootloader",
        challenges=ChallengeStore(),
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
            "iphone": iphone,
            "pixel": pixel,
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)


class TestManagePhones:
    def test_returns_other_phones_excluding_self(self, server_with_phones):
        """Pixel asks; gets back the iPhone (not itself)."""
        ctx = server_with_phones
        url = f"{ctx['base_url']}/v0.4/manage/phones?phone_id={ctx['pixel'].phone_id}"
        status, body = _http_get(url)
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
        url = f"{ctx['base_url']}/v0.4/manage/phones?phone_id={ctx['iphone'].phone_id}"
        status, body = _http_get(url)
        assert status == HTTPStatus.OK
        assert len(body["phones"]) == 1
        other = body["phones"][0]
        assert other["phone_id"] == ctx["pixel"].phone_id
        assert other["device_label"] == "Pixel 10 Pro Fold"

    def test_returns_empty_when_only_self_paired(self, tmp_path: Path):
        """Single-phone case: the requesting phone is the only one
        registered; response is an empty list (not the self-entry)."""
        state = StateStore(state_dir=tmp_path)
        only = PhoneRegistration.new(
            device_label="Only Phone",
            public_key_b64u="only-pubkey",
            supported_algorithms=("ed25519",),
        )
        state.register_phone(only)
        server = create_server(
            bind_host="127.0.0.1",
            bind_port=0,
            state=state,
            bootloader_id="test-bootloader",
            challenges=ChallengeStore(),
            ssl_context=None,
        )
        host, port = server.server_address
        base_url = f"http://{host}:{port}"
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"{base_url}/v0.4/manage/phones?phone_id={only.phone_id}"
            status, body = _http_get(url)
            assert status == HTTPStatus.OK
            assert body == {"phones": []}
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5.0)

    def test_missing_phone_id_returns_400(self, server_with_phones):
        """No phone_id query param == BootloaderError == HTTP 400."""
        ctx = server_with_phones
        url = f"{ctx['base_url']}/v0.4/manage/phones"
        status, body = _http_get(url)
        assert status == HTTPStatus.BAD_REQUEST
        assert body["error"] == "bootloader_error"
        assert "phone_id" in body["detail"]

    def test_unknown_phone_id_returns_400(self, server_with_phones):
        """Caller asserting an unregistered phone_id is rejected (matches
        /v0.4/pending's strict posture: only paired phones can ask)."""
        ctx = server_with_phones
        url = f"{ctx['base_url']}/v0.4/manage/phones?phone_id=00000000-0000-0000-0000-000000000000"
        status, body = _http_get(url)
        assert status == HTTPStatus.BAD_REQUEST
        assert body["error"] == "bootloader_error"
        assert "not registered" in body["detail"]

    def test_returns_n_minus_1_when_three_paired(self, tmp_path: Path):
        """N-paired case: requester gets back N-1 entries (every
        other phone, excluding itself)."""
        state = StateStore(state_dir=tmp_path)
        a = PhoneRegistration.new(
            device_label="Phone A",
            public_key_b64u="a-pubkey",
            supported_algorithms=("ecdsa-p256",),
        )
        b = PhoneRegistration.new(
            device_label="Phone B",
            public_key_b64u="b-pubkey",
            supported_algorithms=("ecdsa-p256",),
        )
        c = PhoneRegistration.new(
            device_label="Phone C",
            public_key_b64u="c-pubkey",
            supported_algorithms=("ed25519",),
        )
        for p in (a, b, c):
            state.register_phone(p)
        server = create_server(
            bind_host="127.0.0.1",
            bind_port=0,
            state=state,
            bootloader_id="test-bootloader",
            challenges=ChallengeStore(),
            ssl_context=None,
        )
        host, port = server.server_address
        base_url = f"http://{host}:{port}"
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"{base_url}/v0.4/manage/phones?phone_id={a.phone_id}"
            status, body = _http_get(url)
            assert status == HTTPStatus.OK
            assert len(body["phones"]) == 2
            labels = sorted(p["device_label"] for p in body["phones"])
            assert labels == ["Phone B", "Phone C"]
            # Algorithm projection from supported_algorithms[0].
            algo_by_label = {p["device_label"]: p["algorithm"] for p in body["phones"]}
            assert algo_by_label["Phone B"] == "ecdsa-p256"
            assert algo_by_label["Phone C"] == "ed25519"
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5.0)
