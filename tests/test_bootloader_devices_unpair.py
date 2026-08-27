"""Tests for POST /v0.4/devices/unpair (Phase H end-user UNPAIR relay).

Sibling of test_bootloader_devices_pair.py. The bootloader is a thin
relay that forwards a user-signed revoke attestation to the consumer's
/api/v1/devices/pairing/revoke endpoint, applying the consumer-specific
X-Openclaw-Token webhook secret along the way. Tests stand up a real
bootloader + a fake consumer, both on random ports, and exercise the
relay end-to-end.

Coverage:
  * Endpoint disabled (empty consumer registry) returns 404.
  * Unknown consumer_base_url returns 404 with diagnostic.
  * Missing body fields return 400 (note: NO pairing_code field — unpair
    identifies the binding by the bound pubkey, not a fresh code).
  * Consumer URL with/without trailing slash both resolve.
  * Happy path: bootloader forwards {masterPubkeyHex, capabilityJws} to
    /api/v1/devices/pairing/revoke with the token, relays response verbatim.
  * Consumer 4xx errors propagate (consumer_status + consumer_body relayed).
  * Consumer unreachable (port closed) returns 502.
  * Consumer non-JSON body relayed as {"raw": ...}.
"""

from __future__ import annotations

import json
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib import request as urlrequest
from urllib.error import HTTPError

import pytest

from recto.bootloader.server import ChallengeStore, create_server
from recto.bootloader.state import StateStore


# ── Helpers ───────────────────────────────────────────────────────


def _http_post_json(url, body):
    data = json.dumps(body).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    req = urlrequest.Request(url, data=data, headers=headers, method="POST")
    try:
        with urlrequest.urlopen(req, timeout=5.0) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except HTTPError as e:
        body_bytes = e.read()
        try:
            return e.code, json.loads(body_bytes.decode("utf-8"))
        except json.JSONDecodeError:
            return e.code, {"_raw_body": body_bytes.decode("utf-8", errors="replace")}


# ── Fake consumer server (records every request it received) ──────


class _FakeConsumerHandler(BaseHTTPRequestHandler):
    """Records every POST to /api/v1/devices/pairing/revoke for assertion."""

    received: list[dict] = []
    response_status: int = 200
    response_body: object = {"status": "unpaired"}
    response_is_json: bool = True

    def log_message(self, format, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length) if length else b""
        try:
            parsed_body = json.loads(raw_body) if raw_body else None
        except json.JSONDecodeError:
            parsed_body = {"_raw": raw_body.decode("utf-8", errors="replace")}

        self.__class__.received.append({
            "path": self.path,
            "headers": dict(self.headers),
            "body": parsed_body,
        })

        body_bytes: bytes
        if self.__class__.response_is_json:
            body_bytes = json.dumps(self.__class__.response_body).encode("utf-8")
            content_type = "application/json"
        else:
            body_bytes = (
                self.__class__.response_body
                if isinstance(self.__class__.response_body, bytes)
                else str(self.__class__.response_body).encode("utf-8")
            )
            content_type = "text/plain"

        self.send_response(self.__class__.response_status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)


@pytest.fixture
def fake_consumer():
    _FakeConsumerHandler.received = []
    _FakeConsumerHandler.response_status = 200
    _FakeConsumerHandler.response_body = {"status": "unpaired"}
    _FakeConsumerHandler.response_is_json = True

    server = HTTPServer(("127.0.0.1", 0), _FakeConsumerHandler)
    host, port = server.server_address
    base_url = f"http://{host}:{port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {
            "base_url": base_url,
            "received": _FakeConsumerHandler.received,
            "handler": _FakeConsumerHandler,
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)


@pytest.fixture
def bootloader(tmp_path: Path):
    def _make(consumer_tokens: dict[str, str] | None = None):
        state = StateStore(state_dir=tmp_path)
        challenges = ChallengeStore()
        server = create_server(
            bind_host="127.0.0.1",
            bind_port=0,
            state=state,
            bootloader_id="test-devices-unpair",
            challenges=challenges,
            ssl_context=None,
            devices_pair_consumer_webhook_tokens=consumer_tokens,
        )
        host, port = server.server_address
        base_url = f"http://{host}:{port}"
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return {"server": server, "thread": thread, "base_url": base_url}

    instances = []
    try:
        def _factory(consumer_tokens=None):
            ctx = _make(consumer_tokens)
            instances.append(ctx)
            return ctx
        yield _factory
    finally:
        for ctx in instances:
            ctx["server"].shutdown()
            ctx["server"].server_close()
            ctx["thread"].join(timeout=5.0)


# ── Constants used across tests ──────────────────────────────────


_VALID_PUBKEY = (
    "2b29338bdce6fa59f120d3972ae4b4300d4f43b88387efed0dff43e2a068c669"
    "e8a815fafe8639a2e225b01fe380369f1ddda6ea17a943bb7730e6dc5c4112d1"
)
_VALID_JWS = "eyJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJ0ZXN0In0.AA"  # opaque to relay


# ── Tests ─────────────────────────────────────────────────────────


class TestDevicesUnpairDisabled:
    """When no consumers are registered, the endpoint returns 404."""

    def test_endpoint_disabled_returns_404(self, bootloader):
        ctx = bootloader(consumer_tokens=None)
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/devices/unpair",
            {
                "consumer_base_url": "https://consumer.example.com",
                "user_pubkey_hex": _VALID_PUBKEY,
                "user_jws": _VALID_JWS,
            },
        )
        assert status == HTTPStatus.NOT_FOUND
        assert body["error"] == "unknown_endpoint"

    def test_empty_dict_also_disabled(self, bootloader):
        ctx = bootloader(consumer_tokens={})
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/devices/unpair",
            {
                "consumer_base_url": "https://consumer.example.com",
                "user_pubkey_hex": _VALID_PUBKEY,
                "user_jws": _VALID_JWS,
            },
        )
        assert status == HTTPStatus.NOT_FOUND
        assert body["error"] == "unknown_endpoint"


class TestDevicesUnpairBodyValidation:
    """Body field validation — no pairing_code on the unpair path."""

    def test_missing_consumer_base_url(self, bootloader):
        ctx = bootloader(consumer_tokens={"https://x.com": "tok"})
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/devices/unpair",
            {"user_pubkey_hex": _VALID_PUBKEY, "user_jws": _VALID_JWS},
        )
        assert status == HTTPStatus.BAD_REQUEST
        assert "consumer_base_url" in body.get("detail", "")

    def test_missing_user_pubkey_hex(self, bootloader):
        ctx = bootloader(consumer_tokens={"https://x.com": "tok"})
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/devices/unpair",
            {"consumer_base_url": "https://x.com", "user_jws": _VALID_JWS},
        )
        assert status == HTTPStatus.BAD_REQUEST
        assert "user_pubkey_hex" in body.get("detail", "")

    def test_missing_user_jws(self, bootloader):
        ctx = bootloader(consumer_tokens={"https://x.com": "tok"})
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/devices/unpair",
            {"consumer_base_url": "https://x.com", "user_pubkey_hex": _VALID_PUBKEY},
        )
        assert status == HTTPStatus.BAD_REQUEST
        assert "user_jws" in body.get("detail", "")

    def test_empty_strings_rejected(self, bootloader):
        ctx = bootloader(consumer_tokens={"https://x.com": "tok"})
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/devices/unpair",
            {"consumer_base_url": "  ", "user_pubkey_hex": "  ", "user_jws": "  "},
        )
        assert status == HTTPStatus.BAD_REQUEST


class TestDevicesUnpairUnknownConsumer:
    """Unknown consumer_base_url returns 404 with diagnostic body."""

    def test_unknown_consumer_url_returns_404(self, bootloader):
        ctx = bootloader(consumer_tokens={"https://x.com": "tok"})
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/devices/unpair",
            {
                "consumer_base_url": "https://different.example.com",
                "user_pubkey_hex": _VALID_PUBKEY,
                "user_jws": _VALID_JWS,
            },
        )
        assert status == HTTPStatus.NOT_FOUND
        assert body["error"] == "unknown_consumer"


class TestDevicesUnpairHappyPath:
    """Happy path: bootloader forwards to consumer's revoke endpoint."""

    def test_relays_to_registered_consumer(self, bootloader, fake_consumer):
        consumer_url = fake_consumer["base_url"]
        ctx = bootloader(consumer_tokens={consumer_url: "consumer-tok-123"})

        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/devices/unpair",
            {
                "consumer_base_url": consumer_url,
                "user_pubkey_hex": _VALID_PUBKEY,
                "user_jws": _VALID_JWS,
            },
        )

        assert status == HTTPStatus.OK
        assert body["consumer_status"] == 200
        assert body["consumer_body"]["status"] == "unpaired"

        received = fake_consumer["received"]
        assert len(received) == 1
        req = received[0]
        # Forwarded to the REVOKE endpoint, not /complete.
        assert req["path"] == "/api/v1/devices/pairing/revoke"
        assert req["headers"].get("X-Openclaw-Token") == "consumer-tok-123"
        assert req["headers"].get("Content-Type") == "application/json"
        # Body carries pubkey + JWS, NO pairing code.
        assert req["body"]["masterPubkeyHex"] == _VALID_PUBKEY
        assert req["body"]["capabilityJws"] == _VALID_JWS
        assert "code" not in req["body"]

    def test_trailing_slash_in_request_normalizes(self, bootloader, fake_consumer):
        consumer_url = fake_consumer["base_url"]
        ctx = bootloader(consumer_tokens={consumer_url: "consumer-tok-123"})

        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/devices/unpair",
            {
                "consumer_base_url": consumer_url + "/",
                "user_pubkey_hex": _VALID_PUBKEY,
                "user_jws": _VALID_JWS,
            },
        )
        assert status == HTTPStatus.OK
        assert body["consumer_status"] == 200

    def test_trailing_slash_in_registry_normalizes(self, bootloader, fake_consumer):
        consumer_url = fake_consumer["base_url"]
        ctx = bootloader(consumer_tokens={consumer_url + "/": "consumer-tok-123"})

        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/devices/unpair",
            {
                "consumer_base_url": consumer_url,
                "user_pubkey_hex": _VALID_PUBKEY,
                "user_jws": _VALID_JWS,
            },
        )
        assert status == HTTPStatus.OK


class TestDevicesUnpairConsumerErrors:
    """Consumer-side 4xx errors propagate cleanly."""

    def test_consumer_404_not_paired_propagates(self, bootloader, fake_consumer):
        fake_consumer["handler"].response_status = 404
        fake_consumer["handler"].response_body = {
            "error": "not_paired",
            "reason": "No active pairing for this pubkey.",
        }
        consumer_url = fake_consumer["base_url"]
        ctx = bootloader(consumer_tokens={consumer_url: "consumer-tok-123"})

        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/devices/unpair",
            {
                "consumer_base_url": consumer_url,
                "user_pubkey_hex": _VALID_PUBKEY,
                "user_jws": _VALID_JWS,
            },
        )
        assert status == HTTPStatus.NOT_FOUND
        assert body["consumer_status"] == 404
        assert body["consumer_body"]["error"] == "not_paired"

    def test_consumer_401_invalid_jws_propagates(self, bootloader, fake_consumer):
        fake_consumer["handler"].response_status = 401
        fake_consumer["handler"].response_body = {
            "error": "capability_invalid",
            "reason": "signature: did not recover to bound pubkey",
        }
        consumer_url = fake_consumer["base_url"]
        ctx = bootloader(consumer_tokens={consumer_url: "consumer-tok-123"})

        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/devices/unpair",
            {
                "consumer_base_url": consumer_url,
                "user_pubkey_hex": _VALID_PUBKEY,
                "user_jws": _VALID_JWS,
            },
        )
        assert status == HTTPStatus.UNAUTHORIZED
        assert body["consumer_status"] == 401
        assert body["consumer_body"]["error"] == "capability_invalid"

    def test_consumer_non_json_body_relayed_as_raw(self, bootloader, fake_consumer):
        fake_consumer["handler"].response_status = 200
        fake_consumer["handler"].response_body = "not-json-text"
        fake_consumer["handler"].response_is_json = False
        consumer_url = fake_consumer["base_url"]
        ctx = bootloader(consumer_tokens={consumer_url: "consumer-tok-123"})

        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/devices/unpair",
            {
                "consumer_base_url": consumer_url,
                "user_pubkey_hex": _VALID_PUBKEY,
                "user_jws": _VALID_JWS,
            },
        )
        assert status == HTTPStatus.OK
        assert body["consumer_status"] == 200
        assert "raw" in body["consumer_body"]


class TestDevicesUnpairConsumerUnreachable:
    """Consumer connection failures return 502."""

    def test_consumer_port_closed_returns_502(self, bootloader):
        unreachable_url = "http://127.0.0.1:1"
        ctx = bootloader(consumer_tokens={unreachable_url: "consumer-tok-123"})

        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/devices/unpair",
            {
                "consumer_base_url": unreachable_url,
                "user_pubkey_hex": _VALID_PUBKEY,
                "user_jws": _VALID_JWS,
            },
        )
        assert status == HTTPStatus.BAD_GATEWAY
        assert body["error"] == "consumer_unreachable"
