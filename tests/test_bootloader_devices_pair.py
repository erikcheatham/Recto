"""Tests for POST /v0.4/devices/pair (Phase H end-user pairing relay).

The bootloader is a thin relay that forwards user-signed pairing
attestations to the consumer's /api/v1/devices/pairing/complete
endpoint, applying the consumer-specific X-Openclaw-Token webhook
secret along the way. Tests stand up a real bootloader on a random
port + a fake consumer on another random port and exercise the
relay end-to-end.

Coverage:
  * Endpoint disabled (empty consumer registry) returns 404.
  * Unknown consumer_base_url returns 404 with diagnostic.
  * Missing body fields return 400.
  * Consumer URL with/without trailing slash both resolve.
  * Happy path: bootloader forwards correct body + token, returns
    consumer's response verbatim.
  * Consumer 4xx errors propagate (consumer_status + consumer_body
    relayed).
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
    """Records every POST to /api/v1/devices/pairing/complete for assertion.

    Behavior is configurable per-test via class attributes:
      * response_status: HTTP status to return
      * response_body: JSON body to return (or raw bytes if non-JSON-test)
      * response_is_json: whether to JSON-serialize response_body
    """

    received: list[dict] = []
    response_status: int = 200
    response_body: object = {"status": "paired", "userId": "fake-user-id"}
    response_is_json: bool = True

    def log_message(self, format, *args):
        # Quiet — tests don't need stderr spam
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
    """A fake consumer service on a random port.

    Reset between tests via class attributes; each test mutates
    response_status / response_body as needed.
    """
    _FakeConsumerHandler.received = []
    _FakeConsumerHandler.response_status = 200
    _FakeConsumerHandler.response_body = {
        "status": "paired",
        "userId": "fake-user-id",
    }
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
    """Bootloader on a random port; consumer registry is parametric.

    Tests that want the endpoint disabled use this fixture directly.
    Tests that want a registered consumer use bootloader_with_consumer.
    """

    def _make(consumer_tokens: dict[str, str] | None = None):
        state = StateStore(state_dir=tmp_path)
        challenges = ChallengeStore()
        server = create_server(
            bind_host="127.0.0.1",
            bind_port=0,
            state=state,
            bootloader_id="test-devices-pair",
            challenges=challenges,
            ssl_context=None,
            devices_pair_consumer_webhook_tokens=consumer_tokens,
        )
        host, port = server.server_address
        base_url = f"http://{host}:{port}"
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return {
            "server": server,
            "thread": thread,
            "base_url": base_url,
        }

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
_VALID_CODE = "ABCDEF12"


# ── Tests ─────────────────────────────────────────────────────────


class TestDevicesPairDisabled:
    """When no consumers are registered, the endpoint returns 404."""

    def test_endpoint_disabled_returns_404(self, bootloader):
        ctx = bootloader(consumer_tokens=None)
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/devices/pair",
            {
                "consumer_base_url": "https://consumer.example.com",
                "pairing_code": _VALID_CODE,
                "user_pubkey_hex": _VALID_PUBKEY,
                "user_jws": _VALID_JWS,
            },
        )
        assert status == HTTPStatus.NOT_FOUND
        assert body["error"] == "unknown_endpoint"

    def test_empty_dict_also_disabled(self, bootloader):
        ctx = bootloader(consumer_tokens={})
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/devices/pair",
            {
                "consumer_base_url": "https://consumer.example.com",
                "pairing_code": _VALID_CODE,
                "user_pubkey_hex": _VALID_PUBKEY,
                "user_jws": _VALID_JWS,
            },
        )
        assert status == HTTPStatus.NOT_FOUND
        assert body["error"] == "unknown_endpoint"


class TestDevicesPairBodyValidation:
    """Body field validation."""

    def test_missing_consumer_base_url(self, bootloader):
        ctx = bootloader(consumer_tokens={"https://x.com": "tok"})
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/devices/pair",
            {
                "pairing_code": _VALID_CODE,
                "user_pubkey_hex": _VALID_PUBKEY,
                "user_jws": _VALID_JWS,
            },
        )
        assert status == HTTPStatus.BAD_REQUEST
        assert "consumer_base_url" in body.get("detail", "")

    def test_missing_pairing_code(self, bootloader):
        ctx = bootloader(consumer_tokens={"https://x.com": "tok"})
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/devices/pair",
            {
                "consumer_base_url": "https://x.com",
                "user_pubkey_hex": _VALID_PUBKEY,
                "user_jws": _VALID_JWS,
            },
        )
        assert status == HTTPStatus.BAD_REQUEST
        assert "pairing_code" in body.get("detail", "")

    def test_missing_user_pubkey_hex(self, bootloader):
        ctx = bootloader(consumer_tokens={"https://x.com": "tok"})
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/devices/pair",
            {
                "consumer_base_url": "https://x.com",
                "pairing_code": _VALID_CODE,
                "user_jws": _VALID_JWS,
            },
        )
        assert status == HTTPStatus.BAD_REQUEST
        assert "user_pubkey_hex" in body.get("detail", "")

    def test_missing_user_jws(self, bootloader):
        ctx = bootloader(consumer_tokens={"https://x.com": "tok"})
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/devices/pair",
            {
                "consumer_base_url": "https://x.com",
                "pairing_code": _VALID_CODE,
                "user_pubkey_hex": _VALID_PUBKEY,
            },
        )
        assert status == HTTPStatus.BAD_REQUEST
        assert "user_jws" in body.get("detail", "")

    def test_empty_strings_rejected(self, bootloader):
        ctx = bootloader(consumer_tokens={"https://x.com": "tok"})
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/devices/pair",
            {
                "consumer_base_url": "  ",
                "pairing_code": "  ",
                "user_pubkey_hex": "  ",
                "user_jws": "  ",
            },
        )
        assert status == HTTPStatus.BAD_REQUEST


class TestDevicesPairUnknownConsumer:
    """Unknown consumer_base_url returns 404 with diagnostic body."""

    def test_unknown_consumer_url_returns_404(self, bootloader):
        ctx = bootloader(consumer_tokens={"https://x.com": "tok"})
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/devices/pair",
            {
                "consumer_base_url": "https://different.example.com",
                "pairing_code": _VALID_CODE,
                "user_pubkey_hex": _VALID_PUBKEY,
                "user_jws": _VALID_JWS,
            },
        )
        assert status == HTTPStatus.NOT_FOUND
        assert body["error"] == "unknown_consumer"


class TestDevicesPairHappyPath:
    """Happy path: bootloader forwards to consumer, returns response."""

    def test_relays_to_registered_consumer(self, bootloader, fake_consumer):
        consumer_url = fake_consumer["base_url"]
        ctx = bootloader(consumer_tokens={consumer_url: "consumer-tok-123"})

        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/devices/pair",
            {
                "consumer_base_url": consumer_url,
                "pairing_code": _VALID_CODE,
                "user_pubkey_hex": _VALID_PUBKEY,
                "user_jws": _VALID_JWS,
            },
        )

        # Bootloader relayed consumer's response (200 OK)
        assert status == HTTPStatus.OK
        assert body["consumer_status"] == 200
        assert body["consumer_body"]["status"] == "paired"
        assert body["consumer_body"]["userId"] == "fake-user-id"

        # Consumer received exactly one POST with the forwarded fields
        received = fake_consumer["received"]
        assert len(received) == 1
        req = received[0]
        assert req["path"] == "/api/v1/devices/pairing/complete"

        # X-Openclaw-Token applied from the registered webhook secret
        assert req["headers"].get("X-Openclaw-Token") == "consumer-tok-123"
        assert req["headers"].get("Content-Type") == "application/json"

        # Body matches the consumer's CompletePairingRequest schema
        assert req["body"]["code"] == _VALID_CODE
        assert req["body"]["masterPubkeyHex"] == _VALID_PUBKEY
        assert req["body"]["capabilityJws"] == _VALID_JWS

    def test_trailing_slash_in_request_normalizes(self, bootloader, fake_consumer):
        """User submits consumer_base_url with trailing slash; registry has no slash."""
        consumer_url = fake_consumer["base_url"]
        ctx = bootloader(consumer_tokens={consumer_url: "consumer-tok-123"})

        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/devices/pair",
            {
                "consumer_base_url": consumer_url + "/",  # trailing slash
                "pairing_code": _VALID_CODE,
                "user_pubkey_hex": _VALID_PUBKEY,
                "user_jws": _VALID_JWS,
            },
        )

        assert status == HTTPStatus.OK
        assert body["consumer_status"] == 200

    def test_trailing_slash_in_registry_normalizes(self, bootloader, fake_consumer):
        """Operator registered consumer with trailing slash; request has none."""
        consumer_url = fake_consumer["base_url"]
        ctx = bootloader(
            consumer_tokens={consumer_url + "/": "consumer-tok-123"},
        )

        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/devices/pair",
            {
                "consumer_base_url": consumer_url,
                "pairing_code": _VALID_CODE,
                "user_pubkey_hex": _VALID_PUBKEY,
                "user_jws": _VALID_JWS,
            },
        )

        assert status == HTTPStatus.OK


class TestDevicesPairConsumerErrors:
    """Consumer-side 4xx errors propagate cleanly."""

    def test_consumer_404_propagates(self, bootloader, fake_consumer):
        """Consumer responds 404 (e.g. pairing_code_not_found)."""
        fake_consumer["handler"].response_status = 404
        fake_consumer["handler"].response_body = {
            "error": "pairing_code_not_found",
            "reason": "Pairing code is unknown, expired, or already used.",
        }
        consumer_url = fake_consumer["base_url"]
        ctx = bootloader(consumer_tokens={consumer_url: "consumer-tok-123"})

        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/devices/pair",
            {
                "consumer_base_url": consumer_url,
                "pairing_code": _VALID_CODE,
                "user_pubkey_hex": _VALID_PUBKEY,
                "user_jws": _VALID_JWS,
            },
        )

        assert status == HTTPStatus.NOT_FOUND
        assert body["consumer_status"] == 404
        assert body["consumer_body"]["error"] == "pairing_code_not_found"

    def test_consumer_409_propagates(self, bootloader, fake_consumer):
        """Consumer responds 409 (pubkey_already_bound)."""
        fake_consumer["handler"].response_status = 409
        fake_consumer["handler"].response_body = {
            "error": "pubkey_already_bound",
            "reason": "This master pubkey is already paired to a different user.",
        }
        consumer_url = fake_consumer["base_url"]
        ctx = bootloader(consumer_tokens={consumer_url: "consumer-tok-123"})

        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/devices/pair",
            {
                "consumer_base_url": consumer_url,
                "pairing_code": _VALID_CODE,
                "user_pubkey_hex": _VALID_PUBKEY,
                "user_jws": _VALID_JWS,
            },
        )

        assert status == HTTPStatus.CONFLICT
        assert body["consumer_status"] == 409
        assert body["consumer_body"]["error"] == "pubkey_already_bound"

    def test_consumer_401_invalid_jws_propagates(self, bootloader, fake_consumer):
        """Consumer responds 401 (capability_invalid — JWS verification failed)."""
        fake_consumer["handler"].response_status = 401
        fake_consumer["handler"].response_body = {
            "error": "capability_invalid",
            "reason": "signature: did not recover to expected pubkey",
        }
        consumer_url = fake_consumer["base_url"]
        ctx = bootloader(consumer_tokens={consumer_url: "consumer-tok-123"})

        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/devices/pair",
            {
                "consumer_base_url": consumer_url,
                "pairing_code": _VALID_CODE,
                "user_pubkey_hex": _VALID_PUBKEY,
                "user_jws": _VALID_JWS,
            },
        )

        assert status == HTTPStatus.UNAUTHORIZED
        assert body["consumer_status"] == 401
        assert body["consumer_body"]["error"] == "capability_invalid"

    def test_consumer_non_json_body_relayed_as_raw(self, bootloader, fake_consumer):
        """Consumer returns non-JSON — bootloader wraps it as {raw: ...}."""
        fake_consumer["handler"].response_status = 200
        fake_consumer["handler"].response_body = "not-json-text"
        fake_consumer["handler"].response_is_json = False
        consumer_url = fake_consumer["base_url"]
        ctx = bootloader(consumer_tokens={consumer_url: "consumer-tok-123"})

        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/devices/pair",
            {
                "consumer_base_url": consumer_url,
                "pairing_code": _VALID_CODE,
                "user_pubkey_hex": _VALID_PUBKEY,
                "user_jws": _VALID_JWS,
            },
        )

        assert status == HTTPStatus.OK
        assert body["consumer_status"] == 200
        assert "raw" in body["consumer_body"]


class TestDevicesPairConsumerUnreachable:
    """Consumer connection failures return 502."""

    def test_consumer_port_closed_returns_502(self, bootloader):
        """Consumer URL points at a closed port."""
        # 127.0.0.1:1 — well-known closed port (privileged + reserved).
        unreachable_url = "http://127.0.0.1:1"
        ctx = bootloader(consumer_tokens={unreachable_url: "consumer-tok-123"})

        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/devices/pair",
            {
                "consumer_base_url": unreachable_url,
                "pairing_code": _VALID_CODE,
                "user_pubkey_hex": _VALID_PUBKEY,
                "user_jws": _VALID_JWS,
            },
        )

        assert status == HTTPStatus.BAD_GATEWAY
        assert body["error"] == "consumer_unreachable"
