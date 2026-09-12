"""Tests for POST /v0.4/devices/pair.

The bootloader verifies a pairing record + the phone's grant, spends the
grant, then relays to the consumer's /api/v1/devices/pairing/complete
with the consumer's registered webhook token. A real bootloader and a
fake consumer run on random ports.

Coverage:
  * Endpoint disabled (empty consumer registry) returns 404.
  * Unknown consumer_base_url returns 404 with diagnostic.
  * Missing body fields return 400; a body without a record is refused.
  * Refusals by name: wrong bootloader, bad signature, replayed jti,
    scope naming the code but not the fingerprint, wrong fingerprint.
  * Happy path: record + fingerprint forwarded with the token; the
    consumer's response relayed verbatim; 4xx / non-JSON / unreachable.
"""

from __future__ import annotations

import base64
import json
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib import request as urlrequest
from urllib.error import HTTPError

import pytest

from recto.bootloader.server import ChallengeStore, create_server
from recto.bootloader.state import StateStore
from recto.capability.jwt import build_signing_input
from recto.capability.pair_record import PAIR_ACTION, PairRecord
from recto.capability.types import CapabilityClaims, CapabilityClause, CapabilityScope

_MANIFEST_VERSION: str = json.loads(
    (Path(__file__).parent.parent / "recto" / "capability" / "manifest_v1.json")
    .read_text(encoding="utf-8")
)["version"]

_BOOTLOADER_ID = "test-devices-pair"
_VALID_CODE = "ABCDEF12"


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


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _keypair():
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import ec

    priv = ec.generate_private_key(ec.SECP256K1(), default_backend())
    nums = priv.public_key().public_numbers()
    return priv.private_numbers().private_value, (
        nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")
    ).hex()


def _mint(claims: CapabilityClaims, priv_int: int) -> str:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    digest, header_b64, payload_b64 = build_signing_input(claims)
    priv = ec.derive_private_key(priv_int, ec.SECP256K1(), default_backend())
    r, s = utils.decode_dss_signature(priv.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256()))))
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    if s > n // 2:
        s = n - s
    return f"{header_b64}.{payload_b64}.{_b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


@pytest.fixture(scope="module")
def phone():
    pytest.importorskip("cryptography")
    priv, pub = _keypair()
    return {"priv": priv, "pub": pub}


def _record(phone, **overrides) -> PairRecord:
    base = dict(
        bootloader_id=_BOOTLOADER_ID,
        user_id="user-1",
        phone_pubkey=phone["pub"],
        code=_VALID_CODE,
        not_after=int(time.time()) + 600,
    )
    base.update(overrides)
    return PairRecord(**base)


def _grant(phone, record: PairRecord, *, scope: CapabilityScope | None = None,
           priv: int | None = None, jti: str | None = None) -> str:
    now = int(time.time())
    claims = CapabilityClaims(
        iss="phone:user:enclave",
        sub="user:user-1",
        aud=[_BOOTLOADER_ID, "consumer"],
        iat=now, nbf=now, exp=now + 300,
        jti=jti or f"jti-{now}-{id(record)}",
        cap=CapabilityClause(
            tier=0,
            registry_version=_MANIFEST_VERSION,
            scope=scope if scope is not None else CapabilityScope(
                payload_sha256=record.fingerprint(), pairing_code=record.code,
            ),
            allow_actions=[PAIR_ACTION],
        ),
        purpose="pair",
        max_uses=1,
    )
    return _mint(claims, priv if priv is not None else phone["priv"])


def _body(consumer_url: str, phone, record: PairRecord | None = None, jws: str | None = None) -> dict:
    record = record or _record(phone)
    return {
        "consumer_base_url": consumer_url,
        "record": record.to_dict(),
        "user_jws": jws or _grant(phone, record),
    }


# ── Fake consumer server (records every request it received) ──────


class _FakeConsumerHandler(BaseHTTPRequestHandler):
    received: list[dict] = []
    response_status: int = 200
    response_body: object = {"status": "paired", "userId": "fake-user-id"}
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
    _FakeConsumerHandler.response_body = {"status": "paired", "userId": "fake-user-id"}
    _FakeConsumerHandler.response_is_json = True

    server = HTTPServer(("127.0.0.1", 0), _FakeConsumerHandler)
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {
            "base_url": f"http://{host}:{port}",
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
        server = create_server(
            bind_host="127.0.0.1",
            bind_port=0,
            state=StateStore(state_dir=tmp_path),
            bootloader_id=_BOOTLOADER_ID,
            challenges=ChallengeStore(),
            ssl_context=None,
            devices_pair_consumer_webhook_tokens=consumer_tokens,
        )
        host, port = server.server_address
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return {"server": server, "thread": thread, "base_url": f"http://{host}:{port}"}

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


def _pair_url(ctx) -> str:
    return f"{ctx['base_url']}/v0.4/devices/pair"


# ── Tests ─────────────────────────────────────────────────────────


class TestDevicesPairDisabled:
    def test_endpoint_disabled_returns_404(self, bootloader, phone):
        ctx = bootloader(consumer_tokens=None)
        status, body = _http_post_json(_pair_url(ctx), _body("https://consumer.example.com", phone))
        assert status == HTTPStatus.NOT_FOUND
        assert body["error"] == "unknown_endpoint"

    def test_empty_dict_also_disabled(self, bootloader, phone):
        ctx = bootloader(consumer_tokens={})
        status, body = _http_post_json(_pair_url(ctx), _body("https://consumer.example.com", phone))
        assert status == HTTPStatus.NOT_FOUND
        assert body["error"] == "unknown_endpoint"


class TestDevicesPairBodyValidation:
    def test_missing_consumer_base_url(self, bootloader, phone):
        ctx = bootloader(consumer_tokens={"https://x.com": "tok"})
        b = _body("https://x.com", phone)
        del b["consumer_base_url"]
        status, body = _http_post_json(_pair_url(ctx), b)
        assert status == HTTPStatus.BAD_REQUEST
        assert "consumer_base_url" in body.get("detail", "")

    def test_missing_user_jws(self, bootloader, phone):
        ctx = bootloader(consumer_tokens={"https://x.com": "tok"})
        b = _body("https://x.com", phone)
        del b["user_jws"]
        status, body = _http_post_json(_pair_url(ctx), b)
        assert status == HTTPStatus.BAD_REQUEST
        assert "user_jws" in body.get("detail", "")

    def test_legacy_shape_without_record_is_refused(self, bootloader, phone):
        ctx = bootloader(consumer_tokens={"https://x.com": "tok"})
        status, body = _http_post_json(_pair_url(ctx), {
            "consumer_base_url": "https://x.com",
            "pairing_code": _VALID_CODE,
            "user_pubkey_hex": phone["pub"],
            "user_jws": _grant(phone, _record(phone)),
        })
        assert status == HTTPStatus.BAD_REQUEST
        assert body["error"] == "record_required"

    def test_malformed_record_is_refused_by_name(self, bootloader, phone):
        ctx = bootloader(consumer_tokens={"https://x.com": "tok"})
        b = _body("https://x.com", phone)
        b["record"]["phone_pubkey"] = "zz"
        status, body = _http_post_json(_pair_url(ctx), b)
        assert status == HTTPStatus.BAD_REQUEST
        assert body["error"] == "record_pubkey_malformed"


class TestDevicesPairUnknownConsumer:
    def test_unknown_consumer_url_returns_404(self, bootloader, phone):
        ctx = bootloader(consumer_tokens={"https://x.com": "tok"})
        status, body = _http_post_json(_pair_url(ctx), _body("https://different.example.com", phone))
        assert status == HTTPStatus.NOT_FOUND
        assert body["error"] == "unknown_consumer"


class TestDevicesPairRefusals:
    """Each lesser shape is refused by name before anything is relayed."""

    def test_record_naming_another_bootloader(self, bootloader, fake_consumer, phone):
        url = fake_consumer["base_url"]
        ctx = bootloader(consumer_tokens={url: "tok"})
        rec = _record(phone, bootloader_id="some-other-bootloader")
        status, body = _http_post_json(_pair_url(ctx), _body(url, phone, rec))
        assert status == HTTPStatus.FORBIDDEN
        assert body["error"] == "record_bootloader_mismatch"
        assert fake_consumer["received"] == []

    def test_grant_signed_by_another_key(self, bootloader, fake_consumer, phone):
        url = fake_consumer["base_url"]
        ctx = bootloader(consumer_tokens={url: "tok"})
        other_priv, _ = _keypair()
        rec = _record(phone)
        status, body = _http_post_json(_pair_url(ctx), _body(url, phone, rec, _grant(phone, rec, priv=other_priv)))
        assert status == HTTPStatus.FORBIDDEN
        assert body["error"] == "grant_signature_invalid"
        assert fake_consumer["received"] == []

    def test_scope_naming_the_code_but_not_the_act(self, bootloader, fake_consumer, phone):
        url = fake_consumer["base_url"]
        ctx = bootloader(consumer_tokens={url: "tok"})
        rec = _record(phone)
        jws = _grant(phone, rec, scope=CapabilityScope(pairing_code=rec.code))
        status, body = _http_post_json(_pair_url(ctx), _body(url, phone, rec, jws))
        assert status == HTTPStatus.FORBIDDEN
        assert body["error"] == "grant_scope_missing_fingerprint"
        assert fake_consumer["received"] == []

    def test_scope_naming_another_act(self, bootloader, fake_consumer, phone):
        url = fake_consumer["base_url"]
        ctx = bootloader(consumer_tokens={url: "tok"})
        rec = _record(phone)
        other = _record(phone, user_id="user-2")
        jws = _grant(phone, rec, scope=CapabilityScope(payload_sha256=other.fingerprint()))
        status, body = _http_post_json(_pair_url(ctx), _body(url, phone, rec, jws))
        assert status == HTTPStatus.FORBIDDEN
        assert body["error"] == "grant_scope_fingerprint_mismatch"
        assert fake_consumer["received"] == []

    def test_replayed_grant_is_refused(self, bootloader, fake_consumer, phone):
        url = fake_consumer["base_url"]
        ctx = bootloader(consumer_tokens={url: "tok"})
        b = _body(url, phone)
        status, _ = _http_post_json(_pair_url(ctx), b)
        assert status == HTTPStatus.OK
        status, body = _http_post_json(_pair_url(ctx), b)
        assert status == HTTPStatus.FORBIDDEN
        assert body["error"] == "grant_replayed"
        assert len(fake_consumer["received"]) == 1


class TestDevicesPairHappyPath:
    def test_relays_record_and_fingerprint_with_token(self, bootloader, fake_consumer, phone):
        url = fake_consumer["base_url"]
        ctx = bootloader(consumer_tokens={url: "consumer-tok-123"})
        rec = _record(phone)
        jws = _grant(phone, rec)

        status, body = _http_post_json(_pair_url(ctx), _body(url, phone, rec, jws))
        assert status == HTTPStatus.OK
        assert body["consumer_status"] == 200
        assert body["consumer_body"]["status"] == "paired"

        received = fake_consumer["received"]
        assert len(received) == 1
        req = received[0]
        assert req["path"] == "/api/v1/devices/pairing/complete"
        assert req["headers"].get("X-Openclaw-Token") == "consumer-tok-123"
        assert req["body"]["code"] == _VALID_CODE
        assert req["body"]["masterPubkeyHex"] == phone["pub"]
        assert req["body"]["capabilityJws"] == jws
        assert req["body"]["record"] == rec.to_dict()
        assert req["body"]["fingerprint"] == rec.fingerprint()

    def test_trailing_slash_in_request_normalizes(self, bootloader, fake_consumer, phone):
        url = fake_consumer["base_url"]
        ctx = bootloader(consumer_tokens={url: "tok"})
        status, body = _http_post_json(_pair_url(ctx), _body(url + "/", phone))
        assert status == HTTPStatus.OK
        assert body["consumer_status"] == 200

    def test_trailing_slash_in_registry_normalizes(self, bootloader, fake_consumer, phone):
        url = fake_consumer["base_url"]
        ctx = bootloader(consumer_tokens={url + "/": "tok"})
        status, _ = _http_post_json(_pair_url(ctx), _body(url, phone))
        assert status == HTTPStatus.OK


class TestDevicesPairConsumerErrors:
    @pytest.mark.parametrize(
        "code, error",
        [(404, "pairing_code_not_found"), (409, "pubkey_already_bound"), (401, "capability_invalid")],
    )
    def test_consumer_4xx_propagates(self, bootloader, fake_consumer, phone, code, error):
        fake_consumer["handler"].response_status = code
        fake_consumer["handler"].response_body = {"error": error}
        url = fake_consumer["base_url"]
        ctx = bootloader(consumer_tokens={url: "tok"})
        status, body = _http_post_json(_pair_url(ctx), _body(url, phone))
        assert status == code
        assert body["consumer_status"] == code
        assert body["consumer_body"]["error"] == error

    def test_consumer_non_json_body_relayed_as_raw(self, bootloader, fake_consumer, phone):
        fake_consumer["handler"].response_body = "not-json-text"
        fake_consumer["handler"].response_is_json = False
        url = fake_consumer["base_url"]
        ctx = bootloader(consumer_tokens={url: "tok"})
        status, body = _http_post_json(_pair_url(ctx), _body(url, phone))
        assert status == HTTPStatus.OK
        assert "raw" in body["consumer_body"]


class TestDevicesPairConsumerUnreachable:
    def test_consumer_port_closed_returns_502(self, bootloader, phone):
        unreachable_url = "http://127.0.0.1:1"
        ctx = bootloader(consumer_tokens={unreachable_url: "tok"})
        status, body = _http_post_json(_pair_url(ctx), _body(unreachable_url, phone))
        assert status == HTTPStatus.BAD_GATEWAY
        assert body["error"] == "consumer_unreachable"
