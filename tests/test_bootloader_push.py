"""Tests for the silent-push wake substrate (production-scale wave C).

Covers: push-token capture at registration + the multi-URL failover
field, POST /v0.4/manage/push_token rotation, PushDispatcher routing /
best-effort semantics, the ApnsPushSender / FcmPushSender request
shapes (injected fake HTTP clients -- no network), and the end-to-end
"queued request fires a wake push" path through the live HTTP server.
"""

from __future__ import annotations

import base64
import json
import threading
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any
from urllib import request as urlrequest
from urllib.error import HTTPError

import pytest

cryptography = pytest.importorskip(
    "cryptography", reason="recto[v0_4] not installed"
)
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)

from recto.bootloader.push import (  # noqa: E402
    ApnsConfig,
    ApnsPushSender,
    FcmConfig,
    FcmPushSender,
    PushDispatcher,
    PushSender,
    PushSendError,
)
from recto.bootloader.server import ChallengeStore, create_server  # noqa: E402
from recto.bootloader.state import PhoneRegistration, StateStore  # noqa: E402


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _http_post_json(
    url: str, body: dict[str, Any], headers: dict[str, str] | None = None
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


def _http_get_json(url: str) -> tuple[int, dict[str, Any]]:
    req = urlrequest.Request(url, method="GET")
    try:
        with urlrequest.urlopen(req, timeout=5.0) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


class RecordingSender(PushSender):
    """Fake platform sender; records sends + signals an Event so tests
    can wait for the dispatcher's daemon thread deterministically."""

    def __init__(self, platform: str, *, fail: bool = False):
        self._platform = platform
        self.fail = fail
        self.sends: list[tuple[str, str]] = []
        self.fired = threading.Event()

    @property
    def platform(self) -> str:
        return self._platform

    def send_wake(self, push_token: str, *, request_id: str) -> None:
        try:
            if self.fail:
                raise PushSendError("simulated provider failure")
            self.sends.append((push_token, request_id))
        finally:
            self.fired.set()


def _phone(**kw) -> PhoneRegistration:
    defaults = dict(
        device_label="push-test-phone",
        public_key_b64u="AAAA",
        supported_algorithms=("ed25519",),
    )
    defaults.update(kw)
    return PhoneRegistration.new(**defaults)


# ----------------------------------------------------------------------
# PushDispatcher
# ----------------------------------------------------------------------

class TestPushDispatcher:
    def test_routes_to_matching_platform_sender(self):
        apns, fcm = RecordingSender("apns"), RecordingSender("fcm")
        d = PushDispatcher([apns, fcm])
        phone = _phone(push_token="tok-android", push_platform="fcm")
        d.notify(phone, "req-1")
        assert fcm.fired.wait(timeout=5.0)
        assert fcm.sends == [("tok-android", "req-1")]
        assert apns.sends == []

    def test_phone_without_token_is_skipped(self):
        apns = RecordingSender("apns")
        d = PushDispatcher([apns])
        d.notify(_phone(), "req-1")  # no token registered
        assert not apns.fired.wait(timeout=0.3)
        assert apns.sends == []

    def test_unregistered_platform_is_skipped(self):
        apns = RecordingSender("apns")
        d = PushDispatcher([apns])
        d.notify(_phone(push_token="t", push_platform="fcm"), "req-1")
        assert not apns.fired.wait(timeout=0.3)

    def test_sender_failure_is_swallowed(self):
        failing = RecordingSender("apns", fail=True)
        d = PushDispatcher([failing])
        # Must not raise -- push is best-effort by design.
        d.notify(_phone(push_token="t", push_platform="apns"), "req-1")
        assert failing.fired.wait(timeout=5.0)

    def test_platforms_property(self):
        d = PushDispatcher([RecordingSender("fcm"), RecordingSender("apns")])
        assert d.platforms == ["apns", "fcm"]


# ----------------------------------------------------------------------
# Provider senders (fake HTTP clients -- request-shape pins)
# ----------------------------------------------------------------------

class _FakeResponse:
    def __init__(self, status_code: int, body: dict | None = None):
        self.status_code = status_code
        self._body = body or {}

    def json(self) -> dict:
        return self._body


class _FakeHttpClient:
    def __init__(self, responses: list[_FakeResponse]):
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def post(self, url: str, **kw) -> _FakeResponse:
        self.calls.append({"url": url, **kw})
        return self.responses.pop(0)


@pytest.fixture(scope="module")
def ec_p8_pem() -> str:
    """An ES256 (P-256) signing key PEM standing in for an APNs .p8."""
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


@pytest.fixture(scope="module")
def rsa_sa_json() -> str:
    """A minimal FCM service-account JSON with a real RSA key."""
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")
    return json.dumps(
        {"client_email": "push-test@example.iam.gserviceaccount.com",
         "private_key": pem}
    )


class TestApnsPushSender:
    def test_send_shape(self, ec_p8_pem):
        pytest.importorskip("jwt")
        client = _FakeHttpClient([_FakeResponse(200)])
        sender = ApnsPushSender(
            ApnsConfig(
                team_id="TEAM123456",
                key_id="KEY1234567",
                p8_key_pem=ec_p8_pem,
                bundle_id="app.recto.phone",
            ),
            client=client,
        )
        sender.send_wake("device-token-abc", request_id="req-9")
        call = client.calls[0]
        assert call["url"] == (
            "https://api.push.apple.com/3/device/device-token-abc"
        )
        h = call["headers"]
        assert h["apns-topic"] == "app.recto.phone"
        assert h["apns-push-type"] == "background"
        assert h["apns-priority"] == "5"
        assert h["authorization"].startswith("bearer ")
        # Hard property 1: bare wake marker, zero request content.
        assert call["json"] == {
            "aps": {"content-available": 1},
            "recto": "pending_wake",
        }

    def test_sandbox_gateway(self, ec_p8_pem):
        pytest.importorskip("jwt")
        client = _FakeHttpClient([_FakeResponse(200)])
        sender = ApnsPushSender(
            ApnsConfig(
                team_id="T", key_id="K", p8_key_pem=ec_p8_pem,
                bundle_id="b", use_sandbox=True,
            ),
            client=client,
        )
        sender.send_wake("tok", request_id="r")
        assert client.calls[0]["url"].startswith(
            "https://api.sandbox.push.apple.com/"
        )

    def test_non_200_raises_push_send_error(self, ec_p8_pem):
        pytest.importorskip("jwt")
        client = _FakeHttpClient([_FakeResponse(410)])
        sender = ApnsPushSender(
            ApnsConfig(team_id="T", key_id="K", p8_key_pem=ec_p8_pem,
                       bundle_id="b"),
            client=client,
        )
        with pytest.raises(PushSendError, match="410"):
            sender.send_wake("tok", request_id="r")

    def test_provider_jwt_is_cached(self, ec_p8_pem):
        pytest.importorskip("jwt")
        client = _FakeHttpClient([_FakeResponse(200), _FakeResponse(200)])
        sender = ApnsPushSender(
            ApnsConfig(team_id="T", key_id="K", p8_key_pem=ec_p8_pem,
                       bundle_id="b"),
            client=client,
        )
        sender.send_wake("tok", request_id="r1")
        sender.send_wake("tok", request_id="r2")
        auth1 = client.calls[0]["headers"]["authorization"]
        auth2 = client.calls[1]["headers"]["authorization"]
        assert auth1 == auth2  # minted once inside the cache window


class TestFcmPushSender:
    def test_send_shape_with_token_exchange(self, rsa_sa_json):
        pytest.importorskip("jwt")
        client = _FakeHttpClient([
            _FakeResponse(200, {"access_token": "oauth-tok",
                                "expires_in": 3600}),
            _FakeResponse(200),
        ])
        sender = FcmPushSender(
            FcmConfig(project_id="recto-prod", service_account_json=rsa_sa_json),
            client=client,
        )
        sender.send_wake("fcm-token-xyz", request_id="req-3")
        exchange, send = client.calls
        assert exchange["url"] == "https://oauth2.googleapis.com/token"
        assert send["url"] == (
            "https://fcm.googleapis.com/v1/projects/recto-prod/messages:send"
        )
        assert send["headers"]["authorization"] == "Bearer oauth-tok"
        # Hard property 1: data-only wake marker (no notification block).
        assert send["json"] == {
            "message": {
                "token": "fcm-token-xyz",
                "data": {"recto": "pending_wake"},
                "android": {"priority": "HIGH"},
            }
        }

    def test_oauth_token_cached_across_sends(self, rsa_sa_json):
        pytest.importorskip("jwt")
        client = _FakeHttpClient([
            _FakeResponse(200, {"access_token": "tok", "expires_in": 3600}),
            _FakeResponse(200),
            _FakeResponse(200),
        ])
        sender = FcmPushSender(
            FcmConfig(project_id="p", service_account_json=rsa_sa_json),
            client=client,
        )
        sender.send_wake("t", request_id="r1")
        sender.send_wake("t", request_id="r2")
        # 3 calls total: ONE exchange + two sends.
        assert len(client.calls) == 3

    def test_failed_exchange_raises(self, rsa_sa_json):
        pytest.importorskip("jwt")
        client = _FakeHttpClient([_FakeResponse(403)])
        sender = FcmPushSender(
            FcmConfig(project_id="p", service_account_json=rsa_sa_json),
            client=client,
        )
        with pytest.raises(PushSendError, match="403"):
            sender.send_wake("t", request_id="r")


# ----------------------------------------------------------------------
# Live-server integration: registration fields, token rotation, and
# queued-request-fires-wake
# ----------------------------------------------------------------------

@pytest.fixture
def push_server(tmp_path: Path):
    state = StateStore(state_dir=tmp_path)
    challenges = ChallengeStore()
    dispatcher_sender = RecordingSender("fcm")
    server = create_server(
        bind_host="127.0.0.1",
        bind_port=0,
        state=state,
        bootloader_id="push-test-bootloader",
        challenges=challenges,
        ssl_context=None,
        capability_agent_tokens={"agent-1": "tok-agent-1"},
        push_dispatcher=PushDispatcher([dispatcher_sender]),
        public_urls=["https://bootloader.example.com",
                     "https://bootloader-failover.example.com"],
    )
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {
            "base_url": f"http://{host}:{port}",
            "state": state,
            "challenges": challenges,
            "sender": dispatcher_sender,
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)


def _register_phone_http(ctx, *, push_token=None, push_platform=None):
    """Full HTTP registration with a real Ed25519 proof."""
    code, _exp = ctx["challenges"].issue_pairing_code()
    status, challenge_body = _http_get_json(
        f"{ctx['base_url']}/v0.4/registration_challenge?code={code}"
    )
    assert status == 200
    challenge = challenge_body["challenge_b64u"]

    key = Ed25519PrivateKey.generate()
    pub_raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    # Canonical convention: sign the literal ASCII bytes of the
    # base64url challenge string.
    signature = key.sign(challenge.encode("ascii"))

    body = {
        "phone_id": "phone-supplied-id-ignored",
        "device_label": "push-integration-phone",
        "public_key_b64u": _b64u(pub_raw),
        "supported_algorithms": ["ed25519"],
        "v0_4_protocol": 1,
        "registration_proof": {
            "challenge": challenge,
            "signature_b64u": _b64u(signature),
        },
    }
    if push_token is not None:
        body["push_token"] = push_token
    if push_platform is not None:
        body["push_platform"] = push_platform
    return _http_post_json(f"{ctx['base_url']}/v0.4/register", body)


class TestRegistrationPushFields:
    def test_register_captures_push_token_and_emits_urls(self, push_server):
        status, body = _register_phone_http(
            push_server, push_token="fcm-tok-1", push_platform="fcm"
        )
        assert status == 201
        assert body["registered"] is True
        # Multi-URL failover field, primary first.
        assert body["bootloader_urls"] == [
            "https://bootloader.example.com",
            "https://bootloader-failover.example.com",
        ]
        phone = push_server["state"].get_phone(body["phone_id"])
        assert phone.push_token == "fcm-tok-1"
        assert phone.push_platform == "fcm"

    def test_register_without_push_token_is_poll_only(self, push_server):
        status, body = _register_phone_http(push_server)
        assert status == 201
        phone = push_server["state"].get_phone(body["phone_id"])
        assert phone.push_token is None
        assert phone.push_platform is None

    def test_register_rejects_unknown_platform(self, push_server):
        status, body = _register_phone_http(
            push_server, push_token="t", push_platform="carrier-pigeon"
        )
        assert status == 400
        assert "push_platform" in body["detail"]


class TestPushTokenUpdateEndpoint:
    def test_rotation_updates_registration(self, push_server):
        _, reg = _register_phone_http(
            push_server, push_token="old-tok", push_platform="fcm"
        )
        phone_id = reg["phone_id"]
        status, body = _http_post_json(
            f"{push_server['base_url']}/v0.4/manage/push_token",
            {"phone_id": phone_id, "push_token": "new-tok",
             "push_platform": "fcm"},
        )
        assert status == 200
        assert body == {"updated": True, "phone_id": phone_id}
        phone = push_server["state"].get_phone(phone_id)
        assert phone.push_token == "new-tok"
        # Everything else survives the rotation.
        assert phone.device_label == "push-integration-phone"

    def test_unknown_phone_rejected(self, push_server):
        status, body = _http_post_json(
            f"{push_server['base_url']}/v0.4/manage/push_token",
            {"phone_id": "nope", "push_token": "t", "push_platform": "apns"},
        )
        assert status == 400

    def test_missing_fields_rejected(self, push_server):
        _, reg = _register_phone_http(push_server)
        status, _ = _http_post_json(
            f"{push_server['base_url']}/v0.4/manage/push_token",
            {"phone_id": reg["phone_id"], "push_token": ""},
        )
        assert status == 400


class TestQueuedRequestFiresWake:
    def test_capability_request_wakes_target_phone(self, push_server):
        from recto.capability.types import (
            CapabilityClaims,
            CapabilityClause,
            CapabilityLimits,
            CapabilityScope,
        )

        _, reg = _register_phone_http(
            push_server, push_token="wake-me", push_platform="fcm"
        )
        now = int(time.time())
        claims = CapabilityClaims(
            iss="phone:operator:enclave",
            sub="agent:test",
            aud=["consumer-app"],
            iat=now,
            nbf=now,
            exp=now + 3600,
            jti=f"cap_push_test_{now}",
            cap=CapabilityClause(
                tier=0,
                registry_version="2026-05-05",
                groups=[],
                scope=CapabilityScope(env=[], services=[], repos=[]),
                allow_actions=["doc:edit"],
                deny_actions=[],
                limits=CapabilityLimits(per_hour={}, per_day={},
                                        per_session={}),
            ),
            purpose="push wake integration test",
        )
        status, body = _http_post_json(
            f"{push_server['base_url']}/v0.4/capability/request",
            {"phone_id": reg["phone_id"], "claims": asdict(claims)},
            headers={
                "X-Recto-Agent-Id": "agent-1",
                "X-Recto-Agent-Token": "tok-agent-1",
            },
        )
        assert status == 201
        sender = push_server["sender"]
        assert sender.fired.wait(timeout=5.0), "wake push never fired"
        token, request_id = sender.sends[0]
        assert token == "wake-me"
        assert request_id == body["request_id"]
