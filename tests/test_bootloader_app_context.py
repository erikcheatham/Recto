"""Tests for Phase 5 Wave C part 3: AppContext on phone-rendered
PendingRequests.

Three layers:

1. ``AppContext`` dataclass: construction validation, frozen
   semantics, optional-field defaults.

2. ``BootloaderConfig.principal_apps`` registry: lookup by
   cap_agent_id (capability_request flow) and service-name fallback,
   gracefully None when no registration exists.

3. ``_pending_to_wire`` emits a nested ``app_context`` object under
   ``context`` when set, omits when None. Nested optional fields
   (app_url / app_icon_url / app_version) are also emit-only-when-
   set so the wire shape stays compact.

4. End-to-end through the live HTTP ``BootloaderHandler``: an
   external agent POSTs a capability_request; bootloader injects
   the registered AppContext at queue time; the phone's
   ``GET /v0.4/pending`` view shows the AppContext fields under
   context.app_context.

The bootloader's HTTP API only exposes capability_request for
queueing today; other phone-rendered request kinds are created by
the launcher's in-process flow. This module covers the full
HTTP-queueable surface; the launcher-driven kinds will gain
AppContext support when the launcher integration lands (Wave C
part 4+).
"""

from __future__ import annotations

import base64
import json
import threading
import time
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any
from urllib import request as urlrequest
from urllib.error import HTTPError

import pytest

from recto.bootloader.server import (
    BootloaderHandler,
    ChallengeStore,
    create_server,
)
from recto.bootloader.state import (
    AppContext,
    PendingRequest,
    PhoneRegistration,
    StateStore,
)
from recto.capability.types import (
    CapabilityClaims,
    CapabilityClause,
    CapabilityLimits,
    CapabilityScope,
)


def _b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------------------
# AppContext dataclass: construction + validation
# ---------------------------------------------------------------------------


class TestAppContextConstruction:
    def test_minimal_happy_path(self) -> None:
        ac = AppContext(app_id="myservice", app_name="MyService")
        assert ac.app_id == "myservice"
        assert ac.app_name == "MyService"
        assert ac.app_description == ""
        assert ac.app_url is None
        assert ac.app_icon_url is None
        assert ac.app_version is None

    def test_full_happy_path(self) -> None:
        ac = AppContext(
            app_id="myservice",
            app_name="MyService",
            app_description="Media review platform",
            app_url="https://example.com",
            app_icon_url="https://example.com/icon.png",
            app_version="1.4.2",
        )
        assert ac.app_url == "https://example.com"
        assert ac.app_icon_url == "https://example.com/icon.png"
        assert ac.app_version == "1.4.2"

    def test_empty_app_id_rejected(self) -> None:
        with pytest.raises(ValueError, match="app_id"):
            AppContext(app_id="", app_name="x")

    def test_empty_app_name_rejected(self) -> None:
        with pytest.raises(ValueError, match="app_name"):
            AppContext(app_id="x", app_name="")

    def test_frozen_immutable(self) -> None:
        ac = AppContext(app_id="x", app_name="y")
        with pytest.raises(AttributeError):
            ac.app_name = "modified"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# PendingRequest field
# ---------------------------------------------------------------------------


class TestPendingRequestAppContextField:
    def test_default_is_none(self) -> None:
        req = PendingRequest.new(
            kind="single_sign", service="svc", secret="s",
            phone_id="p", operation_description="x",
            payload_hash_b64u="aA", child_pid=1, child_argv0="x",
        )
        assert req.app_context is None

    def test_replace_sets_field(self) -> None:
        req = PendingRequest.new(
            kind="single_sign", service="svc", secret="s",
            phone_id="p", operation_description="x",
            payload_hash_b64u="aA", child_pid=1, child_argv0="x",
        )
        ac = AppContext(app_id="t", app_name="Test App")
        enriched = replace(req, app_context=ac)
        assert enriched.app_context is ac
        # Original unchanged (frozen dataclass).
        assert req.app_context is None


# ---------------------------------------------------------------------------
# _pending_to_wire emit
# ---------------------------------------------------------------------------


class TestPendingToWireAppContext:
    def _build_req(self, app_context: AppContext | None) -> PendingRequest:
        req = PendingRequest.new(
            kind="single_sign", service="svc", secret="s",
            phone_id="p", operation_description="x",
            payload_hash_b64u="aA", child_pid=1, child_argv0="x",
        )
        if app_context is not None:
            req = replace(req, app_context=app_context)
        return req

    def test_omits_app_context_when_none(self) -> None:
        wire = BootloaderHandler._pending_to_wire(
            self._build_req(app_context=None)
        )
        assert "app_context" not in wire["context"]

    def test_emits_minimal_app_context(self) -> None:
        ac = AppContext(app_id="x", app_name="Test")
        wire = BootloaderHandler._pending_to_wire(
            self._build_req(app_context=ac)
        )
        ac_obj = wire["context"]["app_context"]
        assert ac_obj["app_id"] == "x"
        assert ac_obj["app_name"] == "Test"
        assert ac_obj["app_description"] == ""
        # Optional fields omit when None.
        assert "app_url" not in ac_obj
        assert "app_icon_url" not in ac_obj
        assert "app_version" not in ac_obj

    def test_emits_full_app_context(self) -> None:
        ac = AppContext(
            app_id="myservice", app_name="MyService",
            app_description="Media reviews",
            app_url="https://example.com",
            app_icon_url="https://example.com/icon.png",
            app_version="1.4.2",
        )
        wire = BootloaderHandler._pending_to_wire(
            self._build_req(app_context=ac)
        )
        ac_obj = wire["context"]["app_context"]
        assert ac_obj == {
            "app_id": "myservice",
            "app_name": "MyService",
            "app_description": "Media reviews",
            "app_url": "https://example.com",
            "app_icon_url": "https://example.com/icon.png",
            "app_version": "1.4.2",
        }

    def test_emits_alongside_capability_fields(self) -> None:
        """app_context coexists with cap_*_b64 fields on
        capability_request."""
        from recto.capability.jwt import build_signing_input
        claims = _starter_claims()
        digest, header_b64, payload_b64 = build_signing_input(claims)
        req = PendingRequest.new_capability_request(
            service="recto", secret="capability", phone_id="p",
            operation_description="x",
            payload_hash_b64u=_b64u_encode(digest),
            child_pid=0, child_argv0="(external-agent)",
            cap_header_b64=header_b64, cap_payload_b64=payload_b64,
            cap_agent_id="darwin",
        )
        ac = AppContext(app_id="myservice", app_name="MyService")
        req = replace(req, app_context=ac)
        wire = BootloaderHandler._pending_to_wire(req)
        ctx = wire["context"]
        # Both sets of fields present.
        assert ctx["cap_header_b64"] == header_b64
        assert ctx["cap_agent_id"] == "darwin"
        assert ctx["app_context"]["app_id"] == "myservice"


# ---------------------------------------------------------------------------
# Test fixtures + helpers (mirrored from prior Wave C parts)
# ---------------------------------------------------------------------------


def _starter_claims(*, jti: str | None = None) -> CapabilityClaims:
    now = int(time.time())
    return CapabilityClaims(
        iss="phone:operator:enclave",
        sub="agent:darwin@staging",
        aud=["consumer-app"],
        iat=now, nbf=now, exp=now + 86400,
        jti=jti or f"cap_test_{now}",
        cap=CapabilityClause(
            tier=1,
            registry_version="2026-05-05",
            groups=["darwin:secret-reads"],
            scope=CapabilityScope(env=[], services=[], repos=[]),
            allow_actions=[], deny_actions=[],
            limits=CapabilityLimits(
                per_hour={}, per_day={}, per_session={},
            ),
        ),
        purpose="App context test",
    )


@pytest.fixture(scope="session")
def operator_keypair():
    pytest.importorskip("cryptography")
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import ec
    priv = ec.generate_private_key(ec.SECP256K1(), default_backend())
    pub_nums = priv.public_key().public_numbers()
    pub_bytes = pub_nums.x.to_bytes(32, "big") + pub_nums.y.to_bytes(32, "big")
    return (priv.private_numbers().private_value, pub_bytes)


# ---------------------------------------------------------------------------
# End-to-end: live HTTP server, capability_request injects AppContext
# ---------------------------------------------------------------------------


def _http_get(url: str, headers: dict[str, str] | None = None):
    req = urlrequest.Request(url, headers=headers or {}, method="GET")
    try:
        with urlrequest.urlopen(req, timeout=5.0) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


def _http_post_json(url, body, headers=None):
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


@pytest.fixture
def gate_server(tmp_path: Path, operator_keypair):
    """Live bootloader with principal_apps configured for two
    consumer agents."""
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv_int, pub_bytes = operator_keypair
    state = StateStore(state_dir=tmp_path)

    # Pre-register a phone for capability_request queueing.
    ed_priv = Ed25519PrivateKey.generate()
    ed_pub_bytes = ed_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    phone = PhoneRegistration.new(
        device_label="Test Phone",
        public_key_b64u=_b64u_encode(ed_pub_bytes),
        supported_algorithms=("ed25519",),
    )
    state.register_phone(phone)

    server = create_server(
        bind_host="127.0.0.1", bind_port=0, state=state,
        bootloader_id="t", challenges=ChallengeStore(),
        ssl_context=None,
        capability_operator_pubkey=pub_bytes,
        capability_agent_tokens={
            "darwin": "agent-token-fixture",
            "mytradingapp-bot": "mytradingapp-token-fixture",
        },
        principal_apps={
            "darwin": AppContext(
                app_id="myservice",
                app_name="MyService",
                app_description="Media review platform",
                app_url="https://example.com",
                app_icon_url="https://example.com/icon.png",
                app_version="1.4.2",
            ),
            # Note: mytradingapp-bot does NOT have a registration in this
            # fixture, to test the "no AppContext" path.
        },
    )
    host, port = server.server_address
    base_url = f"http://{host}:{port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {
            "base_url": base_url,
            "phone_id": phone.phone_id,
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)


def _claims_dict() -> dict[str, Any]:
    from dataclasses import asdict
    return asdict(_starter_claims())


class TestCapabilityRequestInjectsAppContext:
    def test_registered_agent_gets_app_context(self, gate_server):
        ctx = gate_server
        # Queue a capability_request from agent_id="darwin" (which is
        # registered in principal_apps).
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/capability/request",
            {
                "phone_id": ctx["phone_id"],
                "claims": _claims_dict(),
                "operation_description": "test",
            },
            headers={
                "X-Recto-Agent-Id": "darwin",
                "X-Recto-Agent-Token": "agent-token-fixture",
            },
        )
        assert status == 201, body
        request_id = body["request_id"]
        # Fetch via /v0.4/pending and verify app_context landed.
        status, pending = _http_get(
            f"{ctx['base_url']}/v0.4/pending?phone_id={ctx['phone_id']}"
        )
        assert status == 200
        assert len(pending["requests"]) == 1
        wire = pending["requests"][0]
        assert wire["request_id"] == request_id
        ac = wire["context"]["app_context"]
        assert ac["app_id"] == "myservice"
        assert ac["app_name"] == "MyService"
        assert ac["app_description"] == "Media review platform"
        assert ac["app_url"] == "https://example.com"
        assert ac["app_icon_url"] == "https://example.com/icon.png"
        assert ac["app_version"] == "1.4.2"

    def test_unregistered_agent_omits_app_context(self, gate_server):
        """mytradingapp-bot is in capability_agent_tokens (so the request
        authenticates) but has no principal_apps entry. The wire
        shape should omit app_context entirely, letting the phone
        render an "Unknown app" warning banner."""
        ctx = gate_server
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/capability/request",
            {
                "phone_id": ctx["phone_id"],
                "claims": _claims_dict(),
                "operation_description": "test",
            },
            headers={
                "X-Recto-Agent-Id": "mytradingapp-bot",
                "X-Recto-Agent-Token": "mytradingapp-token-fixture",
            },
        )
        assert status == 201, body
        # Fetch and verify app_context is absent.
        status, pending = _http_get(
            f"{ctx['base_url']}/v0.4/pending?phone_id={ctx['phone_id']}"
        )
        assert status == 200
        wire = pending["requests"][0]
        assert "app_context" not in wire["context"]

    def test_no_principal_apps_configured_omits_app_context(
        self, tmp_path, operator_keypair
    ):
        """Bootloader without ANY principal_apps registry -> wire
        shape always omits app_context."""
        pytest.importorskip("cryptography")
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        _, pub_bytes = operator_keypair
        state = StateStore(state_dir=tmp_path)
        ed_priv = Ed25519PrivateKey.generate()
        ed_pub_bytes = ed_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        phone = PhoneRegistration.new(
            device_label="x", public_key_b64u=_b64u_encode(ed_pub_bytes),
            supported_algorithms=("ed25519",),
        )
        state.register_phone(phone)
        server = create_server(
            bind_host="127.0.0.1", bind_port=0, state=state,
            bootloader_id="t", challenges=ChallengeStore(),
            ssl_context=None,
            capability_operator_pubkey=pub_bytes,
            capability_agent_tokens={"agent": "tok"},
            # principal_apps left at default empty dict
        )
        host, port = server.server_address
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            status, _ = _http_post_json(
                f"http://{host}:{port}/v0.4/capability/request",
                {
                    "phone_id": phone.phone_id,
                    "claims": _claims_dict(),
                },
                headers={
                    "X-Recto-Agent-Id": "agent",
                    "X-Recto-Agent-Token": "tok",
                },
            )
            assert status == 201
            status, pending = _http_get(
                f"http://{host}:{port}/v0.4/pending?phone_id={phone.phone_id}"
            )
            assert status == 200
            assert "app_context" not in pending["requests"][0]["context"]
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5.0)
