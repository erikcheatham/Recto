"""Actor context on a capability_request card (2026-09-22).

``AppContext`` says which APP delivered a card; it is registered once
per consumer. A platform hosting many agents on one registration could
not say WHICH agent was acting -- the signed subject carries the agent's
id, which nobody recognises at a glance. ``actor`` rides per request in
the body (``actor_id`` · ``actor_name`` · optional ``actor_icon_url``)
and comes out on the wire as ``context.actor_context``.

Transport, never a claim: it is not in the signed bytes. The phone shows
it only beside a signed subject whose acting-agent half equals
``actor_id`` (the C# cross-check has its own tests). These tests pin the
bootloader half: accepted → emitted; absent → omitted; malformed →
refused before the queue, so a half-built actor never reaches a card.
"""

from __future__ import annotations

import base64
import json
import threading
from dataclasses import asdict
from pathlib import Path
from typing import Any
from urllib import request as urlrequest
from urllib.error import HTTPError

import pytest

from recto.bootloader.server import ChallengeStore, create_server
from recto.bootloader.state import (
    ActorContext,
    AppContext,
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


def _starter_claims() -> CapabilityClaims:
    import time as _time
    now = int(_time.time())
    return CapabilityClaims(
        iss="phone:operator:enclave",
        sub="agent:11111111-2222-4333-8444-555555555555@user:66666666-7777-4888-9999-aaaaaaaaaaaa",
        aud=["myservice"],
        iat=now,
        nbf=now,
        exp=now + 300,
        jti="actor-context-test",
        cap=CapabilityClause(
            tier=2,
            registry_version="2026-01-01",
            groups=[],
            scope=CapabilityScope(env=[], services=["myservice"], repos=[]),
            allow_actions=["page:update"],
            deny_actions=[],
            limits=CapabilityLimits(),
        ),
        purpose="Actor context test",
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


def _http_get(url: str):
    req = urlrequest.Request(url, method="GET")
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
        capability_agent_tokens={"myservice-bot": "tok"},
        principal_apps={
            "myservice-bot": AppContext(app_id="myservice", app_name="MyService"),
        },
    )
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {"base_url": f"http://{host}:{port}", "phone_id": phone.phone_id}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)


_HEADERS = {"X-Recto-Agent-Id": "myservice-bot", "X-Recto-Agent-Token": "tok"}


def _post(ctx, extra: dict[str, Any]):
    body = {
        "phone_id": ctx["phone_id"],
        "claims": asdict(_starter_claims()),
        "operation_description": "test",
    }
    body.update(extra)
    return _http_post_json(f"{ctx['base_url']}/v0.4/capability/request", body, headers=_HEADERS)


def _first_wire(ctx):
    status, pending = _http_get(f"{ctx['base_url']}/v0.4/pending?phone_id={ctx['phone_id']}")
    assert status == 200
    assert len(pending["requests"]) == 1
    return pending["requests"][0]


class TestActorContextDataclass:
    def test_requires_id_and_name(self):
        with pytest.raises(ValueError):
            ActorContext(actor_id="", actor_name="Fenwick")
        with pytest.raises(ValueError):
            ActorContext(actor_id="agent:x", actor_name="")

    def test_icon_must_be_http_when_set(self):
        with pytest.raises(ValueError):
            ActorContext(actor_id="agent:x", actor_name="Fenwick", actor_icon_url="javascript:alert(1)")
        with pytest.raises(ValueError):
            ActorContext(actor_id="agent:x", actor_name="Fenwick", actor_icon_url="data:image/png;base64,AAAA")
        ActorContext(actor_id="agent:x", actor_name="Fenwick", actor_icon_url="https://example.com/f.png")
        ActorContext(actor_id="agent:x", actor_name="Fenwick")


class TestCapabilityRequestCarriesActorContext:
    def test_actor_rides_the_wire_beside_app_context(self, gate_server):
        status, body = _post(gate_server, {
            "actor": {
                "actor_id": "agent:11111111-2222-4333-8444-555555555555",
                "actor_name": "Fenwick",
                "actor_icon_url": "https://example.com/agents/fenwick.png",
            },
        })
        assert status == 201, body
        wire = _first_wire(gate_server)
        actor = wire["context"]["actor_context"]
        assert actor == {
            "actor_id": "agent:11111111-2222-4333-8444-555555555555",
            "actor_name": "Fenwick",
            "actor_icon_url": "https://example.com/agents/fenwick.png",
        }
        # the app that delivered it is still the app, unchanged
        assert wire["context"]["app_context"]["app_id"] == "myservice"

    def test_icon_is_omitted_when_absent(self, gate_server):
        status, body = _post(gate_server, {"actor": {"actor_id": "agent:a", "actor_name": "A"}})
        assert status == 201, body
        actor = _first_wire(gate_server)["context"]["actor_context"]
        assert actor == {"actor_id": "agent:a", "actor_name": "A"}

    def test_absent_actor_omits_the_field(self, gate_server):
        status, body = _post(gate_server, {})
        assert status == 201, body
        assert "actor_context" not in _first_wire(gate_server)["context"]

    @pytest.mark.parametrize("actor", [
        "Fenwick",
        {"actor_name": "Fenwick"},
        {"actor_id": "agent:a"},
        {"actor_id": "agent:a", "actor_name": "A", "actor_icon_url": "javascript:alert(1)"},
    ])
    def test_malformed_actor_is_refused_before_the_queue(self, gate_server, actor):
        status, body = _post(gate_server, {"actor": actor})
        assert status == 400, body
        status, pending = _http_get(
            f"{gate_server['base_url']}/v0.4/pending?phone_id={gate_server['phone_id']}"
        )
        assert status == 200
        assert pending["requests"] == []
