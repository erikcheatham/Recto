"""Tests for the grant-window re-stamp (queued-card flow, v0.6+).

A capability request that declares ``grant_ttl_seconds`` gets its
claims' iat/nbf/exp REBUILT at card-open — the first phone fetch of
``GET /v0.4/pending`` — so a short authority window and a long queue
wait can coexist. Two clocks, two meanings: ``ttl_seconds`` bounds how
long the CARD waits on the queue; ``grant_ttl_seconds`` bounds how long
the signed AUTHORITY lives.

The properties under test, each its own case:

1. A declared grant TTL re-stamps at first fetch: exp - nbf equals the
   declared TTL and the window is anchored at fetch time, not queue time.
2. The stamp happens EXACTLY ONCE — a second fetch returns byte-identical
   segments (the phone signs what it fetched; mutating bytes on a later
   poll would orphan the returned signature).
3. The Ed25519 envelope hash follows the rebuilt bytes — payload_hash_b64u
   is SHA-256 over the RE-STAMPED signing input.
4. No grant TTL declared = untouched bytes (the shipped posture).
5. Out-of-range grant_ttl_seconds refuses at the queue endpoint.
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
from typing import Any
from urllib import request as urlrequest
from urllib.error import HTTPError

import pytest

from recto.bootloader.server import ChallengeStore, create_server
from recto.bootloader.state import PhoneRegistration, StateStore
from recto.capability.jwt import build_signing_input
from recto.capability.types import (
    CapabilityClaims,
    CapabilityClause,
    CapabilityLimits,
    CapabilityScope,
)

AGENT_ID = "task-bridge"
AGENT_TOKEN = "grant-window-test-token-fixture-only"


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _claims(*, exp_offset_seconds: int = 1800) -> CapabilityClaims:
    now = int(time.time())
    return CapabilityClaims(
        iss="phone:operator:enclave",
        sub="agent:task-bridge",
        aud=["repo:example/example"],
        iat=now,
        nbf=now,
        exp=now + exp_offset_seconds,
        jti=f"grantwin_test_{now}",
        cap=CapabilityClause(
            tier=1,
            registry_version="2026-05-05",
            groups=[],
            scope=CapabilityScope(
                env=[], services=[], repos=["example/example"],
                # The push-approval scope extension: the fingerprint of the
                # exact payload being approved. Asserted below to SURVIVE the
                # re-stamp — the restamp round-trips the payload through
                # _dict_to_claims, which silently DROPS unknown scope keys,
                # so an unregistered extension would vanish between the queue
                # and the signature (measured live 2026-08-25).
                payload_sha256="a" * 64,
            ),
            allow_actions=["restart-service"],
            deny_actions=[],
            limits=CapabilityLimits(per_hour={}, per_day={}, per_session={}),
        ),
        purpose="grant-window re-stamp test",
    )


@pytest.fixture()
def live_server(tmp_path):
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()
    pub_b64u = base64.urlsafe_b64encode(
        priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).rstrip(b"=").decode("ascii")

    state = StateStore(state_dir=tmp_path)
    phone = PhoneRegistration.new(
        device_label="Grant Window Test Phone",
        public_key_b64u=pub_b64u,
        supported_algorithms=("ed25519",),
    )
    state.register_phone(phone)

    server = create_server(
        bind_host="127.0.0.1",
        bind_port=0,
        state=state,
        bootloader_id="grant-window-test",
        challenges=ChallengeStore(),
        ssl_context=None,
        capability_agent_tokens={AGENT_ID: AGENT_TOKEN},
    )
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {
            "base_url": f"http://{host}:{port}",
            "state": state,
            "phone_id": phone.phone_id,
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)


def _post(base_url: str, path: str, body: dict[str, Any]) -> tuple[int, dict]:
    req = urlrequest.Request(
        base_url + path,
        data=json.dumps(body).encode(),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Recto-Agent-Id": AGENT_ID,
            "X-Recto-Agent-Token": AGENT_TOKEN,
        },
    )
    try:
        with urlrequest.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read() or b"{}")
    except HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def _fetch_pending(base_url: str, phone_id: str) -> list[dict]:
    with urlrequest.urlopen(
        f"{base_url}/v0.4/pending?phone_id={phone_id}", timeout=10
    ) as r:
        return json.loads(r.read())["requests"]


def _queue(base_url: str, phone_id: str, *, grant_ttl: int | None) -> dict:
    _digest, header_b64, payload_b64 = build_signing_input(_claims())
    body: dict[str, Any] = {
        "phone_id": phone_id,
        "claims": json.loads(_b64u_decode(payload_b64)),
        "operation_description": "grant-window test card",
        "ttl_seconds": 1800,
    }
    if grant_ttl is not None:
        body["grant_ttl_seconds"] = grant_ttl
    code, resp = _post(base_url, "/v0.4/capability/request", body)
    assert code == 201, resp
    return resp


class TestGrantWindowRestamp:
    def test_first_fetch_restamps_window_to_declared_ttl(self, live_server):
        ctx = live_server
        _queue(ctx["base_url"], ctx["phone_id"], grant_ttl=120)
        before_fetch = int(time.time())
        [card] = _fetch_pending(ctx["base_url"], ctx["phone_id"])

        payload = json.loads(_b64u_decode(card["context"]["cap_payload_b64"]))
        assert payload["exp"] - payload["nbf"] == 120
        assert payload["iat"] == payload["nbf"]
        # Anchored at fetch time (small tolerance for the wire round-trip).
        assert abs(payload["nbf"] - before_fetch) <= 5

    def test_scope_extension_survives_the_restamp(self, live_server):
        ctx = live_server
        _queue(ctx["base_url"], ctx["phone_id"], grant_ttl=120)
        [card] = _fetch_pending(ctx["base_url"], ctx["phone_id"])
        payload = json.loads(_b64u_decode(card["context"]["cap_payload_b64"]))
        # The window moved (re-stamped) but the payload pin did not vanish:
        # the restamp's round-trip through the typed claims must carry every
        # registered scope extension. A drop here would strip the one claim
        # that binds the approval to the change the operator saw.
        assert payload["cap"]["scope"]["payload_sha256"] == "a" * 64

    def test_restamp_happens_exactly_once(self, live_server):
        ctx = live_server
        _queue(ctx["base_url"], ctx["phone_id"], grant_ttl=120)
        [first] = _fetch_pending(ctx["base_url"], ctx["phone_id"])
        time.sleep(1.1)  # a second poll in a later second must not move the window
        [second] = _fetch_pending(ctx["base_url"], ctx["phone_id"])

        assert first["context"]["cap_payload_b64"] == second["context"]["cap_payload_b64"]
        assert first["context"]["cap_header_b64"] == second["context"]["cap_header_b64"]
        assert first["context"]["payload_hash_b64u"] == second["context"]["payload_hash_b64u"]

    def test_envelope_hash_follows_the_restamped_bytes(self, live_server):
        ctx = live_server
        _queue(ctx["base_url"], ctx["phone_id"], grant_ttl=120)
        [card] = _fetch_pending(ctx["base_url"], ctx["phone_id"])

        ctx_w = card["context"]
        signing_input = f"{ctx_w['cap_header_b64']}.{ctx_w['cap_payload_b64']}".encode("ascii")
        expected = base64.urlsafe_b64encode(
            hashlib.sha256(signing_input).digest()
        ).rstrip(b"=").decode("ascii")
        assert card["context"]["payload_hash_b64u"] == expected

    def test_no_grant_ttl_means_untouched_bytes(self, live_server):
        ctx = live_server
        _digest, _header, queued_payload_b64 = build_signing_input(_claims())
        _queue(ctx["base_url"], ctx["phone_id"], grant_ttl=None)
        [card] = _fetch_pending(ctx["base_url"], ctx["phone_id"])
        # The queue endpoint re-encodes through the same canonical encoder,
        # so the window fields are the ones the agent authored — no re-stamp.
        payload = json.loads(_b64u_decode(card["context"]["cap_payload_b64"]))
        queued = json.loads(_b64u_decode(queued_payload_b64))
        assert payload["exp"] - payload["nbf"] == queued["exp"] - queued["nbf"]

    @pytest.mark.parametrize("bad_ttl", [0, 29, 901, "120"])
    def test_out_of_range_grant_ttl_refuses(self, live_server, bad_ttl):
        ctx = live_server
        _digest, _header, payload_b64 = build_signing_input(_claims())
        code, resp = _post(ctx["base_url"], "/v0.4/capability/request", {
            "phone_id": ctx["phone_id"],
            "claims": json.loads(_b64u_decode(payload_b64)),
            "operation_description": "bad grant ttl",
            "grant_ttl_seconds": bad_ttl,
        })
        assert code == 400, (code, resp)
