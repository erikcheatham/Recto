"""A DEAD CARD IS WITHDRAWN, NOT SERVED (2026-09-21).

A capability card has two clocks: `ttl_seconds` bounds how long it may WAIT on the queue
(default 3600) and the signed claims' `exp` bounds how long its AUTHORITY lives (ten minutes
from the bridge). When `exp` has passed the card can be neither approved nor denied, yet
the queue kept serving it for the rest of its ttl and the phone showed "window closed,
nothing to tap here" for up to fifty minutes -- measured in staging, 2026-09-21.

RED-BUILD: drop the withdrawal from _handle_pending and `test_an_expired_card_is_withdrawn`
serves the corpse. POSITIVE CONTROL: a live card is still served, and a non-capability kind
(no claims to judge) is never touched.
"""

from __future__ import annotations

import base64
import json
import threading
import time
from pathlib import Path
from typing import Any
from urllib import request as urlrequest
from urllib.error import HTTPError

import pytest

from recto.bootloader.server import ChallengeStore, create_server
from recto.bootloader.state import PendingRequest, PhoneRegistration, StateStore


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _get(url: str) -> tuple[int, dict[str, Any]]:
    try:
        with urlrequest.urlopen(url, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8") or "{}")
    except HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8") or "{}")


@pytest.fixture
def ctx(tmp_path: Path):
    state = StateStore(state_dir=tmp_path)
    phone = state.register_phone(PhoneRegistration.new(
        device_label="pixel", public_key_b64u="pixel-pub", supported_algorithms=("ed25519",),
    ))
    server = create_server(
        bind_host="127.0.0.1", bind_port=0, state=state, bootloader_id="dead-cards-test",
        challenges=ChallengeStore(state=state), ssl_context=None, signed_poll_mode="off",
    )
    host, port = server.server_address
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield {"base_url": f"http://{host}:{port}", "state": state, "phone_id": phone.phone_id}
    finally:
        server.shutdown()


def _card(phone_id: str, *, exp: int) -> PendingRequest:
    now = int(time.time())
    header = _b64u(json.dumps({"alg": "EdDSA", "typ": "JWT"}).encode())
    payload = _b64u(json.dumps({
        "iss": "bridge", "sub": "agent:test", "aud": ["consumer"], "iat": now - 60, "nbf": now - 60,
        "exp": exp, "jti": "j1", "purpose": "dead card test",
        "cap": {"tier": 0, "registry_version": "0", "scope": {}, "allow_actions": ["x:y"]},
    }).encode())
    return PendingRequest.new_capability_request(
        service="recto", secret="capability", phone_id=phone_id,
        operation_description="a card", payload_hash_b64u="AAAA", child_pid=0,
        child_argv0="(test)", cap_header_b64=header, cap_payload_b64=payload,
        cap_agent_id="agent-1", ttl_seconds=3600,
    )


def _pending(ctx) -> list[dict[str, Any]]:
    status, body = _get(f"{ctx['base_url']}/v0.4/pending?phone_id={ctx['phone_id']}")
    assert status == 200, body
    return body["requests"]


def _dead_card(phone_id: str) -> PendingRequest:
    """Born live (the factory refuses a past exp at creation -- the queue-time gate), then
    dies ON the queue, which is the only way a real card dies."""
    card = _card(phone_id, exp=int(time.time()) + 1)
    time.sleep(1.2)
    return card


def test_an_expired_card_is_withdrawn_on_the_next_poll(ctx):
    """RED-BUILD: without the withdrawal, the corpse is served for the rest of its hour."""
    dead = _dead_card(ctx["phone_id"])
    ctx["state"].add_pending(dead)
    assert ctx["state"].list_pending_for_phone(ctx["phone_id"]), "seeded"

    assert _pending(ctx) == [], "a card whose authority has expired was served"
    assert ctx["state"].list_pending_for_phone(ctx["phone_id"]) == [], "withdrawn from the queue, not just hidden"


def test_a_live_card_is_still_served(ctx):
    live = _card(ctx["phone_id"], exp=int(time.time()) + 600)
    ctx["state"].add_pending(live)
    served = _pending(ctx)
    assert [r["request_id"] for r in served] == [live.request_id]


def test_only_the_dead_one_goes(ctx):
    dead = _dead_card(ctx["phone_id"])
    live = _card(ctx["phone_id"], exp=int(time.time()) + 600)
    ctx["state"].add_pending(dead)
    ctx["state"].add_pending(live)
    assert [r["request_id"] for r in _pending(ctx)] == [live.request_id]


def test_a_non_capability_card_is_never_judged(ctx):
    """No claims, no verdict: a secret.read card lives by its queue ttl alone."""
    plain = PendingRequest.new(
        kind="secret.read", service="svc", secret="key", phone_id=ctx["phone_id"],
        operation_description="plain", payload_hash_b64u="AAAA", child_pid=1, child_argv0="t",
    )
    ctx["state"].add_pending(plain)
    assert [r["request_id"] for r in _pending(ctx)] == [plain.request_id]
