"""Tests for the per-agent requestable-action policy on
``POST /v0.4/capability/request`` (``capability_agent_requestable``).

The policy is a PRE-CARDING filter on what an agent may ASK for:

* An agent WITH a policy entry is deny-by-default — a request whose
  resolved action set (groups expanded via the manifest, allow_actions
  added, deny_actions subtracted; the same resolution verifiers use)
  strays outside its list is refused 403 and NOTHING is queued. The
  refusal names the disallowed actions.
* An agent WITHOUT an entry is unrestricted at this layer (legacy
  behavior) — the operator's approval remains the gate.
* Group-bearing claims from a policed agent REQUIRE a loaded manifest;
  with none configured the request is refused unexpanded (fail closed —
  "add a group" must not be the bypass for a policy stated in actions).

Negative-space assertions matter most here: on every refusal the test
asserts the pending queue is EMPTY, because the property being bought
is "a disallowed request never spends the operator's attention", not
merely "the status code is 403".
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any
from urllib import request as urlrequest
from urllib.error import HTTPError

import pytest

from recto.bootloader.server import ChallengeStore, create_server
from recto.bootloader.state import PhoneRegistration, StateStore
from recto.capability.manifest import load_manifest_from_dict

# ---------------------------------------------------------------------------
# Test manifest: three actions, one group bundling the two privileged ones.
# ---------------------------------------------------------------------------

MANIFEST_VERSION = "test-1"

TEST_MANIFEST = load_manifest_from_dict({
    "version": MANIFEST_VERSION,
    "actions": {
        "queue:submit-item": {"count": 1, "description": "submit an item"},
        "queue:approve-item": {"count": 10, "description": "approve an item"},
        "queue:run-item": {"count": 10, "description": "run an item"},
    },
    "groups": {
        "ops:queue-admin": {
            "actions": ["queue:approve-item", "queue:run-item"],
        },
    },
})

POLICED_AGENT = "policed-agent"
POLICED_TOKEN = "policed-agent-token-fixture-only"
FREE_AGENT = "free-agent"
FREE_TOKEN = "free-agent-token-fixture-only"


def _b64u(s: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(s).rstrip(b"=").decode("ascii")


@pytest.fixture
def signing_pair():
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    priv = Ed25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv, _b64u(pub_bytes)


def _spin_server(tmp_path: Path, pub_b64u: str, *, with_manifest: bool):
    state = StateStore(state_dir=tmp_path)
    phone = PhoneRegistration.new(
        device_label="Test Phone",
        public_key_b64u=pub_b64u,
        supported_algorithms=("ed25519",),
    )
    state.register_phone(phone)

    server = create_server(
        bind_host="127.0.0.1",
        bind_port=0,
        state=state,
        bootloader_id="test-bootloader",
        challenges=ChallengeStore(),
        ssl_context=None,
        capability_agent_tokens={
            POLICED_AGENT: POLICED_TOKEN,
            FREE_AGENT: FREE_TOKEN,
        },
        capability_agent_requestable={
            POLICED_AGENT: ["queue:submit-item"],
        },
        capability_manifest=TEST_MANIFEST if with_manifest else None,
    )
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, state, phone.phone_id, f"http://{host}:{port}"


@pytest.fixture(params=[True, False], ids=["manifest", "no-manifest"])
def live(tmp_path: Path, signing_pair, request):
    _, pub_b64u = signing_pair
    server, thread, state, phone_id, base_url = _spin_server(
        tmp_path, pub_b64u, with_manifest=request.param,
    )
    try:
        yield {
            "state": state,
            "phone_id": phone_id,
            "base_url": base_url,
            "has_manifest": request.param,
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)


def _post(url: str, body: dict[str, Any], headers: dict[str, str]):
    data = json.dumps(body).encode("utf-8")
    h = {"Content-Type": "application/json"}
    h.update(headers)
    req = urlrequest.Request(url, data=data, headers=h, method="POST")
    try:
        with urlrequest.urlopen(req, timeout=5.0) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


def _claims(
    *,
    groups: list[str] | None = None,
    allow_actions: list[str] | None = None,
    deny_actions: list[str] | None = None,
) -> dict[str, Any]:
    now = int(time.time())
    return {
        "iss": "phone:operator:enclave",
        "sub": "agent:test@staging",
        "aud": ["consumer-app"],
        "iat": now,
        "nbf": now,
        "exp": now + 3600,
        "jti": f"cap_requestable_test_{now}",
        "cap": {
            "tier": 1,
            "registry_version": MANIFEST_VERSION,
            "groups": groups or [],
            "scope": {"env": ["staging"], "services": [], "repos": []},
            "allow_actions": allow_actions or [],
            "deny_actions": deny_actions or [],
            "limits": {"per_hour": {}, "per_day": {}, "per_session": {}},
        },
        "purpose": "requestable-policy test",
    }


def _request(ctx, agent_id: str, token: str, claims: dict[str, Any]):
    return _post(
        f"{ctx['base_url']}/v0.4/capability/request",
        {
            "phone_id": ctx["phone_id"],
            "claims": claims,
            "operation_description": "requestable-policy test",
        },
        headers={
            "X-Recto-Agent-Id": agent_id,
            "X-Recto-Agent-Token": token,
        },
    )


def _pending_count(ctx) -> int:
    return len(ctx["state"].list_pending_for_phone(ctx["phone_id"]))


class TestRequestablePolicy:
    def test_allowed_action_queues(self, live) -> None:
        status, body = _request(
            live, POLICED_AGENT, POLICED_TOKEN,
            _claims(allow_actions=["queue:submit-item"]),
        )
        assert status == 201, body
        assert "request_id" in body
        assert _pending_count(live) == 1

    def test_disallowed_action_refused_and_never_queued(self, live) -> None:
        status, body = _request(
            live, POLICED_AGENT, POLICED_TOKEN,
            _claims(allow_actions=["queue:approve-item"]),
        )
        assert status == 403, body
        assert body["error"] == "action_not_requestable"
        assert body["disallowed_actions"] == ["queue:approve-item"]
        assert body["requestable_actions"] == ["queue:submit-item"]
        # The property the policy buys: no card ever reached the queue.
        assert _pending_count(live) == 0

    def test_mixed_request_refused_whole(self, live) -> None:
        """One disallowed action poisons the request — no partial carding."""
        status, body = _request(
            live, POLICED_AGENT, POLICED_TOKEN,
            _claims(allow_actions=["queue:submit-item", "queue:run-item"]),
        )
        assert status == 403, body
        assert body["disallowed_actions"] == ["queue:run-item"]
        assert _pending_count(live) == 0

    def test_group_carried_actions_are_seen(self, live) -> None:
        """A policy stated in actions must not be bypassed by naming a
        group that bundles them. With a manifest the group expands and
        refuses on its members; without one it refuses unexpanded."""
        status, body = _request(
            live, POLICED_AGENT, POLICED_TOKEN,
            _claims(groups=["ops:queue-admin"]),
        )
        assert status == 403, body
        if live["has_manifest"]:
            assert body["error"] == "action_not_requestable"
            assert body["disallowed_actions"] == [
                "queue:approve-item", "queue:run-item",
            ]
        else:
            assert body["error"] == "action_policy_unevaluable"
        assert _pending_count(live) == 0

    def test_deny_actions_subtract_before_policy(self, live) -> None:
        """Resolution matches the verifier's: a denied action is not part
        of what is being asked for, so it does not trip the policy."""
        status, body = _request(
            live, POLICED_AGENT, POLICED_TOKEN,
            _claims(
                allow_actions=["queue:submit-item", "queue:approve-item"],
                deny_actions=["queue:approve-item"],
            ),
        )
        assert status == 201, body
        assert _pending_count(live) == 1

    def test_unpoliced_agent_unrestricted(self, live) -> None:
        """An agent without a policy entry passes through unchanged —
        the operator's approval remains its only gate."""
        status, body = _request(
            live, FREE_AGENT, FREE_TOKEN,
            _claims(allow_actions=["queue:approve-item"]),
        )
        assert status == 201, body
        assert _pending_count(live) == 1
