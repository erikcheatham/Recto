"""Tests for POST /v0.4/pairing/code (operator-trusted fresh-code mint).

Removes the friction of restart-to-mint-pairing-code that bit during
the staging-bootloader bring-up + multi-phone pair sequences (the
foreground bootloader minted exactly ONE code at startup with a 1-hr
TTL; after expiry we had to Ctrl-C + relaunch to mint a new one).

Auth posture matches /v0.4/capability/request: ``X-Recto-Agent-Id``
+ ``X-Recto-Agent-Token`` headers, gated on
``cfg.capability_agent_tokens`` being non-empty (404 when disabled).
"""

from __future__ import annotations

import json
import threading
import time
from http import HTTPStatus
from pathlib import Path
from urllib import request as urlrequest
from urllib.error import HTTPError

import pytest

from recto.bootloader.server import ChallengeStore, create_server
from recto.bootloader.state import StateStore


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
        body_bytes = e.read()
        try:
            return e.code, json.loads(body_bytes.decode("utf-8"))
        except json.JSONDecodeError:
            return e.code, {"_raw_body": body_bytes.decode("utf-8", errors="replace")}


def _auth_headers(token: str = "agent-token-fixture") -> dict[str, str]:
    return {
        "X-Recto-Agent-Id": "darwin",
        "X-Recto-Agent-Token": token,
    }


@pytest.fixture
def server_with_agent(tmp_path: Path):
    """Live bootloader on a random port with one trusted agent."""
    state = StateStore(state_dir=tmp_path)
    challenges = ChallengeStore()
    server = create_server(
        bind_host="127.0.0.1",
        bind_port=0,
        state=state,
        bootloader_id="test-pairing-code",
        challenges=challenges,
        ssl_context=None,
        capability_agent_tokens={"darwin": "agent-token-fixture"},
    )
    host, port = server.server_address
    base_url = f"http://{host}:{port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {
            "base_url": base_url,
            "challenges": challenges,
            "agent_token": "agent-token-fixture",
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)


class TestMintPairingCode:
    def test_happy_path_default_ttl(self, server_with_agent):
        """Empty body uses the 300s default TTL."""
        ctx = server_with_agent
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/pairing/code",
            {},
            headers=_auth_headers(),
        )
        assert status == HTTPStatus.OK
        # 6-digit numeric code
        assert isinstance(body["code"], str)
        assert len(body["code"]) == 6
        assert body["code"].isdigit()
        # TTL echoed
        assert body["ttl_seconds"] == 300
        # expires_at_unix is now + ~300s with a few seconds of test jitter
        now = int(time.time())
        assert now + 290 <= body["expires_at_unix"] <= now + 310

    def test_custom_ttl(self, server_with_agent):
        """ttl_seconds in body overrides the default."""
        ctx = server_with_agent
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/pairing/code",
            {"ttl_seconds": 600},
            headers=_auth_headers(),
        )
        assert status == HTTPStatus.OK
        assert body["ttl_seconds"] == 600
        now = int(time.time())
        assert now + 590 <= body["expires_at_unix"] <= now + 610

    def test_minted_code_is_consumable(self, server_with_agent):
        """The minted code unlocks ChallengeStore.consume_pairing_code,
        confirming the mint is wired into the same in-memory store the
        registration_challenge endpoint reads from."""
        ctx = server_with_agent
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/pairing/code",
            {},
            headers=_auth_headers(),
        )
        assert status == HTTPStatus.OK
        code = body["code"]
        # Single-use semantics: first consume succeeds
        assert ctx["challenges"].consume_pairing_code(code) is True
        # Second consume fails (matches the existing pairing-code-is-
        # one-shot convention; a phone that re-tries a successful code
        # gets a fresh challenge from the registration_challenge endpoint).
        assert ctx["challenges"].consume_pairing_code(code) is False

    def test_two_calls_mint_distinct_codes(self, server_with_agent):
        """Two calls in quick succession mint different codes (the
        randbelow(1_000_000) generator should not collide in practice)."""
        ctx = server_with_agent
        codes = set()
        for _ in range(3):
            status, body = _http_post_json(
                f"{ctx['base_url']}/v0.4/pairing/code",
                {},
                headers=_auth_headers(),
            )
            assert status == HTTPStatus.OK
            codes.add(body["code"])
        # Three calls -> three distinct codes (collision possible in
        # principle but vanishingly rare for a 6-digit space)
        assert len(codes) == 3

    def test_ttl_too_low(self, server_with_agent):
        """ttl_seconds < 60 rejected as 400."""
        ctx = server_with_agent
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/pairing/code",
            {"ttl_seconds": 30},
            headers=_auth_headers(),
        )
        assert status == HTTPStatus.BAD_REQUEST
        assert body["error"] == "bootloader_error"
        assert "ttl_seconds" in body["detail"]

    def test_ttl_too_high(self, server_with_agent):
        """ttl_seconds > 3600 rejected as 400 (1-hour ceiling so a
        misbehaving caller can't park codes on disk indefinitely)."""
        ctx = server_with_agent
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/pairing/code",
            {"ttl_seconds": 7200},
            headers=_auth_headers(),
        )
        assert status == HTTPStatus.BAD_REQUEST
        assert body["error"] == "bootloader_error"
        assert "ttl_seconds" in body["detail"]

    def test_ttl_wrong_type(self, server_with_agent):
        """ttl_seconds as a string (or any non-int) rejected as 400."""
        ctx = server_with_agent
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/pairing/code",
            {"ttl_seconds": "300"},
            headers=_auth_headers(),
        )
        assert status == HTTPStatus.BAD_REQUEST
        assert body["error"] == "bootloader_error"
        assert "ttl_seconds" in body["detail"]

    def test_missing_token_rejected(self, server_with_agent):
        """No X-Recto-Agent-Token -> 401 agent_auth_required."""
        ctx = server_with_agent
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/pairing/code",
            {},
            headers=None,
        )
        assert status == HTTPStatus.UNAUTHORIZED
        assert body["error"] == "agent_auth_required"

    def test_wrong_token_rejected(self, server_with_agent):
        """Wrong X-Recto-Agent-Token -> 401 agent_auth_failed."""
        ctx = server_with_agent
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/pairing/code",
            {},
            headers=_auth_headers(token="wrong-token"),
        )
        assert status == HTTPStatus.UNAUTHORIZED
        assert body["error"] == "agent_auth_failed"

    def test_unknown_agent_id_rejected(self, server_with_agent):
        """Unknown agent_id (not in capability_agent_tokens map) -> 401."""
        ctx = server_with_agent
        headers = {
            "X-Recto-Agent-Id": "unknown-agent",
            "X-Recto-Agent-Token": ctx["agent_token"],
        }
        status, body = _http_post_json(
            f"{ctx['base_url']}/v0.4/pairing/code",
            {},
            headers=headers,
        )
        assert status == HTTPStatus.UNAUTHORIZED
        assert body["error"] == "agent_auth_failed"

    def test_endpoint_disabled_when_no_agent_tokens(self, tmp_path: Path):
        """create_server without capability_agent_tokens -> endpoint 404
        (matching the rest of the agent-trusted surface)."""
        state = StateStore(state_dir=tmp_path)
        challenges = ChallengeStore()
        server = create_server(
            bind_host="127.0.0.1",
            bind_port=0,
            state=state,
            bootloader_id="test-no-agents",
            challenges=challenges,
            ssl_context=None,
            # NO capability_agent_tokens
        )
        host, port = server.server_address
        base_url = f"http://{host}:{port}"
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            status, body = _http_post_json(
                f"{base_url}/v0.4/pairing/code",
                {},
                headers=_auth_headers(),
            )
            assert status == HTTPStatus.NOT_FOUND
            assert body["error"] == "unknown_endpoint"
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5.0)
