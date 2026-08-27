"""Tests for the v0.5+ Ethereum signing capability.

Covers two layers:

1. ``PendingRequest.new_eth`` construction + validation in
   ``recto.bootloader.state``.
2. End-to-end queue-and-respond through the live HTTPS-less HTTP
   ``BootloaderHandler``: an ETH ``personal_sign`` request gets queued
   on the StateStore, served on ``GET /v0.4/pending`` with the seven
   ``eth_*`` context fields, then resolved on
   ``POST /v0.4/respond/<id>`` with both the Ed25519 paired-phone proof
   and the opaque ``eth_signature_rsv`` forwarded through to the
   resolver callback.

The ETH layer reuses the existing Ed25519 envelope so the bootloader
keeps proving "the response came from the paired phone" without needing
to know anything about secp256k1 — the rsv signature is forwarded to
the consumer (smart contract / off-chain verifier) verbatim.

These tests require the ``[v0_4]`` extra (``cryptography``) for the
Ed25519 keypair fixture. The ``recto.ethereum`` helpers are exercised
directly in ``tests/test_ethereum.py`` and aren't re-tested here — the
bootloader-side respond path doesn't call them; rsv is opaque on this
seam.
"""

from __future__ import annotations

import base64
import json
import threading
import time
from http.server import HTTPServer
from pathlib import Path
from typing import Any
from urllib import request as urlrequest
from urllib.error import HTTPError

import pytest

from recto.bootloader import BootloaderError
from recto.bootloader.server import (
    BootloaderConfig,
    BootloaderHandler,
    ChallengeStore,
    create_server,
)
from recto.bootloader.state import (
    PendingRequest,
    PhoneRegistration,
    StateStore,
)


def _b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------------------
# State-level: PendingRequest.new_eth construction + validation
# ---------------------------------------------------------------------------


class TestNewEthConstruction:
    def _kwargs(self, **overrides: Any) -> dict[str, Any]:
        base = dict(
            service="svc",
            secret="WALLET_KEY",
            phone_id="phone1",
            operation_description="sign hello world",
            payload_hash_b64u="aGFzaA",
            child_pid=1234,
            child_argv0="python.exe",
            eth_chain_id=1,
            eth_message_kind="personal_sign",
            eth_address="0x" + "ab" * 20,
            eth_message_text="hello world",
        )
        base.update(overrides)
        return base

    def test_personal_sign_happy_path(self) -> None:
        req = PendingRequest.new_eth(**self._kwargs())
        assert req.kind == "eth_sign"
        assert req.eth_chain_id == 1
        assert req.eth_message_kind == "personal_sign"
        assert req.eth_address == "0x" + "ab" * 20  # lowercased
        assert req.eth_derivation_path == "m/44'/60'/0'/0/0"  # default
        assert req.eth_message_text == "hello world"
        assert req.eth_typed_data_json is None
        assert req.eth_transaction_json is None

    def test_typed_data_kind_requires_typed_data_json(self) -> None:
        # personal_sign default body field set, but kind says typed_data.
        with pytest.raises(ValueError, match="eth_typed_data_json"):
            PendingRequest.new_eth(**self._kwargs(eth_message_kind="typed_data"))

    def test_transaction_kind_requires_transaction_json(self) -> None:
        with pytest.raises(ValueError, match="eth_transaction_json"):
            PendingRequest.new_eth(**self._kwargs(eth_message_kind="transaction"))

    def test_typed_data_with_proper_body(self) -> None:
        req = PendingRequest.new_eth(**self._kwargs(
            eth_message_kind="typed_data",
            eth_message_text=None,
            eth_typed_data_json='{"primaryType":"Mail"}',
        ))
        assert req.eth_message_kind == "typed_data"
        assert req.eth_typed_data_json == '{"primaryType":"Mail"}'
        assert req.eth_message_text is None

    def test_transaction_with_proper_body(self) -> None:
        req = PendingRequest.new_eth(**self._kwargs(
            eth_message_kind="transaction",
            eth_message_text=None,
            eth_transaction_json='{"to":"0xabc","value":"0x1"}',
        ))
        assert req.eth_message_kind == "transaction"
        assert req.eth_transaction_json == '{"to":"0xabc","value":"0x1"}'

    def test_unknown_message_kind_rejected(self) -> None:
        with pytest.raises(ValueError, match="eth_message_kind must be one of"):
            PendingRequest.new_eth(**self._kwargs(eth_message_kind="bogus"))

    def test_empty_message_text_rejected(self) -> None:
        with pytest.raises(ValueError, match="eth_message_text"):
            PendingRequest.new_eth(**self._kwargs(eth_message_text=""))

    def test_address_normalized_to_lowercase(self) -> None:
        # Operator UI may pass an EIP-55 mixed-case address; the
        # state layer always lowercases for canonical comparison.
        req = PendingRequest.new_eth(**self._kwargs(
            eth_address="0xDEADBEEF" + "00" * 16,
        ))
        assert req.eth_address == "0xdeadbeef" + "00" * 16

    def test_address_without_0x_rejected(self) -> None:
        with pytest.raises(ValueError, match="0x-prefixed"):
            PendingRequest.new_eth(**self._kwargs(eth_address="ab" * 20))

    def test_address_wrong_length_rejected(self) -> None:
        with pytest.raises(ValueError, match="42-char"):
            PendingRequest.new_eth(**self._kwargs(eth_address="0xabcd"))

    def test_custom_derivation_path(self) -> None:
        req = PendingRequest.new_eth(**self._kwargs(
            eth_derivation_path="m/44'/60'/0'/0/3",
        ))
        assert req.eth_derivation_path == "m/44'/60'/0'/0/3"


# ---------------------------------------------------------------------------
# State-level: round-trip through StateStore
# ---------------------------------------------------------------------------


class TestEthPendingPersistence:
    @pytest.fixture
    def store(self, tmp_path: Path) -> StateStore:
        return StateStore(state_dir=tmp_path)

    def test_eth_pending_round_trips_through_disk(
        self, store: StateStore
    ) -> None:
        req = PendingRequest.new_eth(
            service="svc",
            secret="WALLET",
            phone_id="phone1",
            operation_description="sign Login to MyDApp",
            payload_hash_b64u="aGFzaA",
            child_pid=42,
            child_argv0="python.exe",
            eth_chain_id=8453,  # Base
            eth_message_kind="personal_sign",
            eth_address="0x" + "12" * 20,
            eth_message_text="Login to MyDApp at 1714323456",
        )
        store.add_pending(req)
        # Disk write happened; read via list_pending_for_phone exercises
        # the in-memory cache, but a fresh StateStore would re-read from
        # disk — except that pending is intentionally NOT reloaded (see
        # state.py:_load comment). Use list_pending while the same store
        # is alive to verify the round-trip.
        listed = store.list_pending_for_phone("phone1")
        assert len(listed) == 1
        loaded = listed[0]
        assert loaded.kind == "eth_sign"
        assert loaded.eth_chain_id == 8453
        assert loaded.eth_message_kind == "personal_sign"
        assert loaded.eth_message_text == "Login to MyDApp at 1714323456"

    def test_eth_pending_take_returns_full_request(
        self, store: StateStore
    ) -> None:
        req = PendingRequest.new_eth(
            service="svc",
            secret="WALLET",
            phone_id="phone1",
            operation_description="x",
            payload_hash_b64u="aA",
            child_pid=1,
            child_argv0="x",
            eth_chain_id=1,
            eth_message_kind="personal_sign",
            eth_address="0x" + "ff" * 20,
            eth_message_text="msg",
        )
        store.add_pending(req)
        taken = store.take_pending(req.request_id)
        assert taken is not None
        assert taken.kind == "eth_sign"
        assert taken.eth_message_text == "msg"
        # take is one-shot.
        assert store.take_pending(req.request_id) is None


# ---------------------------------------------------------------------------
# Server-level: _pending_to_wire emits ETH context fields
# ---------------------------------------------------------------------------


class TestPendingToWire:
    def test_eth_context_fields_emitted(self) -> None:
        req = PendingRequest.new_eth(
            service="svc",
            secret="WALLET",
            phone_id="phone1",
            operation_description="x",
            payload_hash_b64u="aA",
            child_pid=1,
            child_argv0="x",
            eth_chain_id=11155111,  # Sepolia
            eth_message_kind="personal_sign",
            eth_address="0x" + "ab" * 20,
            eth_derivation_path="m/44'/60'/0'/0/2",
            eth_message_text="login",
        )
        wire = BootloaderHandler._pending_to_wire(req)
        ctx = wire["context"]
        assert wire["kind"] == "eth_sign"
        assert ctx["eth_chain_id"] == 11155111
        assert ctx["eth_message_kind"] == "personal_sign"
        assert ctx["eth_address"] == "0x" + "ab" * 20
        assert ctx["eth_derivation_path"] == "m/44'/60'/0'/0/2"
        assert ctx["eth_message_text"] == "login"
        # Body fields not relevant to this kind are absent (not None).
        assert "eth_typed_data_json" not in ctx
        assert "eth_transaction_json" not in ctx

    def test_non_eth_kind_omits_eth_fields(self) -> None:
        req = PendingRequest.new(
            kind="single_sign",
            service="svc",
            secret="KEY",
            phone_id="phone1",
            operation_description="x",
            payload_hash_b64u="aA",
            child_pid=1,
            child_argv0="x",
        )
        wire = BootloaderHandler._pending_to_wire(req)
        ctx = wire["context"]
        # Existing v0.4.0 wire shape — no ETH leakage.
        assert "eth_chain_id" not in ctx
        assert "eth_message_kind" not in ctx
        assert "eth_address" not in ctx
        assert "eth_derivation_path" not in ctx

    def test_typed_data_kind_emits_typed_data_field(self) -> None:
        req = PendingRequest.new_eth(
            service="svc",
            secret="WALLET",
            phone_id="phone1",
            operation_description="EIP-712 sign",
            payload_hash_b64u="aA",
            child_pid=1,
            child_argv0="x",
            eth_chain_id=1,
            eth_message_kind="typed_data",
            eth_address="0x" + "11" * 20,
            eth_typed_data_json='{"primaryType":"Mail"}',
        )
        wire = BootloaderHandler._pending_to_wire(req)
        ctx = wire["context"]
        assert ctx["eth_message_kind"] == "typed_data"
        assert ctx["eth_typed_data_json"] == '{"primaryType":"Mail"}'
        assert "eth_message_text" not in ctx
        assert "eth_transaction_json" not in ctx


# ---------------------------------------------------------------------------
# End-to-end: live HTTP server, queue + GET /pending + POST /respond
# ---------------------------------------------------------------------------


@pytest.fixture
def signing_pair():
    """Returns (Ed25519PrivateKey, public_key_b64u). Reused from
    test_bootloader_sessions's pattern."""
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
    return priv, _b64u_encode(pub_bytes)


@pytest.fixture
def live_server(tmp_path: Path, signing_pair):
    """Spin a real BootloaderHandler in a background thread on an
    OS-assigned localhost port. Yields (base_url, state_store, phone_id,
    captured_resolutions) where captured_resolutions is a list the
    notify_fn appends to.

    Cleanup: server is shut down on teardown.
    """
    priv, pub_b64u = signing_pair
    state = StateStore(state_dir=tmp_path)
    # Pre-register one phone so the queue endpoints can find it.
    phone = PhoneRegistration.new(
        device_label="Test Phone",
        public_key_b64u=pub_b64u,
        supported_algorithms=("ed25519",),
    )
    state.register_phone(phone)

    captured: list[dict[str, Any]] = []

    def notify_fn(*, req, ok, signature_b64u, eth_signature_rsv=None, reason):
        captured.append({
            "request_id": req.request_id,
            "kind": req.kind,
            "ok": ok,
            "signature_b64u": signature_b64u,
            "eth_signature_rsv": eth_signature_rsv,
            "reason": reason,
        })

    server = create_server(
        bind_host="127.0.0.1",
        bind_port=0,  # OS-assigned
        state=state,
        bootloader_id="test-bootloader",
        challenges=ChallengeStore(),
        notify_resolved_fn=notify_fn,
        ssl_context=None,  # plain HTTP for tests
    )
    host, port = server.server_address
    base_url = f"http://{host}:{port}"

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {
            "base_url": base_url,
            "state": state,
            "phone_id": phone.phone_id,
            "phone_priv": priv,
            "phone_pub_b64u": pub_b64u,
            "captured": captured,
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)


def _http_get_json(url: str) -> dict[str, Any]:
    with urlrequest.urlopen(url, timeout=5.0) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _http_post_json(url: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    data = json.dumps(body).encode("utf-8")
    req = urlrequest.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlrequest.urlopen(req, timeout=5.0) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


class TestEthEndToEnd:
    def _queue_eth_personal_sign(
        self, ctx: dict[str, Any], message_text: str = "Login to MyDApp"
    ) -> PendingRequest:
        req = PendingRequest.new_eth(
            service="svc",
            secret="WALLET",
            phone_id=ctx["phone_id"],
            operation_description=f"personal_sign: {message_text!r}",
            # In production the launcher computes a stable hash over the
            # request payload; for tests we use a fixed token. The Ed25519
            # signature in the response binds against this exact b64u.
            payload_hash_b64u=_b64u_encode(b"test-eth-payload-hash-32-bytes-1"),
            child_pid=1234,
            child_argv0="python.exe",
            eth_chain_id=8453,
            eth_message_kind="personal_sign",
            eth_address="0x" + "ab" * 20,
            eth_message_text=message_text,
        )
        ctx["state"].add_pending(req)
        return req

    def test_pending_endpoint_returns_eth_request(
        self, live_server: dict[str, Any]
    ) -> None:
        ctx = live_server
        req = self._queue_eth_personal_sign(ctx)
        body = _http_get_json(
            f"{ctx['base_url']}/v0.4/pending?phone_id={ctx['phone_id']}"
        )
        assert len(body["requests"]) == 1
        wire = body["requests"][0]
        assert wire["request_id"] == req.request_id
        assert wire["kind"] == "eth_sign"
        c = wire["context"]
        assert c["eth_chain_id"] == 8453
        assert c["eth_message_kind"] == "personal_sign"
        assert c["eth_message_text"] == "Login to MyDApp"
        assert c["eth_address"] == "0x" + "ab" * 20

    def test_respond_with_valid_ed25519_and_rsv_resolves_ok(
        self, live_server: dict[str, Any]
    ) -> None:
        ctx = live_server
        req = self._queue_eth_personal_sign(ctx)
        # Build a valid Ed25519 sig over the payload hash.
        padding = "=" * (-len(req.payload_hash_b64u) % 4)
        hash_bytes = base64.urlsafe_b64decode(req.payload_hash_b64u + padding)
        ed_sig = ctx["phone_priv"].sign(hash_bytes)
        # Construct a fake (but well-formed) rsv signature. The
        # bootloader does NOT validate the secp256k1 sig — it's opaque.
        rsv_hex = "0x" + "11" * 32 + "22" * 32 + "1b"  # r||s||v with v=0x1b
        status, resp = _http_post_json(
            f"{ctx['base_url']}/v0.4/respond/{req.request_id}",
            {
                "decision": "approved",
                "signature_b64u": _b64u_encode(ed_sig),
                "eth_signature_rsv": rsv_hex,
            },
        )
        assert status == 200
        assert resp == {"resolved": True}
        # Resolver was called with the rsv forwarded through.
        assert len(ctx["captured"]) == 1
        cap = ctx["captured"][0]
        assert cap["ok"] is True
        assert cap["kind"] == "eth_sign"
        assert cap["eth_signature_rsv"] == rsv_hex
        assert cap["signature_b64u"] == _b64u_encode(ed_sig)
        assert cap["reason"] is None

    def test_respond_denied_resolves_with_no_rsv(
        self, live_server: dict[str, Any]
    ) -> None:
        ctx = live_server
        req = self._queue_eth_personal_sign(ctx)
        status, resp = _http_post_json(
            f"{ctx['base_url']}/v0.4/respond/{req.request_id}",
            {"decision": "denied", "reason": "operator declined"},
        )
        assert status == 200
        assert resp == {"resolved": True}
        cap = ctx["captured"][0]
        assert cap["ok"] is False
        assert cap["eth_signature_rsv"] is None
        assert cap["reason"] == "operator declined"

    def test_respond_missing_rsv_on_eth_sign_rejects(
        self, live_server: dict[str, Any]
    ) -> None:
        ctx = live_server
        req = self._queue_eth_personal_sign(ctx)
        padding = "=" * (-len(req.payload_hash_b64u) % 4)
        hash_bytes = base64.urlsafe_b64decode(req.payload_hash_b64u + padding)
        ed_sig = ctx["phone_priv"].sign(hash_bytes)
        # Missing eth_signature_rsv on an eth_sign approval.
        status, resp = _http_post_json(
            f"{ctx['base_url']}/v0.4/respond/{req.request_id}",
            {
                "decision": "approved",
                "signature_b64u": _b64u_encode(ed_sig),
                # no eth_signature_rsv
            },
        )
        assert status == 400
        assert resp["error"] == "bootloader_error"
        assert "eth_signature_rsv" in resp["detail"]
        # Resolver was called with ok=False before the error response.
        assert len(ctx["captured"]) == 1
        assert ctx["captured"][0]["ok"] is False
        assert ctx["captured"][0]["eth_signature_rsv"] is None

    def test_respond_malformed_rsv_rejects(
        self, live_server: dict[str, Any]
    ) -> None:
        ctx = live_server
        req = self._queue_eth_personal_sign(ctx)
        padding = "=" * (-len(req.payload_hash_b64u) % 4)
        hash_bytes = base64.urlsafe_b64decode(req.payload_hash_b64u + padding)
        ed_sig = ctx["phone_priv"].sign(hash_bytes)
        status, resp = _http_post_json(
            f"{ctx['base_url']}/v0.4/respond/{req.request_id}",
            {
                "decision": "approved",
                "signature_b64u": _b64u_encode(ed_sig),
                "eth_signature_rsv": "0xdeadbeef",  # too short
            },
        )
        assert status == 400
        assert resp["error"] == "bootloader_error"
        assert "130 hex chars" in resp["detail"]

    def test_respond_bad_ed25519_rejects_eth_sign(
        self, live_server: dict[str, Any]
    ) -> None:
        ctx = live_server
        req = self._queue_eth_personal_sign(ctx)
        # Sign with a DIFFERENT key (forgery).
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )

        other = Ed25519PrivateKey.generate()
        padding = "=" * (-len(req.payload_hash_b64u) % 4)
        hash_bytes = base64.urlsafe_b64decode(req.payload_hash_b64u + padding)
        forged = other.sign(hash_bytes)
        rsv_hex = "0x" + "33" * 65
        status, resp = _http_post_json(
            f"{ctx['base_url']}/v0.4/respond/{req.request_id}",
            {
                "decision": "approved",
                "signature_b64u": _b64u_encode(forged),
                "eth_signature_rsv": rsv_hex,
            },
        )
        assert status == 400
        assert "approved-response signature invalid" in resp["detail"]
        assert ctx["captured"][0]["ok"] is False

    def test_non_eth_request_still_resolves_without_rsv(
        self, live_server: dict[str, Any]
    ) -> None:
        """Regression test: existing single_sign flow (no eth_*) keeps
        working after the ETH branch was added."""
        ctx = live_server
        req = PendingRequest.new(
            kind="single_sign",
            service="svc",
            secret="KEY",
            phone_id=ctx["phone_id"],
            operation_description="generic single sign",
            payload_hash_b64u=_b64u_encode(b"non-eth-hash-32-bytes-padding!!!"),
            child_pid=1,
            child_argv0="x",
        )
        ctx["state"].add_pending(req)
        padding = "=" * (-len(req.payload_hash_b64u) % 4)
        hash_bytes = base64.urlsafe_b64decode(req.payload_hash_b64u + padding)
        ed_sig = ctx["phone_priv"].sign(hash_bytes)
        status, resp = _http_post_json(
            f"{ctx['base_url']}/v0.4/respond/{req.request_id}",
            {
                "decision": "approved",
                "signature_b64u": _b64u_encode(ed_sig),
            },
        )
        assert status == 200
        cap = ctx["captured"][0]
        assert cap["ok"] is True
        assert cap["kind"] == "single_sign"
        assert cap["eth_signature_rsv"] is None
