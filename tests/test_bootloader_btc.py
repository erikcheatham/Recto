"""Tests for the Bitcoin signing capability through the bootloader.

Mirrors ``test_bootloader_eth.py``'s shape: state-level construction
validation for ``PendingRequest.new_btc``, then end-to-end live HTTP
exercises with the actual ``BootloaderHandler`` over a localhost
loopback socket.

The bootloader doesn't validate the BIP-137 secp256k1 signature
itself per the protocol RFC — its sole job is to verify the Ed25519
paired-phone envelope and forward the opaque BIP-137 sig to the
launcher's resolver callback. The structure-checks the bootloader DOES
enforce (65 bytes after base64 decode, header byte in 27..42) are
exercised here.
"""

from __future__ import annotations

import base64
import json
import threading
from http.server import HTTPServer
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
    PendingRequest,
    PhoneRegistration,
    StateStore,
)


def _b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------------------
# State-level: PendingRequest.new_btc construction + validation
# ---------------------------------------------------------------------------


class TestNewBtcConstruction:
    def _kwargs(self, **overrides: Any) -> dict[str, Any]:
        base = dict(
            service="svc",
            secret="WALLET",
            phone_id="phone1",
            operation_description="sign a Bitcoin login message",
            payload_hash_b64u="aGFzaA",
            child_pid=1234,
            child_argv0="python.exe",
            btc_network="mainnet",
            btc_message_kind="message_signing",
            btc_address="bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",  # canonical BIP-173 vector
            btc_message_text="Login to demo.recto.example",
        )
        base.update(overrides)
        return base

    def test_message_signing_happy_path(self):
        req = PendingRequest.new_btc(**self._kwargs())
        assert req.kind == "btc_sign"
        assert req.btc_network == "mainnet"
        assert req.btc_message_kind == "message_signing"
        assert req.btc_address.startswith("bc1q")
        assert req.btc_derivation_path == "m/84'/0'/0'/0/0"  # default native-SegWit
        assert req.btc_message_text == "Login to demo.recto.example"
        assert req.btc_psbt_base64 is None

    def test_psbt_kind_requires_psbt_body(self):
        with pytest.raises(ValueError, match="btc_psbt_base64"):
            PendingRequest.new_btc(**self._kwargs(btc_message_kind="psbt"))

    def test_psbt_kind_with_proper_body(self):
        req = PendingRequest.new_btc(**self._kwargs(
            btc_message_kind="psbt",
            btc_message_text=None,
            btc_psbt_base64="cHNidP8BAAoCAAAAAAAAAAAA",
        ))
        assert req.btc_message_kind == "psbt"
        assert req.btc_psbt_base64 == "cHNidP8BAAoCAAAAAAAAAAAA"
        assert req.btc_message_text is None

    def test_unknown_message_kind_rejected(self):
        with pytest.raises(ValueError, match="btc_message_kind must be one of"):
            PendingRequest.new_btc(**self._kwargs(btc_message_kind="bogus"))

    def test_empty_message_text_rejected(self):
        with pytest.raises(ValueError, match="btc_message_text"):
            PendingRequest.new_btc(**self._kwargs(btc_message_text=""))

    def test_unknown_network_rejected(self):
        with pytest.raises(ValueError, match="btc_network must be one of"):
            PendingRequest.new_btc(**self._kwargs(btc_network="satoshinet"))

    def test_each_recognized_network_accepted(self):
        for net in ("mainnet", "testnet", "signet", "regtest"):
            req = PendingRequest.new_btc(**self._kwargs(btc_network=net))
            assert req.btc_network == net

    def test_short_address_rejected(self):
        with pytest.raises(ValueError, match="14 chars"):
            PendingRequest.new_btc(**self._kwargs(btc_address="bc1qabc"))

    def test_custom_derivation_path(self):
        req = PendingRequest.new_btc(**self._kwargs(
            btc_derivation_path="m/49'/0'/0'/0/3",
        ))
        assert req.btc_derivation_path == "m/49'/0'/0'/0/3"


# ---------------------------------------------------------------------------
# State-level: round-trip through StateStore
# ---------------------------------------------------------------------------


class TestBtcPendingPersistence:
    @pytest.fixture
    def store(self, tmp_path: Path) -> StateStore:
        return StateStore(state_dir=tmp_path)

    def test_btc_pending_round_trips(self, store: StateStore):
        req = PendingRequest.new_btc(
            service="svc",
            secret="WALLET",
            phone_id="phone1",
            operation_description="login on demo.recto.example",
            payload_hash_b64u="aGFzaA",
            child_pid=42,
            child_argv0="python.exe",
            btc_network="mainnet",
            btc_message_kind="message_signing",
            btc_address="bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            btc_message_text="Login to demo.recto.example at 1714323456",
        )
        store.add_pending(req)
        listed = store.list_pending_for_phone("phone1")
        assert len(listed) == 1
        loaded = listed[0]
        assert loaded.kind == "btc_sign"
        assert loaded.btc_network == "mainnet"
        assert loaded.btc_message_text == "Login to demo.recto.example at 1714323456"


# ---------------------------------------------------------------------------
# Server-level: _pending_to_wire emits BTC fields + omits when not BTC
# ---------------------------------------------------------------------------


class TestPendingToWireBtc:
    def test_btc_context_fields_emitted(self):
        req = PendingRequest.new_btc(
            service="svc",
            secret="WALLET",
            phone_id="phone1",
            operation_description="x",
            payload_hash_b64u="aA",
            child_pid=1,
            child_argv0="x",
            btc_network="testnet",
            btc_message_kind="message_signing",
            btc_address="tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
            btc_derivation_path="m/84'/0'/0'/0/2",
            btc_message_text="login",
        )
        wire = BootloaderHandler._pending_to_wire(req)
        ctx = wire["context"]
        assert wire["kind"] == "btc_sign"
        assert ctx["btc_network"] == "testnet"
        assert ctx["btc_message_kind"] == "message_signing"
        assert ctx["btc_address"] == "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
        assert ctx["btc_derivation_path"] == "m/84'/0'/0'/0/2"
        assert ctx["btc_message_text"] == "login"
        # Body field for the NON-active kind is absent (not None).
        assert "btc_psbt_base64" not in ctx

    def test_non_btc_kind_omits_btc_fields(self):
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
        # Existing v0.4.0 wire shape — no BTC leakage onto non-BTC kinds.
        for key in ("btc_network", "btc_message_kind", "btc_address",
                    "btc_derivation_path", "btc_message_text", "btc_psbt_base64"):
            assert key not in ctx, f"unexpected BTC key {key!r} on non-BTC wire"


# ---------------------------------------------------------------------------
# End-to-end: live HTTP, queue + GET /pending + POST /respond for btc_sign
# ---------------------------------------------------------------------------


@pytest.fixture
def signing_pair():
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv, _b64u_encode(pub_bytes)


@pytest.fixture
def live_server(tmp_path: Path, signing_pair):
    priv, pub_b64u = signing_pair
    state = StateStore(state_dir=tmp_path)
    phone = PhoneRegistration.new(
        device_label="Test Phone",
        public_key_b64u=pub_b64u,
        supported_algorithms=("ed25519",),
    )
    state.register_phone(phone)

    captured: list[dict[str, Any]] = []

    def notify_fn(*, req, ok, signature_b64u, eth_signature_rsv=None,
                  btc_signature_base64=None, reason):
        captured.append({
            "request_id": req.request_id,
            "kind": req.kind,
            "ok": ok,
            "signature_b64u": signature_b64u,
            "eth_signature_rsv": eth_signature_rsv,
            "btc_signature_base64": btc_signature_base64,
            "reason": reason,
        })

    server = create_server(
        bind_host="127.0.0.1",
        bind_port=0,
        state=state,
        bootloader_id="test-bootloader",
        challenges=ChallengeStore(),
        notify_resolved_fn=notify_fn,
        ssl_context=None,
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


class TestBtcEndToEnd:
    def _queue_btc_message_sign(
        self, ctx: dict[str, Any], message_text: str = "Login to demo.recto.example"
    ) -> PendingRequest:
        req = PendingRequest.new_btc(
            service="svc",
            secret="WALLET",
            phone_id=ctx["phone_id"],
            operation_description=f"message_signing: {message_text!r}",
            payload_hash_b64u=_b64u_encode(b"test-btc-payload-hash-32-bytes-1"),
            child_pid=1234,
            child_argv0="python.exe",
            btc_network="mainnet",
            btc_message_kind="message_signing",
            btc_address="bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            btc_message_text=message_text,
        )
        ctx["state"].add_pending(req)
        return req

    def test_pending_endpoint_returns_btc_request(self, live_server: dict[str, Any]):
        ctx = live_server
        req = self._queue_btc_message_sign(ctx)
        body = _http_get_json(
            f"{ctx['base_url']}/v0.4/pending?phone_id={ctx['phone_id']}"
        )
        assert len(body["requests"]) == 1
        wire = body["requests"][0]
        assert wire["request_id"] == req.request_id
        assert wire["kind"] == "btc_sign"
        c = wire["context"]
        assert c["btc_network"] == "mainnet"
        assert c["btc_message_kind"] == "message_signing"
        assert c["btc_address"] == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        assert c["btc_message_text"] == "Login to demo.recto.example"

    def test_respond_with_valid_ed25519_and_compact_sig_resolves_ok(
        self, live_server: dict[str, Any]
    ):
        ctx = live_server
        req = self._queue_btc_message_sign(ctx)
        # Build a valid Ed25519 sig over the payload hash.
        padding = "=" * (-len(req.payload_hash_b64u) % 4)
        hash_bytes = base64.urlsafe_b64decode(req.payload_hash_b64u + padding)
        ed_sig = ctx["phone_priv"].sign(hash_bytes)
        # Construct a fake (but well-formed) BIP-137 compact signature.
        # The bootloader does NOT validate the secp256k1 sig — it's
        # opaque. Just need 65 bytes with header byte in 27..42.
        sig_bytes = bytes([39]) + b"\x11" * 32 + b"\x22" * 32  # P2WPKH header recid=0
        sig_b64 = base64.b64encode(sig_bytes).decode("ascii")
        status, resp = _http_post_json(
            f"{ctx['base_url']}/v0.4/respond/{req.request_id}",
            {
                "decision": "approved",
                "signature_b64u": _b64u_encode(ed_sig),
                "btc_signature_base64": sig_b64,
            },
        )
        assert status == 200
        assert resp == {"resolved": True}
        assert len(ctx["captured"]) == 1
        cap = ctx["captured"][0]
        assert cap["ok"] is True
        assert cap["kind"] == "btc_sign"
        assert cap["btc_signature_base64"] == sig_b64
        assert cap["signature_b64u"] == _b64u_encode(ed_sig)
        assert cap["reason"] is None
        # ETH field should NOT be populated for a btc_sign approval.
        assert cap["eth_signature_rsv"] is None

    def test_respond_denied_resolves_with_no_sig(self, live_server: dict[str, Any]):
        ctx = live_server
        req = self._queue_btc_message_sign(ctx)
        status, resp = _http_post_json(
            f"{ctx['base_url']}/v0.4/respond/{req.request_id}",
            {"decision": "denied", "reason": "operator declined"},
        )
        assert status == 200
        assert resp == {"resolved": True}
        cap = ctx["captured"][0]
        assert cap["ok"] is False
        assert cap["btc_signature_base64"] is None
        assert cap["reason"] == "operator declined"

    def test_respond_missing_sig_on_btc_sign_rejects(self, live_server: dict[str, Any]):
        ctx = live_server
        req = self._queue_btc_message_sign(ctx)
        padding = "=" * (-len(req.payload_hash_b64u) % 4)
        hash_bytes = base64.urlsafe_b64decode(req.payload_hash_b64u + padding)
        ed_sig = ctx["phone_priv"].sign(hash_bytes)
        status, resp = _http_post_json(
            f"{ctx['base_url']}/v0.4/respond/{req.request_id}",
            {
                "decision": "approved",
                "signature_b64u": _b64u_encode(ed_sig),
                # no btc_signature_base64
            },
        )
        assert status == 400
        assert resp["error"] == "bootloader_error"
        assert "btc_signature_base64" in resp["detail"]
        assert ctx["captured"][0]["ok"] is False

    def test_respond_wrong_decoded_length_rejects(self, live_server: dict[str, Any]):
        ctx = live_server
        req = self._queue_btc_message_sign(ctx)
        padding = "=" * (-len(req.payload_hash_b64u) % 4)
        hash_bytes = base64.urlsafe_b64decode(req.payload_hash_b64u + padding)
        ed_sig = ctx["phone_priv"].sign(hash_bytes)
        # 64 bytes instead of 65 — decodes but wrong size.
        bad_sig = base64.b64encode(b"\x00" * 64).decode("ascii")
        status, resp = _http_post_json(
            f"{ctx['base_url']}/v0.4/respond/{req.request_id}",
            {
                "decision": "approved",
                "signature_b64u": _b64u_encode(ed_sig),
                "btc_signature_base64": bad_sig,
            },
        )
        assert status == 400
        assert "65 bytes" in resp["detail"]

    def test_respond_bad_header_byte_rejects(self, live_server: dict[str, Any]):
        ctx = live_server
        req = self._queue_btc_message_sign(ctx)
        padding = "=" * (-len(req.payload_hash_b64u) % 4)
        hash_bytes = base64.urlsafe_b64decode(req.payload_hash_b64u + padding)
        ed_sig = ctx["phone_priv"].sign(hash_bytes)
        # Header byte 26 is below the 27..42 BIP-137 range.
        sig_bytes = bytes([26]) + b"\x11" * 32 + b"\x22" * 32
        sig_b64 = base64.b64encode(sig_bytes).decode("ascii")
        status, resp = _http_post_json(
            f"{ctx['base_url']}/v0.4/respond/{req.request_id}",
            {
                "decision": "approved",
                "signature_b64u": _b64u_encode(ed_sig),
                "btc_signature_base64": sig_b64,
            },
        )
        assert status == 400
        assert "27..42" in resp["detail"]

    def test_respond_bad_ed25519_rejects_btc_sign(self, live_server: dict[str, Any]):
        ctx = live_server
        req = self._queue_btc_message_sign(ctx)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )

        other = Ed25519PrivateKey.generate()
        padding = "=" * (-len(req.payload_hash_b64u) % 4)
        hash_bytes = base64.urlsafe_b64decode(req.payload_hash_b64u + padding)
        forged = other.sign(hash_bytes)
        sig_bytes = bytes([39]) + b"\x33" * 64
        sig_b64 = base64.b64encode(sig_bytes).decode("ascii")
        status, resp = _http_post_json(
            f"{ctx['base_url']}/v0.4/respond/{req.request_id}",
            {
                "decision": "approved",
                "signature_b64u": _b64u_encode(forged),
                "btc_signature_base64": sig_b64,
            },
        )
        assert status == 400
        assert "approved-response signature invalid" in resp["detail"]
        assert ctx["captured"][0]["ok"] is False

    def test_existing_eth_path_unaffected(self, live_server: dict[str, Any]):
        """Regression: btc_sign wiring shouldn't have broken eth_sign."""
        ctx = live_server
        req = PendingRequest.new_eth(
            service="svc",
            secret="WALLET",
            phone_id=ctx["phone_id"],
            operation_description="eth alongside btc",
            payload_hash_b64u=_b64u_encode(b"eth-hash-payload-32-bytes-pad!!!"),
            child_pid=1,
            child_argv0="x",
            eth_chain_id=1,
            eth_message_kind="personal_sign",
            eth_address="0x" + "ab" * 20,
            eth_message_text="hello",
        )
        ctx["state"].add_pending(req)
        padding = "=" * (-len(req.payload_hash_b64u) % 4)
        hash_bytes = base64.urlsafe_b64decode(req.payload_hash_b64u + padding)
        ed_sig = ctx["phone_priv"].sign(hash_bytes)
        rsv = "0x" + "11" * 32 + "22" * 32 + "1b"
        status, resp = _http_post_json(
            f"{ctx['base_url']}/v0.4/respond/{req.request_id}",
            {
                "decision": "approved",
                "signature_b64u": _b64u_encode(ed_sig),
                "eth_signature_rsv": rsv,
            },
        )
        assert status == 200
        cap = ctx["captured"][0]
        assert cap["ok"] is True
        assert cap["kind"] == "eth_sign"
        assert cap["eth_signature_rsv"] == rsv
        assert cap["btc_signature_base64"] is None  # no btc field on eth approval
