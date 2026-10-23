"""Tests for the Ed25519-chains signing capability through the bootloader.

Mirrors ``test_bootloader_btc.py``'s shape: state-level construction
validation for ``PendingRequest.new_ed``, then end-to-end live HTTP
exercises with the actual ``BootloaderHandler`` over a localhost
loopback socket.

The bootloader doesn't validate the chain-specific ed25519 signature
itself — its sole job is to verify the Ed25519 paired-phone envelope
and forward the opaque ed25519 sig + pubkey to the launcher's resolver
callback. The structure-checks the bootloader DOES enforce (signature
decodes to 64 bytes, pubkey is 64 hex chars / 32 bytes, with optional
0x prefix on the pubkey) are exercised here.
"""

from __future__ import annotations

import base64
import json
import threading
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
# State-level: PendingRequest.new_ed construction + validation
# ---------------------------------------------------------------------------


class TestNewEdConstruction:
    def _kwargs(self, **overrides: Any) -> dict[str, Any]:
        base = dict(
            service="svc",
            secret="WALLET",
            phone_id="phone1",
            operation_description="sign a SOL login message",
            payload_hash_b64u="aGFzaA",
            child_pid=1234,
            child_argv0="python.exe",
            ed_chain="sol",
            ed_message_kind="message_signing",
            ed_address="11111111111111111111111111111112",  # SOL "Default" pubkey address
            ed_message_text="Login to demo.recto.example",
        )
        base.update(overrides)
        return base

    def test_sol_message_signing_happy_path(self):
        req = PendingRequest.new_ed(**self._kwargs())
        assert req.kind == "ed_sign"
        assert req.ed_chain == "sol"
        assert req.ed_message_kind == "message_signing"
        assert req.ed_derivation_path == "m/44'/501'/0'/0'"
        assert req.ed_message_text == "Login to demo.recto.example"
        assert req.ed_payload_hex is None

    def test_xlm_default_path_is_sep0005(self):
        req = PendingRequest.new_ed(**self._kwargs(
            ed_chain="xlm",
            # 56-char G-prefix StrKey shape (don't have to be valid CRC
            # at construction time — the loose floor in new_ed only
            # enforces 25+ chars).
            ed_address="GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ))
        assert req.ed_chain == "xlm"
        assert req.ed_derivation_path == "m/44'/148'/0'"

    def test_xrp_default_path_is_xumm_all_hardened(self):
        req = PendingRequest.new_ed(**self._kwargs(
            ed_chain="xrp",
            ed_address="r9cZA1mLK5R5Am25ArfXFmqgNwjZgnfk59",
        ))
        assert req.ed_chain == "xrp"
        assert req.ed_derivation_path == "m/44'/144'/0'/0'/0'"

    def test_unknown_chain_rejected(self):
        with pytest.raises(ValueError, match="ed_chain must be one of"):
            PendingRequest.new_ed(**self._kwargs(ed_chain="ada"))

    def test_unknown_message_kind_rejected(self):
        with pytest.raises(ValueError, match="ed_message_kind must be one of"):
            PendingRequest.new_ed(**self._kwargs(ed_message_kind="bogus"))

    def test_empty_message_text_rejected(self):
        with pytest.raises(ValueError, match="ed_message_text"):
            PendingRequest.new_ed(**self._kwargs(ed_message_text=""))

    def test_missing_message_text_rejected(self):
        with pytest.raises(ValueError, match="ed_message_text"):
            PendingRequest.new_ed(**self._kwargs(ed_message_text=None))

    def test_transaction_kind_is_reserved(self):
        # Transaction signing is reserved for a follow-up wave because
        # each chain has its own transaction-blob hashing rules and
        # those aren't yet wired in the chain modules.
        with pytest.raises(ValueError, match="reserved"):
            PendingRequest.new_ed(**self._kwargs(
                ed_message_kind="transaction",
                ed_message_text=None,
                ed_payload_hex="deadbeef",
            ))

    def test_short_address_rejected(self):
        with pytest.raises(ValueError, match="25 chars"):
            PendingRequest.new_ed(**self._kwargs(ed_address="short"))

    def test_each_recognized_chain_accepted(self):
        for chain, addr in (
            ("sol", "11111111111111111111111111111112"),
            ("xlm", "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            ("xrp", "r9cZA1mLK5R5Am25ArfXFmqgNwjZgnfk59"),
        ):
            req = PendingRequest.new_ed(**self._kwargs(
                ed_chain=chain, ed_address=addr,
            ))
            assert req.ed_chain == chain

    def test_custom_derivation_path(self):
        req = PendingRequest.new_ed(**self._kwargs(
            ed_derivation_path="m/44'/501'/3'/0'",
        ))
        assert req.ed_derivation_path == "m/44'/501'/3'/0'"


# ---------------------------------------------------------------------------
# State-level: round-trip through StateStore
# ---------------------------------------------------------------------------


class TestEdPendingPersistence:
    @pytest.fixture
    def store(self, tmp_path: Path) -> StateStore:
        return StateStore(state_dir=tmp_path)

    def test_ed_pending_round_trips(self, store: StateStore):
        req = PendingRequest.new_ed(
            service="svc",
            secret="WALLET",
            phone_id="phone1",
            operation_description="login on demo.recto.example",
            payload_hash_b64u="aGFzaA",
            child_pid=42,
            child_argv0="python.exe",
            ed_chain="sol",
            ed_message_kind="message_signing",
            ed_address="11111111111111111111111111111112",
            ed_message_text="Login to demo.recto.example at 1714323456",
        )
        store.add_pending(req)
        listed = store.list_pending_for_phone("phone1")
        assert len(listed) == 1
        loaded = listed[0]
        assert loaded.kind == "ed_sign"
        assert loaded.ed_chain == "sol"
        assert loaded.ed_message_text == "Login to demo.recto.example at 1714323456"


# ---------------------------------------------------------------------------
# Server-level: _pending_to_wire emits ED fields + omits when not ED
# ---------------------------------------------------------------------------


class TestPendingToWireEd:
    def test_ed_context_fields_emitted(self):
        req = PendingRequest.new_ed(
            service="svc",
            secret="WALLET",
            phone_id="phone1",
            operation_description="x",
            payload_hash_b64u="aA",
            child_pid=1,
            child_argv0="x",
            ed_chain="xlm",
            ed_message_kind="message_signing",
            ed_address="GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ed_derivation_path="m/44'/148'/3'",
            ed_message_text="login",
        )
        wire = BootloaderHandler._pending_to_wire(req)
        ctx = wire["context"]
        assert wire["kind"] == "ed_sign"
        assert ctx["ed_chain"] == "xlm"
        assert ctx["ed_message_kind"] == "message_signing"
        assert ctx["ed_address"].startswith("G")
        assert ctx["ed_derivation_path"] == "m/44'/148'/3'"
        assert ctx["ed_message_text"] == "login"
        # Body field for the NON-active kind absent.
        assert "ed_payload_hex" not in ctx

    def test_non_ed_kind_omits_ed_fields(self):
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
        # Existing v0.4.0 wire shape — no ED leakage onto non-ED kinds.
        for key in ("ed_chain", "ed_message_kind", "ed_address",
                    "ed_derivation_path", "ed_message_text", "ed_payload_hex"):
            assert key not in ctx, f"unexpected ED key {key!r} on non-ED wire"


# ---------------------------------------------------------------------------
# End-to-end: live HTTP, queue + GET /pending + POST /respond for ed_sign
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
                  btc_signature_base64=None, ed_signature_base64=None,
                  ed_pubkey_hex=None, reason):
        captured.append({
            "request_id": req.request_id,
            "kind": req.kind,
            "ok": ok,
            "signature_b64u": signature_b64u,
            "eth_signature_rsv": eth_signature_rsv,
            "btc_signature_base64": btc_signature_base64,
            "ed_signature_base64": ed_signature_base64,
            "ed_pubkey_hex": ed_pubkey_hex,
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


class TestEdEndToEnd:
    def _queue_ed_sol_sign(
        self, ctx: dict[str, Any], message_text: str = "Login to demo.recto.example"
    ) -> PendingRequest:
        req = PendingRequest.new_ed(
            service="svc",
            secret="WALLET",
            phone_id=ctx["phone_id"],
            operation_description=f"sol message_signing: {message_text!r}",
            payload_hash_b64u=_b64u_encode(b"test-ed-payload-hash-32-bytes-19"),
            child_pid=1234,
            child_argv0="python.exe",
            ed_chain="sol",
            ed_message_kind="message_signing",
            ed_address="11111111111111111111111111111112",
            ed_message_text=message_text,
        )
        ctx["state"].add_pending(req)
        return req

    def test_pending_endpoint_returns_ed_request(self, live_server: dict[str, Any]):
        ctx = live_server
        req = self._queue_ed_sol_sign(ctx)
        body = _http_get_json(
            f"{ctx['base_url']}/v0.4/pending?phone_id={ctx['phone_id']}"
        )
        assert len(body["requests"]) == 1
        wire = body["requests"][0]
        assert wire["request_id"] == req.request_id
        assert wire["kind"] == "ed_sign"
        c = wire["context"]
        assert c["ed_chain"] == "sol"
        assert c["ed_message_kind"] == "message_signing"
        assert c["ed_address"] == "11111111111111111111111111111112"
        assert c["ed_message_text"] == "Login to demo.recto.example"

    def test_respond_with_valid_envelope_and_ed_sig_resolves_ok(
        self, live_server: dict[str, Any]
    ):
        ctx = live_server
        req = self._queue_ed_sol_sign(ctx)
        # Build a valid Ed25519 envelope sig over the payload hash.
        padding = "=" * (-len(req.payload_hash_b64u) % 4)
        hash_bytes = base64.urlsafe_b64decode(req.payload_hash_b64u + padding)
        envelope_sig = ctx["phone_priv"].sign(hash_bytes)
        # Construct a fake (but well-formed) 64-byte ed25519 signature
        # for the chain. The bootloader does NOT validate the chain
        # signature — it's opaque; just need 64 bytes after base64-decode.
        chain_sig_bytes = b"\x33" * 64
        chain_sig_b64 = base64.b64encode(chain_sig_bytes).decode("ascii")
        chain_pub_hex = "ab" * 32  # arbitrary 32-byte pubkey, 64 hex chars
        status, resp = _http_post_json(
            f"{ctx['base_url']}/v0.4/respond/{req.request_id}",
            {
                "decision": "approved",
                "signature_b64u": _b64u_encode(envelope_sig),
                "ed_signature_base64": chain_sig_b64,
                "ed_pubkey_hex": chain_pub_hex,
            },
        )
        assert status == 200
        assert resp == {"resolved": True}
        cap = ctx["captured"][0]
        assert cap["ok"] is True
        assert cap["kind"] == "ed_sign"
        assert cap["ed_signature_base64"] == chain_sig_b64
        assert cap["ed_pubkey_hex"] == chain_pub_hex
        assert cap["signature_b64u"] == _b64u_encode(envelope_sig)
        assert cap["reason"] is None
        # ETH/BTC fields should NOT be populated for an ed_sign approval.
        assert cap["eth_signature_rsv"] is None
        assert cap["btc_signature_base64"] is None

    def test_pubkey_with_0x_prefix_accepted_and_normalized(
        self, live_server: dict[str, Any]
    ):
        ctx = live_server
        req = self._queue_ed_sol_sign(ctx)
        padding = "=" * (-len(req.payload_hash_b64u) % 4)
        hash_bytes = base64.urlsafe_b64decode(req.payload_hash_b64u + padding)
        envelope_sig = ctx["phone_priv"].sign(hash_bytes)
        chain_sig_b64 = base64.b64encode(b"\x44" * 64).decode("ascii")
        prefixed = "0x" + ("cd" * 32)  # 0x + 64 hex chars = 66 chars
        status, resp = _http_post_json(
            f"{ctx['base_url']}/v0.4/respond/{req.request_id}",
            {
                "decision": "approved",
                "signature_b64u": _b64u_encode(envelope_sig),
                "ed_signature_base64": chain_sig_b64,
                "ed_pubkey_hex": prefixed,
            },
        )
        assert status == 200
        cap = ctx["captured"][0]
        assert cap["ok"] is True
        # Stored / forwarded WITHOUT the 0x prefix.
        assert cap["ed_pubkey_hex"] == "cd" * 32

    def test_respond_denied_resolves_with_no_chain_sig(self, live_server: dict[str, Any]):
        ctx = live_server
        req = self._queue_ed_sol_sign(ctx)
        status, resp = _http_post_json(
            f"{ctx['base_url']}/v0.4/respond/{req.request_id}",
            {"decision": "denied", "reason": "operator declined"},
        )
        assert status == 200
        assert resp == {"resolved": True}
        cap = ctx["captured"][0]
        assert cap["ok"] is False
        assert cap["ed_signature_base64"] is None
        assert cap["ed_pubkey_hex"] is None
        assert cap["reason"] == "operator declined"

    def test_respond_missing_chain_sig_rejects(self, live_server: dict[str, Any]):
        ctx = live_server
        req = self._queue_ed_sol_sign(ctx)
        padding = "=" * (-len(req.payload_hash_b64u) % 4)
        hash_bytes = base64.urlsafe_b64decode(req.payload_hash_b64u + padding)
        envelope_sig = ctx["phone_priv"].sign(hash_bytes)
        status, resp = _http_post_json(
            f"{ctx['base_url']}/v0.4/respond/{req.request_id}",
            {
                "decision": "approved",
                "signature_b64u": _b64u_encode(envelope_sig),
                # no ed_signature_base64
            },
        )
        assert status == 400
        assert "ed_signature_base64" in resp["detail"]
        assert ctx["captured"][0]["ok"] is False

    def test_respond_wrong_decoded_sig_length_rejects(self, live_server: dict[str, Any]):
        ctx = live_server
        req = self._queue_ed_sol_sign(ctx)
        padding = "=" * (-len(req.payload_hash_b64u) % 4)
        hash_bytes = base64.urlsafe_b64decode(req.payload_hash_b64u + padding)
        envelope_sig = ctx["phone_priv"].sign(hash_bytes)
        # 65 bytes instead of 64.
        bad_sig = base64.b64encode(b"\x00" * 65).decode("ascii")
        status, resp = _http_post_json(
            f"{ctx['base_url']}/v0.4/respond/{req.request_id}",
            {
                "decision": "approved",
                "signature_b64u": _b64u_encode(envelope_sig),
                "ed_signature_base64": bad_sig,
                "ed_pubkey_hex": "ab" * 32,
            },
        )
        assert status == 400
        assert "64 bytes" in resp["detail"]

    def test_respond_missing_pubkey_rejects(self, live_server: dict[str, Any]):
        ctx = live_server
        req = self._queue_ed_sol_sign(ctx)
        padding = "=" * (-len(req.payload_hash_b64u) % 4)
        hash_bytes = base64.urlsafe_b64decode(req.payload_hash_b64u + padding)
        envelope_sig = ctx["phone_priv"].sign(hash_bytes)
        status, resp = _http_post_json(
            f"{ctx['base_url']}/v0.4/respond/{req.request_id}",
            {
                "decision": "approved",
                "signature_b64u": _b64u_encode(envelope_sig),
                "ed_signature_base64": base64.b64encode(b"\x00" * 64).decode("ascii"),
                # no ed_pubkey_hex
            },
        )
        assert status == 400
        assert "ed_pubkey_hex" in resp["detail"]

    def test_respond_pubkey_wrong_length_rejects(self, live_server: dict[str, Any]):
        ctx = live_server
        req = self._queue_ed_sol_sign(ctx)
        padding = "=" * (-len(req.payload_hash_b64u) % 4)
        hash_bytes = base64.urlsafe_b64decode(req.payload_hash_b64u + padding)
        envelope_sig = ctx["phone_priv"].sign(hash_bytes)
        status, resp = _http_post_json(
            f"{ctx['base_url']}/v0.4/respond/{req.request_id}",
            {
                "decision": "approved",
                "signature_b64u": _b64u_encode(envelope_sig),
                "ed_signature_base64": base64.b64encode(b"\x00" * 64).decode("ascii"),
                "ed_pubkey_hex": "abcdef",  # too short
            },
        )
        assert status == 400
        assert "64 hex chars" in resp["detail"]

    def test_respond_pubkey_not_hex_rejects(self, live_server: dict[str, Any]):
        ctx = live_server
        req = self._queue_ed_sol_sign(ctx)
        padding = "=" * (-len(req.payload_hash_b64u) % 4)
        hash_bytes = base64.urlsafe_b64decode(req.payload_hash_b64u + padding)
        envelope_sig = ctx["phone_priv"].sign(hash_bytes)
        status, resp = _http_post_json(
            f"{ctx['base_url']}/v0.4/respond/{req.request_id}",
            {
                "decision": "approved",
                "signature_b64u": _b64u_encode(envelope_sig),
                "ed_signature_base64": base64.b64encode(b"\x00" * 64).decode("ascii"),
                "ed_pubkey_hex": "z" * 64,  # not hex
            },
        )
        assert status == 400
        assert "hex" in resp["detail"]

    def test_respond_bad_envelope_rejects_ed_sign(self, live_server: dict[str, Any]):
        ctx = live_server
        req = self._queue_ed_sol_sign(ctx)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )

        other = Ed25519PrivateKey.generate()
        padding = "=" * (-len(req.payload_hash_b64u) % 4)
        hash_bytes = base64.urlsafe_b64decode(req.payload_hash_b64u + padding)
        forged_envelope = other.sign(hash_bytes)
        status, resp = _http_post_json(
            f"{ctx['base_url']}/v0.4/respond/{req.request_id}",
            {
                "decision": "approved",
                "signature_b64u": _b64u_encode(forged_envelope),
                "ed_signature_base64": base64.b64encode(b"\x00" * 64).decode("ascii"),
                "ed_pubkey_hex": "ab" * 32,
            },
        )
        assert status == 400
        assert "approved-response signature invalid" in resp["detail"]
        assert ctx["captured"][0]["ok"] is False

    def test_existing_btc_path_unaffected(self, live_server: dict[str, Any]):
        """Regression: ed_sign wiring shouldn't have broken btc_sign."""
        ctx = live_server
        req = PendingRequest.new_btc(
            service="svc",
            secret="WALLET",
            phone_id=ctx["phone_id"],
            operation_description="btc alongside ed",
            payload_hash_b64u=_b64u_encode(b"btc-hash-payload-32-bytes-pad!!!"),
            child_pid=1,
            child_argv0="x",
            btc_network="mainnet",
            btc_message_kind="message_signing",
            btc_address="bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            btc_message_text="hello btc",
        )
        ctx["state"].add_pending(req)
        padding = "=" * (-len(req.payload_hash_b64u) % 4)
        hash_bytes = base64.urlsafe_b64decode(req.payload_hash_b64u + padding)
        envelope_sig = ctx["phone_priv"].sign(hash_bytes)
        sig_bytes = bytes([39]) + b"\x11" * 32 + b"\x22" * 32
        sig_b64 = base64.b64encode(sig_bytes).decode("ascii")
        status, resp = _http_post_json(
            f"{ctx['base_url']}/v0.4/respond/{req.request_id}",
            {
                "decision": "approved",
                "signature_b64u": _b64u_encode(envelope_sig),
                "btc_signature_base64": sig_b64,
            },
        )
        assert status == 200
        cap = ctx["captured"][0]
        assert cap["ok"] is True
        assert cap["kind"] == "btc_sign"
        assert cap["btc_signature_base64"] == sig_b64
        # ed fields should NOT be populated on a btc approval.
        assert cap["ed_signature_base64"] is None
        assert cap["ed_pubkey_hex"] is None

    def test_existing_eth_path_unaffected(self, live_server: dict[str, Any]):
        """Regression: ed_sign wiring shouldn't have broken eth_sign."""
        ctx = live_server
        req = PendingRequest.new_eth(
            service="svc",
            secret="WALLET",
            phone_id=ctx["phone_id"],
            operation_description="eth alongside ed",
            payload_hash_b64u=_b64u_encode(b"eth-hash-payload-32-bytes-pad!!!"),
            child_pid=1,
            child_argv0="x",
            eth_chain_id=1,
            eth_message_kind="personal_sign",
            eth_address="0x" + "ab" * 20,
            eth_message_text="hello eth",
        )
        ctx["state"].add_pending(req)
        padding = "=" * (-len(req.payload_hash_b64u) % 4)
        hash_bytes = base64.urlsafe_b64decode(req.payload_hash_b64u + padding)
        envelope_sig = ctx["phone_priv"].sign(hash_bytes)
        rsv = "0x" + "11" * 32 + "22" * 32 + "1b"
        status, resp = _http_post_json(
            f"{ctx['base_url']}/v0.4/respond/{req.request_id}",
            {
                "decision": "approved",
                "signature_b64u": _b64u_encode(envelope_sig),
                "eth_signature_rsv": rsv,
            },
        )
        assert status == 200
        cap = ctx["captured"][0]
        assert cap["ok"] is True
        assert cap["kind"] == "eth_sign"
        assert cap["eth_signature_rsv"] == rsv
        # ed fields should NOT be populated on an eth approval.
        assert cap["ed_signature_base64"] is None
        assert cap["ed_pubkey_hex"] is None

    def test_existing_single_sign_path_unaffected(self, live_server: dict[str, Any]):
        """Regression: ed_sign wiring shouldn't have broken the v0.4.0 single_sign."""
        ctx = live_server
        req = PendingRequest.new(
            kind="single_sign",
            service="svc",
            secret="KEY",
            phone_id=ctx["phone_id"],
            operation_description="vanilla single_sign",
            payload_hash_b64u=_b64u_encode(b"single-sign-32bytes-padded-to!!!"),
            child_pid=1,
            child_argv0="x",
        )
        ctx["state"].add_pending(req)
        padding = "=" * (-len(req.payload_hash_b64u) % 4)
        hash_bytes = base64.urlsafe_b64decode(req.payload_hash_b64u + padding)
        envelope_sig = ctx["phone_priv"].sign(hash_bytes)
        status, resp = _http_post_json(
            f"{ctx['base_url']}/v0.4/respond/{req.request_id}",
            {
                "decision": "approved",
                "signature_b64u": _b64u_encode(envelope_sig),
            },
        )
        assert status == 200
        cap = ctx["captured"][0]
        assert cap["ok"] is True
        assert cap["kind"] == "single_sign"
        assert cap["ed_signature_base64"] is None
        assert cap["ed_pubkey_hex"] is None
        assert cap["btc_signature_base64"] is None
        assert cap["eth_signature_rsv"] is None
