"""Tests for the TRON signing capability through the bootloader.

Mirrors ``test_bootloader_eth.py`` and ``test_bootloader_btc.py``'s
shape: state-level construction validation for
``PendingRequest.new_tron``, then end-to-end live HTTP exercises
with the actual ``BootloaderHandler`` over a localhost loopback
socket.

The bootloader doesn't validate the secp256k1 signature itself --
its sole job is to verify the Ed25519 paired-phone envelope and
forward the opaque ``tron_signature_rsv`` to the launcher's resolver
callback. The structure-checks the bootloader DOES enforce (rsv is
130 hex chars, decodes to valid hex) are exercised here.
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


# Canonical 34-char T-prefixed TRON address from the secp256k1
# generator point G. Pinned in tests/test_tron.py against the
# external ETH-address reference for G; reused here to exercise
# the new_tron address-shape validation without re-deriving.
GENERATOR_TRON_ADDRESS = "TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC"


def _b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------------------
# State-level: PendingRequest.new_tron construction + validation
# ---------------------------------------------------------------------------


class TestNewTronConstruction:
    def _kwargs(self, **overrides: Any) -> dict[str, Any]:
        base = dict(
            service="svc",
            secret="TRON_WALLET",
            phone_id="phone1",
            operation_description="sign a TRON login message",
            payload_hash_b64u="aGFzaA",
            child_pid=1234,
            child_argv0="python.exe",
            tron_network="mainnet",
            tron_message_kind="message_signing",
            tron_address=GENERATOR_TRON_ADDRESS,
            tron_message_text="Login to demo.recto.example",
        )
        base.update(overrides)
        return base

    def test_mainnet_message_signing_happy_path(self):
        req = PendingRequest.new_tron(**self._kwargs())
        assert req.kind == "tron_sign"
        assert req.tron_network == "mainnet"
        assert req.tron_message_kind == "message_signing"
        assert req.tron_derivation_path == "m/44'/195'/0'/0/0"
        assert req.tron_address == GENERATOR_TRON_ADDRESS
        assert req.tron_message_text == "Login to demo.recto.example"
        assert req.tron_payload_hex is None

    def test_shasta_testnet_accepted(self):
        req = PendingRequest.new_tron(**self._kwargs(tron_network="shasta"))
        assert req.tron_network == "shasta"

    def test_nile_testnet_accepted(self):
        req = PendingRequest.new_tron(**self._kwargs(tron_network="nile"))
        assert req.tron_network == "nile"

    def test_rejects_unknown_network(self):
        with pytest.raises(ValueError, match="tron_network"):
            PendingRequest.new_tron(**self._kwargs(tron_network="ropsten"))

    def test_rejects_unknown_message_kind(self):
        with pytest.raises(ValueError, match="tron_message_kind"):
            PendingRequest.new_tron(
                **self._kwargs(tron_message_kind="typed_data")
            )

    def test_message_signing_requires_message_text(self):
        kwargs = self._kwargs()
        kwargs["tron_message_text"] = None
        with pytest.raises(ValueError, match="tron_message_text"):
            PendingRequest.new_tron(**kwargs)

    def test_transaction_kind_is_reserved(self):
        # tron_message_kind="transaction" is reserved for a follow-up
        # wave (TRON protobuf transaction parser not yet shipped).
        # The constructor must refuse so a phone-side impl can enable
        # it without protocol drift.
        with pytest.raises(ValueError, match="reserved"):
            PendingRequest.new_tron(
                **self._kwargs(
                    tron_message_kind="transaction",
                    tron_message_text=None,
                    tron_payload_hex="0a02deadbeef",
                )
            )

    def test_rejects_short_address(self):
        with pytest.raises(ValueError, match="tron_address"):
            PendingRequest.new_tron(**self._kwargs(tron_address="Tshort"))

    def test_rejects_non_T_prefixed_address(self):
        # Mutate one char so the address is 34 chars but doesn't start
        # with T -- new_tron's loose check refuses without diving into
        # base58check (full validation runs verifier-side).
        bad = "X" + GENERATOR_TRON_ADDRESS[1:]
        with pytest.raises(ValueError, match="tron_address"):
            PendingRequest.new_tron(**self._kwargs(tron_address=bad))

    def test_address_whitespace_stripped(self):
        req = PendingRequest.new_tron(
            **self._kwargs(tron_address=f"  {GENERATOR_TRON_ADDRESS}  ")
        )
        assert req.tron_address == GENERATOR_TRON_ADDRESS

    def test_state_persistence_round_trip(self, tmp_path: Path):
        store = StateStore(state_dir=tmp_path)
        phone = PhoneRegistration.new(
            device_label="Test Phone",
            public_key_b64u="cHViS2V5",
            supported_algorithms=("ed25519",),
        )
        store.register_phone(phone)
        req = PendingRequest.new_tron(
            service="svc",
            secret="TRON_WALLET",
            phone_id=phone.phone_id,
            operation_description="x",
            payload_hash_b64u="aGFzaA",
            child_pid=42,
            child_argv0="python.exe",
            tron_network="mainnet",
            tron_message_kind="message_signing",
            tron_address=GENERATOR_TRON_ADDRESS,
            tron_message_text="Login to demo.recto.example at 1714323456",
        )
        store.add_pending(req)
        listed = store.list_pending_for_phone(phone.phone_id)
        assert len(listed) == 1
        loaded = listed[0]
        assert loaded.kind == "tron_sign"
        assert loaded.tron_network == "mainnet"
        assert loaded.tron_address == GENERATOR_TRON_ADDRESS
        assert (
            loaded.tron_message_text
            == "Login to demo.recto.example at 1714323456"
        )


# ---------------------------------------------------------------------------
# Server-level: _pending_to_wire emits TRON fields + omits when not TRON
# ---------------------------------------------------------------------------


class TestPendingToWireTron:
    def test_tron_context_fields_emitted(self):
        req = PendingRequest.new_tron(
            service="svc",
            secret="TRON",
            phone_id="phone1",
            operation_description="x",
            payload_hash_b64u="aA",
            child_pid=1,
            child_argv0="x",
            tron_network="mainnet",
            tron_message_kind="message_signing",
            tron_address=GENERATOR_TRON_ADDRESS,
            tron_derivation_path="m/44'/195'/0'/0/3",
            tron_message_text="login",
        )
        wire = BootloaderHandler._pending_to_wire(req)
        ctx = wire["context"]
        assert wire["kind"] == "tron_sign"
        assert ctx["tron_network"] == "mainnet"
        assert ctx["tron_message_kind"] == "message_signing"
        assert ctx["tron_address"] == GENERATOR_TRON_ADDRESS
        assert ctx["tron_derivation_path"] == "m/44'/195'/0'/0/3"
        assert ctx["tron_message_text"] == "login"
        # Body field for the non-active kind absent.
        assert "tron_payload_hex" not in ctx

    def test_non_tron_kind_omits_tron_fields(self):
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
        # Existing v0.4.0 wire shape -- no TRON leakage onto non-TRON kinds.
        for key in (
            "tron_network", "tron_message_kind", "tron_address",
            "tron_derivation_path", "tron_message_text", "tron_payload_hex",
        ):
            assert key not in ctx, f"unexpected TRON key {key!r} on non-TRON wire"


# ---------------------------------------------------------------------------
# End-to-end: live HTTP, queue + GET /pending + POST /respond for tron_sign
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
                  ed_pubkey_hex=None, tron_signature_rsv=None, reason):
        captured.append({
            "request_id": req.request_id,
            "kind": req.kind,
            "ok": ok,
            "signature_b64u": signature_b64u,
            "eth_signature_rsv": eth_signature_rsv,
            "btc_signature_base64": btc_signature_base64,
            "ed_signature_base64": ed_signature_base64,
            "ed_pubkey_hex": ed_pubkey_hex,
            "tron_signature_rsv": tron_signature_rsv,
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
            "state": state,
            "phone": phone,
            "priv": priv,
            "base_url": base_url,
            "captured": captured,
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


def _make_pending(state: StateStore, phone: PhoneRegistration) -> PendingRequest:
    req = PendingRequest.new_tron(
        service="svc",
        secret="TRON_WALLET",
        phone_id=phone.phone_id,
        operation_description="sign a TRON login message",
        payload_hash_b64u="aGFzaA",
        child_pid=1234,
        child_argv0="python.exe",
        tron_network="mainnet",
        tron_message_kind="message_signing",
        tron_address=GENERATOR_TRON_ADDRESS,
        tron_message_text="Login to demo.recto.example",
    )
    state.add_pending(req)
    return req


def _envelope_signature(priv, payload_hash_b64u: str) -> str:
    """Sign the raw 32-byte hash bytes with the phone's Ed25519 key
    and return the base64url-encoded signature."""
    padding = "=" * (-len(payload_hash_b64u) % 4)
    hash_bytes = base64.urlsafe_b64decode(payload_hash_b64u + padding)
    sig_bytes = priv.sign(hash_bytes)
    return _b64u_encode(sig_bytes)


def _post_respond(base_url: str, request_id: str, body: dict[str, Any]) -> Any:
    req = urlrequest.Request(
        f"{base_url}/v0.4/respond/{request_id}",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlrequest.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except HTTPError as exc:
        return exc.status, exc.read().decode("utf-8")


# A fake but well-formed 130-hex-char rsv. The bootloader doesn't
# verify the secp256k1 signature itself; only the structure-check
# (130 hex chars after optional 0x prefix) matters at this layer.
_FAKE_RSV_130 = "0x" + ("ab" * 32) + ("cd" * 32) + "1c"  # 64 + 64 + 2 = 130


class TestRespondLiveServerTron:
    def test_good_envelope_plus_good_rsv_resolves_ok(self, live_server):
        info = live_server
        req = _make_pending(info["state"], info["phone"])
        env_sig = _envelope_signature(info["priv"], req.payload_hash_b64u)
        status, body = _post_respond(
            info["base_url"], req.request_id,
            {
                "decision": "approved",
                "signature_b64u": env_sig,
                "tron_signature_rsv": _FAKE_RSV_130,
            },
        )
        assert status == 200
        assert body == {"resolved": True}
        assert len(info["captured"]) == 1
        ev = info["captured"][0]
        assert ev["ok"] is True
        assert ev["kind"] == "tron_sign"
        assert ev["tron_signature_rsv"] == _FAKE_RSV_130
        # Other-kind sigs stay None for a tron_sign request.
        assert ev["eth_signature_rsv"] is None
        assert ev["btc_signature_base64"] is None
        assert ev["ed_signature_base64"] is None

    def test_denied_resolves_with_reason(self, live_server):
        info = live_server
        req = _make_pending(info["state"], info["phone"])
        status, body = _post_respond(
            info["base_url"], req.request_id,
            {"decision": "denied", "reason": "operator declined"},
        )
        assert status == 200
        ev = info["captured"][0]
        assert ev["ok"] is False
        assert ev["reason"] == "operator declined"
        assert ev["tron_signature_rsv"] is None

    def test_missing_rsv_rejected(self, live_server):
        info = live_server
        req = _make_pending(info["state"], info["phone"])
        env_sig = _envelope_signature(info["priv"], req.payload_hash_b64u)
        status, body = _post_respond(
            info["base_url"], req.request_id,
            {"decision": "approved", "signature_b64u": env_sig},
        )
        assert status >= 400
        ev = info["captured"][0]
        assert ev["ok"] is False
        assert "tron_signature_rsv missing" in (ev["reason"] or "")

    def test_wrong_length_rsv_rejected(self, live_server):
        info = live_server
        req = _make_pending(info["state"], info["phone"])
        env_sig = _envelope_signature(info["priv"], req.payload_hash_b64u)
        # 128 hex chars -- one byte short.
        bad_rsv = "0x" + ("ab" * 32) + ("cd" * 32)
        status, body = _post_respond(
            info["base_url"], req.request_id,
            {
                "decision": "approved",
                "signature_b64u": env_sig,
                "tron_signature_rsv": bad_rsv,
            },
        )
        assert status >= 400
        ev = info["captured"][0]
        assert ev["ok"] is False
        assert "wrong length" in (ev["reason"] or "")

    def test_non_hex_rsv_rejected(self, live_server):
        info = live_server
        req = _make_pending(info["state"], info["phone"])
        env_sig = _envelope_signature(info["priv"], req.payload_hash_b64u)
        # Right length but contains non-hex chars.
        bad_rsv = "z" * 130
        status, body = _post_respond(
            info["base_url"], req.request_id,
            {
                "decision": "approved",
                "signature_b64u": env_sig,
                "tron_signature_rsv": bad_rsv,
            },
        )
        assert status >= 400
        ev = info["captured"][0]
        assert ev["ok"] is False
        assert "not hex" in (ev["reason"] or "")

    def test_forged_envelope_rejected(self, live_server):
        info = live_server
        req = _make_pending(info["state"], info["phone"])
        # Forged Ed25519 envelope -- not signed by the registered phone.
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        attacker = Ed25519PrivateKey.generate()
        padding = "=" * (-len(req.payload_hash_b64u) % 4)
        hash_bytes = base64.urlsafe_b64decode(req.payload_hash_b64u + padding)
        forged_sig = _b64u_encode(attacker.sign(hash_bytes))
        status, body = _post_respond(
            info["base_url"], req.request_id,
            {
                "decision": "approved",
                "signature_b64u": forged_sig,
                "tron_signature_rsv": _FAKE_RSV_130,
            },
        )
        assert status >= 400
        ev = info["captured"][0]
        assert ev["ok"] is False
        assert "signature verification failed" in (ev["reason"] or "")
        # Forged-envelope path must NOT leak a tron_signature_rsv to
        # the resolver; only verified-and-approved tron_sign reaches
        # the rsv-extraction stage.
        assert ev["tron_signature_rsv"] is None

    def test_non_tron_single_sign_regression(self, live_server):
        # Plain single_sign request (no tron_*) must still work and
        # MUST NOT carry a tron_signature_rsv into notify_fn even if
        # the body happens to include one.
        info = live_server
        req = PendingRequest.new(
            kind="single_sign",
            service="svc",
            secret="API_KEY",
            phone_id=info["phone"].phone_id,
            operation_description="single sign",
            payload_hash_b64u="aGFzaA",
            child_pid=1234,
            child_argv0="python.exe",
        )
        info["state"].add_pending(req)
        env_sig = _envelope_signature(info["priv"], req.payload_hash_b64u)
        status, body = _post_respond(
            info["base_url"], req.request_id,
            {
                "decision": "approved",
                "signature_b64u": env_sig,
                # Even if the client mistakenly sends this on a
                # non-tron request, the server must ignore it and
                # not surface it to notify_fn.
                "tron_signature_rsv": _FAKE_RSV_130,
            },
        )
        assert status == 200
        ev = info["captured"][0]
        assert ev["ok"] is True
        assert ev["kind"] == "single_sign"
        assert ev["tron_signature_rsv"] is None
