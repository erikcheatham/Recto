"""Tests for recto.bootloader.sessions.

JWT EdDSA verify, raw Ed25519 signature verify, canonical payload
shapes. All tests require the [v0_4] extra (cryptography + pyjwt)
since the module wraps both libraries.
"""

from __future__ import annotations

import base64
import time
from typing import Any

import pytest

from recto.bootloader import BootloaderError
from recto.bootloader.sessions import (
    SessionClaims,
    build_session_issuance_payload,
    build_sign_request_payload,
    verify_jwt,
    verify_signature,
)
from tests.enclave_stub import EnclaveStubSource


def _b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64u_decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


@pytest.fixture
def signing_pair() -> tuple[Any, str]:
    """Returns (Ed25519PrivateKey, public_key_b64u). Used by tests
    that need to mint signatures to verify against."""
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


# ---------------------------------------------------------------------------
# verify_signature
# ---------------------------------------------------------------------------


class TestVerifySignature:
    def test_valid_signature_returns_true(
        self, signing_pair: tuple[Any, str]
    ) -> None:
        priv, pub_b64u = signing_pair
        payload = b"hello, recto"
        sig = priv.sign(payload)
        assert verify_signature(
            payload=payload, signature_b64u=_b64u_encode(sig),
            public_key_b64u=pub_b64u,
        ) is True

    def test_wrong_key_returns_false(
        self, signing_pair: tuple[Any, str]
    ) -> None:
        priv, _pub = signing_pair
        # Sign with priv but verify against a different key.
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        other = Ed25519PrivateKey.generate()
        other_pub = other.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        payload = b"x"
        sig = priv.sign(payload)
        assert verify_signature(
            payload=payload, signature_b64u=_b64u_encode(sig),
            public_key_b64u=_b64u_encode(other_pub),
        ) is False

    def test_tampered_payload_returns_false(
        self, signing_pair: tuple[Any, str]
    ) -> None:
        priv, pub_b64u = signing_pair
        sig = priv.sign(b"original")
        assert verify_signature(
            payload=b"tampered", signature_b64u=_b64u_encode(sig),
            public_key_b64u=pub_b64u,
        ) is False

    def test_wrong_length_signature_returns_false(
        self, signing_pair: tuple[Any, str]
    ) -> None:
        _priv, pub_b64u = signing_pair
        short_sig = _b64u_encode(b"\x00" * 32)  # only 32 bytes; Ed25519 needs 64
        assert verify_signature(
            payload=b"x", signature_b64u=short_sig, public_key_b64u=pub_b64u,
        ) is False


# ---------------------------------------------------------------------------
# verify_jwt
# ---------------------------------------------------------------------------


class TestVerifyJwt:
    def _mint_jwt(
        self, signing_pair: tuple[Any, str], **claim_overrides: Any,
    ) -> str:
        """Mint an EdDSA-signed JWT using the test keypair."""
        import jwt

        priv, _pub = signing_pair
        now = int(time.time())
        claims = {
            "iss": "test-phone-fingerprint",
            "sub": "myservice:MY_KEY",
            "aud": "test-bootloader-id",
            "iat": now,
            "exp": now + 3600,
            "jti": "test-jti-123",
            "recto:scope": ["sign"],
            "recto:max_uses": 1000,
            **claim_overrides,
        }
        return jwt.encode(claims, priv, algorithm="EdDSA")

    def test_valid_jwt_parses_claims(
        self, signing_pair: tuple[Any, str]
    ) -> None:
        _priv, pub_b64u = signing_pair
        token = self._mint_jwt(signing_pair)
        claims = verify_jwt(
            token, public_key_b64u=pub_b64u, audience="test-bootloader-id",
        )
        assert isinstance(claims, SessionClaims)
        assert claims.service == "myservice"
        assert claims.secret == "MY_KEY"
        assert claims.aud == "test-bootloader-id"
        assert claims.recto_max_uses == 1000

    def test_expired_jwt_raises(
        self, signing_pair: tuple[Any, str]
    ) -> None:
        _priv, pub_b64u = signing_pair
        now = int(time.time())
        token = self._mint_jwt(signing_pair, exp=now - 100, iat=now - 200)
        with pytest.raises(BootloaderError) as exc_info:
            verify_jwt(
                token, public_key_b64u=pub_b64u, audience="test-bootloader-id",
            )
        assert "expired" in str(exc_info.value).lower()

    def test_wrong_audience_raises(
        self, signing_pair: tuple[Any, str]
    ) -> None:
        _priv, pub_b64u = signing_pair
        token = self._mint_jwt(signing_pair)
        with pytest.raises(BootloaderError) as exc_info:
            verify_jwt(
                token, public_key_b64u=pub_b64u, audience="different-bootloader",
            )
        assert "audience" in str(exc_info.value).lower()

    def test_wrong_signing_key_raises(
        self, signing_pair: tuple[Any, str]
    ) -> None:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        token = self._mint_jwt(signing_pair)
        # Verify against a different key.
        other = Ed25519PrivateKey.generate()
        other_pub = other.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        with pytest.raises(BootloaderError):
            verify_jwt(
                token, public_key_b64u=_b64u_encode(other_pub),
                audience="test-bootloader-id",
            )

    def test_session_claims_is_expired_property(self) -> None:
        now = int(time.time())
        live = SessionClaims(
            iss="x", sub="s:k", aud="b", exp=now + 100, iat=now,
            jti="j", recto_scope=("sign",), recto_max_uses=10,
        )
        expired = SessionClaims(
            iss="x", sub="s:k", aud="b", exp=now - 100, iat=now - 200,
            jti="j", recto_scope=("sign",), recto_max_uses=10,
        )
        assert live.is_expired is False
        assert expired.is_expired is True


# ---------------------------------------------------------------------------
# Canonical payload builders
# ---------------------------------------------------------------------------


class TestPayloadBuilders:
    def test_session_issuance_payload_shape(self) -> None:
        body = build_session_issuance_payload(
            service="myservice", secret="KEY",
            bootloader_id="bl-uuid", lifetime_seconds=3600, max_uses=500,
        )
        assert body == {
            "sub": "myservice:KEY",
            "aud": "bl-uuid",
            "recto:scope": ["sign"],
            "recto:max_uses": 500,
            "recto:lifetime_seconds": 3600,
        }

    def test_sign_request_payload_shape(self) -> None:
        body = build_sign_request_payload(
            service="myservice", secret="KEY",
            payload_hash_b64u="aGFzaA",
            requested_at_unix=1714175400, request_id="req-123",
        )
        assert body == {
            "request_id": "req-123",
            "service": "myservice",
            "secret": "KEY",
            "payload_hash_b64u": "aGFzaA",
            "requested_at_unix": 1714175400,
        }


# ---------------------------------------------------------------------------
# End-to-end with EnclaveStubSource as the signer
# ---------------------------------------------------------------------------


class TestEndToEndWithStub:
    def test_stub_signature_verifies_via_helper(self) -> None:
        """The stub backend signs; verify_signature confirms.

        This wires the stub to bootloader's verify path the way real
        v0.4 will (phone signs, bootloader verifies). For the stub case
        we sign locally and verify locally; the contract is identical."""
        from recto.secrets.base import SigningCapability

        src = EnclaveStubSource("svc")
        cap = src.fetch("MY_KEY", {})
        assert isinstance(cap, SigningCapability)
        payload = b"some bytes to sign"
        sig = cap.sign(payload)
        assert verify_signature(
            payload=payload,
            signature_b64u=_b64u_encode(sig),
            public_key_b64u=src.public_key_b64u,
        ) is True
