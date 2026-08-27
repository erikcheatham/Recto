"""Tests for tests/enclave_stub.py (relocated 2026-08-05 from
recto.secrets.enclave_stub — the stub no longer ships in the package).

The stub backend exists to exercise the launcher's SigningCapability
code path without phone hardware. Tests verify:
- Round-trip signing produces verifiable Ed25519 signatures.
- Deterministic seed produces stable keypairs across instances.
- Construction validates service-name shape.
- list_names returns empty (per stub design).
- Lazy cryptography import surfaces a clear error when [v0_4] extra
  is missing (skipped when extra IS installed).

Each test is platform-independent; the stub is the same on every OS.
"""

from __future__ import annotations

import base64

import pytest

from recto.secrets import SecretSourceError, SigningCapability
from tests.enclave_stub import EnclaveStubSource


# ---------------------------------------------------------------------------
# Construction / validation
# ---------------------------------------------------------------------------


class TestConstruction:
    def test_empty_service_rejected(self) -> None:
        with pytest.raises(SecretSourceError):
            EnclaveStubSource("")

    def test_colon_in_service_rejected(self) -> None:
        with pytest.raises(SecretSourceError):
            EnclaveStubSource("svc:bad")

    def test_default_construction_generates_random_key(self) -> None:
        a = EnclaveStubSource("svc")
        b = EnclaveStubSource("svc")
        # Two fresh instances MUST have different public keys.
        assert a.public_key_b64u != b.public_key_b64u

    def test_seed_reproduces_same_key(self) -> None:
        seed = base64.urlsafe_b64encode(b"\x01" * 32).rstrip(b"=").decode("ascii")
        a = EnclaveStubSource("svc", seed_b64u=seed)
        b = EnclaveStubSource("svc", seed_b64u=seed)
        assert a.public_key_b64u == b.public_key_b64u

    def test_bad_seed_length_rejected(self) -> None:
        bad = base64.urlsafe_b64encode(b"\x01" * 16).rstrip(b"=").decode("ascii")
        with pytest.raises(SecretSourceError):
            EnclaveStubSource("svc", seed_b64u=bad)


# ---------------------------------------------------------------------------
# fetch / SigningCapability shape
# ---------------------------------------------------------------------------


class TestFetch:
    def test_fetch_returns_signing_capability(self) -> None:
        src = EnclaveStubSource("svc")
        result = src.fetch("MY_KEY", {})
        assert isinstance(result, SigningCapability)
        assert result.algorithm == "ed25519"
        assert len(result.public_key) == 32

    def test_signing_capability_signs_round_trip(self) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )

        src = EnclaveStubSource("svc")
        cap = src.fetch("MY_KEY", {})
        assert isinstance(cap, SigningCapability)
        payload = b"hello, recto v0.4"
        signature = cap.sign(payload)
        assert isinstance(signature, bytes)
        assert len(signature) == 64
        # Verify with the public key from the capability.
        pub = Ed25519PublicKey.from_public_bytes(cap.public_key)
        pub.verify(signature, payload)  # raises on invalid

    def test_different_payloads_produce_different_signatures(self) -> None:
        src = EnclaveStubSource("svc")
        cap = src.fetch("MY_KEY", {})
        assert isinstance(cap, SigningCapability)
        sig1 = cap.sign(b"payload one")
        sig2 = cap.sign(b"payload two")
        assert sig1 != sig2

    def test_same_payload_produces_same_signature(self) -> None:
        # Ed25519 is deterministic (RFC 8032): same key + same payload -> same sig.
        src = EnclaveStubSource("svc")
        cap = src.fetch("MY_KEY", {})
        assert isinstance(cap, SigningCapability)
        sig1 = cap.sign(b"payload")
        sig2 = cap.sign(b"payload")
        assert sig1 == sig2

    def test_secret_name_does_not_change_key(self) -> None:
        # Stub uses one key per source instance regardless of secret_name.
        # Production backends scope keys per-secret at the registry layer.
        src = EnclaveStubSource("svc")
        cap_a = src.fetch("KEY_A", {})
        cap_b = src.fetch("KEY_B", {})
        assert isinstance(cap_a, SigningCapability)
        assert isinstance(cap_b, SigningCapability)
        assert cap_a.public_key == cap_b.public_key


# ---------------------------------------------------------------------------
# Misc backend conformance
# ---------------------------------------------------------------------------


class TestBackendConformance:
    def test_name_is_stub_selector(self) -> None:
        assert EnclaveStubSource("svc").name == "enclave-stub"

    def test_service_property_echoes_construction(self) -> None:
        assert EnclaveStubSource("myservice").service == "myservice"

    def test_list_names_returns_empty(self) -> None:
        assert EnclaveStubSource("svc").list_names() == []

    def test_does_not_support_lifecycle(self) -> None:
        assert EnclaveStubSource("svc").supports_lifecycle() is False

    def test_does_not_support_rotation(self) -> None:
        assert EnclaveStubSource("svc").supports_rotation() is False


# ---------------------------------------------------------------------------
# Repr / str safety -- secrets MUST NOT leak via repr
# ---------------------------------------------------------------------------


class TestReprSafety:
    def test_signing_capability_repr_does_not_leak_key(self) -> None:
        src = EnclaveStubSource("svc")
        cap = src.fetch("MY_KEY", {})
        rep = repr(cap)
        # No part of the public-key bytes (or anything resembling them)
        # should appear in repr. The frozen-dataclass __repr__ override
        # should produce just "<SigningCapability algorithm='ed25519' redacted>".
        assert "redacted" in rep
        assert "ed25519" in rep
        # The actual public-key b64 MUST NOT appear.
        assert isinstance(cap, SigningCapability)
        assert base64.urlsafe_b64encode(cap.public_key).decode("ascii") not in rep
