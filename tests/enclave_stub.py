"""In-memory Ed25519 SigningCapability backend — TEST FIXTURE ONLY.

RELOCATED 2026-08-05 from ``recto/secrets/enclave_stub.py``. It used to
ship inside the installed package with a registered ``enclave-stub``
selector, meaning every production install carried a server-resident
software-key backend that a single ``service.yaml`` edit could activate.
Nothing production-side ever referenced it — but "unreferenced" is a
weaker guarantee than "absent", so the stub now lives in the test tree,
which ``pip install recto`` never ships (``[tool.setuptools.packages.find]
include = ["recto*"]``). The registry's ``register_source()`` remains the
sanctioned seam for tests (or integrators' test suites) to register this
class themselves; the production package no longer knows the selector.

The production v0.4 backend is `recto.secrets.enclave` (TBD), which routes
sign requests to a phone-resident vault via the bootloader (see
`docs/v0.4-protocol.md`). That backend depends on real hardware -- you
can't unit-test it without a phone enclave producing real signatures.

This stub fills the gap: it generates an Ed25519 keypair in process
memory, holds the private key directly, and returns a SigningCapability
whose `sign` callable signs locally with that in-process key. The
launcher's SigningCapability handling code path can then be exercised
end-to-end without any phone or network dependency.

DO NOT USE IN PRODUCTION. The whole point of v0.4 is that private keys
DON'T sit on the server; this backend defeats that by definition.

Persistence shape:

By default each `EnclaveStubSource(service)` generates a fresh keypair
on construction. For tests that need a stable public key across runs
(e.g. asserting on a specific signature value), pass
`seed_b64u=<32-byte base64url>` to derive the keypair deterministically
from the seed. The seed is NOT a secret in this stub -- it lives in
test code and exists only to make assertions reproducible.
"""

from __future__ import annotations

import base64
from typing import Any

from recto.secrets.base import (
    SecretMaterial,
    SecretSource,
    SecretSourceError,
    SigningCapability,
)

__all__ = [
    "EnclaveStubSource",
]


def _b64u_decode(s: str) -> bytes:
    """Decode a base64url string (no padding required)."""
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def _b64u_encode(b: bytes) -> str:
    """Encode bytes as base64url (no padding)."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


class EnclaveStubSource(SecretSource):
    """In-memory Ed25519 backend. NOT FOR PRODUCTION.

    Constructor takes the service name (as in metadata.name from
    service.yaml). Each instance owns one Ed25519 keypair, used for
    every secret_name fetched via this instance. The launcher's
    expected behavior is that each `(service, secret)` pair gets its
    own SecretSource instance -- so distinct keys per secret are
    achieved at the registry layer, not here.

    Args:
        service: Logical service name. Forwarded into SigningCapability
            metadata for diagnostic purposes; not load-bearing.
        seed_b64u: Optional 32-byte base64url-encoded seed. When
            provided, the keypair is derived deterministically. When
            None (default), a fresh random keypair is generated.

    Raises:
        SecretSourceError: if `cryptography` is not installed (the
            stub depends on `pip install recto[v0_4]` for the Ed25519
            primitives).
    """

    def __init__(self, service: str, *, seed_b64u: str | None = None):
        if not service:
            raise SecretSourceError(
                "EnclaveStubSource requires a non-empty service name"
            )
        if ":" in service:
            raise SecretSourceError(
                f"service name must not contain ':' (got {service!r})"
            )
        self._service = service

        # Lazy-import cryptography. Without the [v0_4] extra installed,
        # the import error surfaces with a clear remediation message
        # rather than a cryptic AttributeError downstream.
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )
        except ImportError as exc:
            raise SecretSourceError(
                "EnclaveStubSource requires the `cryptography` package; "
                "install via `pip install recto[v0_4]`."
            ) from exc

        if seed_b64u is not None:
            seed = _b64u_decode(seed_b64u)
            if len(seed) != 32:
                raise SecretSourceError(
                    f"seed must decode to 32 bytes; got {len(seed)}"
                )
            self._private_key = Ed25519PrivateKey.from_private_bytes(seed)
        else:
            self._private_key = Ed25519PrivateKey.generate()

        # Cache the public-key bytes so list_names() / fetch() don't
        # re-derive on every call.
        from cryptography.hazmat.primitives import serialization

        self._public_key_bytes = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @property
    def name(self) -> str:
        return "enclave-stub"

    @property
    def service(self) -> str:
        return self._service

    @property
    def public_key_b64u(self) -> str:
        """Base64url-encoded public key. Useful for tests that need to
        verify signatures the stub produced."""
        return _b64u_encode(self._public_key_bytes)

    def fetch(self, secret_name: str, config: dict[str, Any]) -> SecretMaterial:
        """Return a SigningCapability backed by the in-process key.

        The `sign` callable in the returned SigningCapability is a
        closure over `self._private_key`. Each call signs the input
        bytes and returns the 64-byte raw Ed25519 signature.

        `secret_name` is recorded in the SigningCapability metadata
        (via the `algorithm` field by convention here) but doesn't
        change the signing key -- this stub uses one key per source
        instance regardless of `secret_name`. Production backends that
        scope keys per-secret implement that at the source layer.
        """
        del config  # unused for this backend; no required/optional logic

        # Capture private key by closure. Frozen dataclass + the
        # SecretMaterial __repr__ override keep the key from leaking
        # via logging / repr.
        priv = self._private_key

        def sign(payload: bytes) -> bytes:
            return priv.sign(payload)

        return SigningCapability(
            sign=sign,
            public_key=self._public_key_bytes,
            algorithm="ed25519",
        )

    def list_names(self) -> list[str]:
        """Stub doesn't track per-secret names (one key per instance).

        Returns the empty list rather than fabricating a fake inventory
        -- the recto secrets list command will skip this backend by
        design.
        """
        return []

    def supports_lifecycle(self) -> bool:
        return False

    def supports_rotation(self) -> bool:
        # Rotation in the production enclave backend means "phone
        # generates a new keypair." The stub could simulate by
        # regenerating in-process, but rotate() semantics across all
        # backends should be uniform; for now the stub doesn't claim
        # support and tests that need new keys construct new instances.
        return False
