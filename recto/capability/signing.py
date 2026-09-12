"""
ES256K signing for bodies that hold a key of their own (a bootloader
signing its pairing result). Uses ``cryptography`` (the v0_4 extra) —
the verify side stays pure stdlib. A configured key with the library
absent is refused at startup, never at request time.
"""

from __future__ import annotations

import hashlib
from typing import Any

from recto.capability.jwt import assemble_jws, build_signing_input
from recto.capability.types import CapabilityClaims

_SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class SigningUnavailable(RuntimeError):
    """The ``cryptography`` extra is not installed."""


def _ec() -> tuple[Any, Any, Any, Any]:
    try:
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, utils
    except ImportError as exc:  # pragma: no cover - exercised by the startup refusal test
        raise SigningUnavailable(
            "ES256K signing needs 'cryptography' (the recto[v0_4] extra)"
        ) from exc
    return default_backend, hashes, ec, utils


def require_signing() -> None:
    """Raise ``SigningUnavailable`` unless the extra is importable."""
    _ec()


def public_key_hex(private_key: bytes) -> str:
    """128 lowercase hex (X||Y, no 0x04) for a 32-byte private key."""
    default_backend, _, ec, _ = _ec()
    priv = ec.derive_private_key(int.from_bytes(private_key, "big"), ec.SECP256K1(), default_backend())
    nums = priv.public_key().public_numbers()
    return (nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")).hex()


def sign_digest(digest: bytes, private_key: bytes) -> bytes:
    """64-byte r||s (low-s) over a 32-byte digest."""
    if len(digest) != 32:
        raise ValueError(f"digest must be 32 bytes, got {len(digest)}")
    if len(private_key) != 32:
        raise ValueError(f"private key must be 32 bytes, got {len(private_key)}")
    default_backend, hashes, ec, utils = _ec()
    priv = ec.derive_private_key(int.from_bytes(private_key, "big"), ec.SECP256K1(), default_backend())
    der = priv.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    r, s = utils.decode_dss_signature(der)
    if s > _SECP256K1_N // 2:
        s = _SECP256K1_N - s
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def mint_jws(claims: CapabilityClaims, private_key: bytes) -> str:
    """Sign ``claims`` into a 3-part ES256K JWS."""
    digest, header_b64, payload_b64 = build_signing_input(claims)
    return assemble_jws(header_b64, payload_b64, sign_digest(digest, private_key))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
