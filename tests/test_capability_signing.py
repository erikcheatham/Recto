"""Tests for ``recto/capability/signing.py``: a minted JWS verifies with the
stdlib verifier; signatures are low-s; the key's public half is canonical."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from recto.capability.jwt import verify_jws
from recto.capability.types import CapabilityClaims, CapabilityClause, CapabilityScope

pytest.importorskip("cryptography")

from recto.capability.signing import mint_jws, public_key_hex, sign_digest  # noqa: E402

_MANIFEST_VERSION: str = json.loads(
    (Path(__file__).parent.parent / "recto" / "capability" / "manifest_v1.json")
    .read_text(encoding="utf-8")
)["version"]

_KEY = bytes.fromhex("1" * 64)
_NOW = 1_800_000_000


def _claims() -> CapabilityClaims:
    return CapabilityClaims(
        iss="bootloader:bl-test", sub="user:user-1", aud=["consumer"],
        iat=_NOW, nbf=_NOW, exp=_NOW + 300, jti="jti-1",
        cap=CapabilityClause(tier=0, registry_version=_MANIFEST_VERSION,
                             scope=CapabilityScope(payload_sha256="ab" * 32),
                             allow_actions=["devices:pair_result"]),
        purpose="test", max_uses=1,
    )


def test_public_key_is_128_lowercase_hex():
    pub = public_key_hex(_KEY)
    assert len(pub) == 128 and pub == pub.lower()
    int(pub, 16)


def test_signature_is_64_bytes_low_s():
    sig = sign_digest(b"\x42" * 32, _KEY)
    assert len(sig) == 64
    s = int.from_bytes(sig[32:], "big")
    assert s <= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 // 2


def test_minted_jws_verifies_with_the_stdlib_verifier():
    jws = mint_jws(_claims(), _KEY)
    claims = verify_jws(jws, expected_pubkey=bytes.fromhex(public_key_hex(_KEY)),
                        expected_aud="consumer", now=_NOW + 1)
    assert claims.cap.scope.payload_sha256 == "ab" * 32
    assert claims.cap.allow_actions == ["devices:pair_result"]


def test_minted_jws_does_not_verify_with_another_key():
    jws = mint_jws(_claims(), _KEY)
    other = bytes.fromhex("2" * 64)
    with pytest.raises(ValueError, match="signature"):
        verify_jws(jws, expected_pubkey=bytes.fromhex(public_key_hex(other)), now=_NOW + 1)


@pytest.mark.parametrize("bad", [b"\x00" * 31, b"\x00" * 33])
def test_wrong_digest_length_is_refused(bad):
    with pytest.raises(ValueError):
        sign_digest(bad, _KEY)
