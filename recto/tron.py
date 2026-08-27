"""TRON-side helpers for the ``tron_sign`` credential kind.

Wave-9 addition (2026-04-30). TRON is a close cousin of Ethereum at
the cryptography layer: same secp256k1 curve, same Keccak-256 hash,
same uncompressed-pubkey-X||Y representation. The differences sit at
the address-encoding layer (base58check with version byte ``0x41``
instead of EIP-55 hex) and at the signed-message preamble layer
(TIP-191 ``"\\x19TRON Signed Message:\\n"`` instead of EIP-191
``"\\x19Ethereum Signed Message:\\n"``).

Architectural placement
-----------------------

This module is the launcher / bootloader / consumer-facing side of
TRON signing. It does NOT hold private keys -- those live on the
phone, derived at signing time from the operator's BIP-39 mnemonic
in platform secure storage at ``m/44'/195'/0'/0/N`` (the standard
secp256k1 BIP-32 path for TRON; SLIP-0010 ed25519 doesn't apply
because TRON is secp256k1, not ed25519).

The phone signs over a 32-byte hash. This module:
  (a) computes that hash (TIP-191 preamble + Keccak-256),
  (b) recovers the signer's public key from a (hash, rsv) pair, and
  (c) converts the recovered pubkey to a TRON base58check address so
      a verifier can compare ``recovered_address == expected_address``.

Threat model
------------

Identical to ``recto.ethereum``: no private-key material is ever on
this Python side, all secp256k1 ops are recovery / verification,
never signing. The phone-side ``MauiTronSignService`` (Wave 9 part 2)
does the actual private-key arithmetic.

Public surface
--------------

- ``BIP44_PATH_DEFAULT`` -- ``"m/44'/195'/0'/0/0"`` (standard TRON
  derivation path).
- ``MESSAGE_PREAMBLE`` -- ``b"TRON Signed Message:\\n"`` (NOTE: the
  leading ``\\x19`` byte is added by ``signed_message_hash``; this
  constant is the bare preamble string for protocol-doc reference).
- ``VERSION_BYTE_MAINNET`` -- ``0x41`` (TRON mainnet version byte;
  base58check'ing produces the canonical ``T...`` address prefix).
  TRON's testnets (Shasta, Nile) use the same version byte; the
  difference between mainnet/testnet lives at the RPC + explorer
  layer, not the address encoding.
- ``signed_message_hash(message: bytes | str) -> bytes`` -- TIP-191
  hash. Layout: ``keccak256(b"\\x19TRON Signed Message:\\n" +
  ascii(len(message)) + message)``. Same shape as EIP-191 with the
  preamble string swapped.
- ``address_from_public_key(pubkey64: bytes) -> str`` -- derive a
  TRON address from a 64-byte uncompressed secp256k1 public key
  (X||Y, no 0x04 prefix). Layout: ``base58check(0x41 ||
  keccak256(pubkey64)[-20:])``. Output is always 34 ASCII chars
  starting with ``T``.
- ``address_to_hex(address: str) -> str`` -- decode a ``T...``
  address back to its 21-byte ``0x41`` || hash160-equivalent in hex
  (``"41" + 40 hex chars``). Useful for cross-checking against
  blockchain explorers + dev debugging.
- ``recover_public_key(msg_hash, signature_rsv) -> bytes`` -- delegates
  to ``recto.ethereum.recover_public_key`` (same secp256k1 math).
  Re-exported here so consumer code can ``from recto.tron import
  recover_public_key`` without touching the ethereum module.
- ``recover_address(msg_hash, signature_rsv) -> str`` -- recover the
  signer's TRON address from a TIP-191-hashed message + rsv signature.
  This is the verifier's main entry point.
- ``verify_signature(message, signature_rsv, expected_address) ->
  bool`` -- full round-trip: hash the message via TIP-191, recover
  the signer's address, compare against ``expected_address``.

Optional extra
--------------

This module is in the ``recto[tron]`` extra. Address encoding uses
only Python stdlib (``hashlib`` for SHA-256 inside base58check).
Signature verification reuses ``recto.ethereum``'s pure-Python
secp256k1 recovery, so ``recto[tron]`` requires ``recto[ethereum]``
transitively but pulls no net-new third-party deps.
"""

from __future__ import annotations

import hashlib

from recto.ethereum import (
    keccak256,
    parse_signature_rsv,
    recover_public_key as _eth_recover_public_key,
)

__all__ = [
    "BIP44_PATH_DEFAULT",
    "MESSAGE_PREAMBLE",
    "VERSION_BYTE_MAINNET",
    "signed_message_hash",
    "address_from_public_key",
    "address_to_hex",
    "recover_public_key",
    "recover_address",
    "verify_signature",
]


# Standard TRON BIP-44 path. SLIP-0044 registry lists coin-type 195
# for TRON. The leaf ``/0`` is non-hardened (BIP-32 standard for
# secp256k1 trees, unlike SLIP-0010 ed25519 which requires every
# step hardened).
BIP44_PATH_DEFAULT = "m/44'/195'/0'/0/0"

# TIP-191 preamble. Bare string (no leading 0x19); ``signed_message_hash``
# adds the byte itself. Pinned here as a public symbol so consumer
# tooling and the protocol RFC can refer to it without duplicating
# the literal.
MESSAGE_PREAMBLE = b"TRON Signed Message:\n"

# TRON mainnet address version byte. base58check of (0x41 || hash160-
# equivalent) always starts with ``T`` once the 25-byte payload is
# encoded -- that's the canonical TRON-address visual signature.
VERSION_BYTE_MAINNET = 0x41


# ---------------------------------------------------------------------------
# Bitcoin-alphabet base58 helpers (with checksum -- TRON is base58check)
# ---------------------------------------------------------------------------
#
# Solana ships a no-checksum base58 in ``recto.solana``; Bitcoin ships
# a private-symbol base58check in ``recto.bitcoin._base58check_encode``.
# TRON wants base58check using the SAME alphabet as both. Rather than
# reach into a private symbol or duplicate the alphabet, we declare
# our own copy here so this module is self-contained and the alphabet
# stays a single source of truth per-chain (matches the Wave-8 pattern
# where each chain's encoder lives in its own module).

_BASE58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58_INDEX: dict[int, int] = {c: i for i, c in enumerate(_BASE58_ALPHABET)}


def _double_sha256(data: bytes) -> bytes:
    """Bitcoin-style double SHA-256. Used here only for the 4-byte
    base58check checksum on TRON addresses."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def _base58check_encode(payload: bytes) -> str:
    """base58check-encode ``payload`` (typically 21 bytes:
    ``version_byte || hash160-equivalent``).

    Layout:
        base58(payload || double_sha256(payload)[:4])

    Leading 0x00 bytes in the payload + checksum prefix map to leading
    ``"1"`` characters in the output -- the standard base58 leading-zero
    preservation. For a 21-byte 0x41-prefixed TRON payload, the high
    nibble means the encoding is always 34 chars starting with ``T``.
    """
    checksum = _double_sha256(payload)[:4]
    data = payload + checksum
    leading_zeros = 0
    for b in data:
        if b == 0:
            leading_zeros += 1
        else:
            break
    n = int.from_bytes(data, "big") if data else 0
    out = bytearray()
    while n > 0:
        n, r = divmod(n, 58)
        out.append(_BASE58_ALPHABET[r])
    out.reverse()
    return ("1" * leading_zeros) + out.decode("ascii")


def _base58check_decode(text: str) -> bytes:
    """Inverse of ``_base58check_encode``. Returns the ``payload``
    portion (everything except the trailing 4-byte checksum) and
    raises ``ValueError`` if the checksum doesn't match.

    Used internally by ``address_to_hex`` and the verify path. NOT
    exported as public API -- consumers usually want
    ``address_to_hex`` (which returns hex) instead of raw bytes.
    """
    if not isinstance(text, str):
        raise TypeError(
            f"_base58check_decode expects str, got {type(text).__name__}"
        )
    leading_ones = 0
    for c in text:
        if c == "1":
            leading_ones += 1
        else:
            break
    n = 0
    for c in text:
        idx = _BASE58_INDEX.get(ord(c))
        if idx is None:
            raise ValueError(f"base58 character {c!r} not in alphabet")
        n = n * 58 + idx
    body = bytearray()
    while n > 0:
        n, r = divmod(n, 256)
        body.append(r)
    body.reverse()
    full = (b"\x00" * leading_ones) + bytes(body)
    if len(full) < 5:
        raise ValueError(
            f"base58check input decodes to only {len(full)} bytes "
            f"(must be at least 5: payload + 4-byte checksum)"
        )
    payload, checksum = full[:-4], full[-4:]
    expected = _double_sha256(payload)[:4]
    if checksum != expected:
        raise ValueError(
            f"base58check checksum mismatch: payload-derived "
            f"{expected.hex()}, address-carried {checksum.hex()}"
        )
    return payload


# ---------------------------------------------------------------------------
# Address derivation
# ---------------------------------------------------------------------------


def address_from_public_key(pubkey64: bytes) -> str:
    """Derive a TRON address from a 64-byte uncompressed secp256k1
    public key (X||Y, big-endian, no leading 0x04 byte).

    Layout:
        last20 = keccak256(pubkey64)[-20:]
        payload = bytes([0x41]) + last20
        return base58check(payload)

    The first 12 bytes of the keccak digest are discarded, exactly
    as Ethereum does -- TRON's address derivation is intentionally
    interoperable with the EVM at the hash-160-equivalent layer.
    The visible difference is the version byte (0x41 vs ETH's
    implicit 0x00) and the encoding (base58check vs EIP-55 hex).
    """
    if not isinstance(pubkey64, (bytes, bytearray)):
        raise TypeError(
            f"public key must be bytes, got {type(pubkey64).__name__}"
        )
    if len(pubkey64) != 64:
        raise ValueError(
            f"TRON public key must be 64 bytes (X||Y), got {len(pubkey64)}"
        )
    last20 = keccak256(bytes(pubkey64))[-20:]
    payload = bytes([VERSION_BYTE_MAINNET]) + last20
    return _base58check_encode(payload)


def address_to_hex(address: str) -> str:
    """Decode a TRON ``T...`` base58check address back to its 21-byte
    payload as a hex string (42 chars, leading ``41`` for mainnet).

    Useful for cross-checking against blockchain explorers (Tronscan
    surfaces addresses in both forms) and for debugging mismatches
    between phone-side and verifier-side address derivation. Raises
    ``ValueError`` if the input has a bad checksum or decodes to the
    wrong length (must be exactly 21 bytes).
    """
    payload = _base58check_decode(address)
    if len(payload) != 21:
        raise ValueError(
            f"TRON address payload must be 21 bytes, got {len(payload)} "
            f"(input: {address!r})"
        )
    return payload.hex()


# ---------------------------------------------------------------------------
# Message hashing (TIP-191)
# ---------------------------------------------------------------------------


def signed_message_hash(message: bytes | str) -> bytes:
    """Compute the TIP-191 signed-message hash.

    Layout:
        keccak256(0x19 || "TRON Signed Message:\\n" || ascii(len(msg)) || msg)

    Identical structure to EIP-191 with the preamble string swapped.
    Modern TronWeb's ``signMessageV2`` produces signatures over this
    exact hash; TronLink + Phantom-for-TRON-style wallets compose to
    the same digest.

    The leading ``\\x19`` byte is the version-discriminator that's
    been load-bearing since the EIP-191 wave-4 hash audit (caught
    2026-04-28; banked as a CLAUDE.md gotcha). Any future TRON
    digest impl must include it; cross-check against an external
    verifier (TronWeb / tronpy / tronscan signature verify) before
    trusting an internal-consistency-only round-trip.
    """
    if isinstance(message, str):
        message = message.encode("utf-8")
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError(
            f"message must be bytes or str, got {type(message).__name__}"
        )
    msg_bytes = bytes(message)
    prefix = b"\x19" + MESSAGE_PREAMBLE + str(len(msg_bytes)).encode("ascii")
    return keccak256(prefix + msg_bytes)


# ---------------------------------------------------------------------------
# Signature parsing + recovery
# ---------------------------------------------------------------------------


def recover_public_key(msg_hash: bytes, signature_rsv: str | bytes) -> bytes:
    """Recover the 64-byte uncompressed public key (X||Y) that signed
    ``msg_hash`` to produce ``signature_rsv``.

    Thin re-export of ``recto.ethereum.recover_public_key`` -- TRON
    uses the same secp256k1 curve and the same r||s||v signature
    format that ETH does. Provided here so consumers can
    ``from recto.tron import recover_public_key`` without
    cross-importing.
    """
    return _eth_recover_public_key(msg_hash, signature_rsv)


def recover_address(msg_hash: bytes, signature_rsv: str | bytes) -> str:
    """Recover the TRON ``T...`` base58check address that signed
    ``msg_hash`` to produce ``signature_rsv``.

    Pipeline: rsv -> recover_public_key (64-byte X||Y) ->
    address_from_public_key. The verifier's main entry point.
    """
    pubkey64 = recover_public_key(msg_hash, signature_rsv)
    return address_from_public_key(pubkey64)


def verify_signature(
    message: bytes | str,
    signature_rsv: str | bytes,
    expected_address: str,
) -> bool:
    """Full round-trip TRON signature verification.

    Hashes ``message`` via TIP-191, recovers the signer's address
    from ``signature_rsv``, and returns True iff that recovered
    address equals ``expected_address`` (case-sensitive: TRON
    base58check addresses are case-sensitive by spec).

    Returns False on any malformed-signature path so consumer code
    can branch on the boolean rather than catch ValueError. Returns
    False on address-mismatch even if the signature is internally
    valid -- the verifier's job is to confirm the operator-approved
    address signed, not just that *someone* signed.
    """
    try:
        msg_hash = signed_message_hash(message)
        recovered = recover_address(msg_hash, signature_rsv)
    except (ValueError, TypeError):
        return False
    return recovered == expected_address
