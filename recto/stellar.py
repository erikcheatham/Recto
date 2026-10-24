"""Stellar-side helpers for the ed_sign credential kind (chain="xlm").

This module is the launcher / bootloader / consumer-facing side of the
XLM flavor of ``ed_sign``. It does NOT hold private keys — those live
exclusively on the phone, derived at signing time from the operator's
BIP-39 mnemonic in platform secure storage at the SLIP-0010 ed25519
hardened path ``m/44'/148'/N'`` (SEP-0005 convention; only three path
components, all hardened, because Stellar's ecosystem standardized on
a flatter HD shape than Bitcoin / Solana).

Threat model
------------

- Private keys are NEVER on this Python side. Every operation here is
  either (a) hashing a payload to produce something the phone signs,
  (b) deriving an XLM address from a known public key, or (c)
  verifying a 64-byte ed25519 signature returned by the phone matches
  an expected (message, public-key) pair.
- ed25519 verification, when wanted, delegates to the ``cryptography``
  package (consistent with ``recto.solana`` and
  ``recto.bootloader.sessions``).
- StrKey encoding (the ``G…`` account-public-key format) is base32
  with a version byte and a 16-bit CRC16-XMODEM checksum. Pure-stdlib.
  Reference: SEP-0023 ("Strkey representation") for the encoding
  format and CRC polynomial.

Public surface
--------------

- ``BIP44_PATH_DEFAULT`` — ``"m/44'/148'/0'"`` (SEP-0005).
- ``MESSAGE_PREAMBLE`` — Recto's chosen Stellar off-chain message
  preamble (``b"Stellar signed message:\\n"``). Stellar has no canonical
  off-chain signed-message standard akin to EIP-191 — most usage signs
  transaction envelopes, not raw messages — so we pin a Recto-specific
  convention. Phone-side and verifier-side must agree.
- ``VERSION_BYTE_ACCOUNT_PUBLIC`` — ``0x30`` (the byte that makes a
  StrKey start with ``G``).
- ``crc16_xmodem(data: bytes) -> int`` — CRC16-XMODEM (poly 0x1021,
  init 0x0000) used by StrKey checksumming.
- ``strkey_encode(version_byte: int, payload: bytes) -> str`` — encode
  ``version_byte || payload || crc16(version_byte||payload)`` in
  RFC-4648 base32 (no padding, uppercase).
- ``strkey_decode(text: str) -> tuple[int, bytes]`` — reverse; returns
  ``(version_byte, payload)``. Raises ValueError on bad checksum, bad
  length, or bad base32 characters.
- ``address_from_public_key(pubkey32: bytes) -> str`` — derive a
  ``G…`` account address from a 32-byte ed25519 public key.
- ``public_key_from_address(address: str) -> bytes`` — reverse.
- ``signed_message_hash(message: bytes | str) -> bytes`` — 32-byte
  SHA-256 hash of ``MESSAGE_PREAMBLE + message``.
- ``verify_signature(message, signature, public_key) -> bool``.
- ``verify_signature_against_address(message, signature, expected_address) -> bool``.

Optional extra
--------------

This module is in the ``recto[ed25519]`` extra (alongside
``recto.solana`` and ``recto.ripple``). Address encoding and message
hashing use only Python stdlib (``hashlib`` for SHA-256, base32 via
``base64.b32encode/decode``, hand-rolled CRC16-XMODEM). Signature
verification requires ``cryptography>=42``.
"""

from __future__ import annotations

import base64
import hashlib

__all__ = [
    "BIP44_PATH_DEFAULT",
    "MESSAGE_PREAMBLE",
    "VERSION_BYTE_ACCOUNT_PUBLIC",
    "VERSION_BYTE_SEED",
    "VERSION_BYTE_PRE_AUTH_TX",
    "VERSION_BYTE_HASH_X",
    "VERSION_BYTE_MUXED_ACCOUNT",
    "VERSION_BYTE_SIGNED_PAYLOAD",
    "crc16_xmodem",
    "strkey_encode",
    "strkey_decode",
    "address_from_public_key",
    "public_key_from_address",
    "signed_message_hash",
    "verify_signature",
    "verify_signature_against_address",
]


# SEP-0005 path. All three components hardened (SLIP-0010 ed25519
# requires hardened-only). Stellar's wallet ecosystem standardized on
# this 3-component shape rather than BIP-44's 5-component shape.
BIP44_PATH_DEFAULT = "m/44'/148'/0'"

# Recto's chosen XLM off-chain message preamble. Stellar has no
# canonical off-chain message-signing standard — the ecosystem signs
# transaction envelopes (hash = sha256(network_id || envelope_type ||
# transaction_signature_payload)) for on-chain ops. For Recto's
# message_signing modality we pin a stable preamble; transaction
# signing (kind="transaction") uses the canonical XDR envelope hash
# instead.
MESSAGE_PREAMBLE = b"Stellar signed message:\n"

# StrKey version bytes (SEP-0023). Each is a 5-bit value left-shifted
# 3 to align with the base32 alphabet's first character. The first
# character of the encoded string is determined by the version byte
# (G for account, S for seed, T for pre-auth-tx, X for hash-x, etc.).
VERSION_BYTE_ACCOUNT_PUBLIC = 6 << 3  # 0x30 — strings start with 'G'
VERSION_BYTE_SEED = 18 << 3           # 0x90 — strings start with 'S' (private key — never produced here)
VERSION_BYTE_PRE_AUTH_TX = 19 << 3    # 0x98 — strings start with 'T'
VERSION_BYTE_HASH_X = 23 << 3         # 0xB8 — strings start with 'X'
VERSION_BYTE_MUXED_ACCOUNT = 12 << 3  # 0x60 — strings start with 'M' (muxed = subaccount)
VERSION_BYTE_SIGNED_PAYLOAD = 11 << 3  # 0x58 — strings start with 'P'


# ---------------------------------------------------------------------------
# CRC16-XMODEM (polynomial 0x1021, initial value 0x0000, no reflection,
# final XOR 0x0000). Matches the CRC used by StrKey checksumming.
# ---------------------------------------------------------------------------


def crc16_xmodem(data: bytes) -> int:
    """Compute CRC16-XMODEM over ``data``. Returns a 16-bit unsigned int.

    Polynomial 0x1021, initial value 0x0000, no input/output reflection,
    final XOR 0x0000. This matches the CRC variant Stellar uses for
    StrKey checksumming (per SEP-0023). Bit-by-bit reference impl —
    Stellar StrKeys are short (35 input bytes) so a table-free
    implementation is fine.
    """
    crc = 0
    for byte in data:
        crc ^= (byte & 0xFF) << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


# ---------------------------------------------------------------------------
# StrKey encoding (SEP-0023)
# ---------------------------------------------------------------------------


def strkey_encode(version_byte: int, payload: bytes) -> str:
    """Encode ``payload`` as a Stellar StrKey with the given version byte.

    Layout:
        base32(version_byte || payload || crc16_xmodem(version_byte||payload))

    The base32 encoding is RFC 4648 uppercase with NO padding. For an
    account public key (version=0x30, payload=32 bytes) the output is
    exactly 56 characters and starts with 'G'.

    The CRC checksum is little-endian (low byte first), per SEP-0023.
    """
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError(f"payload must be bytes, got {type(payload).__name__}")
    if not 0 <= version_byte <= 0xFF:
        raise ValueError(
            f"version_byte must be a single byte (0..255), got {version_byte}"
        )
    head = bytes([version_byte]) + bytes(payload)
    crc = crc16_xmodem(head)
    # CRC is appended LITTLE-endian (low byte first) per SEP-0023.
    full = head + bytes([crc & 0xFF, (crc >> 8) & 0xFF])
    encoded = base64.b32encode(full).decode("ascii")
    # Strip trailing '=' padding — Stellar StrKeys never include it.
    return encoded.rstrip("=")


def strkey_decode(text: str) -> tuple[int, bytes]:
    """Decode a Stellar StrKey, returning ``(version_byte, payload)``.

    Raises ``ValueError`` if:
    - the input contains characters outside RFC-4648 base32 alphabet,
    - the length doesn't match a known StrKey type,
    - the CRC16-XMODEM checksum doesn't validate.
    """
    if not isinstance(text, str):
        raise TypeError(f"strkey_decode expects str, got {type(text).__name__}")
    text = text.strip()
    # Add back any padding base32 needs (length divisible by 8).
    padding = "=" * (-len(text) % 8)
    try:
        raw = base64.b32decode(text + padding, casefold=False)
    except Exception as exc:  # binascii.Error is a subclass of ValueError
        raise ValueError(f"strkey base32 decode failed: {exc}") from exc
    if len(raw) < 3:
        raise ValueError(f"strkey too short to contain a checksum: {len(raw)} bytes")
    version_byte = raw[0]
    payload = raw[1:-2]
    crc_low, crc_high = raw[-2], raw[-1]
    expected_crc = crc_low | (crc_high << 8)
    actual_crc = crc16_xmodem(raw[:-2])
    if expected_crc != actual_crc:
        raise ValueError(
            f"strkey CRC mismatch: expected {expected_crc:#06x}, got {actual_crc:#06x}"
        )
    return version_byte, bytes(payload)


# ---------------------------------------------------------------------------
# Address derivation
# ---------------------------------------------------------------------------


def address_from_public_key(pubkey32: bytes) -> str:
    """Derive a Stellar account public key (``G…`` address) from a
    32-byte ed25519 public key.

    The result is always 56 ASCII characters and starts with ``G``.
    """
    if not isinstance(pubkey32, (bytes, bytearray)):
        raise TypeError(f"public key must be bytes, got {type(pubkey32).__name__}")
    if len(pubkey32) != 32:
        raise ValueError(f"Stellar public key must be 32 bytes, got {len(pubkey32)}")
    return strkey_encode(VERSION_BYTE_ACCOUNT_PUBLIC, bytes(pubkey32))


def public_key_from_address(address: str) -> bytes:
    """Recover the 32-byte ed25519 public key from a Stellar ``G…``
    account address.

    Raises ``ValueError`` if the version byte isn't
    ``VERSION_BYTE_ACCOUNT_PUBLIC`` (i.e. the StrKey is some other
    flavor — seed, muxed, pre-auth-tx, etc.) or if the payload length
    isn't 32.
    """
    version_byte, payload = strkey_decode(address)
    if version_byte != VERSION_BYTE_ACCOUNT_PUBLIC:
        raise ValueError(
            f"address must be an account public key (G…), got version "
            f"byte {version_byte:#04x} (expected {VERSION_BYTE_ACCOUNT_PUBLIC:#04x})"
        )
    if len(payload) != 32:
        raise ValueError(
            f"Stellar account public key payload must be 32 bytes, got {len(payload)}"
        )
    return payload


# ---------------------------------------------------------------------------
# Message hashing
# ---------------------------------------------------------------------------


def signed_message_hash(message: bytes | str) -> bytes:
    """Compute the 32-byte SHA-256 hash of the canonical Recto Stellar
    signed-message prefix concatenated with ``message``.

    Layout:
        sha256(b"Stellar signed message:\\n" + message)

    Phone-side signing computes the same hash, signs it with ed25519,
    and returns the raw 64-byte signature. Verifier side recomputes
    the hash and feeds it to ed25519_verify against the operator-
    approved public key.

    NOTE — this is the ``message_signing`` modality only. Transaction
    signing (kind="transaction") uses the canonical Stellar transaction
    envelope hash defined by Horizon's network-passphrase + envelope
    XDR; that's deferred to a follow-up wave.
    """
    if isinstance(message, str):
        message = message.encode("utf-8")
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError(
            f"message must be bytes or str, got {type(message).__name__}"
        )
    return hashlib.sha256(MESSAGE_PREAMBLE + bytes(message)).digest()


# ---------------------------------------------------------------------------
# Signature verification (delegates to cryptography library)
# ---------------------------------------------------------------------------


def _coerce_signature_bytes(signature: bytes | str) -> bytes:
    """Accept raw 64 bytes, base64, or base64url; return raw 64 bytes."""
    if isinstance(signature, (bytes, bytearray)):
        if len(signature) != 64:
            raise ValueError(
                f"ed25519 signature must be 64 bytes, got {len(signature)}"
            )
        return bytes(signature)
    if not isinstance(signature, str):
        raise TypeError(
            f"signature must be bytes or str, got {type(signature).__name__}"
        )
    s = signature.strip()
    try:
        decoded = base64.b64decode(s, validate=False)
        if len(decoded) == 64:
            return decoded
    except Exception:  # noqa: BLE001
        pass
    padding = "=" * (-len(s) % 4)
    decoded = base64.urlsafe_b64decode(s + padding)
    if len(decoded) != 64:
        raise ValueError(
            f"ed25519 signature must decode to 64 bytes, got {len(decoded)}"
        )
    return decoded


def _coerce_pubkey_bytes(public_key: bytes | str) -> bytes:
    """Accept raw 32 bytes, hex, or a StrKey ``G…`` address."""
    if isinstance(public_key, (bytes, bytearray)):
        if len(public_key) != 32:
            raise ValueError(
                f"ed25519 public key must be 32 bytes, got {len(public_key)}"
            )
        return bytes(public_key)
    if not isinstance(public_key, str):
        raise TypeError(
            f"public key must be bytes or str, got {type(public_key).__name__}"
        )
    s = public_key.strip()
    if len(s) == 64:
        try:
            decoded = bytes.fromhex(s)
            if len(decoded) == 32:
                return decoded
        except ValueError:
            pass
    return public_key_from_address(s)


def verify_signature(
    message: bytes | str,
    signature: bytes | str,
    public_key: bytes | str,
) -> bool:
    """Verify a 64-byte ed25519 signature was produced by ``public_key``
    over ``signed_message_hash(message)``.

    Returns True / False. Raises ``ImportError`` if ``cryptography`` is
    not installed.
    """
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
    except ImportError as exc:
        raise ImportError(
            "recto.stellar.verify_signature requires `cryptography`; "
            "install via `pip install recto[ed25519]` or "
            "`pip install recto[v0_4]`."
        ) from exc
    sig_bytes = _coerce_signature_bytes(signature)
    pub_bytes = _coerce_pubkey_bytes(public_key)
    msg_hash = signed_message_hash(message)
    pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
    try:
        pub.verify(sig_bytes, msg_hash)
    except InvalidSignature:
        return False
    return True


def verify_signature_against_address(
    message: bytes | str,
    signature: bytes | str,
    expected_address: str,
) -> bool:
    """Verify ``signature`` matches ``message`` against the ed25519
    public key encoded in ``expected_address``.

    Returns False on any malformed-address path.
    """
    try:
        pubkey = public_key_from_address(expected_address)
    except (ValueError, TypeError):
        return False
    return verify_signature(message, signature, pubkey)
