"""Solana-side helpers for the ed_sign credential kind (chain="sol").

This module is the launcher / bootloader / consumer-facing side of the
SOL flavor of ``ed_sign``. It does NOT hold private keys — those live
exclusively on the phone, derived at signing time from the operator's
BIP-39 mnemonic in platform secure storage at the SLIP-0010 ed25519
hardened path ``m/44'/501'/N'/0'`` (Phantom / Solflare convention; the
last segment ``/0'`` is "change=0" but Solana doesn't actually use the
HD-wallet change concept — it's there for BIP-44 shape parity).

Threat model
------------

- Private keys are NEVER on this Python side. Every operation here is
  either (a) hashing a payload to produce something the phone signs,
  (b) deriving a SOL address from a known public key, or (c) verifying
  a 64-byte ed25519 signature returned by the phone matches an
  expected (message, public-key) pair. The phone-side MAUI service
  (IEdChainSignService) does the actual private-key arithmetic.
- ed25519 verification, when wanted, delegates to the ``cryptography``
  package. Following the same posture as
  ``recto.bootloader.sessions.verify_signature`` — ``cryptography`` is
  already a transitive dep of the v0.4 bootloader, so consumers in the
  bootloader path get it for free. Stand-alone verifier callers must
  install ``recto[ed25519]``.
- Solana's address encoding is base58-of-raw-pubkey (NO version byte,
  NO checksum). The Bitcoin-alphabet base58 encoder lives here because
  ``recto.bitcoin``'s encoder is Base58Check (with checksum) and
  doesn't fit the SOL shape. Pure-stdlib.

Public surface
--------------

- ``BIP44_PATH_DEFAULT`` — ``"m/44'/501'/0'/0'"`` (Phantom / Solflare
  default; the leaf is hardened too because SLIP-0010 ed25519 requires
  every step to be hardened).
- ``base58_encode(data: bytes) -> str`` — Bitcoin-alphabet base58 of
  the raw payload. NOT Base58Check; no checksum is appended.
- ``base58_decode(text: str) -> bytes`` — reverse; raises ValueError
  on invalid characters.
- ``address_from_public_key(pubkey32: bytes) -> str`` — derive a SOL
  address from a 32-byte ed25519 public key. Solana addresses are
  just ``base58(pubkey32)`` so the address is a 32–44 character string.
- ``public_key_from_address(address: str) -> bytes`` — reverse; raises
  ``ValueError`` if the decoded length isn't 32.
- ``signed_message_hash(message: bytes | str) -> bytes`` — 32-byte
  SHA-256 hash of ``b"Solana signed message:\\n" + message``. This
  prefix convention is Recto's choice — Solana has no canonical
  off-chain message-signing standard. Phantom's "sign message" verb
  signs raw message bytes with no preamble; Solflare's signs with a
  preamble similar to ours; Backpack does its own thing. Recto's
  convention pins a stable hash so the phone-side and verifier-side
  agree on what's being signed.
- ``verify_signature(message: bytes | str, signature: bytes | str,
  public_key: bytes | str) -> bool`` — verify a 64-byte ed25519
  signature was produced by ``public_key`` over the
  ``signed_message_hash`` of ``message``. Imports ``cryptography``
  lazily; raises ``ImportError`` if not installed.
- ``verify_signature_against_address(message, signature,
  expected_address) -> bool`` — convenience: decode address →
  ed25519_verify(pubkey, hash, sig). Returns False on any
  malformed-address path so consumer code can branch on the boolean.

Optional extra
--------------

This module is in the ``recto[ed25519]`` extra. Address encoding and
message hashing use only Python stdlib (``hashlib`` for SHA-256,
``int``/``divmod`` for base58). Signature verification requires
``cryptography>=42`` — installed transitively when the v0.4 bootloader
extra is present, or explicitly via ``recto[ed25519]``.
"""

from __future__ import annotations

import hashlib

__all__ = [
    "BIP44_PATH_DEFAULT",
    "MESSAGE_PREAMBLE",
    "base58_encode",
    "base58_decode",
    "address_from_public_key",
    "public_key_from_address",
    "signed_message_hash",
    "verify_signature",
    "verify_signature_against_address",
]


# Phantom / Solflare default. The terminal `/0'` is "change=0" by BIP-44
# convention; SOL doesn't actually have HD-wallet change accounting,
# but the path shape mirrors Bitcoin's m/44'/0'/0'/0/N for tooling
# parity. SLIP-0010 ed25519 requires every step to be hardened.
BIP44_PATH_DEFAULT = "m/44'/501'/0'/0'"

# Recto's chosen Solana off-chain message preamble. Solana has no
# canonical standard here (Phantom signs raw bytes, Solflare uses a
# different preamble, etc.) so we pin a Recto-specific convention.
# Phone-side signing logic and verifier-side hashing must agree.
MESSAGE_PREAMBLE = b"Solana signed message:\n"


# ---------------------------------------------------------------------------
# Bitcoin-alphabet base58 (no checksum)
# ---------------------------------------------------------------------------
#
# Solana uses the same alphabet as Bitcoin (the original Satoshi
# alphabet, no 0/O/l/I confusable characters) but does NOT append a
# Base58Check checksum to addresses — a SOL address is just the raw
# 32-byte ed25519 public key encoded in base58. We replicate the
# encoder here rather than reach into ``recto.bitcoin._base58check_encode``
# because the latter ships a checksum that Solana doesn't expect.

_BASE58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58_INDEX: dict[int, int] = {c: i for i, c in enumerate(_BASE58_ALPHABET)}


def base58_encode(data: bytes) -> str:
    """Encode ``data`` in Bitcoin-alphabet base58 with NO checksum.

    Leading 0x00 bytes in ``data`` map to leading ``"1"`` characters
    in the output — the standard base58 leading-zero preservation.
    Used for Solana addresses (base58 of raw 32-byte ed25519 pubkey).
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"base58_encode expects bytes, got {type(data).__name__}")
    # Count leading zero bytes for the leading-1s prefix.
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


def base58_decode(text: str) -> bytes:
    """Decode a Bitcoin-alphabet base58 string back to bytes (no checksum).

    Raises ValueError if any character is not in the base58 alphabet.
    Empty string decodes to empty bytes. Leading ``"1"`` characters
    map back to leading 0x00 bytes — the standard base58 leading-zero
    preservation.
    """
    if not isinstance(text, str):
        raise TypeError(f"base58_decode expects str, got {type(text).__name__}")
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
    return (b"\x00" * leading_ones) + bytes(body)


# ---------------------------------------------------------------------------
# Address derivation
# ---------------------------------------------------------------------------


def address_from_public_key(pubkey32: bytes) -> str:
    """Derive a Solana address from a 32-byte ed25519 public key.

    Solana addresses are NOT version-byte-prefixed and have NO
    checksum — the address is literally ``base58(pubkey32)``. Output
    is 32–44 ASCII characters depending on the leading-byte
    distribution of the pubkey (more leading zero bytes = shorter
    encoding because base58 preserves leading zeros as ``"1"``).
    """
    if not isinstance(pubkey32, (bytes, bytearray)):
        raise TypeError(f"public key must be bytes, got {type(pubkey32).__name__}")
    if len(pubkey32) != 32:
        raise ValueError(f"Solana public key must be 32 bytes, got {len(pubkey32)}")
    return base58_encode(bytes(pubkey32))


def public_key_from_address(address: str) -> bytes:
    """Recover the 32-byte ed25519 public key from a Solana address.

    Inverse of ``address_from_public_key``. Raises ``ValueError`` if
    the address decodes to anything other than 32 bytes (which would
    indicate a corrupted or non-Solana address).
    """
    raw = base58_decode(address)
    if len(raw) != 32:
        raise ValueError(
            f"Solana address must decode to 32 bytes, got {len(raw)} "
            f"(input: {address!r})"
        )
    return raw


# ---------------------------------------------------------------------------
# Message hashing
# ---------------------------------------------------------------------------


def signed_message_hash(message: bytes | str) -> bytes:
    """Compute the 32-byte SHA-256 hash of the canonical Recto Solana
    signed-message prefix concatenated with ``message``.

    Layout:
        sha256(b"Solana signed message:\\n" + message)

    Phone-side signing computes the same hash, signs it with ed25519,
    and returns the raw 64-byte signature. Verifier side (this module's
    ``verify_signature``) recomputes the hash and feeds it to
    ed25519_verify against the operator-approved public key.
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
    """Accept either raw 64 bytes or a base64 / base64url string."""
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
    import base64 as _base64
    s = signature.strip()
    # Try standard base64 first (the wire format used by ed_signature_base64).
    try:
        decoded = _base64.b64decode(s, validate=False)
        if len(decoded) == 64:
            return decoded
    except Exception:  # noqa: BLE001 — broad on purpose, fall through to base64url
        pass
    # Fallback: base64url with optional padding stripping.
    padding = "=" * (-len(s) % 4)
    decoded = _base64.urlsafe_b64decode(s + padding)
    if len(decoded) != 64:
        raise ValueError(
            f"ed25519 signature must decode to 64 bytes, got {len(decoded)}"
        )
    return decoded


def _coerce_pubkey_bytes(public_key: bytes | str) -> bytes:
    """Accept either raw 32 bytes, a hex string, or a SOL base58 address."""
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
    # Hex first (most explicit).
    if len(s) == 64:
        try:
            decoded = bytes.fromhex(s)
            if len(decoded) == 32:
                return decoded
        except ValueError:
            pass
    # Otherwise treat as a SOL base58 address.
    return public_key_from_address(s)


def verify_signature(
    message: bytes | str,
    signature: bytes | str,
    public_key: bytes | str,
) -> bool:
    """Verify a 64-byte ed25519 signature was produced by ``public_key``
    over ``signed_message_hash(message)``.

    Returns True / False. Raises ``ImportError`` if ``cryptography`` is
    not installed; raises ``ValueError`` on malformed inputs (wrong
    sig length, wrong pubkey length, undecodable base58 address). Does
    NOT raise on valid-but-not-matching signatures — those return False
    so callers can branch without try/except.
    """
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
    except ImportError as exc:
        raise ImportError(
            "recto.solana.verify_signature requires `cryptography`; "
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

    Returns False on any malformed-address path (bad base58, wrong
    decoded length) so consumer code can branch on the boolean
    without try/except.
    """
    try:
        pubkey = public_key_from_address(expected_address)
    except (ValueError, TypeError):
        return False
    return verify_signature(message, signature, pubkey)
