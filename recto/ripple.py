"""Ripple-side helpers for the ed_sign credential kind (chain="xrp").

This module is the launcher / bootloader / consumer-facing side of the
XRP flavor of ``ed_sign``. It does NOT hold private keys — those live
exclusively on the phone, derived at signing time from the operator's
BIP-39 mnemonic in platform secure storage. XRP's HD-wallet path
convention for ed25519 keys is non-canonical across the ecosystem;
Recto follows the SLIP-0010-style hardened-only convention used by
Xumm and most modern XRP wallets supporting ed25519:

    m/44'/144'/0'/0'/N'

(All five segments hardened. Compare with secp256k1 XRP keys which
typically use the unhardened ``m/44'/144'/0'/0/N`` BIP-44 shape.
Recto's ed_sign credential targets ed25519 only — secp256k1 XRP keys
are out of scope and would re-use the eth_sign machinery anyway.)

Threat model
------------

- Private keys are NEVER on this Python side. Every operation here is
  either (a) hashing a payload to produce something the phone signs,
  (b) deriving an XRP classic address from a known public key, or (c)
  verifying a 64-byte ed25519 signature returned by the phone matches
  an expected (message, public-key) pair.
- ed25519 verification, when wanted, delegates to the ``cryptography``
  package (consistent with ``recto.solana`` and ``recto.stellar``).
- XRP's address encoding uses a Ripple-specific base58 alphabet
  (different ordering than Bitcoin's), a HASH160-style hash of the
  ed25519 public key with a leading ``0xED`` prefix byte, and a
  Base58Check-style 4-byte double-SHA-256 checksum. Pure-stdlib.
  RIPEMD-160 is delegated to ``recto.bitcoin.ripemd160`` (which lives
  in the bitcoin extra and is pure-stdlib too).

Public surface
--------------

- ``BIP44_PATH_DEFAULT`` — ``"m/44'/144'/0'/0'/0'"`` (XRP ed25519
  hardened-only convention).
- ``MESSAGE_PREAMBLE`` — Recto's chosen XRP off-chain message preamble
  (``b"XRP signed message:\\n"``). XRP has no canonical off-chain
  signed-message standard; on-chain signing uses the SHA-512Half of a
  serialized transaction blob with HashPrefix.transactionSig (TX_PREFIX
  = ``b"STX\\x00"``). Recto's message_signing modality pins a stable
  preamble; transaction signing (kind="transaction") uses the
  canonical XRPL hash instead.
- ``ED25519_PUBKEY_PREFIX`` — ``0xED``. XRP distinguishes ed25519
  public keys from secp256k1 public keys by prefixing the 32-byte
  ed25519 raw key with this single byte (giving a 33-byte XRP-format
  public key). The prefix is included in AccountID derivation.
- ``RIPPLE_BASE58_ALPHABET`` — ``rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz``
  (58 chars; distinct from Bitcoin's alphabet — see XRPL
  ``base58_alphabet`` reference).
- ``base58_encode(data: bytes) -> str`` — encode raw bytes in the XRP
  base58 alphabet with NO checksum.
- ``base58check_encode(payload: bytes) -> str`` — encode
  ``payload || double_sha256(payload)[:4]`` in the XRP alphabet.
- ``base58_decode(text: str) -> bytes`` / ``base58check_decode(text: str) -> bytes``
  — reverses; raise ValueError on invalid characters or bad checksum.
- ``account_id_from_public_key(pubkey32: bytes) -> bytes`` — return
  20-byte AccountID = RIPEMD160(SHA256(0xED || pubkey32)).
- ``address_from_public_key(pubkey32: bytes) -> str`` — derive a
  classic XRP address (``r…``) from a 32-byte ed25519 public key.
- ``account_id_from_address(address: str) -> bytes`` — reverse of
  the address part (NOT the public key, which is non-recoverable from
  AccountID; XRP addresses are 1-way hashes of the pubkey).
- ``signed_message_hash(message: bytes | str) -> bytes`` — 32-byte
  SHA-256 hash of ``MESSAGE_PREAMBLE + message``.
- ``verify_signature(message, signature, public_key) -> bool``.
- ``verify_signature_against_address(message, signature,
  public_key, expected_address) -> bool`` — verify both the signature
  AND that the public key derives to the expected address. Note the
  signature: XRP addresses are non-reversible, so the verifier must
  receive the public key separately (typically as ``ed_pubkey_hex``
  on the wire) and check that its hash matches the operator-approved
  address.

Optional extra
--------------

This module is in the ``recto[ed25519]`` extra alongside ``recto.solana``
and ``recto.stellar``, but it ALSO requires ``recto.bitcoin`` for the
RIPEMD-160 implementation (pure-Python ISO/IEC 10118-3 reference
shipped with the bitcoin module). Both modules are pure-stdlib so the
extra still adds no native deps. Signature verification additionally
requires ``cryptography>=42``.
"""

from __future__ import annotations

import base64
import hashlib

from recto.bitcoin import ripemd160 as _ripemd160

__all__ = [
    "BIP44_PATH_DEFAULT",
    "MESSAGE_PREAMBLE",
    "ED25519_PUBKEY_PREFIX",
    "RIPPLE_BASE58_ALPHABET",
    "ACCOUNT_ID_VERSION",
    "base58_encode",
    "base58_decode",
    "base58check_encode",
    "base58check_decode",
    "account_id_from_public_key",
    "address_from_public_key",
    "account_id_from_address",
    "signed_message_hash",
    "verify_signature",
    "verify_signature_against_address",
]


# XRP ed25519 BIP-44-style path. Five hardened components — the inner
# `0'` in slot 4 differs from secp256k1 XRP wallets which use an
# unhardened `0` there. SLIP-0010 ed25519 requires every step to be
# hardened, and Xumm + the XRP ed25519 ecosystem standardized on this
# shape.
BIP44_PATH_DEFAULT = "m/44'/144'/0'/0'/0'"

# Recto's chosen XRP off-chain message preamble. XRPL has canonical
# transaction-signing semantics (sha512-half with TX_PREFIX) but no
# off-chain message-signing standard. We pin our own preamble for
# message_signing; transaction signing (kind="transaction") uses
# the canonical XRPL transaction-blob hash.
MESSAGE_PREAMBLE = b"XRP signed message:\n"

# XRP's leading byte for ed25519 public keys. secp256k1 keys start
# with 0x02 / 0x03 (compressed SEC1 form, 33 bytes total); ed25519
# keys are prefixed with 0xED so they're also 33 bytes total but
# distinguishable. The prefix is INCLUDED when computing AccountID.
ED25519_PUBKEY_PREFIX = 0xED

# XRP's base58 alphabet. Notice it starts with 'r' (so the version
# byte 0x00 encodes to 'r' as the leading char of every classic
# address). Each character's ordinal position in this string equals
# its base58 numeric value.
RIPPLE_BASE58_ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
_RIPPLE_BASE58_BYTES = RIPPLE_BASE58_ALPHABET.encode("ascii")
_RIPPLE_BASE58_INDEX: dict[int, int] = {
    c: i for i, c in enumerate(_RIPPLE_BASE58_BYTES)
}

# Version byte prepended to AccountID when encoding a classic XRP
# address. 0x00 = classic AccountID (the byte that encodes to 'r' in
# the XRP alphabet, hence the 'r…' addresses).
ACCOUNT_ID_VERSION = 0x00


# ---------------------------------------------------------------------------
# XRP base58 (Ripple alphabet)
# ---------------------------------------------------------------------------


def base58_encode(data: bytes) -> str:
    """Encode ``data`` in the Ripple base58 alphabet, NO checksum.

    Leading 0x00 bytes in ``data`` map to leading ``"r"`` characters
    (since ``r`` is the first character of the Ripple alphabet, the
    XRP equivalent of Bitcoin's leading-1s prefix).
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"base58_encode expects bytes, got {type(data).__name__}")
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
        out.append(_RIPPLE_BASE58_BYTES[r])
    out.reverse()
    return (RIPPLE_BASE58_ALPHABET[0] * leading_zeros) + out.decode("ascii")


def base58_decode(text: str) -> bytes:
    """Decode a Ripple base58 string back to bytes (no checksum).

    Leading ``"r"`` characters map back to leading 0x00 bytes.
    """
    if not isinstance(text, str):
        raise TypeError(f"base58_decode expects str, got {type(text).__name__}")
    leading_rs = 0
    for c in text:
        if c == RIPPLE_BASE58_ALPHABET[0]:  # 'r'
            leading_rs += 1
        else:
            break
    n = 0
    for c in text:
        idx = _RIPPLE_BASE58_INDEX.get(ord(c))
        if idx is None:
            raise ValueError(f"Ripple base58 character {c!r} not in alphabet")
        n = n * 58 + idx
    body = bytearray()
    while n > 0:
        n, r = divmod(n, 256)
        body.append(r)
    body.reverse()
    return (b"\x00" * leading_rs) + bytes(body)


def base58check_encode(payload: bytes) -> str:
    """Encode ``payload || double_sha256(payload)[:4]`` in the Ripple
    base58 alphabet. The 4-byte checksum is the same Base58Check style
    Bitcoin uses, just with the alphabet swapped."""
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58_encode(payload + checksum)


def base58check_decode(text: str) -> bytes:
    """Decode an XRP Base58Check string and verify the 4-byte checksum.

    Returns the payload (without the checksum). Raises ValueError on
    bad checksum or malformed input.
    """
    raw = base58_decode(text)
    if len(raw) < 5:
        raise ValueError(
            f"XRP base58check decoded length {len(raw)} is too short for a checksum"
        )
    payload, checksum = raw[:-4], raw[-4:]
    expected = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if checksum != expected:
        raise ValueError(
            f"XRP base58check checksum mismatch: expected {expected.hex()}, "
            f"got {checksum.hex()}"
        )
    return payload


# ---------------------------------------------------------------------------
# Address derivation
# ---------------------------------------------------------------------------


def account_id_from_public_key(pubkey32: bytes) -> bytes:
    """Return the 20-byte AccountID for an ed25519 public key.

    AccountID = RIPEMD160(SHA256(0xED || pubkey32)).

    The 0xED prefix is XRP's ed25519 discriminator — it's PART of the
    pre-hash bytes, not stripped. Without the prefix the resulting
    AccountID would collide with a (different) secp256k1 key's
    AccountID by happenstance.
    """
    if not isinstance(pubkey32, (bytes, bytearray)):
        raise TypeError(f"public key must be bytes, got {type(pubkey32).__name__}")
    if len(pubkey32) != 32:
        raise ValueError(f"XRP ed25519 public key must be 32 bytes, got {len(pubkey32)}")
    prefixed = bytes([ED25519_PUBKEY_PREFIX]) + bytes(pubkey32)
    return _ripemd160(hashlib.sha256(prefixed).digest())


def address_from_public_key(pubkey32: bytes) -> str:
    """Derive a classic XRP address (``r…``) from a 32-byte ed25519
    public key.

    Layout:
        base58check_xrp(0x00 || RIPEMD160(SHA256(0xED || pubkey32)))

    Output is 25–35 ASCII characters and starts with 'r'.
    """
    account_id = account_id_from_public_key(pubkey32)
    return base58check_encode(bytes([ACCOUNT_ID_VERSION]) + account_id)


def account_id_from_address(address: str) -> bytes:
    """Recover the 20-byte AccountID from a classic XRP address.

    NOTE — this does NOT recover the underlying public key. XRP
    addresses are one-way: the public key is hashed (HASH160-style)
    so the verifier must receive the public key separately when
    validating ed_sign responses.
    """
    payload = base58check_decode(address)
    if len(payload) != 21:
        raise ValueError(
            f"XRP classic-address payload must be 21 bytes (1 version + 20 AccountID), "
            f"got {len(payload)}"
        )
    if payload[0] != ACCOUNT_ID_VERSION:
        raise ValueError(
            f"XRP classic-address version must be {ACCOUNT_ID_VERSION:#04x}, "
            f"got {payload[0]:#04x}"
        )
    return payload[1:]


# ---------------------------------------------------------------------------
# Message hashing
# ---------------------------------------------------------------------------


def signed_message_hash(message: bytes | str) -> bytes:
    """Compute the 32-byte SHA-256 hash of the canonical Recto XRP
    signed-message prefix concatenated with ``message``.

    Layout:
        sha256(b"XRP signed message:\\n" + message)

    Phone-side signing computes the same hash, signs it with ed25519,
    and returns the raw 64-byte signature.

    NOTE — this is the ``message_signing`` modality only. Transaction
    signing (kind="transaction") uses the canonical XRPL transaction-
    blob hash (sha512-half with TX_PREFIX = ``b"STX\\x00"``); deferred
    to a follow-up wave.
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
    """Accept raw 32 bytes or hex.

    Note: unlike ``recto.solana`` and ``recto.stellar``, we CANNOT
    accept an XRP address here because XRP addresses are one-way
    hashes of the public key. The pubkey must be supplied directly.
    """
    if isinstance(public_key, (bytes, bytearray)):
        if len(public_key) == 33 and public_key[0] == ED25519_PUBKEY_PREFIX:
            # XRP-flavored 33-byte form (0xED || raw32). Strip the prefix.
            return bytes(public_key[1:])
        if len(public_key) != 32:
            raise ValueError(
                f"ed25519 public key must be 32 bytes (or 33 with leading 0xED), "
                f"got {len(public_key)}"
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
    if len(s) == 66:
        try:
            decoded = bytes.fromhex(s)
            if len(decoded) == 33 and decoded[0] == ED25519_PUBKEY_PREFIX:
                return decoded[1:]
        except ValueError:
            pass
    raise ValueError(
        f"XRP public key must be 32 bytes raw / 64 hex chars / "
        f"33 bytes with 0xED prefix / 66 hex chars with ED prefix; got {public_key!r}"
    )


def verify_signature(
    message: bytes | str,
    signature: bytes | str,
    public_key: bytes | str,
) -> bool:
    """Verify a 64-byte ed25519 signature was produced by ``public_key``
    over ``signed_message_hash(message)``.

    Returns True / False. Raises ``ImportError`` if ``cryptography`` is
    not installed.

    ``public_key`` may be supplied as raw 32 bytes, 64 hex chars,
    33-byte XRP-prefixed form (0xED || raw32), or 66 hex chars with
    the ED prefix. Cannot be supplied as an XRP address — addresses
    are one-way hashes.
    """
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
    except ImportError as exc:
        raise ImportError(
            "recto.ripple.verify_signature requires `cryptography`; "
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
    public_key: bytes | str,
    expected_address: str,
) -> bool:
    """Verify ``signature`` matches ``message`` against ``public_key``,
    AND that ``public_key`` derives to ``expected_address``.

    Both checks are required because XRP addresses don't carry the
    public key (they're HASH160s) — without the address-derivation
    check, an attacker who picks an arbitrary key pair could fool a
    naive verifier into trusting their signature for the operator-
    approved address.

    Returns False on any malformed-input path so consumer code can
    branch on the boolean.
    """
    try:
        pub_bytes = _coerce_pubkey_bytes(public_key)
    except (ValueError, TypeError):
        return False
    if not verify_signature(message, signature, pub_bytes):
        return False
    try:
        derived = address_from_public_key(pub_bytes)
    except (ValueError, TypeError):
        return False
    return derived == expected_address.strip()
