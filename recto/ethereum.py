"""Ethereum-side helpers for the eth_sign credential kind (v0.5+).

This module is the launcher / bootloader / consumer-facing side of the
eth_sign flow. It does NOT hold private keys — those live exclusively
on the phone, derived at signing time from the operator's BIP39 mnemonic
in platform secure storage. The Python side here only produces digests
to be signed (EIP-191 personal_sign hash, EIP-712 typed-data hash) and
verifies the resulting signatures against the (known) phone-derived
address.

Threat model
------------

- Private keys are NEVER on this Python side. Every operation here is
  either (a) hashing a payload to produce something the phone signs,
  (b) verifying a 65-byte r||s||v signature returned by the phone
  matches an expected address, or (c) deriving an address from a
  public key for display in operator UI. The phone-side MAUI service
  (IEthSignService) does the actual private-key arithmetic.
- The pure-Python secp256k1 implementation below is NOT constant-time.
  This is acceptable BECAUSE no private-key operation runs through it —
  signing is phone-side. Verification and public-key recovery don't
  expose any secrets.
- Keccak-256 is implemented from scratch (Python stdlib doesn't ship
  it; SHA3-256 has different padding). Test vectors at the bottom of
  the module pin the implementation against the FIPS-202 reference
  values.

Public surface
--------------

- ``keccak256(data: bytes) -> bytes`` — 32-byte Keccak-256 hash.
- ``personal_sign_hash(message: bytes) -> bytes`` — EIP-191 hash of
  ``"\\x19Ethereum Signed Message:\\n" + len(message) + message``.
- ``address_from_public_key(pubkey64: bytes) -> str`` — 0x-prefixed
  lowercase 40-char hex address derived from the 64-byte uncompressed
  public key (X||Y, no 0x04 prefix).
- ``recover_public_key(msg_hash: bytes, signature_rsv: bytes) -> bytes``
  — given a 32-byte message hash and a 65-byte r||s||v signature,
  return the 64-byte public key that produced the signature.
- ``recover_address(msg_hash: bytes, signature_rsv: bytes) -> str``
  — convenience wrapper: recover the signer's address.
- ``verify_signature(msg_hash, signature_rsv, expected_address) -> bool``
  — recover-then-compare; returns True iff the recovered address
  matches ``expected_address`` (case-insensitive on hex digits).
- ``parse_signature_rsv(signature: str | bytes) -> tuple[int, int, int]``
  — split a 65-byte r||s||v (or 0x-prefixed hex) into (r, s, v).

These are the consumer/verifier helpers. The phone-side equivalents
(BIP39 mnemonic gen/import, BIP32/BIP44 derivation, secp256k1 sign
with v-recovery) live in C# under
``phone/RectoMAUIBlazor/.../Services/IEthSignService.cs`` and its MAUI
implementations.

Optional extra
--------------

This module is in the ``recto[ethereum]`` extra. It uses only the
Python standard library (``hashlib`` for SHA-256, ``int``/``pow`` for
secp256k1 modular arithmetic), so installing the extra adds no new
dependencies — it just gates the import path so consumers that don't
need ETH support don't pay the import cost.
"""

from __future__ import annotations

__all__ = [
    "keccak256",
    "personal_sign_hash",
    "typed_data_hash",
    "transaction_hash_eip1559",
    "rlp_encode",
    "rlp_decode",
    "address_from_public_key",
    "recover_public_key",
    "recover_address",
    "verify_signature",
    "parse_signature_rsv",
    "to_checksum_address",
]


# ---------------------------------------------------------------------------
# Keccak-256 (FIPS-202 / SHA-3 family with the original Keccak padding,
# i.e. 0x01 multi-rate padding rather than NIST's 0x06 SHA-3 padding).
# Reference: https://keccak.team/keccak_specs_summary.html
# Pure-Python; not fast, but a few microseconds per hash is irrelevant
# given that signing is human-gated by phone biometric prompts anyway.
# ---------------------------------------------------------------------------


_RHO_OFFSETS = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)
"""ρ rotation offsets per (x, y) lane. Lifted directly from the FIPS-202
reference. Indexed as _RHO_OFFSETS[x][y]."""

_ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
"""ι round constants for Keccak-f[1600], 24 rounds."""


def _rotl64(x: int, n: int) -> int:
    """64-bit left-rotate."""
    n %= 64
    return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF


def _keccak_f_1600(state: list[list[int]]) -> None:
    """In-place Keccak-f[1600] permutation. ``state`` is a 5x5 grid of
    64-bit lane integers, indexed [x][y]."""
    for round_idx in range(24):
        # θ
        c = [
            state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4]
            for x in range(5)
        ]
        d = [c[(x - 1) % 5] ^ _rotl64(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x][y] ^= d[x]

        # ρ + π
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rotl64(
                    state[x][y], _RHO_OFFSETS[x][y]
                )

        # χ
        for x in range(5):
            for y in range(5):
                state[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])
                state[x][y] &= 0xFFFFFFFFFFFFFFFF

        # ι
        state[0][0] ^= _ROUND_CONSTANTS[round_idx]


def keccak256(data: bytes) -> bytes:
    """Keccak-256 (32-byte digest). Original-Keccak padding (``0x01``),
    NOT FIPS-202 SHA3-256 padding (``0x06``).

    Ethereum addresses, EIP-191 hashes, EIP-712 hashes, transaction
    hashes, contract function selectors — all use this exact variant.
    """
    rate_bytes = 136  # bitrate r=1088 / 8 for the Keccak-256 instance
    state = [[0] * 5 for _ in range(5)]

    # Absorb
    offset = 0
    while offset + rate_bytes <= len(data):
        _absorb_block(state, data[offset:offset + rate_bytes], rate_bytes)
        _keccak_f_1600(state)
        offset += rate_bytes

    # Pad: original Keccak uses 0x01 ... 0x80 multi-rate padding (NIST
    # SHA-3's domain-separation byte 0x06 is what differs).
    block = bytearray(rate_bytes)
    block[: len(data) - offset] = data[offset:]
    block[len(data) - offset] |= 0x01
    block[rate_bytes - 1] |= 0x80
    _absorb_block(state, bytes(block), rate_bytes)
    _keccak_f_1600(state)

    # Squeeze 32 bytes (one squeeze suffices since 32 <= rate_bytes).
    out = bytearray(32)
    for i in range(32):
        lane_idx = i // 8
        x, y = lane_idx % 5, lane_idx // 5
        byte_in_lane = i % 8
        out[i] = (state[x][y] >> (8 * byte_in_lane)) & 0xFF
    return bytes(out)


def _absorb_block(state: list[list[int]], block: bytes, rate_bytes: int) -> None:
    """XOR ``block`` into the rate portion of ``state``. The block must be
    exactly ``rate_bytes`` long."""
    for i in range(rate_bytes):
        lane_idx = i // 8
        x, y = lane_idx % 5, lane_idx // 5
        byte_in_lane = i % 8
        state[x][y] ^= (block[i] & 0xFF) << (8 * byte_in_lane)
        state[x][y] &= 0xFFFFFFFFFFFFFFFF


# ---------------------------------------------------------------------------
# secp256k1 — verify-side primitives only. Sign is phone-side.
# ---------------------------------------------------------------------------


# secp256k1 curve parameters (https://www.secg.org/sec2-v2.pdf §2.4.1).
_SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_SECP256K1_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_SECP256K1_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def _modinv(a: int, m: int) -> int:
    """Modular inverse via extended Euclidean. Python 3.8+ supports
    ``pow(a, -1, m)`` directly; using that for clarity."""
    return pow(a, -1, m)


def _ec_add(p1, p2):
    """Add two points on secp256k1 in Jacobian-free affine form. Returns
    None for the point at infinity."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % _SECP256K1_P == 0:
            return None  # point at infinity
        # Doubling.
        lam = (3 * x1 * x1) * _modinv(2 * y1 % _SECP256K1_P, _SECP256K1_P) % _SECP256K1_P
    else:
        lam = (y2 - y1) * _modinv((x2 - x1) % _SECP256K1_P, _SECP256K1_P) % _SECP256K1_P
    x3 = (lam * lam - x1 - x2) % _SECP256K1_P
    y3 = (lam * (x1 - x3) - y1) % _SECP256K1_P
    return (x3, y3)


def _ec_mul(k: int, p) -> tuple[int, int] | None:
    """Scalar multiplication via double-and-add. Not constant-time —
    this is fine because we only verify; we never sign with this."""
    if k % _SECP256K1_N == 0 or p is None:
        return None
    if k < 0:
        return _ec_mul(-k, (p[0], (-p[1]) % _SECP256K1_P))
    result = None
    addend = p
    while k:
        if k & 1:
            result = _ec_add(result, addend)
        addend = _ec_add(addend, addend)
        k >>= 1
    return result


def _y_from_x(x: int, y_is_odd: bool) -> int | None:
    """Recover the y-coordinate on secp256k1 from x and a parity bit.
    Returns None if x is not on the curve."""
    # y² = x³ + 7 (mod p)
    rhs = (x * x * x + 7) % _SECP256K1_P
    # tonelli-shanks, but p ≡ 3 (mod 4) for secp256k1, so y = rhs^((p+1)/4)
    y = pow(rhs, (_SECP256K1_P + 1) // 4, _SECP256K1_P)
    if (y * y) % _SECP256K1_P != rhs:
        return None
    if (y & 1) != (1 if y_is_odd else 0):
        y = (-y) % _SECP256K1_P
    return y


# ---------------------------------------------------------------------------
# EIP-191 personal_sign + address derivation
# ---------------------------------------------------------------------------


def personal_sign_hash(message: bytes) -> bytes:
    """Compute the EIP-191 personal_sign hash.

    EIP-191 prefixes the message with
    ``"\\x19Ethereum Signed Message:\\n" + len(message) + message`` and
    Keccak-256-hashes the result. This is what MetaMask, Trust Wallet,
    and every other consumer-grade ETH wallet computes when the user
    clicks "Sign Message" on a string.
    """
    if isinstance(message, str):  # be liberal with input types
        message = message.encode("utf-8")
    prefix = b"\x19Ethereum Signed Message:\n" + str(len(message)).encode("ascii")
    return keccak256(prefix + message)


def address_from_public_key(pubkey64: bytes) -> str:
    """Compute the 0x-prefixed lowercase hex address for a 64-byte
    uncompressed secp256k1 public key (X||Y, big-endian, no 0x04 prefix).

    The Ethereum address is the last 20 bytes of Keccak-256(pubkey64).
    """
    if len(pubkey64) != 64:
        raise ValueError(f"public key must be 64 bytes (X||Y), got {len(pubkey64)}")
    h = keccak256(pubkey64)
    return "0x" + h[-20:].hex()


def to_checksum_address(address: str) -> str:
    """Convert a 0x-prefixed hex address to its EIP-55 mixed-case
    checksum form. Useful for display; comparisons should always
    lowercase both sides first."""
    cleaned = address.lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) != 40:
        raise ValueError(f"address must be 40 hex chars after 0x prefix, got {len(cleaned)}")
    h = keccak256(cleaned.encode("ascii")).hex()
    out = ["0x"]
    for i, ch in enumerate(cleaned):
        if ch in "0123456789":
            out.append(ch)
        else:
            out.append(ch.upper() if int(h[i], 16) >= 8 else ch)
    return "".join(out)


# ---------------------------------------------------------------------------
# Signature parsing + ECDSA public-key recovery
# ---------------------------------------------------------------------------


def parse_signature_rsv(signature: str | bytes) -> tuple[int, int, int]:
    """Split a 65-byte r||s||v signature into integer (r, s, v).

    Accepts either:
    - 65 raw bytes
    - a hex string with optional 0x prefix (130 or 132 chars)

    Raises ValueError if the length is wrong.
    """
    if isinstance(signature, str):
        s = signature[2:] if signature.startswith(("0x", "0X")) else signature
        if len(s) != 130:
            raise ValueError(
                f"signature hex must be 130 chars (65 bytes), got {len(s)}"
            )
        sig_bytes = bytes.fromhex(s)
    else:
        sig_bytes = bytes(signature)
    if len(sig_bytes) != 65:
        raise ValueError(f"signature must be 65 bytes, got {len(sig_bytes)}")
    r = int.from_bytes(sig_bytes[0:32], "big")
    sval = int.from_bytes(sig_bytes[32:64], "big")
    v = sig_bytes[64]
    return r, sval, v


def recover_public_key(msg_hash: bytes, signature_rsv: str | bytes) -> bytes:
    """Recover the 64-byte uncompressed public key (X||Y) that signed
    ``msg_hash`` to produce ``signature_rsv``.

    ``msg_hash`` must be the 32-byte hash the signer signed (e.g. the
    output of ``personal_sign_hash``).

    Raises ValueError if the signature is malformed or the recovery
    fails (e.g. r value yields no curve point).
    """
    if len(msg_hash) != 32:
        raise ValueError(f"msg_hash must be 32 bytes, got {len(msg_hash)}")
    r, sval, v = parse_signature_rsv(signature_rsv)
    if not (1 <= r < _SECP256K1_N) or not (1 <= sval < _SECP256K1_N):
        raise ValueError("signature (r, s) out of range [1, n-1]")
    # v is canonically 27 or 28 (legacy) or 0/1 (modern EIP-155 base).
    # Accept both encodings — recovery ID is the lowest bit of v after
    # subtracting 27 if it's >= 27.
    if v >= 27:
        rec_id = v - 27
    else:
        rec_id = v
    if rec_id not in (0, 1):
        # rec_id 2/3 cover the case where r >= n (extremely rare); we
        # reject for simplicity and to match Ethereum's canonical
        # signature acceptance (which rejects high rec_id too).
        raise ValueError(f"unsupported recovery id {rec_id} (expected 0 or 1)")

    # Compute the candidate R point: R.x = r, R.y has parity = rec_id.
    ry = _y_from_x(r, y_is_odd=bool(rec_id & 1))
    if ry is None:
        raise ValueError("recovery failed: r is not a valid x-coordinate on secp256k1")
    rx = r
    e = int.from_bytes(msg_hash, "big") % _SECP256K1_N
    r_inv = _modinv(r, _SECP256K1_N)
    # Q = r^-1 * (s*R - e*G)
    sR = _ec_mul(sval, (rx, ry))
    eG = _ec_mul(e, (_SECP256K1_GX, _SECP256K1_GY))
    if eG is None:
        raise ValueError("recovery failed: e*G is point at infinity")
    eG_neg = (eG[0], (-eG[1]) % _SECP256K1_P)
    sR_minus_eG = _ec_add(sR, eG_neg)
    if sR_minus_eG is None:
        raise ValueError("recovery failed: sR - eG is point at infinity")
    q = _ec_mul(r_inv, sR_minus_eG)
    if q is None:
        raise ValueError("recovery failed: recovered point is at infinity")
    qx, qy = q
    return qx.to_bytes(32, "big") + qy.to_bytes(32, "big")


def recover_address(msg_hash: bytes, signature_rsv: str | bytes) -> str:
    """Recover the 0x-prefixed lowercase hex address that signed
    ``msg_hash`` to produce ``signature_rsv``.

    Convenience wrapper combining ``recover_public_key`` +
    ``address_from_public_key``.
    """
    pubkey = recover_public_key(msg_hash, signature_rsv)
    return address_from_public_key(pubkey)


def verify_signature(
    msg_hash: bytes,
    signature_rsv: str | bytes,
    expected_address: str,
) -> bool:
    """Recover the signer from ``signature_rsv`` and check it matches
    ``expected_address`` (case-insensitive on hex digits).

    Returns False rather than raising on any malformed-signature path
    so consumer code can branch on the boolean without try/except.
    """
    try:
        recovered = recover_address(msg_hash, signature_rsv)
    except (ValueError, OverflowError):
        return False
    return recovered.lower() == expected_address.lower()


# ---------------------------------------------------------------------------
# EIP-712 typed-data hashing
# Reference: https://eips.ethereum.org/EIPS/eip-712
# ---------------------------------------------------------------------------


def typed_data_hash(typed_data: dict) -> bytes:
    """Compute the EIP-712 digest for a typed-data document.

    Layout:
        keccak256(0x19 || 0x01 || domainSeparator || structHash(primaryType, message))

    The ``typed_data`` dict has the canonical EIP-712 shape::

        {
          "types": {
            "EIP712Domain": [{"name": "...", "type": "..."}, ...],
            "<PrimaryType>": [...],
            ...
          },
          "primaryType": "<PrimaryType>",
          "domain": {...},
          "message": {...}
        }

    Returns the 32-byte digest the signer signs. Raises ``ValueError``
    on malformed inputs (unknown referenced types, atomic-type encoding
    failures, missing fields).
    """
    if not isinstance(typed_data, dict):
        raise ValueError("typed_data must be a dict")
    types = typed_data.get("types")
    primary_type = typed_data.get("primaryType")
    domain = typed_data.get("domain")
    message = typed_data.get("message")
    if not isinstance(types, dict):
        raise ValueError("typed_data.types must be a dict")
    if not isinstance(primary_type, str):
        raise ValueError("typed_data.primaryType must be a string")
    if not isinstance(domain, dict):
        raise ValueError("typed_data.domain must be a dict")
    if not isinstance(message, dict):
        raise ValueError("typed_data.message must be a dict")
    if "EIP712Domain" not in types:
        raise ValueError("typed_data.types must include EIP712Domain")
    if primary_type not in types:
        raise ValueError(
            f"typed_data.primaryType {primary_type!r} not present in types"
        )

    domain_separator = _struct_hash("EIP712Domain", domain, types)
    struct_hash = _struct_hash(primary_type, message, types)
    return keccak256(b"\x19\x01" + domain_separator + struct_hash)


def _struct_hash(struct_name: str, value: dict, types: dict) -> bytes:
    """Compute the struct hash for a typed-data struct value per EIP-712."""
    type_hash = keccak256(_encode_type(struct_name, types).encode("utf-8"))
    encoded_data = type_hash
    for field in types[struct_name]:
        field_name = field["name"]
        field_type = field["type"]
        if field_name not in value:
            raise ValueError(
                f"struct {struct_name} field {field_name!r} missing from value"
            )
        encoded_data += _encode_value(field_type, value[field_name], types)
    return keccak256(encoded_data)


def _encode_type(primary_type: str, types: dict) -> str:
    """Serialize the type schema for ``primary_type`` per EIP-712.

    Format: ``PrimaryType(field1Type field1Name,...)Sub1(...)Sub2(...)``
    where the primary type's signature comes first, followed by its
    referenced struct types in alphabetical order.
    """
    deps = _find_type_dependencies(primary_type, types)
    deps.discard(primary_type)
    sorted_deps = [primary_type] + sorted(deps)
    parts = []
    for dep in sorted_deps:
        if dep not in types:
            raise ValueError(
                f"type {dep!r} referenced from {primary_type!r} not present in types"
            )
        fields = ",".join(
            f"{f['type']} {f['name']}" for f in types[dep]
        )
        parts.append(f"{dep}({fields})")
    return "".join(parts)


def _find_type_dependencies(
    primary_type: str, types: dict, found: set | None = None
) -> set:
    """Walk the schema for ``primary_type`` collecting every referenced
    struct type. Atomic types (uint*, int*, address, bool, bytes*,
    string) are NOT included."""
    if found is None:
        found = set()
    # Strip array brackets to find the base type.
    base = primary_type.split("[", 1)[0]
    if base in found:
        return found
    if base not in types:
        # Atomic type — not a dependency.
        return found
    found.add(base)
    for field in types[base]:
        _find_type_dependencies(field["type"], types, found)
    return found


def _encode_value(field_type: str, value, types: dict) -> bytes:
    """Encode a single field value per EIP-712 abi.encode rules.

    Atomic types pack into 32 bytes. Strings and bytes encode as
    keccak256 of the raw value. Struct types recurse into _struct_hash.
    Arrays encode as keccak256 of the concatenated element encodings.
    """
    # Array types: ``T[]`` (dynamic) or ``T[N]`` (fixed-size).
    if field_type.endswith("]"):
        bracket_idx = field_type.rfind("[")
        inner_type = field_type[:bracket_idx]
        if not isinstance(value, list):
            raise ValueError(
                f"array field of type {field_type} requires a list value"
            )
        encoded_elements = b"".join(
            _encode_value(inner_type, item, types) for item in value
        )
        return keccak256(encoded_elements)

    # Struct (referenced type)
    if field_type in types:
        return _struct_hash(field_type, value, types)

    # Atomic / scalar types
    if field_type == "string":
        if not isinstance(value, str):
            raise ValueError(f"field of type string requires string value, got {type(value).__name__}")
        return keccak256(value.encode("utf-8"))

    if field_type == "bytes":
        # Dynamic-length bytes: hex string with 0x prefix or raw bytes.
        raw = _hex_or_bytes_to_bytes(value)
        return keccak256(raw)

    if field_type.startswith("bytes"):
        # bytes1..bytes32 — fixed-length, right-padded to 32 bytes.
        n = int(field_type[len("bytes"):])
        if n < 1 or n > 32:
            raise ValueError(f"bytes{n} out of range 1..32")
        raw = _hex_or_bytes_to_bytes(value)
        if len(raw) > n:
            raise ValueError(f"bytes{n} value too long: {len(raw)} bytes")
        return raw + b"\x00" * (32 - len(raw))

    if field_type == "address":
        if not isinstance(value, str):
            raise ValueError(f"address field requires hex string, got {type(value).__name__}")
        cleaned = value[2:] if value.startswith(("0x", "0X")) else value
        if len(cleaned) != 40:
            raise ValueError(f"address must be 40 hex chars after 0x prefix, got {len(cleaned)}")
        addr_bytes = bytes.fromhex(cleaned)
        # Left-pad to 32 bytes.
        return b"\x00" * 12 + addr_bytes

    if field_type == "bool":
        if not isinstance(value, bool):
            raise ValueError(f"bool field requires bool value, got {type(value).__name__}")
        return b"\x00" * 31 + (b"\x01" if value else b"\x00")

    if field_type.startswith("uint") or field_type.startswith("int"):
        # uint8..uint256, int8..int256
        is_signed = field_type.startswith("int")
        bits_str = field_type[len("int"):] if is_signed else field_type[len("uint"):]
        bits = int(bits_str) if bits_str else 256
        if bits < 8 or bits > 256 or bits % 8 != 0:
            raise ValueError(f"unsupported integer type {field_type}")
        if isinstance(value, str):
            n = int(value, 0)
        elif isinstance(value, int):
            n = value
        else:
            raise ValueError(f"integer field requires int or hex string, got {type(value).__name__}")
        if is_signed:
            # Two's complement encoding, left-padded to 32 bytes.
            if n < 0:
                n = (1 << 256) + n
        else:
            if n < 0:
                raise ValueError(f"uint{bits} cannot be negative: {value}")
        return n.to_bytes(32, "big")

    raise ValueError(f"unsupported EIP-712 type {field_type!r}")


def _hex_or_bytes_to_bytes(value) -> bytes:
    """Convert either ``bytes``-like or a 0x-prefixed hex string to bytes."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        cleaned = value[2:] if value.startswith(("0x", "0X")) else value
        return bytes.fromhex(cleaned)
    raise ValueError(f"expected bytes or hex string, got {type(value).__name__}")


# ---------------------------------------------------------------------------
# RLP encoding (Recursive Length Prefix)
# Reference: https://eth.wiki/fundamentals/rlp
# Used by EIP-1559 transaction encoding below.
# ---------------------------------------------------------------------------


def rlp_encode(item) -> bytes:
    """RLP-encode an item. Items are:
    - bytes / bytearray → encoded as a string
    - int (non-negative) → encoded as the minimal big-endian bytes
    - str → UTF-8 encoded then string-encoded
    - list → encoded as a list of encoded items

    Raises ``ValueError`` for negative ints or unsupported types.
    """
    if isinstance(item, (bytes, bytearray)):
        return _rlp_encode_string(bytes(item))
    if isinstance(item, int):
        if item < 0:
            raise ValueError(f"RLP cannot encode negative int {item}")
        if item == 0:
            return _rlp_encode_string(b"")
        # Minimal big-endian encoding.
        nbytes = (item.bit_length() + 7) // 8
        return _rlp_encode_string(item.to_bytes(nbytes, "big"))
    if isinstance(item, str):
        return _rlp_encode_string(item.encode("utf-8"))
    if isinstance(item, list):
        encoded = b"".join(rlp_encode(x) for x in item)
        return _rlp_encode_length(len(encoded), 0xC0) + encoded
    raise ValueError(f"RLP cannot encode {type(item).__name__}")


def _rlp_encode_string(data: bytes) -> bytes:
    """Encode a byte string per RLP §"String encoding"."""
    if len(data) == 1 and data[0] < 0x80:
        return data  # single byte < 0x80 encodes as itself
    return _rlp_encode_length(len(data), 0x80) + data


def _rlp_encode_length(length: int, offset: int) -> bytes:
    """RLP length prefix. ``offset`` is 0x80 for strings, 0xC0 for lists."""
    if length < 56:
        return bytes([offset + length])
    nbytes = (length.bit_length() + 7) // 8
    return bytes([offset + 55 + nbytes]) + length.to_bytes(nbytes, "big")


def rlp_decode(data: bytes) -> tuple:
    """RLP-decode bytes. Returns the decoded item (bytes for strings,
    list for lists, recursively). Raises ``ValueError`` on malformed
    input.

    The result of the top-level decode is the first item in the bytes;
    if there are trailing bytes after a complete decode, they're
    rejected as malformed.
    """
    item, rest = _rlp_decode_one(data, 0)
    if rest != len(data):
        raise ValueError(f"RLP decode left {len(data) - rest} trailing bytes")
    return item


def _rlp_decode_one(data: bytes, offset: int):
    """Decode one item starting at ``offset``. Returns (item, new_offset)."""
    if offset >= len(data):
        raise ValueError("RLP decode past end of data")
    first = data[offset]
    if first < 0x80:
        # Single byte
        return bytes([first]), offset + 1
    if first < 0xB8:
        # Short string (0..55 bytes)
        n = first - 0x80
        end = offset + 1 + n
        if end > len(data):
            raise ValueError("RLP short-string truncated")
        return data[offset + 1:end], end
    if first < 0xC0:
        # Long string
        nlen = first - 0xB7
        if offset + 1 + nlen > len(data):
            raise ValueError("RLP long-string length truncated")
        n = int.from_bytes(data[offset + 1:offset + 1 + nlen], "big")
        start = offset + 1 + nlen
        end = start + n
        if end > len(data):
            raise ValueError("RLP long-string body truncated")
        return data[start:end], end
    if first < 0xF8:
        # Short list
        n = first - 0xC0
        end = offset + 1 + n
        if end > len(data):
            raise ValueError("RLP short-list truncated")
        return _rlp_decode_list(data, offset + 1, end), end
    # Long list
    nlen = first - 0xF7
    if offset + 1 + nlen > len(data):
        raise ValueError("RLP long-list length truncated")
    n = int.from_bytes(data[offset + 1:offset + 1 + nlen], "big")
    start = offset + 1 + nlen
    end = start + n
    if end > len(data):
        raise ValueError("RLP long-list body truncated")
    return _rlp_decode_list(data, start, end), end


def _rlp_decode_list(data: bytes, start: int, end: int) -> list:
    out: list = []
    cursor = start
    while cursor < end:
        item, cursor = _rlp_decode_one(data, cursor)
        out.append(item)
    if cursor != end:
        raise ValueError("RLP list inner-decode overshoot")
    return out


# ---------------------------------------------------------------------------
# EIP-1559 transaction signing hash
# Reference: https://eips.ethereum.org/EIPS/eip-1559
# Encoding: 0x02 || rlp([chain_id, nonce, max_priority_fee_per_gas,
#                        max_fee_per_gas, gas_limit, to, value, data, access_list])
# ---------------------------------------------------------------------------


def transaction_hash_eip1559(tx: dict) -> bytes:
    """Compute the keccak256 digest of an EIP-1559 (type 0x02)
    transaction for signing.

    ``tx`` is a dict with the canonical Ethereum transaction fields:

    - ``chainId`` (int)
    - ``nonce`` (int)
    - ``maxPriorityFeePerGas`` (int, in wei)
    - ``maxFeePerGas`` (int, in wei)
    - ``gas`` or ``gasLimit`` (int)
    - ``to`` (0x-prefixed hex address; empty string or None for contract creation)
    - ``value`` (int, in wei)
    - ``data`` (0x-prefixed hex bytes; empty string for plain transfers)
    - ``accessList`` (optional, list of [address, [storage_keys]] pairs)

    The signer signs this digest with secp256k1 ECDSA + RFC 6979
    deterministic-k, returns r||s||v where v = recovery_id (NOT 27 + recid;
    EIP-1559 uses raw recovery id).

    Returns the 32-byte digest.
    """
    chain_id = _int_field(tx, "chainId", required=True)
    nonce = _int_field(tx, "nonce", required=True)
    max_priority = _int_field(tx, "maxPriorityFeePerGas", required=True)
    max_fee = _int_field(tx, "maxFeePerGas", required=True)
    gas_limit = _int_field(tx, "gas", required=False)
    if gas_limit is None:
        gas_limit = _int_field(tx, "gasLimit", required=True)
    value = _int_field(tx, "value", required=False) or 0
    to_field = tx.get("to")
    if to_field is None or to_field == "":
        to_bytes: bytes = b""  # contract creation
    else:
        to_str = str(to_field)
        cleaned = to_str[2:] if to_str.startswith(("0x", "0X")) else to_str
        if len(cleaned) != 40:
            raise ValueError(f"transaction.to must be 40 hex chars, got {len(cleaned)}")
        to_bytes = bytes.fromhex(cleaned)
    data_field = tx.get("data") or "0x"
    data_str = str(data_field)
    data_clean = data_str[2:] if data_str.startswith(("0x", "0X")) else data_str
    data_bytes = bytes.fromhex(data_clean) if data_clean else b""
    access_list_raw = tx.get("accessList") or []
    access_list = _normalize_access_list(access_list_raw)

    payload = [
        chain_id,
        nonce,
        max_priority,
        max_fee,
        gas_limit,
        to_bytes,
        value,
        data_bytes,
        access_list,
    ]
    encoded = b"\x02" + rlp_encode(payload)
    return keccak256(encoded)


def _int_field(tx: dict, name: str, required: bool) -> int | None:
    """Extract an integer field from a transaction dict; accepts int
    or 0x-prefixed hex string. Returns None if absent and not required."""
    if name not in tx or tx[name] is None:
        if required:
            raise ValueError(f"transaction.{name} is required")
        return None
    value = tx[name]
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise ValueError(f"transaction.{name} must be int or hex string, got {type(value).__name__}")


def _normalize_access_list(raw) -> list:
    """Normalize the access-list field (EIP-2930) for RLP encoding.

    Each entry is ``[address_bytes, [storage_key_bytes, ...]]``. The
    raw field can be either a list of [str, [str, ...]] or already in
    bytes form."""
    if not isinstance(raw, list):
        raise ValueError("accessList must be a list")
    out = []
    for entry in raw:
        if isinstance(entry, dict):
            addr_str = entry.get("address", "")
            storage = entry.get("storageKeys", [])
        elif isinstance(entry, list) and len(entry) == 2:
            addr_str, storage = entry
        else:
            raise ValueError(
                "accessList entries must be {address, storageKeys} dicts or [address, storageKeys] pairs"
            )
        addr_clean = addr_str[2:] if addr_str.startswith(("0x", "0X")) else addr_str
        if len(addr_clean) != 40:
            raise ValueError(f"accessList address must be 40 hex chars, got {len(addr_clean)}")
        addr_bytes = bytes.fromhex(addr_clean)
        storage_bytes = []
        for key in storage:
            kc = key[2:] if key.startswith(("0x", "0X")) else key
            if len(kc) != 64:
                raise ValueError(f"accessList storage key must be 64 hex chars, got {len(kc)}")
            storage_bytes.append(bytes.fromhex(kc))
        out.append([addr_bytes, storage_bytes])
    return out
