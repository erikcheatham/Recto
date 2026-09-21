"""Tests for ``recto.bitcoin``.

Pins the Bitcoin-side helpers against canonical reference vectors:

- RIPEMD-160 against Dobbertin/Bosselaers/Preneel published vectors.
- Bech32 / bech32m against BIP-173 / BIP-350 reference test addresses.
- HASH160 of secp256k1 generator G → canonical
  ``bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4`` P2WPKH address.
- Bitcoin signed-message hash against canonical example.
- BIP-137 compact signature parse + sign-then-recover round-trip.

Most of the cross-wallet interop confidence comes from the BIP-173
test vector — if our bech32 encoder produces the literal address
string the BIP defines for HASH160(G), every external consumer
(Bitcoin Core, Electrum, hardware wallets, web verifiers) will
recover signatures from this implementation correctly.
"""

from __future__ import annotations

import base64
import hashlib
import secrets

import pytest

from recto.bitcoin import (
    address_from_public_key,
    bech32_decode,
    bech32_encode,
    compress_public_key,
    double_sha256,
    hash160,
    parse_compact_signature,
    recover_address,
    recover_public_key,
    ripemd160,
    signed_message_hash,
    verify_signature,
)


# ---------------------------------------------------------------------------
# secp256k1 generator point fixtures (used for end-to-end address derivation
# tests). Same generator both Ethereum and Bitcoin use.
# ---------------------------------------------------------------------------


_GENERATOR_X = bytes.fromhex(
    "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
)
_GENERATOR_Y = bytes.fromhex(
    "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
)
_GENERATOR_UNCOMPRESSED = _GENERATOR_X + _GENERATOR_Y  # 64 bytes X || Y


# ---------------------------------------------------------------------------
# RIPEMD-160 test vectors (from the original RIPEMD-160 paper, Appendix A).
# ---------------------------------------------------------------------------


class TestRipemd160:
    @pytest.mark.parametrize("data,expected", [
        (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
        (b"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
        (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
        (b"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
        (b"abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"),
        (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "12a053384a9c0c88e405a06c27dcf49ada62eb2b"),
    ])
    def test_canonical_vectors(self, data: bytes, expected: str):
        assert ripemd160(data).hex() == expected

    def test_million_a(self):
        # The published vector for 1,000,000 'a's — confirms the
        # padding logic handles long inputs correctly.
        assert ripemd160(b"a" * 1_000_000).hex() == "52783243c1697bdbe16d37f97f68f08325dc1528"


# ---------------------------------------------------------------------------
# HASH160 + double-SHA-256 sanity vectors.
# ---------------------------------------------------------------------------


class TestHashes:
    def test_hash160_matches_ripemd160_of_sha256(self):
        # Definition test: HASH160(x) MUST equal RIPEMD-160(SHA-256(x)).
        for data in (b"", b"hello", b"\x00" * 64, secrets.token_bytes(33)):
            expected = ripemd160(hashlib.sha256(data).digest())
            assert hash160(data) == expected

    def test_double_sha256_canonical(self):
        # Canonical: double_sha256(b"") = 5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456
        assert double_sha256(b"").hex() == (
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
        )


# ---------------------------------------------------------------------------
# Public-key compression round-trip.
# ---------------------------------------------------------------------------


class TestCompressPublicKey:
    def test_generator_compresses_to_known_value(self):
        compressed = compress_public_key(_GENERATOR_UNCOMPRESSED)
        # G's Y coordinate is even, so prefix is 0x02.
        # The compressed form is 0x02 || X.
        assert compressed.hex() == (
            "02"
            + "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        )
        assert len(compressed) == 33

    def test_rejects_wrong_length(self):
        with pytest.raises(ValueError):
            compress_public_key(b"\x00" * 63)
        with pytest.raises(ValueError):
            compress_public_key(b"\x00" * 65)


# ---------------------------------------------------------------------------
# Bech32 / bech32m (BIP-173 / BIP-350) reference vectors.
# ---------------------------------------------------------------------------


class TestBech32Encode:
    def test_bip173_mainnet_p2wpkh_canonical(self):
        # BIP-173 test vector: HASH160 of generator G compressed pubkey
        # encodes as bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4.
        program = bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6")
        assert (
            bech32_encode("bc", 0, program)
            == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        )

    def test_bip173_testnet_p2wpkh_canonical(self):
        program = bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6")
        assert (
            bech32_encode("tb", 0, program)
            == "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
        )

    def test_bip350_mainnet_p2wsh_canonical(self):
        # BIP-173 P2WSH (32-byte program at witver=0): bc1qrp33g0q5c5...
        program = bytes.fromhex(
            "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"
        )
        addr = bech32_encode("bc", 0, program)
        assert addr == (
            "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"
        )

    def test_bech32_decode_round_trip(self):
        original_hrp = "bc"
        original_witver = 0
        original_program = bytes.fromhex(
            "751e76e8199196d454941c45d1b3a323f1433bd6"
        )
        addr = bech32_encode(original_hrp, original_witver, original_program)
        hrp, witver, program = bech32_decode(addr)
        assert hrp == original_hrp
        assert witver == original_witver
        assert program == original_program

    def test_decode_rejects_mixed_case(self):
        # bech32 explicitly forbids mixed case to avoid OCR ambiguity.
        with pytest.raises(ValueError, match="mixed"):
            bech32_decode("BC1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")

    def test_decode_accepts_uppercase(self):
        addr_upper = "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4"
        hrp, witver, program = bech32_decode(addr_upper)
        assert hrp == "bc"
        assert witver == 0
        assert program == bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6")

    def test_decode_rejects_bad_checksum(self):
        # Flip one character in the checksum portion.
        with pytest.raises(ValueError, match="checksum"):
            bech32_decode("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5")

    def test_decode_rejects_missing_separator(self):
        with pytest.raises(ValueError, match="separator"):
            bech32_decode("bcqw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")


# ---------------------------------------------------------------------------
# address_from_public_key — end-to-end address derivation.
# ---------------------------------------------------------------------------


class TestAddressDerivation:
    def test_p2wpkh_mainnet_from_generator(self):
        addr = address_from_public_key(_GENERATOR_UNCOMPRESSED, "mainnet", "p2wpkh")
        assert addr == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"

    def test_p2wpkh_testnet_from_generator(self):
        addr = address_from_public_key(_GENERATOR_UNCOMPRESSED, "testnet", "p2wpkh")
        assert addr == "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"

    def test_p2pkh_mainnet_starts_with_1(self):
        addr = address_from_public_key(_GENERATOR_UNCOMPRESSED, "mainnet", "p2pkh")
        assert addr.startswith("1")
        # Length: P2PKH addresses are 26-35 chars (depends on leading-zeros count).
        assert 26 <= len(addr) <= 35

    def test_p2pkh_testnet_starts_with_m_or_n(self):
        addr = address_from_public_key(_GENERATOR_UNCOMPRESSED, "testnet", "p2pkh")
        assert addr[0] in ("m", "n")

    def test_p2sh_p2wpkh_mainnet_starts_with_3(self):
        addr = address_from_public_key(_GENERATOR_UNCOMPRESSED, "mainnet", "p2sh-p2wpkh")
        assert addr.startswith("3")

    def test_p2sh_p2wpkh_testnet_starts_with_2(self):
        addr = address_from_public_key(_GENERATOR_UNCOMPRESSED, "testnet", "p2sh-p2wpkh")
        assert addr.startswith("2")

    def test_unknown_kind_rejected(self):
        with pytest.raises(ValueError, match="kind"):
            address_from_public_key(_GENERATOR_UNCOMPRESSED, "mainnet", "p2tr")

    def test_unknown_network_rejected(self):
        with pytest.raises(ValueError, match="network"):
            address_from_public_key(_GENERATOR_UNCOMPRESSED, "satoshinet", "p2wpkh")


# ---------------------------------------------------------------------------
# Bitcoin signed-message hash (BIP-137).
# ---------------------------------------------------------------------------


class TestSignedMessageHash:
    def test_hello_canonical(self):
        # Computed from the canonical BIP-137 prefix:
        # double_sha256("\x18Bitcoin Signed Message:\n" + varint(5) + "hello")
        # = double_sha256(0x18 ++ "Bitcoin Signed Message:\n" ++ 0x05 ++ "hello")
        # Reference value computed by Bitcoin Core's signmessage.
        # We verify our impl is internally consistent + cross-validated by
        # the BIP-137 sign+recover round trip in TestBip137SignVerify.
        h = signed_message_hash(b"hello")
        assert len(h) == 32
        # double_sha256 of the prefix-and-message bytes — fixed value the
        # impl must produce. Recomputed from the spec to pin the impl.
        expected_preimage = (
            b"\x18"                                  # length-prefix byte
            + b"Bitcoin Signed Message:\n"           # 24 bytes
            + b"\x05"                                # varint(5)
            + b"hello"                               # message bytes
        )
        assert h == double_sha256(expected_preimage)

    def test_long_message_uses_varint_encoding(self):
        # Messages >= 253 bytes use multi-byte varint encoding (0xfd prefix).
        msg = b"x" * 300
        h = signed_message_hash(msg)
        # varint(300) = 0xfd 0x2c 0x01
        expected_preimage = (
            b"\x18"
            + b"Bitcoin Signed Message:\n"
            + b"\xfd\x2c\x01"
            + msg
        )
        assert h == double_sha256(expected_preimage)


class TestSignedMessageHashCoinFamily:
    """Wave-7 coin-aware hashing. BTC + BCH share Bitcoin's preamble
    (24-char "Bitcoin Signed Message:\\n" → length byte 0x18). LTC +
    DOGE have their own 25-char preambles → length byte 0x19. Each
    produces a distinct hash for the same message."""

    def test_btc_default_matches_explicit(self):
        h_default = signed_message_hash(b"hello")
        h_explicit = signed_message_hash(b"hello", coin="btc")
        assert h_default == h_explicit

    def test_bch_uses_bitcoin_preamble(self):
        # BCH retained Bitcoin's signed-message preamble post-fork,
        # so BCH and BTC produce the SAME hash for the same message.
        h_btc = signed_message_hash(b"hello", coin="btc")
        h_bch = signed_message_hash(b"hello", coin="bch")
        assert h_btc == h_bch

    def test_ltc_distinct_from_btc(self):
        # LTC preamble: "Litecoin Signed Message:\n" (25 chars).
        h_btc = signed_message_hash(b"hello", coin="btc")
        h_ltc = signed_message_hash(b"hello", coin="ltc")
        assert h_btc != h_ltc

        expected_ltc_preimage = (
            b"\x19"                                   # length byte = 25
            + b"Litecoin Signed Message:\n"           # 25 bytes
            + b"\x05"                                 # varint(5)
            + b"hello"
        )
        assert h_ltc == double_sha256(expected_ltc_preimage)

    def test_doge_distinct_from_btc_and_ltc(self):
        # DOGE preamble: "Dogecoin Signed Message:\n" (25 chars).
        h_btc = signed_message_hash(b"hello", coin="btc")
        h_ltc = signed_message_hash(b"hello", coin="ltc")
        h_doge = signed_message_hash(b"hello", coin="doge")
        assert h_doge != h_btc
        assert h_doge != h_ltc

        expected_doge_preimage = (
            b"\x19"
            + b"Dogecoin Signed Message:\n"
            + b"\x05"
            + b"hello"
        )
        assert h_doge == double_sha256(expected_doge_preimage)

    def test_unknown_coin_rejected(self):
        import pytest
        with pytest.raises(ValueError, match="coin must be one of"):
            signed_message_hash(b"hello", coin="xrp")


class TestAddressFromPublicKeyCoinFamily:
    """Wave-7 coin-aware address derivation. Same compressed pubkey
    produces different addresses across BTC / LTC / DOGE / BCH because
    the version bytes / HRPs differ. P2WPKH is rejected for DOGE / BCH
    (no native SegWit support)."""

    # Generator G (compressed): "\x02" || X-coordinate of secp256k1 G.
    # Equivalently: bytes(33) where pubkey64 = G.x || G.y uncompressed.
    # We use the well-known generator point for cross-implementation
    # reference compatibility — every secp256k1 lib computes the same
    # HASH160 from this canonical pubkey.
    _G_UNCOMPRESSED = (
        bytes.fromhex(
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
        )
    )

    def test_btc_p2wpkh_default(self):
        addr = address_from_public_key(self._G_UNCOMPRESSED, network="mainnet", coin="btc")
        # Canonical "HASH160 of G" P2WPKH address from BIP-173 examples.
        assert addr == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"

    def test_ltc_p2wpkh_starts_with_ltc1q(self):
        addr = address_from_public_key(self._G_UNCOMPRESSED, network="mainnet", coin="ltc")
        assert addr.startswith("ltc1q"), f"LTC bech32 mainnet addr should start with ltc1q, got {addr}"

    def test_doge_p2pkh_starts_with_D(self):
        # Default address kind is p2pkh for DOGE (no native SegWit).
        addr = address_from_public_key(self._G_UNCOMPRESSED, network="mainnet", coin="doge")
        assert addr.startswith("D"), f"DOGE mainnet P2PKH (version 0x1E) should start with 'D', got {addr}"

    def test_bch_p2pkh_starts_with_1(self):
        # BCH legacy P2PKH (version 0x00) shares format with BTC's legacy.
        addr = address_from_public_key(self._G_UNCOMPRESSED, network="mainnet", coin="bch")
        assert addr.startswith("1"), f"BCH mainnet legacy P2PKH should start with '1', got {addr}"

    def test_doge_rejects_p2wpkh(self):
        import pytest
        with pytest.raises(ValueError, match="does not support native SegWit"):
            address_from_public_key(self._G_UNCOMPRESSED, network="mainnet", kind="p2wpkh", coin="doge")

    def test_bch_rejects_p2wpkh(self):
        import pytest
        with pytest.raises(ValueError, match="does not support native SegWit"):
            address_from_public_key(self._G_UNCOMPRESSED, network="mainnet", kind="p2wpkh", coin="bch")


# ---------------------------------------------------------------------------
# BIP-137 compact signature parse.
# ---------------------------------------------------------------------------


class TestParseCompactSignature:
    def _make_sig(self, header: int, r: int = 1, s: int = 2) -> bytes:
        return bytes([header]) + r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def test_p2pkh_uncompressed_header_27_to_30(self):
        for header in (27, 28, 29, 30):
            r, s, recid, kind = parse_compact_signature(self._make_sig(header))
            assert kind == "p2pkh-uncompressed"
            assert recid == header - 27

    def test_p2pkh_compressed_header_31_to_34(self):
        for header in (31, 32, 33, 34):
            _, _, recid, kind = parse_compact_signature(self._make_sig(header))
            assert kind == "p2pkh"
            assert recid == header - 31

    def test_p2sh_p2wpkh_header_35_to_38(self):
        for header in (35, 36, 37, 38):
            _, _, recid, kind = parse_compact_signature(self._make_sig(header))
            assert kind == "p2sh-p2wpkh"
            assert recid == header - 35

    def test_p2wpkh_header_39_to_42(self):
        for header in (39, 40, 41, 42):
            _, _, recid, kind = parse_compact_signature(self._make_sig(header))
            assert kind == "p2wpkh"
            assert recid == header - 39

    def test_rejects_header_below_27(self):
        with pytest.raises(ValueError, match="27..42"):
            parse_compact_signature(self._make_sig(26))

    def test_rejects_header_above_42(self):
        with pytest.raises(ValueError, match="27..42"):
            parse_compact_signature(self._make_sig(43))

    def test_accepts_base64_input(self):
        raw = self._make_sig(40)
        sig_b64 = base64.b64encode(raw).decode("ascii")
        r, s, recid, kind = parse_compact_signature(sig_b64)
        assert kind == "p2wpkh"
        assert recid == 40 - 39

    def test_rejects_wrong_length(self):
        with pytest.raises(ValueError, match="65 bytes"):
            parse_compact_signature(b"\x27" + b"\x00" * 63)


# ---------------------------------------------------------------------------
# BIP-137 sign-then-recover round trip — proves verification works
# end-to-end against signatures produced by reference signing code.
#
# We sign with a known private key (derived from a fixed test scalar)
# and confirm recover_address recovers the matching P2WPKH address.
# ---------------------------------------------------------------------------


def _sign_btc_message(privkey: int, message: bytes) -> tuple[bytes, str]:
    """Test-only helper: sign a Bitcoin message with the given private
    key and return (compact_sig_bytes, expected_p2wpkh_address). Uses
    the Ethereum module's signing primitives (same curve, RFC 6979
    deterministic-k) and converts the resulting r||s||v to BIP-137
    P2WPKH header form."""
    # Use the ethereum module's secp256k1 + RFC 6979 — same curve.
    # We need to import the lower-level primitive here since
    # recto.ethereum doesn't expose a "sign" verb publicly (its public
    # surface is verify-only). For tests, reaching into private helpers
    # is fine.
    from recto.ethereum import (
        _ec_mul, _SECP256K1_GX, _SECP256K1_GY, _SECP256K1_N,
        address_from_public_key as _eth_addr,
    )
    # Derive the public key.
    pub_point = _ec_mul(privkey, (_SECP256K1_GX, _SECP256K1_GY))
    assert pub_point is not None
    px, py = pub_point
    pub64 = px.to_bytes(32, "big") + py.to_bytes(32, "big")
    # RFC 6979 deterministic-k via the cryptography library would be
    # cleanest, but we can also just inline a non-deterministic-k sign
    # using Python's stdlib for tests. For deterministic test results
    # we use a fixed-k sign — this is INSECURE for real signing but
    # fine for verifying that our recover code path works.
    msg_hash = signed_message_hash(message)
    e = int.from_bytes(msg_hash, "big") % _SECP256K1_N
    # Fixed test k that's coprime with N; in production, RFC 6979 derives
    # k deterministically from (privkey, msg_hash).
    k = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
    k = k % _SECP256K1_N
    R = _ec_mul(k, (_SECP256K1_GX, _SECP256K1_GY))
    assert R is not None
    rx, ry = R
    r = rx % _SECP256K1_N
    if r == 0:
        raise RuntimeError("test-fixture k landed on r=0; pick another k")
    k_inv = pow(k, -1, _SECP256K1_N)
    s = (k_inv * (e + r * privkey)) % _SECP256K1_N
    if s == 0:
        raise RuntimeError("test-fixture k landed on s=0; pick another k")
    # Canonicalize to low-s.
    half_n = _SECP256K1_N >> 1
    if s > half_n:
        s = _SECP256K1_N - s
        # When s is canonicalized, recovery_id flips its low bit.
        recovery_id = 1 - (ry & 1)
    else:
        recovery_id = ry & 1
    # Add 2 to recovery_id if x > N (extremely rare on secp256k1; we don't bother).
    # Build the BIP-137 compact signature header byte for P2WPKH (39 + recid).
    header = 27 + 12 + recovery_id
    sig_bytes = bytes([header]) + r.to_bytes(32, "big") + s.to_bytes(32, "big")
    expected_addr = address_from_public_key(pub64, "mainnet", "p2wpkh")
    return sig_bytes, expected_addr


class TestBip137SignVerify:
    def test_round_trip_verifies(self):
        privkey = 0xC0FFEE7E57DEC0DEDA7AB1ED1234567890ABCDEF1234567890ABCDEF12345678
        message = b"Recto test signature"
        sig_bytes, expected_addr = _sign_btc_message(privkey, message)
        msg_hash = signed_message_hash(message)
        recovered = recover_address(msg_hash, sig_bytes, network="mainnet")
        assert recovered.lower() == expected_addr.lower()

    def test_round_trip_via_base64(self):
        # Real wire-format: phone returns base64-encoded compact sig.
        privkey = 0xDEADBEEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF12345678
        message = b"hello world"
        sig_bytes, expected_addr = _sign_btc_message(privkey, message)
        sig_b64 = base64.b64encode(sig_bytes).decode("ascii")
        msg_hash = signed_message_hash(message)
        recovered = recover_address(msg_hash, sig_b64, network="mainnet")
        assert recovered.lower() == expected_addr.lower()

    def test_verify_signature_returns_true_for_valid(self):
        privkey = 0xABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789
        message = b"verify me"
        sig_bytes, expected_addr = _sign_btc_message(privkey, message)
        msg_hash = signed_message_hash(message)
        assert verify_signature(msg_hash, sig_bytes, expected_addr, "mainnet") is True

    def test_verify_signature_returns_false_for_wrong_address(self):
        privkey = 0xABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789
        message = b"verify me"
        sig_bytes, _ = _sign_btc_message(privkey, message)
        msg_hash = signed_message_hash(message)
        wrong_addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"  # G's HASH160
        assert verify_signature(msg_hash, sig_bytes, wrong_addr, "mainnet") is False

    def test_recover_public_key_matches_signing_pubkey(self):
        privkey = 0x1A2B3C4D5E6F70819A2B3C4D5E6F70819A2B3C4D5E6F70819A2B3C4D5E6F7081
        message = b"recover the pubkey directly"
        sig_bytes, _ = _sign_btc_message(privkey, message)
        msg_hash = signed_message_hash(message)
        recovered_pub = recover_public_key(msg_hash, sig_bytes)
        # Compute the expected pubkey directly via the same primitive
        # the test helper used.
        from recto.ethereum import _ec_mul, _SECP256K1_GX, _SECP256K1_GY
        pub_point = _ec_mul(privkey, (_SECP256K1_GX, _SECP256K1_GY))
        assert pub_point is not None
        px, py = pub_point
        expected_pub = px.to_bytes(32, "big") + py.to_bytes(32, "big")
        assert recovered_pub == expected_pub
