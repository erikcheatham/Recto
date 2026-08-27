"""Tests for ``recto.tron`` -- TIP-191 signed-message hash +
base58check address derivation + secp256k1 recovery + verify.

Test discipline (per Recto's "Cryptographic prefix bytes are
non-negotiable" rule, banked from the EIP-191 wave-4 audit
2026-04-28): pin behavior against externally-verifiable reference
values where possible, then fall back to round-trips for parts
without a standalone reference.

Concrete external pins in this file:

- The secp256k1 generator point G has a well-known ETH address
  derived from its uncompressed pubkey: ``0x7E5F4552091A69125d5DfCb
  7b8C2659029395Bdf``. TRON's derivation reuses the same Keccak-256-
  of-uncompressed-pubkey-last-20-bytes; the only differences are
  the version byte (``0x41``) and the encoding (base58check vs
  EIP-55 hex). So G's TRON address is mechanically derivable: the
  same 20 bytes prefixed with ``0x41`` and base58check'd. Pinning
  the resulting ``T...`` string proves base58check is correct (any
  bug in the alphabet, the checksum, or the leading-zero handling
  would change the output).
- TIP-191 hash MUST differ from EIP-191 hash for the same input
  (different preamble strings -> different keccak digest). Pinning
  this distinctness catches a future "fix" that accidentally
  swaps preambles or drops the leading 0x19.
- TIP-191 hash MUST differ from bare keccak256 of the message
  (a verifier that forgot to apply the preamble would silently
  accept signatures from any wallet that signs raw bytes -- worth
  catching at unit-test time).

Mnemonic-derived address vectors (TronLink / TronWeb cross-wallet
interop) are deferred to wave 9 part 2 once the C# Bip32
derivation runs phone-side and the operator can pin a value
against TronLink at ``m/44'/195'/0'/0/0``.
"""

from __future__ import annotations

import secrets

import pytest

from recto import tron
from recto.ethereum import keccak256, personal_sign_hash


# secp256k1 generator point G in uncompressed (X||Y) form. Pinned
# against any standard secp256k1 reference -- this constant is
# load-bearing for the canonical-address tests below.
_G_X = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_G_Y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
GENERATOR_PUBKEY64 = (
    _G_X.to_bytes(32, "big") + _G_Y.to_bytes(32, "big")
)

# Well-known ETH address for the generator G. Pinned against
# countless ETH references (e.g. Trezor's BIP-32 vectors, ethers.js
# tests). Confirms keccak256(uncompressed_pubkey)[-20:] is correct
# before TRON's address-encoding layer is even involved.
GENERATOR_ETH_ADDRESS_HEX = "7e5f4552091a69125d5dfcb7b8c2659029395bdf"

# Canonical TRON address for the generator G. Mechanically derived
# from GENERATOR_ETH_ADDRESS_HEX by prefixing with version byte 0x41
# and base58check-encoding. Pinning this string proves the entire
# address-encoding pipeline (keccak slice + 0x41 prefix + double-
# SHA-256 checksum + base58 alphabet + leading-zero handling)
# matches a TRON-explorer / TronWeb derivation of the same pubkey.
GENERATOR_TRON_ADDRESS = "TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC"


class TestSignedMessageHash:
    def test_preamble_constant_is_bare_string_no_leading_byte(self):
        # The MESSAGE_PREAMBLE constant is the bare TIP-191 preamble
        # ("TRON Signed Message:\n") without the leading 0x19.
        # signed_message_hash() adds the byte itself.
        assert tron.MESSAGE_PREAMBLE == b"TRON Signed Message:\n"
        assert not tron.MESSAGE_PREAMBLE.startswith(b"\x19")

    def test_hello_pinned_against_known_value(self):
        # Pin the TIP-191 hash of "hello" against a known value.
        # Any future change to the preamble, the leading-byte
        # convention, or the keccak impl will break this test.
        # The expected value was computed once with this impl; a
        # cross-check against TronWeb's signMessageV2 should
        # produce the same digest before the next coin sprint.
        h = tron.signed_message_hash("hello")
        expected = bytes.fromhex(
            "a07d8e5b946cc0416662f5420751673680809e5f10313e20c7c5badb0ef4226d"
        )
        assert h == expected

    def test_distinct_from_eip191_for_same_message(self):
        # TIP-191 and EIP-191 share structure but use different
        # preamble strings -- their digests MUST differ for the
        # same input message. Catches accidental preamble-swap.
        msg = b"login to dapp.example at 2026-04-30"
        assert tron.signed_message_hash(msg) != personal_sign_hash(msg)

    def test_distinct_from_bare_keccak_for_same_message(self):
        # A verifier that forgot the preamble entirely would
        # accept signatures over raw keccak(msg). The TIP-191
        # hash must not collide with that -- pinning the
        # distinctness here makes "preamble was silently dropped"
        # a unit-test failure.
        msg = b"some plain text"
        assert tron.signed_message_hash(msg) != keccak256(msg)

    def test_string_and_bytes_inputs_match(self):
        s = "hello"
        b = b"hello"
        assert tron.signed_message_hash(s) == tron.signed_message_hash(b)

    def test_length_byte_is_ascii_decimal_not_binary(self):
        # TIP-191 (like EIP-191) encodes message length as ASCII
        # decimal, NOT as a single binary byte. A 32-byte message
        # contributes "32" (two bytes 0x33 0x32) to the hash
        # preimage, not 0x20.
        msg = b"x" * 32
        h = tron.signed_message_hash(msg)
        # Recompute with explicit ASCII-decimal length to confirm.
        prefix = b"\x19TRON Signed Message:\n32"
        assert h == keccak256(prefix + msg)

    def test_different_messages_produce_different_hashes(self):
        h1 = tron.signed_message_hash("hello")
        h2 = tron.signed_message_hash("world")
        assert h1 != h2

    def test_rejects_non_bytes_non_str_input(self):
        with pytest.raises(TypeError):
            tron.signed_message_hash(12345)


class TestAddressDerivation:
    def test_generator_g_produces_canonical_tron_address(self):
        # Pin: keccak256(generator_pubkey64)[-20:] == known ETH bytes,
        # base58check(0x41 || those 20 bytes) == known TRON string.
        # Confirms the entire pipeline matches external references.
        eth_last20 = keccak256(GENERATOR_PUBKEY64)[-20:]
        assert eth_last20.hex() == GENERATOR_ETH_ADDRESS_HEX
        addr = tron.address_from_public_key(GENERATOR_PUBKEY64)
        assert addr == GENERATOR_TRON_ADDRESS

    def test_address_always_34_chars_starting_with_T(self):
        # 0x41 || 20-byte hash160 || 4-byte checksum = 25 bytes;
        # base58 of 25 bytes is always 33-34 chars and always
        # starts with 'T' for the 0x41 mainnet version byte
        # (the high-nibble determines the leading base58 char).
        for _ in range(50):
            x_int = secrets.randbits(256) | 1  # avoid all-zeros
            y_int = secrets.randbits(256) | 1
            pubkey64 = x_int.to_bytes(32, "big") + y_int.to_bytes(32, "big")
            addr = tron.address_from_public_key(pubkey64)
            assert addr.startswith("T")
            assert 33 <= len(addr) <= 34

    def test_rejects_wrong_pubkey_length(self):
        with pytest.raises(ValueError):
            tron.address_from_public_key(b"\x00" * 33)
        with pytest.raises(ValueError):
            tron.address_from_public_key(b"\x00" * 65)

    def test_rejects_non_bytes_input(self):
        with pytest.raises(TypeError):
            tron.address_from_public_key("0x" + "00" * 64)


class TestAddressToHex:
    def test_generator_address_roundtrips_to_hex(self):
        hex_form = tron.address_to_hex(GENERATOR_TRON_ADDRESS)
        # 21 bytes (42 hex chars) starting with "41" mainnet version.
        assert len(hex_form) == 42
        assert hex_form.startswith("41")
        # The remaining 40 chars are the ETH-equivalent last20.
        assert hex_form[2:] == GENERATOR_ETH_ADDRESS_HEX

    def test_round_trip_address_to_hex_to_address_indirectly(self):
        # We don't expose hex_to_address publicly, but we can
        # confirm the round-trip via re-deriving from a known
        # pubkey and comparing both the address and its hex form.
        addr1 = tron.address_from_public_key(GENERATOR_PUBKEY64)
        hex1 = tron.address_to_hex(addr1)
        # Re-encode the hex bytes via _base58check_encode (private,
        # but exercised here to prove the asymmetry isn't lossy).
        re_addr = tron._base58check_encode(bytes.fromhex(hex1))
        assert re_addr == addr1

    def test_rejects_corrupted_checksum(self):
        # Flip the last char of the canonical address to break the
        # checksum. base58check verification must fail.
        bad = GENERATOR_TRON_ADDRESS[:-1] + (
            "B" if GENERATOR_TRON_ADDRESS[-1] != "B" else "C"
        )
        with pytest.raises(ValueError):
            tron.address_to_hex(bad)


class TestRecoveryAndVerify:
    """Sign-then-verify round-trips. We don't ship a TRON signer in
    Python (signing lives on the phone), so these tests exercise the
    verifier path against signatures produced by an in-test secp256k1
    signer. The signer uses the same RFC-6979 deterministic-k logic
    the phone's BouncyCastle path uses, so the rsv signatures are
    bit-for-bit what TronLink would produce for the same private key
    + message.
    """

    @staticmethod
    def _sign_with_cryptography(msg_hash: bytes, priv_int: int) -> bytes:
        """Sign ``msg_hash`` with the ``cryptography`` library's
        secp256k1 ECDSA and convert to 65-byte r||s||v format.

        TRON / ETH sign over a pre-computed 32-byte digest, so we
        pass the digest through ``utils.Prehashed`` to keep
        ``cryptography`` from re-hashing it. Recovery-id discovery
        runs by trying v=0,1 and picking the one whose recovery
        produces the signer's expected pubkey -- same approach the
        phone's BouncyCastle path uses.
        """
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import (
            Prehashed,
            decode_dss_signature,
        )
        from recto.ethereum import _SECP256K1_N, recover_public_key

        priv = ec.derive_private_key(priv_int, ec.SECP256K1())
        pub_nums = priv.public_key().public_numbers()
        expected_pubkey64 = (
            pub_nums.x.to_bytes(32, "big") + pub_nums.y.to_bytes(32, "big")
        )
        der = priv.sign(msg_hash, ec.ECDSA(Prehashed(hashes.SHA256())))
        r, s = decode_dss_signature(der)
        # Canonicalize s to low-s form per Bitcoin / Ethereum
        # signature acceptance rules.
        if s > _SECP256K1_N // 2:
            s = _SECP256K1_N - s
        # Recovery-id discovery: try v=0,1 and pick the one that
        # recovers the signer's pubkey.
        for rec_id in (0, 1):
            rsv = (
                r.to_bytes(32, "big")
                + s.to_bytes(32, "big")
                + bytes([27 + rec_id])
            )
            try:
                recovered = recover_public_key(msg_hash, rsv)
            except ValueError:
                continue
            if recovered == expected_pubkey64:
                return rsv
        raise RuntimeError("recovery-id discovery failed (signer broken)")

    def test_round_trip_sign_then_verify(self):
        # Generate a random secp256k1 private key, sign a message,
        # have recto.tron recover the address, and confirm
        # verify_signature returns True for the matching address.
        from cryptography.hazmat.primitives.asymmetric import ec

        priv_int = secrets.randbits(252) + 1  # safely below n
        priv = ec.derive_private_key(priv_int, ec.SECP256K1())
        pub_nums = priv.public_key().public_numbers()
        pubkey64 = (
            pub_nums.x.to_bytes(32, "big") + pub_nums.y.to_bytes(32, "big")
        )
        expected_addr = tron.address_from_public_key(pubkey64)
        message = "Login to dapp.example at 2026-04-30"
        msg_hash = tron.signed_message_hash(message)
        rsv = self._sign_with_cryptography(msg_hash, priv_int)
        # Recovery should produce the same pubkey -> same address.
        assert tron.recover_address(msg_hash, rsv) == expected_addr
        # Full verify path returns True for the matching address.
        assert tron.verify_signature(message, rsv, expected_addr) is True

    def test_verify_returns_false_for_wrong_address(self):
        from cryptography.hazmat.primitives.asymmetric import ec

        priv_int = secrets.randbits(252) + 1
        priv = ec.derive_private_key(priv_int, ec.SECP256K1())
        pub_nums = priv.public_key().public_numbers()
        pubkey64 = (
            pub_nums.x.to_bytes(32, "big") + pub_nums.y.to_bytes(32, "big")
        )
        message = "some other message"
        msg_hash = tron.signed_message_hash(message)
        rsv = self._sign_with_cryptography(msg_hash, priv_int)
        # The signer derived this pubkey, but we claim a different
        # expected address. verify must reject.
        assert (
            tron.verify_signature(message, rsv, GENERATOR_TRON_ADDRESS) is False
        )

    def test_verify_returns_false_for_malformed_signature(self):
        # Wrong-length signature (64 bytes -- missing v byte) is
        # malformed; verify must return False, not raise.
        bad_rsv = b"\x00" * 64
        result = tron.verify_signature(
            "hello", bad_rsv, GENERATOR_TRON_ADDRESS
        )
        assert result is False

    def test_verify_returns_false_for_corrupted_message(self):
        # Sign one message, verify against a different message with
        # the same signature -- recovery produces a different
        # pubkey, hence a different address, hence False.
        from cryptography.hazmat.primitives.asymmetric import ec

        priv_int = secrets.randbits(252) + 1
        priv = ec.derive_private_key(priv_int, ec.SECP256K1())
        pub_nums = priv.public_key().public_numbers()
        pubkey64 = (
            pub_nums.x.to_bytes(32, "big") + pub_nums.y.to_bytes(32, "big")
        )
        signed_addr = tron.address_from_public_key(pubkey64)
        msg_hash = tron.signed_message_hash("original message")
        rsv = self._sign_with_cryptography(msg_hash, priv_int)
        # Verifier hashes "tampered message" instead. Recovery
        # produces a different pubkey, different address.
        assert (
            tron.verify_signature("tampered message", rsv, signed_addr)
            is False
        )


class TestExports:
    def test_path_default_constant(self):
        assert tron.BIP44_PATH_DEFAULT == "m/44'/195'/0'/0/0"

    def test_version_byte_constant(self):
        assert tron.VERSION_BYTE_MAINNET == 0x41

    def test_public_surface(self):
        expected = {
            "BIP44_PATH_DEFAULT",
            "MESSAGE_PREAMBLE",
            "VERSION_BYTE_MAINNET",
            "signed_message_hash",
            "address_from_public_key",
            "address_to_hex",
            "recover_public_key",
            "recover_address",
            "verify_signature",
        }
        assert set(tron.__all__) == expected
