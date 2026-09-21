"""Tests for ``recto.solana`` — base58 + SOL address derivation +
signed-message hash + ed25519 signature verification.

The test discipline (per Recto's "Cryptographic prefix bytes are
non-negotiable" rule, IM 2026-04-28): pin behavior against externally
verifiable reference values where possible, then fall back to round-
trips for the parts that don't have a standalone-verifiable reference.

Concrete external pins in this file:
- SOL System Program pubkey (32 zero bytes) round-trips to
  ``"11111111111111111111111111111111"`` (32 ones). Documented across
  the entire SOL ecosystem.
- SOL "Default" pubkey (31 zeros + 0x01) round-trips to
  ``"11111111111111111111111111111112"``.
- ed25519 sign-then-verify against the cryptography library's own
  signing key — Recto's verifier must accept signatures the library
  itself produces.

Mnemonic-derived address vectors (Phantom / Solflare cross-wallet
interop) are deferred to wave 8 part 2 once SLIP-0010 derivation
lands phone-side and the operator can pin a value against a real wallet.
"""

from __future__ import annotations

import secrets

import pytest

from recto import solana


class TestBase58:
    def test_empty_bytes_encode_to_empty_string(self):
        assert solana.base58_encode(b"") == ""

    def test_empty_string_decodes_to_empty_bytes(self):
        assert solana.base58_decode("") == b""

    def test_all_zero_bytes_encode_to_all_ones(self):
        # 32 leading zero bytes → 32 leading '1' characters. SOL System
        # Program ID is exactly this — all-zeros pubkey.
        assert solana.base58_encode(b"\x00" * 32) == "1" * 32

    def test_31_zeros_plus_one_encodes_to_31_ones_plus_two(self):
        # 31 zero bytes + value 1 → "1"*31 + "2". The "2" is base58
        # alphabet position 1 (the alphabet starts with '1','2','3',...).
        result = solana.base58_encode(b"\x00" * 31 + b"\x01")
        assert result == "1" * 31 + "2"

    def test_round_trip_random_32_bytes(self):
        # Hundred random round-trips. Bitcoin-alphabet base58 has a
        # well-known property that all leading-zero bytes preserve;
        # this exercises both the body encoding and the leading-zero
        # preservation.
        for _ in range(100):
            data = secrets.token_bytes(32)
            assert solana.base58_decode(solana.base58_encode(data)) == data

    def test_round_trip_random_with_leading_zeros(self):
        for n_zeros in range(0, 33):
            data = b"\x00" * n_zeros + secrets.token_bytes(32 - n_zeros)
            encoded = solana.base58_encode(data)
            assert solana.base58_decode(encoded) == data
            # Each leading zero byte → exactly one leading '1' char.
            assert encoded.startswith("1" * n_zeros)

    def test_decode_rejects_non_alphabet_characters(self):
        # '0' (zero) is NOT in the base58 alphabet — that's the whole
        # point of base58, it's chosen to avoid 0/O/l/I confusables.
        with pytest.raises(ValueError, match="not in alphabet"):
            solana.base58_decode("110")
        # 'O' (capital O), 'I' (capital i), 'l' (lower L) similarly excluded.
        with pytest.raises(ValueError):
            solana.base58_decode("OIl")

    def test_decode_rejects_wrong_input_type(self):
        with pytest.raises(TypeError):
            solana.base58_decode(b"abc")
        with pytest.raises(TypeError):
            solana.base58_encode("abc")


class TestAddressDerivation:
    def test_zero_pubkey_yields_system_program_address(self):
        # The SOL System Program is at the all-zeros pubkey, address
        # "11111111111111111111111111111111".
        addr = solana.address_from_public_key(b"\x00" * 32)
        assert addr == "1" * 32

    def test_address_is_round_trip_with_decode(self):
        # SOL addresses literally ARE base58(pubkey32) — so decoding
        # the address must return the same 32 bytes.
        for _ in range(20):
            pub = secrets.token_bytes(32)
            addr = solana.address_from_public_key(pub)
            assert solana.public_key_from_address(addr) == pub

    def test_address_length_in_canonical_range(self):
        # SOL addresses are 32–44 chars. Most random 32-byte pubkeys
        # produce 43–44-char addresses; pubkeys with leading zero bytes
        # produce shorter addresses (down to 32 chars for all-zeros).
        for _ in range(50):
            pub = secrets.token_bytes(32)
            addr = solana.address_from_public_key(pub)
            assert 32 <= len(addr) <= 44

    def test_wrong_length_pubkey_rejected(self):
        with pytest.raises(ValueError, match="32 bytes"):
            solana.address_from_public_key(b"\x00" * 31)
        with pytest.raises(ValueError, match="32 bytes"):
            solana.address_from_public_key(b"\x00" * 33)

    def test_non_bytes_pubkey_rejected(self):
        with pytest.raises(TypeError):
            solana.address_from_public_key("not-bytes")  # type: ignore[arg-type]

    def test_decode_address_with_wrong_length_raises(self):
        # Encoding 31 bytes produces an address that decodes to 31
        # bytes — public_key_from_address rejects it.
        short_addr = solana.base58_encode(b"\x00" * 31)
        with pytest.raises(ValueError, match="32 bytes"):
            solana.public_key_from_address(short_addr)


class TestSignedMessageHash:
    def test_preamble_is_recto_specific(self):
        # Recto's chosen preamble — pin the bytes so future edits flag
        # phone-side disagreement (the phone MUST compute the same hash
        # the verifier here computes, or every signature drops on the
        # floor).
        assert solana.MESSAGE_PREAMBLE == b"Solana signed message:\n"

    def test_hash_is_32_bytes(self):
        h = solana.signed_message_hash(b"login")
        assert len(h) == 32

    def test_hash_is_deterministic(self):
        h1 = solana.signed_message_hash("Hello, Solana")
        h2 = solana.signed_message_hash("Hello, Solana")
        assert h1 == h2

    def test_hash_changes_with_message(self):
        assert solana.signed_message_hash(b"a") != solana.signed_message_hash(b"b")

    def test_str_and_bytes_inputs_equivalent(self):
        assert solana.signed_message_hash("hello") == solana.signed_message_hash(b"hello")

    def test_unicode_message(self):
        # UTF-8 encoded under the hood.
        h = solana.signed_message_hash("héllo, Solána ☀️")
        assert len(h) == 32


class TestVerifySignature:
    @pytest.fixture
    def keypair(self):
        pytest.importorskip("cryptography")
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return priv, pub

    def test_round_trip_sign_and_verify(self, keypair):
        priv, pub = keypair
        message = b"Login to demo.recto.example"
        msg_hash = solana.signed_message_hash(message)
        sig = priv.sign(msg_hash)
        assert solana.verify_signature(message, sig, pub) is True

    def test_wrong_message_returns_false(self, keypair):
        priv, pub = keypair
        msg_hash = solana.signed_message_hash(b"original")
        sig = priv.sign(msg_hash)
        assert solana.verify_signature(b"tampered", sig, pub) is False

    def test_wrong_pubkey_returns_false(self, keypair):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        priv, _ = keypair
        msg_hash = solana.signed_message_hash(b"original")
        sig = priv.sign(msg_hash)
        wrong_pub = Ed25519PrivateKey.generate().public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        assert solana.verify_signature(b"original", sig, wrong_pub) is False

    def test_wrong_signature_length_raises(self, keypair):
        _, pub = keypair
        with pytest.raises(ValueError, match="64 bytes"):
            solana.verify_signature(b"x", b"\x00" * 63, pub)

    def test_signature_as_base64_string(self, keypair):
        import base64 as _base64
        priv, pub = keypair
        msg_hash = solana.signed_message_hash(b"test")
        sig = priv.sign(msg_hash)
        sig_b64 = _base64.b64encode(sig).decode("ascii")
        assert solana.verify_signature(b"test", sig_b64, pub) is True

    def test_pubkey_as_address_string(self, keypair):
        priv, pub = keypair
        addr = solana.address_from_public_key(pub)
        msg_hash = solana.signed_message_hash(b"test")
        sig = priv.sign(msg_hash)
        assert solana.verify_signature(b"test", sig, addr) is True

    def test_pubkey_as_hex_string(self, keypair):
        priv, pub = keypair
        msg_hash = solana.signed_message_hash(b"test")
        sig = priv.sign(msg_hash)
        assert solana.verify_signature(b"test", sig, pub.hex()) is True

    def test_verify_against_address_happy_path(self, keypair):
        priv, pub = keypair
        addr = solana.address_from_public_key(pub)
        msg_hash = solana.signed_message_hash(b"hello")
        sig = priv.sign(msg_hash)
        assert solana.verify_signature_against_address(b"hello", sig, addr) is True

    def test_verify_against_bogus_address_returns_false(self, keypair):
        priv, _ = keypair
        msg_hash = solana.signed_message_hash(b"hello")
        sig = priv.sign(msg_hash)
        # Address with non-base58 character — should return False, not raise.
        assert solana.verify_signature_against_address(b"hello", sig, "0not-base58") is False

    def test_default_path_is_phantom_convention(self):
        assert solana.BIP44_PATH_DEFAULT == "m/44'/501'/0'/0'"
