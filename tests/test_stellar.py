"""Tests for ``recto.stellar`` — base32 StrKey + CRC16-XMODEM + XLM
address derivation + signed-payload hash + ed25519 signature verification.

External pins in this file:
- CRC16-XMODEM("123456789") == 0x31C3 — the canonical CRC16-XMODEM
  reference vector cited in every CRC implementation across every
  language. If our implementation doesn't match this, the polynomial
  / initial value / direction is wrong and StrKeys won't validate
  against the wider Stellar ecosystem.
- StrKey for an account public key always starts with 'G' (version
  byte 0x30 maps to 'G' in RFC 4648 base32 alphabet).
- StrKey for an all-zero pubkey is exactly 56 chars (35-byte raw =
  28 base32 quintets, no padding suppressed).

Mnemonic-derived address vectors (SEP-0005 cross-wallet interop) are
deferred to wave 8 part 2 once SLIP-0010 derivation lands phone-side.
"""

from __future__ import annotations

import secrets

import pytest

from recto import stellar


class TestCrc16Xmodem:
    def test_canonical_reference_vector(self):
        # The "123456789" CRC reference vector is canonical across every
        # CRC implementation. CRC16-XMODEM (poly 0x1021, init 0x0000,
        # no reflection) MUST produce 0x31C3 for this input.
        assert stellar.crc16_xmodem(b"123456789") == 0x31C3

    def test_empty_input_is_zero(self):
        # CRC16-XMODEM init value is 0x0000 with no final XOR, so
        # empty input gives back the init value.
        assert stellar.crc16_xmodem(b"") == 0x0000

    def test_single_byte_inputs_differ(self):
        assert stellar.crc16_xmodem(b"\x00") != stellar.crc16_xmodem(b"\x01")

    def test_crc_is_in_uint16_range(self):
        for _ in range(50):
            data = secrets.token_bytes(secrets.randbelow(64))
            crc = stellar.crc16_xmodem(data)
            assert 0 <= crc <= 0xFFFF


class TestStrKey:
    def test_account_public_key_starts_with_G(self):
        # version byte 0x30 → leading char is 'G' in RFC 4648 base32.
        for _ in range(20):
            pub = secrets.token_bytes(32)
            encoded = stellar.strkey_encode(stellar.VERSION_BYTE_ACCOUNT_PUBLIC, pub)
            assert encoded.startswith("G")

    def test_account_strkey_length_is_56(self):
        # 1 version + 32 payload + 2 CRC = 35 bytes. Base32 of 35 bytes
        # is 56 chars (no padding stripped because 35 isn't divisible by 5
        # — it produces 56 chars + 0 '=' chars).
        encoded = stellar.strkey_encode(stellar.VERSION_BYTE_ACCOUNT_PUBLIC, b"\x00" * 32)
        assert len(encoded) == 56

    def test_round_trip_account_public_key(self):
        for _ in range(20):
            pub = secrets.token_bytes(32)
            encoded = stellar.strkey_encode(stellar.VERSION_BYTE_ACCOUNT_PUBLIC, pub)
            version, payload = stellar.strkey_decode(encoded)
            assert version == stellar.VERSION_BYTE_ACCOUNT_PUBLIC
            assert payload == pub

    def test_round_trip_arbitrary_version_byte(self):
        # Other StrKey types (pre-auth-tx, hash-x, signed-payload) all
        # round-trip the same way.
        for vb in (
            stellar.VERSION_BYTE_PRE_AUTH_TX,
            stellar.VERSION_BYTE_HASH_X,
            stellar.VERSION_BYTE_SIGNED_PAYLOAD,
        ):
            payload = secrets.token_bytes(32)
            encoded = stellar.strkey_encode(vb, payload)
            decoded_vb, decoded_payload = stellar.strkey_decode(encoded)
            assert decoded_vb == vb
            assert decoded_payload == payload

    def test_corrupted_strkey_fails_crc(self):
        encoded = stellar.strkey_encode(stellar.VERSION_BYTE_ACCOUNT_PUBLIC, b"\x00" * 32)
        # Flip a character in the body to trigger CRC mismatch.
        # Pick one that's still in the base32 alphabet so we get a
        # checksum failure rather than a charset failure.
        body = list(encoded)
        body[5] = "X" if body[5] != "X" else "Y"
        bad = "".join(body)
        with pytest.raises(ValueError, match="CRC mismatch"):
            stellar.strkey_decode(bad)

    def test_invalid_base32_raises(self):
        # '1' is NOT in RFC 4648 base32 alphabet (which uses A-Z + 2-7).
        with pytest.raises(ValueError, match="base32"):
            stellar.strkey_decode("11111111111111111111111111111111111111111111111111111111")


class TestAddressDerivation:
    def test_address_starts_with_G_and_is_56_chars(self):
        for _ in range(10):
            pub = secrets.token_bytes(32)
            addr = stellar.address_from_public_key(pub)
            assert addr.startswith("G")
            assert len(addr) == 56

    def test_round_trip_via_address(self):
        for _ in range(20):
            pub = secrets.token_bytes(32)
            addr = stellar.address_from_public_key(pub)
            assert stellar.public_key_from_address(addr) == pub

    def test_wrong_length_pubkey_rejected(self):
        with pytest.raises(ValueError, match="32 bytes"):
            stellar.address_from_public_key(b"\x00" * 31)

    def test_decode_non_account_strkey_raises(self):
        # Encode with the pre-auth-tx version byte (0x98), then try
        # to decode AS an account public key — should fail because the
        # version byte doesn't match.
        encoded = stellar.strkey_encode(stellar.VERSION_BYTE_PRE_AUTH_TX, b"\x11" * 32)
        with pytest.raises(ValueError, match="account public key"):
            stellar.public_key_from_address(encoded)


class TestSignedMessageHash:
    def test_preamble_is_recto_specific(self):
        assert stellar.MESSAGE_PREAMBLE == b"Stellar signed message:\n"

    def test_hash_is_32_bytes(self):
        assert len(stellar.signed_message_hash(b"x")) == 32

    def test_str_and_bytes_inputs_equivalent(self):
        assert stellar.signed_message_hash("hi") == stellar.signed_message_hash(b"hi")

    def test_hash_differs_per_message(self):
        assert stellar.signed_message_hash(b"a") != stellar.signed_message_hash(b"b")


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
        sig = priv.sign(stellar.signed_message_hash(message))
        assert stellar.verify_signature(message, sig, pub) is True

    def test_wrong_message_returns_false(self, keypair):
        priv, pub = keypair
        sig = priv.sign(stellar.signed_message_hash(b"orig"))
        assert stellar.verify_signature(b"tampered", sig, pub) is False

    def test_pubkey_as_strkey_address(self, keypair):
        priv, pub = keypair
        addr = stellar.address_from_public_key(pub)
        sig = priv.sign(stellar.signed_message_hash(b"hi"))
        assert stellar.verify_signature(b"hi", sig, addr) is True

    def test_verify_against_address_happy_path(self, keypair):
        priv, pub = keypair
        addr = stellar.address_from_public_key(pub)
        sig = priv.sign(stellar.signed_message_hash(b"hi"))
        assert stellar.verify_signature_against_address(b"hi", sig, addr) is True

    def test_verify_against_bad_address_returns_false(self, keypair):
        priv, _ = keypair
        sig = priv.sign(stellar.signed_message_hash(b"hi"))
        assert stellar.verify_signature_against_address(b"hi", sig, "GBADADDRESS!!!") is False

    def test_default_path_is_sep0005(self):
        assert stellar.BIP44_PATH_DEFAULT == "m/44'/148'/0'"
