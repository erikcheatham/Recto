"""Tests for ``recto.ripple`` — XRP-flavored base58 + 0xED ed25519
prefix + AccountID derivation + Base58Check + signed-payload hash +
ed25519 signature verification.

External pins in this file:
- The Ripple base58 alphabet starts with 'r' so XRP classic addresses
  (version byte 0x00) ALWAYS start with 'r'.
- The 0xED prefix byte is part of the AccountID pre-image for ed25519
  keys — without it, ed25519 and secp256k1 keys could collide on
  AccountID by happenstance.
- Base58Check checksum is double-SHA-256(payload)[:4]. Tampering with
  any byte of the encoded address triggers a checksum-mismatch error.

Mnemonic-derived address vectors (Xumm / XRPL ed25519 cross-wallet
interop) are deferred to wave 8 part 2.
"""

from __future__ import annotations

import hashlib
import secrets

import pytest

from recto import ripple


class TestRippleBase58:
    def test_alphabet_pin(self):
        # The XRP alphabet differs from Bitcoin's. Pin the exact string
        # so future edits flag any drift — phone-side and verifier-side
        # MUST agree on the alphabet down to character ordering.
        assert (
            ripple.RIPPLE_BASE58_ALPHABET
            == "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
        )

    def test_alphabet_starts_with_r(self):
        # Position 0 in the alphabet is 'r' — that's why XRP classic
        # addresses start with 'r' (the 0x00 version byte encodes to 'r').
        assert ripple.RIPPLE_BASE58_ALPHABET[0] == "r"

    def test_alphabet_has_58_unique_chars(self):
        assert len(ripple.RIPPLE_BASE58_ALPHABET) == 58
        assert len(set(ripple.RIPPLE_BASE58_ALPHABET)) == 58

    def test_zero_byte_encodes_to_r(self):
        # Single zero byte → "r" (one leading-r, no body).
        assert ripple.base58_encode(b"\x00") == "r"

    def test_empty_bytes_encode_to_empty_string(self):
        assert ripple.base58_encode(b"") == ""

    def test_round_trip_random_bytes(self):
        for _ in range(50):
            data = secrets.token_bytes(secrets.randbelow(48) + 1)
            assert ripple.base58_decode(ripple.base58_encode(data)) == data

    def test_decode_rejects_bitcoin_alphabet_chars(self):
        # 'l' (lowercase L) is in Bitcoin's alphabet but NOT in XRP's.
        with pytest.raises(ValueError, match="not in alphabet"):
            ripple.base58_decode("rrrrlrr")


class TestBase58Check:
    def test_round_trip(self):
        for _ in range(20):
            payload = secrets.token_bytes(secrets.randbelow(32) + 4)
            assert ripple.base58check_decode(ripple.base58check_encode(payload)) == payload

    def test_corrupted_address_fails_checksum(self):
        addr = ripple.base58check_encode(b"\x00" + b"\xab" * 20)
        # Flip one character (still in alphabet) to trigger checksum failure.
        chars = list(addr)
        chars[5] = "p" if chars[5] != "p" else "s"
        with pytest.raises(ValueError, match="checksum mismatch"):
            ripple.base58check_decode("".join(chars))


class TestAccountIdDerivation:
    def test_account_id_is_20_bytes(self):
        for _ in range(10):
            pub = secrets.token_bytes(32)
            account_id = ripple.account_id_from_public_key(pub)
            assert len(account_id) == 20

    def test_0xED_prefix_is_part_of_preimage(self):
        # The 0xED byte must be hashed alongside the pubkey, NOT
        # stripped. Verify by recomputing the formula manually using
        # the same RIPEMD-160 + SHA-256 primitives and asserting the
        # impl matches when the prefix is INCLUDED, and differs when
        # it isn't. Without this check, a future bug that drops the
        # prefix would still produce a 20-byte AccountID — just a
        # different one — and the surrounding tests would silently
        # pass against a wrong-but-self-consistent address.
        from recto.bitcoin import ripemd160
        pub = b"\x42" * 32
        # With prefix (correct) — must match impl.
        expected_with_prefix = ripemd160(
            hashlib.sha256(bytes([0xED]) + pub).digest()
        )
        # Without prefix (would-be bug).
        expected_without_prefix = ripemd160(hashlib.sha256(pub).digest())
        actual = ripple.account_id_from_public_key(pub)
        assert actual == expected_with_prefix, (
            "AccountID must include the 0xED ed25519 discriminator byte"
        )
        assert actual != expected_without_prefix, (
            "AccountID-without-prefix collision would mask a bug"
        )

    def test_wrong_length_pubkey_rejected(self):
        with pytest.raises(ValueError, match="32 bytes"):
            ripple.account_id_from_public_key(b"\x00" * 31)


class TestAddressDerivation:
    def test_address_starts_with_r(self):
        for _ in range(10):
            pub = secrets.token_bytes(32)
            addr = ripple.address_from_public_key(pub)
            assert addr.startswith("r")

    def test_address_round_trips_account_id(self):
        # Address → AccountID round-trip (NOT pubkey, since the hash is
        # one-way).
        for _ in range(10):
            pub = secrets.token_bytes(32)
            account_id = ripple.account_id_from_public_key(pub)
            addr = ripple.address_from_public_key(pub)
            assert ripple.account_id_from_address(addr) == account_id

    def test_pubkey_NOT_recoverable_from_address(self):
        # XRP addresses are HASH160s — explicitly verify that two
        # different pubkeys produce DIFFERENT addresses, but you can't
        # get back from address to pubkey.
        pub1 = b"\x01" * 32
        pub2 = b"\x02" * 32
        addr1 = ripple.address_from_public_key(pub1)
        addr2 = ripple.address_from_public_key(pub2)
        assert addr1 != addr2
        # account_id_from_address gives us 20 bytes, NOT the 32-byte pubkey.
        assert len(ripple.account_id_from_address(addr1)) == 20

    def test_address_length_in_canonical_range(self):
        # XRP classic addresses are 25–35 characters typically.
        for _ in range(20):
            pub = secrets.token_bytes(32)
            addr = ripple.address_from_public_key(pub)
            assert 25 <= len(addr) <= 35


class TestSignedMessageHash:
    def test_preamble_is_recto_specific(self):
        assert ripple.MESSAGE_PREAMBLE == b"XRP signed message:\n"

    def test_hash_is_32_bytes(self):
        assert len(ripple.signed_message_hash(b"x")) == 32

    def test_str_and_bytes_inputs_equivalent(self):
        assert ripple.signed_message_hash("hi") == ripple.signed_message_hash(b"hi")


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
        sig = priv.sign(ripple.signed_message_hash(b"hello"))
        assert ripple.verify_signature(b"hello", sig, pub) is True

    def test_pubkey_as_hex_works(self, keypair):
        priv, pub = keypair
        sig = priv.sign(ripple.signed_message_hash(b"hello"))
        assert ripple.verify_signature(b"hello", sig, pub.hex()) is True

    def test_pubkey_with_xrp_ED_prefix_byte(self, keypair):
        # XRP-format pubkey is 33 bytes with 0xED prefix. The verify
        # path strips it and uses the underlying 32-byte ed25519 key.
        priv, pub = keypair
        sig = priv.sign(ripple.signed_message_hash(b"hello"))
        prefixed = bytes([ripple.ED25519_PUBKEY_PREFIX]) + pub
        assert ripple.verify_signature(b"hello", sig, prefixed) is True

    def test_pubkey_with_ED_hex_prefix(self, keypair):
        priv, pub = keypair
        sig = priv.sign(ripple.signed_message_hash(b"hello"))
        prefixed_hex = "ED" + pub.hex()
        assert ripple.verify_signature(b"hello", sig, prefixed_hex) is True

    def test_address_NOT_accepted_as_pubkey(self, keypair):
        # XRP addresses don't carry the pubkey. Trying to use one as
        # the public_key argument should raise (NOT silently fall
        # through).
        priv, pub = keypair
        sig = priv.sign(ripple.signed_message_hash(b"hello"))
        addr = ripple.address_from_public_key(pub)
        with pytest.raises(ValueError):
            ripple.verify_signature(b"hello", sig, addr)

    def test_verify_against_address_happy_path(self, keypair):
        priv, pub = keypair
        sig = priv.sign(ripple.signed_message_hash(b"hello"))
        addr = ripple.address_from_public_key(pub)
        # verify_against_address requires BOTH the pubkey AND the
        # expected_address, since address->pubkey is non-recoverable.
        assert ripple.verify_signature_against_address(
            b"hello", sig, pub, addr
        ) is True

    def test_verify_against_address_with_wrong_address_returns_false(self, keypair):
        priv, pub = keypair
        sig = priv.sign(ripple.signed_message_hash(b"hello"))
        # Build a different address from a different pubkey.
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        other_pub = Ed25519PrivateKey.generate().public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        other_addr = ripple.address_from_public_key(other_pub)
        # Sig + pub are valid (sig was made with priv, verifies against pub),
        # BUT address doesn't match pub — verify_against_address must
        # reject both kinds of mismatch.
        assert ripple.verify_signature_against_address(
            b"hello", sig, pub, other_addr
        ) is False

    def test_default_path_is_xumm_convention(self):
        assert ripple.BIP44_PATH_DEFAULT == "m/44'/144'/0'/0'/0'"
