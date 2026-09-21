"""GATE 5c-a -- the passphrase as a signing member of the operator set.

WHAT THIS FILE IS GUARDING. Everything here protects ONE property:

    THE SAME EIGHT WORDS MUST REBUILD THE SAME KEY, FOREVER, ON ANY MACHINE.

That is not a nicety. The passphrase exists because two devices cannot give
both theft-resistance and loss-resistance, and it can only play that role if a
phrase written on paper today still produces the identical key years from now
on hardware that does not exist yet. **Every test below is a way for that
property to fail loudly instead of silently.**

A silent failure here looks like this: the operator loses both phones, types
the words he faithfully preserved, and gets a key that is not the sealed one.
There is no error message in that scenario -- just a stranger's signature.

THE PIN IS THE CONTRACT. `test_the_recoverability_pin` asserts a fixed phrase
maps to a fixed public key. **If that test ever fails, DO NOT UPDATE THE PIN.**
A changed pin means every already-sealed passphrase member has been orphaned.
The correct response is to find what changed and revert it, or to treat it as
a deliberate genesis-breaking migration with the version string bumped.

THE POSITIVE CONTROL IS `test_a_normal_phrase_derives_signs_and_verifies`.
Several tests below assert a refusal or an inequality, and a module that raised
on everything -- or returned a constant -- would satisfy them. Without one test
proving the ordinary path works end to end, this file cannot tell "the
derivation is sound" from "the derivation is broken in a strict-looking way".
"""

from __future__ import annotations

import hashlib

import pytest

from recto.profile.passphrase_member import (
    MIN_PASSPHRASE_WORDS,
    PASSPHRASE_ARGON2_MEMORY_COST_KIB,
    PASSPHRASE_ARGON2_PARALLELISM,
    PASSPHRASE_ARGON2_TIME_COST,
    PASSPHRASE_MEMBER_V1,
    WeakPassphraseError,
    derive_passphrase_member,
    normalize_passphrase,
    passphrase_member_pubkey,
    verify_passphrase_signature,
)

# A throwaway phrase. NEVER the operator's -- his words are host-only and have
# never been typed into any file, prompt, or agent, including whatever wrote
# this test.
PHRASE = "correct horse battery staple ridge lantern copper meadow"
OTHER = "eight totally different words go right here now ok"

# EVERY DERIVATION COSTS ~1s LOCALLY AND ~3.5s ON THE macOS RUNNER, BY DESIGN
# (t=8, 256 MiB). That is the security parameter working, so the answer is not
# to weaken it in tests -- weakened parameters would also invalidate the pin,
# which is the one thing here that must never move.
#
# The answer is to STOP PAYING A KDF TO COMPARE STRINGS. Normalisation is a
# pure string function; test it at the string layer, and keep exactly ONE
# end-to-end case proving normalisation actually reaches the key.
#
# This file cost ~71s of CI on its first run and, because `Surface skip count`
# re-runs the whole suite, was charged twice -- which is what pushed the job
# past its 10-minute ceiling. Derivations are now counted deliberately.
_CACHE: dict[str, bytes] = {}


def pub(phrase: str) -> bytes:
    if phrase not in _CACHE:
        _CACHE[phrase] = passphrase_member_pubkey(phrase)
    return _CACHE[phrase]


# --------------------------------------------------------------------------
# THE POSITIVE CONTROL -- read this one first.
# --------------------------------------------------------------------------

def test_a_normal_phrase_derives_signs_and_verifies():
    """The ordinary path, end to end. If this fails, nothing else here means
    anything -- a module that refused every input would pass most of the rest."""
    pk = pub(PHRASE)
    assert isinstance(pk, bytes) and len(pk) == 32, f"bad pubkey: {pk!r}"

    priv = derive_passphrase_member(PHRASE)
    sig = priv.sign(b"genesis")
    assert verify_passphrase_signature(pk, sig, b"genesis"), (
        "the member cannot sign something its own sealed pubkey verifies"
    )


# --------------------------------------------------------------------------
# THE RECOVERABILITY CONTRACT
# --------------------------------------------------------------------------

def test_the_recoverability_pin():
    """A FIXED PHRASE MAPS TO A FIXED KEY. This is the whole design.

    **IF THIS FAILS, DO NOT UPDATE THE EXPECTED VALUE.** A changed pin means
    every passphrase member sealed before the change is now unreachable by the
    words that were supposed to rebuild it. Find what moved -- normalisation,
    salt, Argon2 parameters, input framing -- and revert it, or bump
    PASSPHRASE_MEMBER_V1 and treat it as a genesis migration.
    """
    assert pub(PHRASE).hex() == (
        "39c9583996d294749c627b59c5b7bd563db8a6ebd64b1bf9cc742ca4f1b9f9bc"
    )


def test_the_parameters_are_frozen_at_genesis():
    """The key is a pure function of these numbers, so changing any of them
    silently orphans every sealed member.

    This test exists so that such a change CANNOT be made quietly: it turns
    red, and whoever made it has to decide, on purpose, that they meant to
    break genesis. Chosen 2026-08-18 by the operator from measured timings.
    """
    assert PASSPHRASE_MEMBER_V1 == "recto-passphrase-member-v1"
    assert PASSPHRASE_ARGON2_TIME_COST == 8
    assert PASSPHRASE_ARGON2_MEMORY_COST_KIB == 256 * 1024
    assert PASSPHRASE_ARGON2_PARALLELISM == 4
    assert MIN_PASSPHRASE_WORDS == 8


def test_determinism_across_repeated_derivations():
    assert passphrase_member_pubkey(PHRASE) == pub(PHRASE)


# --------------------------------------------------------------------------
# NORMALISATION -- typed by a human, years later, from paper
# --------------------------------------------------------------------------

@pytest.mark.parametrize("typed", [
    "  correct horse battery staple ridge lantern copper meadow  ",  # padding
    "Correct Horse Battery Staple Ridge Lantern Copper Meadow",      # title case
    "CORRECT HORSE BATTERY STAPLE RIDGE LANTERN COPPER MEADOW",      # caps lock
    "correct  horse   battery staple ridge lantern copper meadow",   # double spaces
    "correct\thorse\nbattery staple ridge lantern copper meadow",    # tab / newline
])
def test_messy_typing_normalises_to_one_canonical_phrase(typed):
    """**A failure here is a lockout with the paper still in hand.**

    The operator will type these words under stress, years later, possibly on
    a different keyboard, possibly having lost both phones. Any variation
    producing a different canonical form would mean the member is gone while
    the phrase is perfectly intact.

    ASSERTED AT THE STRING LAYER ON PURPOSE. The derivation is a pure function
    of the normalised phrase, so equal normalisation IS equal key -- and
    `test_normalisation_actually_reaches_the_key` below proves that link once,
    end to end. Paying five Argon2id runs to compare five strings bought
    nothing and cost more CI than the whole rest of this file.
    """
    assert normalize_passphrase(typed) == normalize_passphrase(PHRASE), (
        f"typing variation changed the canonical phrase: {typed!r}"
    )


def test_normalisation_actually_reaches_the_key():
    """THE LINK the test above depends on: normalisation is not merely computed,
    it is what the KDF consumes. One end-to-end case, deliberately paid for."""
    messy = "  Correct   HORSE battery\tstaple ridge lantern copper meadow "
    assert pub(messy) == pub(PHRASE)


def test_normalisation_is_idempotent():
    once = normalize_passphrase(PHRASE)
    assert normalize_passphrase(once) == once


def test_word_ORDER_still_matters():
    """Forgiving of HOW it is typed, unforgiving of WHICH words and in what
    order. Reordering is a different phrase, not a typo."""
    reordered = " ".join(reversed(PHRASE.split()))
    assert pub(reordered) != pub(PHRASE)


def test_a_different_phrase_gives_a_different_key():
    assert pub(OTHER) != pub(PHRASE)


# --------------------------------------------------------------------------
# REFUSAL AT THE ENTROPY FLOOR
# --------------------------------------------------------------------------

@pytest.mark.parametrize("short", [
    "",
    "one",
    "only seven words here not quite enough",
])
def test_below_the_floor_is_refused_not_warned(short):
    """The fixed-salt trade is only sound above the entropy floor.

    Accepting a short phrase would move the design outside the analysis that
    justifies it -- and would do so silently, which is the failure mode this
    whole file exists to prevent. A refusal is a contract; a warning is noise.
    """
    with pytest.raises(WeakPassphraseError) as exc:
        passphrase_member_pubkey(short)
    assert "at least 8" in str(exc.value)


def test_the_floor_is_exactly_eight():
    """Eight passes, seven does not. Pins the boundary rather than assuming it."""
    eight = "alpha bravo charlie delta echo foxtrot golf hotel"
    assert len(passphrase_member_pubkey(eight)) == 32
    with pytest.raises(WeakPassphraseError):
        passphrase_member_pubkey(" ".join(eight.split()[:7]))


def test_a_non_string_is_rejected():
    with pytest.raises(TypeError):
        normalize_passphrase(b"bytes are not a phrase")  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# THE TWO CONFUSIONS THAT PRODUCE A VALID-LOOKING WRONG KEY
# --------------------------------------------------------------------------
#
# Both of these were found on 2026-08-19 BY THE OPERATOR ASKING, before genesis
# rather than during a recovery. Each passes the eight-word floor and derives a
# perfectly well-formed key that is not his. **There is no error in that
# scenario and never would be** -- which is why these are refusals, not
# normalisation.

def test_the_dice_rolls_are_not_the_passphrase():
    """A diceware sheet has numbers and words. THE NUMBERS ARE THE INDEX.

    Eight roll-groups pass the word-count floor and derive a real key. Sealing
    that key means the paper's WORDS no longer open the vault -- and nothing
    says so until it matters.
    """
    with pytest.raises(WeakPassphraseError) as exc:
        passphrase_member_pubkey("41533 24261 11256 63421 52134 31627 45512 16334")
    assert "DICE ROLLS" in str(exc.value)


def test_rolls_interleaved_with_words_are_refused():
    """The worse variant: it looks MORE right, not less. Sixteen tokens, half
    of them the real words, and it sails past a naive word-count check."""
    with pytest.raises(WeakPassphraseError) as exc:
        passphrase_member_pubkey(
            "41533 lantern 24261 copper 11256 ridge 63421 meadow"
        )
    assert "are numbers" in str(exc.value)


@pytest.mark.parametrize("typed,why", [
    ("lantern, copper, ridge, meadow, alpha, bravo, charlie, delta", "commas"),
    ("1. lantern 2. copper 3. ridge 4. meadow 5. a 6. b 7. c 8. d", "numbering"),
    ("lantern copper ridge meadow alpha bravo charlie delta.", "trailing stop"),
])
def test_punctuation_is_refused_rather_than_stripped(typed, why):
    """REFUSED, NOT CLEANED UP, AND THAT IS THE DESIGN.

    Stripping punctuation silently would be more forgiving and strictly worse:
    it would let a phrase the operator typed WRONG derive a key that looks
    right. Normalisation is forgiving about whitespace and case because those
    carry no information; punctuation means the operator is reading something
    other than the eight words.
    """
    with pytest.raises(WeakPassphraseError) as exc:
        passphrase_member_pubkey(typed)
    assert "non-letters" in str(exc.value), why


def test_the_refusals_did_not_move_the_pin():
    """Guards were added on 2026-08-19, AFTER the pin was set. If adding a
    refusal had changed the derivation, every sealed member would have been
    orphaned by a safety feature. Pinned here so that can never happen quietly."""
    assert passphrase_member_pubkey(PHRASE).hex() == (
        "39c9583996d294749c627b59c5b7bd563db8a6ebd64b1bf9cc742ca4f1b9f9bc"
    )


# --------------------------------------------------------------------------
# DOMAIN SEPARATION
# --------------------------------------------------------------------------

def test_not_a_bare_hash_of_the_phrase():
    """The derivation must not coincide with any obvious digest of the words."""
    naive = hashlib.sha256(PHRASE.encode("utf-8")).digest()
    assert pub(PHRASE) != naive


def test_the_kdf_input_is_domain_separated():
    """The SAME words used in any other lane must not produce this key.

    Any future lane running Argon2id over a passphrase -- and there WAS one,
    the removable-media backup removed 2026-08-19 -- must not be able to
    produce this signing key from the same words. The input is domain-prefixed
    so two lanes cannot collide even with identical words AND identical
    parameters.

    **The prefix is inside the KDF input, so this test also pins the
    derivation**: if the domain separation were ever removed as dead weight
    now that it has no sibling, the sealed member would be orphaned. It is not
    dead weight, it is the pin.
    """
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    salt = hashlib.sha256(PASSPHRASE_MEMBER_V1.encode("ascii")).digest()
    undomained = Argon2id(
        salt=salt, length=32,
        iterations=PASSPHRASE_ARGON2_TIME_COST,
        lanes=PASSPHRASE_ARGON2_PARALLELISM,
        memory_cost=PASSPHRASE_ARGON2_MEMORY_COST_KIB,
    ).derive(normalize_passphrase(PHRASE).encode("utf-8"))
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    would_be = Ed25519PrivateKey.from_private_bytes(undomained).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    assert pub(PHRASE) != would_be, (
        "the input is not domain-separated -- a phrase reused in another "
        "Argon2id lane would derive the same signing key"
    )


# --------------------------------------------------------------------------
# VERIFICATION REFUSES EVERYTHING IT SHOULD
# --------------------------------------------------------------------------

def test_verification_rejects_a_wrong_message():
    sig = derive_passphrase_member(PHRASE).sign(b"genesis")
    assert not verify_passphrase_signature(pub(PHRASE), sig, b"not-genesis")


def test_verification_rejects_another_members_signature():
    sig = derive_passphrase_member(OTHER).sign(b"genesis")
    assert not verify_passphrase_signature(pub(PHRASE), sig, b"genesis")


@pytest.mark.parametrize("junk", [b"", b"\x00" * 64, b"not-a-signature"])
def test_verification_returns_false_rather_than_raising(junk):
    """A verifier that throws on malformed input is a denial-of-service surface
    on a bootloader that accepts data from the network. It must answer no."""
    assert verify_passphrase_signature(pub(PHRASE), junk, b"genesis") is False


def test_verification_never_needs_the_phrase():
    """Verification takes the SEALED PUBKEY only.

    A bootloader must be able to check a passphrase signature having never
    seen, stored, or been transmitted the words -- that is what allows the
    phrase to stay host-only and off every deployed machine forever.
    """
    pk = pub(PHRASE)
    sig = derive_passphrase_member(PHRASE).sign(b"genesis")
    assert verify_passphrase_signature(bytes(pk), sig, b"genesis")
