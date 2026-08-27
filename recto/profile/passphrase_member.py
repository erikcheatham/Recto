"""The PASSPHRASE as a signing member of the operator set (GATE 5c-a).

WHY THIS EXISTS, AND WHY IT IS NOT A DEVICE. Two devices cannot give both
theft-resistance and loss-resistance: 2-of-2 survives theft but a lost device
locks you out forever; 1-of-2 survives loss but one theft takes everything.
That is arithmetic, not engineering. The resolution (operator ruling
2026-08-17) is a THIRD member that is not an object:

    eight diceware words -> Argon2id -> Ed25519 keypair, pubkey sealed at genesis

**It cannot be stolen alongside the phone, because it is not a thing in the
room.** It is single-purpose, shares no chain with any other account, and its
written copy has never shared a location with the recovery device.

WHY THIS IS NOT INTERCHANGEABLE WITH ANY OTHER ARGON2ID USE. An encryption
lane derives a key to unlock a blob, and can store a random salt inside that
blob. This module derives a SIGNING key and there is no blob: **the phrase
alone must rebuild the key after everything else is gone.** Same primitive,
opposite storage assumption. Never merge a signing derivation with an
encrypting one, however similar the call looks.

**THERE IS EXACTLY ONE ARGON2ID LANE IN RECTO, AND THAT IS A PROPERTY WORTH
KEEPING.** A second one was removed 2026-08-19 rather than maintained. Adding
another is a decision, not a convenience: two lanes over the same primitive
invite one operator phrase being reused across both, and then a compromise of
the weaker lane reaches the stronger one.

=== THE SALT IS A FIXED CONSTANT, DELIBERATELY, AND HERE IS THE TRADE ===

A random per-user salt would have to be stored somewhere. Anywhere it is
stored is a thing that can be lost -- and losing it would destroy the member
this design exists to make unloseable. **A stored salt defeats the entire
purpose.** So the salt is a published constant derived from the version
string.

What that costs: no per-user precomputation resistance. What makes that
acceptable: eight EFF-long-list words is 8 * log2(7776) ~= 103 bits. **Nobody
tables 2^103.** Rainbow tables threaten human-chosen passwords, not
high-entropy phrases, and Argon2id's memory hardness still applies per guess.

**This trade is only valid while the entropy floor holds**, which is why
`derive_passphrase_member` REFUSES fewer than eight words rather than warning.
A warning in a key-derivation primitive is noise; a refusal is a contract.

=== NORMALISATION IS A RECOVERABILITY FEATURE, NOT A CONVENIENCE ===

The operator will type these words years from now, possibly from paper,
possibly on a different keyboard, possibly with a capital first letter or two
spaces between words. **Any of those producing a different key would mean the
member is lost while the phrase is intact.** So the input is normalised
(NFKD, casefold, whitespace collapsed) before it reaches the KDF, and that
normalisation is pinned by tests.

=== WHAT THIS MODULE WILL NOT DO ===

It never logs, prints, persists, or returns the phrase. It accepts a `str`,
uses it, and best-effort clears its own working copies. **The caller must read
the phrase with no echo and must never accept it via argv** -- argv lands in
shell history and in every process listing on the box.

**THE PHRASE IS HOST-ONLY (operator ruling 2026-08-18). IT MUST NEVER BE TYPED
INTO A PHONE, INCLUDING THE RECTO APP.** The whole reason this member is strong
is that it does not live where the devices live: entering it on the recovery
iPhone would put a genesis member and its independent third factor on one
object, collapsing the asymmetry back into a threshold. Tier-3 is therefore
RECOVERY signing ON THE PHONE and PASSPHRASE signing ON THE HOST, submitted
together. **A future "just let me type it on the phone" convenience is not a
feature request; it is this design being undone.**
"""

from __future__ import annotations

import hashlib
import unicodedata

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives import serialization

__all__ = [
    "PASSPHRASE_MEMBER_V1",
    "PASSPHRASE_ARGON2_TIME_COST",
    "PASSPHRASE_ARGON2_MEMORY_COST_KIB",
    "PASSPHRASE_ARGON2_PARALLELISM",
    "MIN_PASSPHRASE_WORDS",
    "WeakPassphraseError",
    "normalize_passphrase",
    "derive_passphrase_member",
    "passphrase_member_pubkey",
    "verify_passphrase_signature",
]

# Domain separation. Bumping this string is how a v2 derivation stays
# distinguishable from v1 -- and note that bumping it CHANGES EVERY DERIVED
# KEY, so it is a genesis-breaking change, never a patch.
PASSPHRASE_MEMBER_V1 = "recto-passphrase-member-v1"

# The fixed salt. Published, not secret -- see the module docstring for why a
# stored random salt would defeat the purpose.
_SALT = hashlib.sha256(PASSPHRASE_MEMBER_V1.encode("ascii")).digest()

# THESE NUMBERS ARE PART OF THE OPERATOR'S IDENTITY, not a tuning knob.
# Changing an encryption lane's cost merely re-encrypts a blob; changing THIS
# one CHANGES THE KEY, because the key is a pure function of these numbers.
# **They are frozen at genesis.** Treat any edit below as a genesis-breaking
# change.
#
# CHOSEN 2026-08-18 BY THE OPERATOR, from measurements on staging hardware:
#     t=2  128MiB  0.22s   1x   (rejected: too cheap for a signing key)
#     t=8  256MiB  0.88s   8x   <- CHOSEN
#     t=8  512MiB  2.23s  16x   (rejected: iOS may kill an app at this size)
#     t=12 1024MiB 5.89s  48x   (rejected: host-only, and ~6s every use)
#
# 256 MiB was chosen over 512 even though the phrase is HOST-ONLY today,
# because a ceiling that only holds while a policy holds is not a ceiling.
# **8 diceware words is ~103 bits; the KDF is defence in depth, not the
# defence.** These numbers matter if and only if the phrase is weaker than
# assumed -- which is exactly the case worth surviving.
PASSPHRASE_ARGON2_TIME_COST = 8
PASSPHRASE_ARGON2_MEMORY_COST_KIB = 256 * 1024   # 256 MiB
PASSPHRASE_ARGON2_PARALLELISM = 4
_HASH_LEN = 32                                    # -> Ed25519 seed

MIN_PASSPHRASE_WORDS = 8


class WeakPassphraseError(ValueError):
    """The phrase does not meet the entropy floor the fixed salt assumes.

    Raised rather than warned. The fixed-salt trade in this module is only
    sound above the floor, so accepting a short phrase would silently move the
    design outside the analysis that justifies it.
    """


def normalize_passphrase(passphrase: str) -> str:
    """Canonicalise a typed phrase so the same words always give the same key.

    NFKD, casefold, collapse all whitespace runs to single spaces, strip. This
    is deliberately forgiving of HOW the phrase is typed and completely
    unforgiving of WHICH words it contains.

    Pinned by tests: changing this function invalidates every existing derived
    member, which makes it a genesis-breaking change.
    """
    if not isinstance(passphrase, str):
        raise TypeError("passphrase must be a str")
    decomposed = unicodedata.normalize("NFKD", passphrase)
    return " ".join(decomposed.casefold().split())


def _validate_words(words: "list[str]") -> None:
    """Refuse input that is probably not the phrase, LOUDLY.

    NORMALISATION IS FORGIVING ABOUT WHITESPACE AND CASE AND NOTHING ELSE, and
    that is deliberate: **silently stripping characters would turn a wrong
    phrase into a plausible key.** These checks exist because both of the
    mistakes below produce a VALID-LOOKING derivation and no error at all --
    the operator seals a member, walks away, and finds out years later.

    Both were found before genesis, on 2026-08-19, by the operator asking.
    """
    numeric = [w for w in words if w.isdigit()]
    if numeric and len(numeric) == len(words):
        raise WeakPassphraseError(
            f"every token is a number ({' '.join(words[:3])} ...). **THOSE ARE "
            "THE DICE ROLLS, NOT THE PASSPHRASE.** The passphrase is the WORDS "
            "those numbers index in the wordlist. Type the words. (The words "
            "also need no lookup table to recover -- the numbers would tie your "
            "trust root to one wordlist edition, forever.)"
        )
    if numeric:
        raise WeakPassphraseError(
            f"{len(numeric)} token(s) are numbers ({', '.join(numeric[:3])}). "
            "If you are reading a diceware sheet, enter ONLY the words -- the "
            "roll numbers are not part of the phrase and including them derives "
            "a different key with no error."
        )
    bad = [w for w in words if not w.isalpha()]
    if bad:
        raise WeakPassphraseError(
            f"{len(bad)} token(s) contain non-letters ({', '.join(bad[:3])}). "
            "Enter the words alone, separated by spaces -- no commas, no "
            "numbering, no trailing punctuation. **This is refused rather than "
            "cleaned up on purpose:** stripping characters silently would let a "
            "mistyped phrase derive a real-looking key."
        )


def _seed(passphrase: str, *, min_words: int) -> bytes:
    normalized = normalize_passphrase(passphrase)
    words = normalized.split(" ") if normalized else []
    if words:
        _validate_words(words)
    if len(words) < min_words:
        raise WeakPassphraseError(
            f"passphrase has {len(words)} word(s); this derivation requires at "
            f"least {min_words}. The fixed salt is only sound above that floor "
            "(see recto/profile/passphrase_member.py). This is a refusal, not "
            "a warning -- a short phrase here would weaken the operator set "
            "silently."
        )
    kdf = Argon2id(
        salt=_SALT,
        length=_HASH_LEN,
        iterations=PASSPHRASE_ARGON2_TIME_COST,
        lanes=PASSPHRASE_ARGON2_PARALLELISM,
        memory_cost=PASSPHRASE_ARGON2_MEMORY_COST_KIB,
    )
    # Domain-separate the INPUT too, so this digest can never coincide with a
    # key derived by any other lane even if the same words are reused. THIS
    # LINE IS PART OF THE PIN -- the prefix is inside the KDF input, so editing
    # it changes the derived key and orphans the sealed member.
    material = PASSPHRASE_MEMBER_V1.encode("ascii") + b"\x00" + normalized.encode("utf-8")
    return kdf.derive(material)


def derive_passphrase_member(
    passphrase: str,
    *,
    min_words: int = MIN_PASSPHRASE_WORDS,
) -> Ed25519PrivateKey:
    """Rebuild the passphrase member's SIGNING key from the phrase.

    Deterministic: the same words always rebuild the same key, on any machine,
    forever. That property is what makes a written phrase a recoverable member
    rather than a one-shot secret.

    The returned key signs through the same path the Enclave and StrongBox
    already satisfy -- this member is not a special case at verification time.

    NEVER log, print, or persist the return value or the input.
    """
    seed = _seed(passphrase, min_words=min_words)
    try:
        return Ed25519PrivateKey.from_private_bytes(seed)
    finally:
        # Best-effort: rebind so the seed is not left as the most recent
        # reference. Python gives no guarantee here; this is hygiene, not a
        # security control, and is documented as such rather than overclaimed.
        seed = b"\x00" * len(seed)


def passphrase_member_pubkey(
    passphrase: str,
    *,
    min_words: int = MIN_PASSPHRASE_WORDS,
) -> bytes:
    """The 32-byte raw Ed25519 public key -- the ONLY value that leaves this
    module and the only one that is safe to write down, seal, or display.

    This is what gets sealed at genesis and what the membership test checks
    signatures against.
    """
    priv = derive_passphrase_member(passphrase, min_words=min_words)
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def verify_passphrase_signature(
    pubkey: bytes, signature: bytes, message: bytes
) -> bool:
    """Verify a signature from the passphrase member.

    Takes the SEALED PUBKEY, never the phrase -- verification must be possible
    on a bootloader that has never seen and must never see the words.
    """
    try:
        Ed25519PublicKey.from_public_bytes(bytes(pubkey)).verify(
            bytes(signature), bytes(message)
        )
        return True
    except Exception:
        return False
