"""K-of-N quorum -- and almost every test here is about ONE failure mode.

    A QUORUM VERIFIER THAT COUNTS SIGNATURES INSTEAD OF MEMBERS REPORTS
    "2-of-3" WHEN ONE KEY OPENED THE VAULT.

That is not a forged-signature attack. Every signature involved is genuine and
verifies. The break is arithmetic: present one member's signature twice, or put
one key under two roster names, and a counter-per-accepted-signature says the
quorum was met. Nothing in a log looks wrong afterwards.

THE POSITIVE CONTROL IS `test_two_distinct_members_meet_a_2_of_3`. Most tests
below assert a REFUSAL, and a verifier that returned `met=False` unconditionally
would satisfy all of them.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from recto.quorum import QuorumConfigError, QuorumResult, verify_quorum

MSG = b"recto-quorum-test|challenge|2026-08-19"
OTHER = b"recto-quorum-test|a different challenge"


def _signer():
    """A real Ed25519 keypair -> (sign(msg), verifier(sig, msg))."""
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()

    def verifier(signature: bytes, message: bytes) -> bool:
        try:
            pk.verify(signature, message)
            return True
        except Exception:
            return False

    return sk.sign, verifier


@pytest.fixture
def three():
    """Three real members: returns (members, sign_by_name)."""
    signers = {name: _signer() for name in ("primary", "recovery", "passphrase")}
    members = {name: v for name, (_s, v) in signers.items()}
    signs = {name: s for name, (s, _v) in signers.items()}
    return members, signs


# ---------------------------------------------------------------------------
# THE POSITIVE CONTROL
# ---------------------------------------------------------------------------

def test_two_distinct_members_meet_a_2_of_3(three):
    members, signs = three
    r = verify_quorum(MSG, [signs["recovery"](MSG), signs["passphrase"](MSG)], members, k=2)
    assert r.met is True
    assert r.count == 2
    assert r.satisfied_by == frozenset({"recovery", "passphrase"})
    assert r.unmatched_signatures == 0


# ---------------------------------------------------------------------------
# THE ONE THAT MATTERS
# ---------------------------------------------------------------------------

def test_one_member_signing_twice_does_NOT_meet_a_2_of_3(three):
    """**THE WHOLE REASON THIS MODULE EXISTS.**

    Both signatures are genuine and both verify. A verifier that counted
    accepted signatures would return met=True on a single key.
    """
    members, signs = three
    sig = signs["passphrase"](MSG)
    r = verify_quorum(MSG, [sig, sig], members, k=2)
    assert r.met is False
    assert r.count == 1
    assert r.satisfied_by == frozenset({"passphrase"})


def test_distinct_signatures_from_the_SAME_member_do_not_inflate(three):
    """Ed25519 is deterministic, so two calls give identical bytes -- but a
    caller could re-sign a re-framed message, or a future member could use a
    randomised scheme. Dedup must key on the MEMBER, not on signature bytes."""
    members, signs = three
    r = verify_quorum(MSG, [signs["primary"](MSG)] * 5, members, k=2)
    assert r.met is False and r.count == 1


def test_one_key_under_two_roster_names_counts_ONCE(three):
    """A roster mistake, not an attack -- and the more likely one.

    If the same key is enrolled as two identities, a single signature must not
    satisfy both. This is what the `break` after a match is for.
    """
    members, signs = three
    members = dict(members)
    members["recovery_duplicate"] = members["recovery"]  # same verifier object
    r = verify_quorum(MSG, [signs["recovery"](MSG)], members, k=2)
    assert r.met is False, "one key satisfied two roster entries"
    assert r.count == 1


# ---------------------------------------------------------------------------
# CONFIGURATION FAULTS ARE NOT AUTHORISATION FAILURES
# ---------------------------------------------------------------------------

def test_k_larger_than_the_roster_raises_rather_than_returning_false(three):
    """`met=False` would report a permanently impossible quorum as a routine
    failure, and the caller would retry forever."""
    members, _ = three
    with pytest.raises(QuorumConfigError, match="never be met"):
        verify_quorum(MSG, [], members, k=4)


def test_an_empty_roster_raises(three):
    _, signs = three
    with pytest.raises(QuorumConfigError, match="empty member set"):
        verify_quorum(MSG, [signs["primary"](MSG)], {}, k=1)


@pytest.mark.parametrize("bad", [0, -1, -99])
def test_k_below_one_raises(three, bad):
    members, _ = three
    with pytest.raises(QuorumConfigError, match="k must be >= 1"):
        verify_quorum(MSG, [], members, k=bad)


def test_k_as_a_bool_raises(three):
    """`k=True` is `k=1` to Python. A caller that passed a flag by mistake
    would silently get a 1-of-N vault."""
    members, _ = three
    with pytest.raises(QuorumConfigError, match="must be an int"):
        verify_quorum(MSG, [], members, k=True)


# ---------------------------------------------------------------------------
# HOSTILE AND MALFORMED INPUT MUST NOT BECOME AN ACCEPT OR A CRASH
# ---------------------------------------------------------------------------

def test_a_raising_verifier_is_a_rejection_and_does_not_abort_the_batch(three):
    """A recovery path is exactly when a denial of service hurts most, so one
    bad member must not take down the check for the others."""
    members, signs = three
    def explode(sig, msg):
        raise RuntimeError("HSM unplugged")
    members = dict(members, broken=explode)

    r = verify_quorum(MSG, [signs["primary"](MSG), signs["recovery"](MSG)], members, k=2)
    assert r.met is True, "a throwing member blocked an otherwise valid quorum"
    assert "broken" not in r.satisfied_by


def test_a_verifier_returning_a_truthy_nonbool_is_coerced_to_an_accept(three):
    """A verifier may return any truthy value; `met` must still be a real bool.

    **THIS TEST WAS WRONG ON ITS FIRST RUN AND THE CODE WAS RIGHT.** It
    originally gave `sloppy` (which accepts anything) the SAME signature that
    `primary` had already matched, and asserted a count of 2 -- that is, it
    asserted that one signature may satisfy two members, which is the exact
    thing `verify_quorum`'s `break` exists to prevent. The failure was the
    invariant defending itself against its own test suite. `sloppy` now gets
    a signature of its own.
    """
    members, signs = three
    members = dict(members, sloppy=lambda s, m: "yes")
    r = verify_quorum(MSG, [signs["primary"](MSG), b"unsigned garbage"], members, k=2)
    assert r.met is True and r.count == 2
    assert r.satisfied_by == frozenset({"primary", "sloppy"})
    assert r.met is True and isinstance(r.met, bool), "met leaked a non-bool"


def test_signatures_over_a_DIFFERENT_message_do_not_count(three):
    members, signs = three
    r = verify_quorum(MSG, [signs[n](OTHER) for n in ("primary", "recovery")], members, k=2)
    assert r.met is False and r.count == 0
    assert r.unmatched_signatures == 2


def test_empty_and_garbage_signatures_are_counted_as_unmatched_not_crashes(three):
    members, signs = three
    r = verify_quorum(MSG, [b"", b"\x00" * 64, signs["primary"](MSG)], members, k=1)
    assert r.met is True and r.count == 1
    assert r.unmatched_signatures == 2


def test_no_signatures_at_all(three):
    members, _ = three
    r = verify_quorum(MSG, [], members, k=1)
    assert r.met is False and r.count == 0


# ---------------------------------------------------------------------------
# SHAPE
# ---------------------------------------------------------------------------

def test_order_does_not_matter(three):
    members, signs = three
    a, b = signs["primary"](MSG), signs["passphrase"](MSG)
    assert verify_quorum(MSG, [a, b], members, k=2).satisfied_by == \
           verify_quorum(MSG, [b, a], members, k=2).satisfied_by


def test_surplus_valid_signatures_do_not_break_a_met_quorum(three):
    members, signs = three
    r = verify_quorum(MSG, [signs[n](MSG) for n in members], members, k=2)
    assert r.met is True and r.count == 3


def test_k_equal_to_the_whole_roster_is_allowed(three):
    members, signs = three
    r = verify_quorum(MSG, [signs[n](MSG) for n in members], members, k=3)
    assert r.met is True


def test_result_is_frozen_so_a_caller_cannot_edit_the_verdict(three):
    members, signs = three
    r = verify_quorum(MSG, [signs["primary"](MSG)], members, k=1)
    with pytest.raises(Exception):
        r.met = False  # type: ignore[misc]


def test_count_is_members_not_signatures(three):
    """The invariant, stated once as an assertion rather than only in prose."""
    members, signs = three
    r = verify_quorum(MSG, [signs["primary"](MSG)] * 4, members, k=1)
    assert r.count == len(r.satisfied_by) == 1
    assert isinstance(r, QuorumResult)
