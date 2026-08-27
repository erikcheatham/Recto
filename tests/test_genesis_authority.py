"""GATE 5c-c tier 3 -- k-of-N over the sealed genesis members.

THE SET, AS RULED 2026-08-19: the RECOVERY PHONE and the PASSPHRASE. The
operator root is NOT a member -- the BIP-39 master stays in custody and never
signs a challenge online.

That ruling is why this file is short. An earlier draft tested a verifier
registry, an unverifiable-member error, and a secp256k1 root; none of it
survived the root leaving the set. **What remains is worth more than what
went**: every member is now verifiable by the one function the rest of the
bootloader already trusts.

THE POSITIVE CONTROL IS `test_two_members_meet_a_two_of_two`.
"""

from __future__ import annotations

import base64
import pathlib

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from recto.bootloader import genesis_authority as ga
from recto.bootloader.sessions import SUPPORTED_ALGORITHMS
from recto.bootloader.state import GENESIS_ALGORITHMS, GenesisMember, StateStore
from recto.quorum import QuorumConfigError

MSG = b"tier3|restore-operator|nonce-4d71"


def _ed25519():
    sk = Ed25519PrivateKey.generate()
    return sk.public_key().public_bytes_raw(), (lambda m: sk.sign(m))


def _p256():
    """An iOS-Secure-Enclave-shaped signer: raw r||s, not DER."""
    sk = ec.generate_private_key(ec.SECP256R1())
    nums = sk.public_key().public_numbers()
    pub = nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")

    def sign(m: bytes) -> bytes:
        r, s = decode_dss_signature(sk.sign(m, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    return pub, sign


@pytest.fixture
def vault(tmp_path):
    """Passphrase (ed25519) + recovery phone (ecdsa-p256) -- the real set."""
    state = StateStore(state_dir=pathlib.Path(tmp_path))
    pp_pub, pp_sign = _ed25519()
    rec_pub, rec_sign = _p256()
    state.put_genesis_member("passphrase", pp_pub, "ed25519")
    state.put_genesis_member("recovery", rec_pub, "ecdsa-p256")
    return state, pp_sign, rec_sign


# ---------------------------------------------------------------------------
# THE POSITIVE CONTROL -- both real curves, through the real verifier
# ---------------------------------------------------------------------------

def test_two_members_meet_a_two_of_two(vault):
    state, pp_sign, rec_sign = vault
    r = ga.verify_tier3(MSG, [pp_sign(MSG), rec_sign(MSG)], state, k=2)
    assert r.met is True
    assert r.satisfied_by == frozenset({"passphrase", "recovery"})


def test_the_passphrase_alone_does_not_meet_a_two_of_two(vault):
    """Losing the phone must not be survivable by the phrase alone -- that is
    the entire reason the set has two members."""
    state, pp_sign, _ = vault
    r = ga.verify_tier3(MSG, [pp_sign(MSG)], state, k=2)
    assert r.met is False and r.satisfied_by == frozenset({"passphrase"})


def test_the_recovery_phone_alone_does_not_meet_a_two_of_two(vault):
    """The symmetric case: a stolen phone is not enough either."""
    state, _, rec_sign = vault
    r = ga.verify_tier3(MSG, [rec_sign(MSG)], state, k=2)
    assert r.met is False and r.satisfied_by == frozenset({"recovery"})


def test_one_member_signing_twice_does_not_meet_a_two_of_two(vault):
    """The quorum invariant survives the trip through this layer."""
    state, pp_sign, _ = vault
    sig = pp_sign(MSG)
    assert ga.verify_tier3(MSG, [sig, sig], state, k=2).met is False


def test_signatures_over_a_different_message_do_not_count(vault):
    state, pp_sign, rec_sign = vault
    other = b"tier3|restore-operator|nonce-DIFFERENT"
    r = ga.verify_tier3(MSG, [pp_sign(other), rec_sign(other)], state, k=2)
    assert r.met is False and r.count == 0


def test_a_single_member_set_can_still_meet_a_one_of_one(vault, tmp_path):
    """Before the recovery phone is enrolled, the vault holds only the
    passphrase. That state must be coherent rather than an error."""
    solo = pathlib.Path(tmp_path) / "solo"
    solo.mkdir()
    state = StateStore(state_dir=solo)
    pub, sign = _ed25519()
    state.put_genesis_member("passphrase", pub, "ed25519")
    assert ga.verify_tier3(MSG, [sign(MSG)], state, k=1).met is True


# ---------------------------------------------------------------------------
# STRUCTURAL FAULTS ARE NOT SIGNATURE FAULTS
# ---------------------------------------------------------------------------

def test_a_vault_with_no_sealed_members_raises(tmp_path):
    state = StateStore(state_dir=pathlib.Path(tmp_path))
    with pytest.raises(ga.GenesisSetError, match="no genesis members"):
        ga.verify_tier3(MSG, [], state, k=1)


def test_an_unsupported_algorithm_raises_rather_than_failing_the_quorum(vault, monkeypatch):
    """The store and the verifier keep their algorithm lists in different
    files. If they ever drift, a sealed member becomes unreadable -- and that
    must not look like "the quorum was not met", or the operator re-presents
    correct signatures forever."""
    state, _, _ = vault
    monkeypatch.setattr(ga, "SUPPORTED_ALGORITHMS", ("ed25519",))
    with pytest.raises(ga.GenesisSetError) as exc:
        ga.verify_tier3(MSG, [], state, k=2)
    assert "recovery (ecdsa-p256)" in str(exc.value)
    assert "NOT a failed authorisation" in str(exc.value)


def test_a_partial_verifier_set_is_never_returned(vault, monkeypatch):
    """2-of-3 over a set the code can read two of is really 2-of-2."""
    state, _, _ = vault
    monkeypatch.setattr(ga, "SUPPORTED_ALGORITHMS", ("ed25519",))
    with pytest.raises(ga.GenesisSetError):
        ga.build_member_verifiers(ga.collect_genesis_set(state))


def test_the_check_happens_before_any_signature_is_examined(vault, monkeypatch):
    state, _, _ = vault
    monkeypatch.setattr(ga, "SUPPORTED_ALGORITHMS", ("ed25519",))
    with pytest.raises(ga.GenesisSetError):
        ga.verify_tier3(MSG, [b"\x00" * 64], state, k=1)


def test_quorum_config_errors_still_surface(vault):
    """k greater than the roster can never be met and must not read as a
    routine failure just because it arrived through tier 3."""
    state, _, _ = vault
    with pytest.raises(QuorumConfigError, match="never be met"):
        ga.verify_tier3(MSG, [], state, k=3)


# ---------------------------------------------------------------------------
# THE TWO ALGORITHM LISTS MUST NOT DRIFT
# ---------------------------------------------------------------------------

def test_the_sealable_algorithms_are_exactly_the_verifiable_ones():
    """**THE DRIFT GUARD, AND IT SPANS TWO FILES.**

    `state.GENESIS_ALGORITHMS` decides what can be SEALED.
    `sessions.SUPPORTED_ALGORITHMS` decides what can be VERIFIED.

    A member sealed under an algorithm the verifier cannot read is discovered
    at recovery and nowhere earlier. Neither list can be checked against
    itself -- only against the other.
    """
    assert set(GENESIS_ALGORITHMS) == set(SUPPORTED_ALGORITHMS)


def test_secp256k1_is_not_sealable(tmp_path):
    """The operator root is not a genesis member, so its curve has no signer
    in this set. Re-adding it means the master key signs online -- a decision,
    not a merge."""
    state = StateStore(state_dir=pathlib.Path(tmp_path))
    with pytest.raises(ValueError, match="unknown genesis member algorithm"):
        state.put_genesis_member("root", bytes(range(1, 65)), "secp256k1")


def test_a_p256_member_round_trips_through_the_store_and_verifier(tmp_path):
    """64 raw bytes in, 64 raw bytes out, and it still verifies -- the store
    must not re-encode a key on the way through."""
    state = StateStore(state_dir=pathlib.Path(tmp_path))
    pub, sign = _p256()
    state.put_genesis_member("recovery", pub, "ecdsa-p256")
    assert state.get_genesis_member("recovery") == pub
    assert ga.verify_tier3(MSG, [sign(MSG)], state, k=1).met is True
