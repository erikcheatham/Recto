"""GATE 5 -- the genesis membership chain.

    A CODE GUARD CANNOT DEFEND A FILE FROM SOMEONE WHO HAS THE FILE.

So the property under test is not "the writer refuses" but "an edit is
VISIBLE". Every test below is a different way of tampering with a stored
chain, and each must be caught at replay.

THE POSITIVE CONTROL IS `test_a_well_formed_chain_replays_to_its_membership`.
Every other test asserts a ChainError, and a replay that raised on everything
would satisfy them all.
"""

from __future__ import annotations

import base64
import dataclasses

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from recto.bootloader.genesis_chain import (
    ChainError,
    build_entry,
    entry_hash,
    replay,
    signing_bytes,
)


def _ed():
    sk = Ed25519PrivateKey.generate()
    return sk.public_key().public_bytes_raw(), "ed25519", sk.sign


def _p256():
    sk = ec.generate_private_key(ec.SECP256R1())
    n = sk.public_key().public_numbers()
    pub = n.x.to_bytes(32, "big") + n.y.to_bytes(32, "big")

    def sign(m: bytes) -> bytes:
        r, s = decode_dss_signature(sk.sign(m, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    return pub, "ecdsa-p256", sign


def _genesis(pub, algo, kind="passphrase"):
    return build_entry(seq=0, op="add", kind=kind, pubkey=pub,
                       algorithm=algo, prev=None)


def _next(chain, *, op, kind, pubkey, algorithm, signers):
    """Build the next entry, signed by `signers` (list of sign callables)."""
    prev = entry_hash(chain[-1])
    seq = len(chain)
    msg = signing_bytes(seq=seq, op=op, kind=kind, pubkey=pubkey,
                        algorithm=algorithm, prev=prev)
    return build_entry(seq=seq, op=op, kind=kind, pubkey=pubkey,
                       algorithm=algorithm, prev=prev,
                       signatures=[s(msg) for s in signers])


@pytest.fixture
def two_member_chain():
    """Genesis passphrase, then a recovery phone added with the passphrase's
    signature -- the real shape of this vault."""
    pp_pub, pp_algo, pp_sign = _ed()
    rec_pub, rec_algo, rec_sign = _p256()
    chain = [_genesis(pp_pub, pp_algo)]
    chain.append(_next(chain, op="add", kind="recovery", pubkey=rec_pub,
                       algorithm=rec_algo, signers=[pp_sign]))
    return chain, pp_sign, rec_sign, rec_pub


# ---------------------------------------------------------------------------
# THE POSITIVE CONTROL
# ---------------------------------------------------------------------------

def test_a_well_formed_chain_replays_to_its_membership(two_member_chain):
    chain, *_ = two_member_chain
    members = replay(chain)
    assert set(members) == {"passphrase", "recovery"}
    assert members["recovery"].algorithm == "ecdsa-p256"


def test_a_lone_genesis_entry_is_a_valid_chain():
    pub, algo, _ = _ed()
    assert set(replay([_genesis(pub, algo)])) == {"passphrase"}


def test_a_removal_signed_by_everyone_takes_effect(two_member_chain):
    chain, pp_sign, rec_sign, rec_pub = two_member_chain
    chain.append(_next(chain, op="remove", kind="recovery", pubkey=rec_pub,
                       algorithm="ecdsa-p256", signers=[pp_sign, rec_sign]))
    assert set(replay(chain)) == {"passphrase"}


# ---------------------------------------------------------------------------
# THE THRESHOLD -- a majority of the set as it stands
# ---------------------------------------------------------------------------

def test_a_change_missing_one_members_signature_is_refused(two_member_chain):
    """**THE THRESHOLD.** A majority of two is two, so one signature is not
    enough -- a compromised phone cannot rewrite the roster alone."""
    chain, pp_sign, _, rec_pub = two_member_chain
    third_pub, third_algo, _ = _ed()
    chain.append(_next(chain, op="add", kind="third", pubkey=third_pub,
                       algorithm=third_algo, signers=[pp_sign]))
    with pytest.raises(ChainError, match="requires 2"):
        replay(chain)


def test_one_member_signing_twice_is_not_two_members(two_member_chain):
    """Counts MEMBERS satisfied, never signatures accepted -- the same
    invariant `recto.quorum` exists to hold, restated here because replay
    cannot take a verifier map from a caller."""
    chain, pp_sign, _, _ = two_member_chain
    third_pub, third_algo, _ = _ed()
    entry = _next(chain, op="add", kind="third", pubkey=third_pub,
                  algorithm=third_algo, signers=[pp_sign, pp_sign])
    chain.append(entry)
    with pytest.raises(ChainError, match="requires 2"):
        replay(chain)


def test_a_signature_from_a_NON_member_does_not_count(two_member_chain):
    chain, pp_sign, _, _ = two_member_chain
    stranger_pub, _, stranger_sign = _ed()
    third_pub, third_algo, _ = _ed()
    chain.append(_next(chain, op="add", kind="third", pubkey=third_pub,
                       algorithm=third_algo, signers=[pp_sign, stranger_sign]))
    with pytest.raises(ChainError, match="requires 2"):
        replay(chain)


# ---------------------------------------------------------------------------
# TAMPERING IS VISIBLE -- the actual gate
# ---------------------------------------------------------------------------

def test_editing_a_SIGNED_entry_invalidates_its_own_signature(two_member_chain):
    """**THE ONE THE WHOLE DESIGN EXISTS FOR.** Swap the key an entry admits
    and the entry's own signature stops verifying, because the key is inside
    the signed bytes.

    Caught one entry EARLIER than the hash link would have. Both mechanisms
    are live; this is simply the first to fire on a signed entry.
    """
    chain, pp_sign, rec_sign, rec_pub = two_member_chain
    chain.append(_next(chain, op="remove", kind="recovery", pubkey=rec_pub,
                       algorithm="ecdsa-p256", signers=[pp_sign, rec_sign]))
    attacker_pub, _, _ = _p256()
    chain[1] = dataclasses.replace(chain[1], pubkey=attacker_pub)
    # Entry 1 is validated against the set as it stood BEFORE it -- just the
    # passphrase -- so the refusal reads "requires 1", not 2. Matching the
    # stable part of the message rather than a count that depends on where in
    # the chain the tamper landed.
    with pytest.raises(ChainError, match="valid member signature"):
        replay(chain)


def test_editing_the_UNSIGNED_genesis_entry_breaks_the_hash_link(two_member_chain):
    """Genesis carries no signature, so the signature check cannot catch a
    change to it. **The hash link is what covers genesis** -- and genesis is
    exactly the entry an attacker would most want to rewrite, because every
    later signature is anchored to it.
    """
    chain, *_ = two_member_chain
    attacker_pub, _, _ = _ed()
    chain[0] = dataclasses.replace(chain[0], pubkey=attacker_pub)
    with pytest.raises(ChainError, match="An earlier entry was altered"):
        replay(chain)


def test_appending_an_unsigned_entry_is_refused(two_member_chain):
    chain, *_ = two_member_chain
    rogue_pub, rogue_algo, _ = _ed()
    prev = entry_hash(chain[-1])
    chain.append(build_entry(seq=2, op="add", kind="rogue", pubkey=rogue_pub,
                             algorithm=rogue_algo, prev=prev))
    with pytest.raises(ChainError, match="requires 2"):
        replay(chain)


def test_deleting_a_middle_entry_breaks_the_sequence(two_member_chain):
    chain, pp_sign, rec_sign, rec_pub = two_member_chain
    chain.append(_next(chain, op="remove", kind="recovery", pubkey=rec_pub,
                       algorithm="ecdsa-p256", signers=[pp_sign, rec_sign]))
    del chain[1]
    with pytest.raises(ChainError, match="sequence broken"):
        replay(chain)


def test_truncating_the_chain_does_not_yield_an_earlier_membership(two_member_chain):
    """A chain that stops verifying must not degrade to "the set as of the
    last good entry" -- an attacker who can truncate would then choose which
    membership you get. Truncation IS valid here (it is a prefix), which is
    why the STORE must also pin the length; recorded as the boundary."""
    chain, *_ = two_member_chain
    assert set(replay(chain[:1])) == {"passphrase"}, (
        "a prefix replays cleanly by construction -- the chain alone cannot "
        "detect truncation, so the store records the expected length"
    )


def test_a_reordered_chain_is_refused(two_member_chain):
    chain, *_ = two_member_chain
    with pytest.raises(ChainError, match="sequence broken"):
        replay(list(reversed(chain)))


# ---------------------------------------------------------------------------
# GENESIS
# ---------------------------------------------------------------------------

def test_the_genesis_entry_must_not_carry_signatures():
    """Nothing could have signed it, so a signature there is a claim no
    verifier can check -- and accepting unverifiable claims is how a chain
    starts lying."""
    pub, algo, sign = _ed()
    bad = build_entry(seq=0, op="add", kind="passphrase", pubkey=pub,
                      algorithm=algo, prev=None, signatures=[sign(b"anything")])
    with pytest.raises(ChainError, match="must carry no signatures"):
        replay([bad])


def test_the_genesis_entry_must_be_an_add():
    pub, algo, _ = _ed()
    bad = build_entry(seq=0, op="remove", kind="passphrase", pubkey=pub,
                      algorithm=algo, prev=None)
    with pytest.raises(ChainError, match="must be an 'add'"):
        replay([bad])


def test_a_genesis_entry_claiming_a_prev_is_refused():
    pub, algo, _ = _ed()
    bad = build_entry(seq=0, op="add", kind="passphrase", pubkey=pub,
                      algorithm=algo, prev="deadbeef")
    with pytest.raises(ChainError, match="does not follow"):
        replay([bad])


# ---------------------------------------------------------------------------
# LOCKOUT GUARDS
# ---------------------------------------------------------------------------

def test_removing_the_last_member_is_refused(two_member_chain):
    """A set with no members can never authorise another change. The vault
    would still open, but the roster would be permanently unmanageable."""
    chain, pp_sign, rec_sign, rec_pub = two_member_chain
    chain.append(_next(chain, op="remove", kind="recovery", pubkey=rec_pub,
                       algorithm="ecdsa-p256", signers=[pp_sign, rec_sign]))
    pp_entry = chain[0]
    chain.append(_next(chain, op="remove", kind="passphrase",
                       pubkey=pp_entry.pubkey, algorithm=pp_entry.algorithm,
                       signers=[pp_sign]))
    with pytest.raises(ChainError, match="removes the last member"):
        replay(chain)


def test_removing_a_kind_that_is_not_a_member_is_refused(two_member_chain):
    chain, pp_sign, rec_sign, _ = two_member_chain
    ghost_pub, ghost_algo, _ = _ed()
    chain.append(_next(chain, op="remove", kind="ghost", pubkey=ghost_pub,
                       algorithm=ghost_algo, signers=[pp_sign, rec_sign]))
    with pytest.raises(ChainError, match="not a member at that point"):
        replay(chain)


# ---------------------------------------------------------------------------
# SHAPE
# ---------------------------------------------------------------------------

def test_signing_bytes_exclude_signatures():
    """Otherwise the second signer signs over the first signature, and no two
    members could ever sign the same entry."""
    pub, algo, _ = _ed()
    a = signing_bytes(seq=1, op="add", kind="k", pubkey=pub, algorithm=algo, prev="ab")
    b = signing_bytes(seq=1, op="add", kind="k", pubkey=pub, algorithm=algo, prev="ab")
    assert a == b
    assert b"signature" not in a


def test_signing_bytes_are_domain_separated():
    pub, algo, _ = _ed()
    assert signing_bytes(
        seq=0, op="add", kind="k", pubkey=pub, algorithm=algo, prev=None
    ).startswith(b"recto-genesis-chain-v1\x00")


def test_an_unsupported_algorithm_cannot_enter_the_chain():
    pub, _, _ = _ed()
    with pytest.raises(ChainError, match="no verifier supports"):
        build_entry(seq=0, op="add", kind="k", pubkey=pub,
                    algorithm="secp256k1", prev=None)


def test_an_unknown_op_is_refused():
    pub, algo, _ = _ed()
    with pytest.raises(ChainError, match="unknown chain op"):
        build_entry(seq=0, op="replace", kind="k", pubkey=pub,
                    algorithm=algo, prev=None)


# ---------------------------------------------------------------------------
# THE STORE READS THE CHAIN, AND A BROKEN ONE IS "UNREADABLE" NOT "ABSENT"
# ---------------------------------------------------------------------------

def _store(tmp_path, body):
    import json as _json, pathlib
    from recto.bootloader.state import StateStore
    (pathlib.Path(tmp_path) / "genesis_members.json").write_text(
        _json.dumps(body), encoding="utf-8")
    return StateStore(state_dir=pathlib.Path(tmp_path))


def test_the_store_replays_a_stored_chain(tmp_path, two_member_chain):
    chain, *_ = two_member_chain
    s = _store(tmp_path, {"chain": [e.as_record() for e in chain]})
    assert set(s.list_genesis_members_full()) == {"passphrase", "recovery"}
    assert s.list_unreadable_genesis_members() == {}


def test_a_tampered_stored_chain_reads_as_UNREADABLE(tmp_path, two_member_chain):
    """**THE PROPERTY THE CHAIN EXISTS FOR, END TO END.** The file is edited
    directly -- which no code guard could prevent -- and the store reports the
    set as unreadable rather than handing back the attacker's membership."""
    chain, *_ = two_member_chain
    records = [e.as_record() for e in chain]
    records[1]["kind"] = "attacker"
    s = _store(tmp_path, {"chain": records})
    assert s.list_genesis_members_full() == {}
    bad = s.list_unreadable_genesis_members()
    assert "<chain>" in bad and "does not verify" in bad["<chain>"]


def test_an_appended_entry_reads_as_UNREADABLE(tmp_path, two_member_chain):
    chain, *_ = two_member_chain
    pub, algo, _ = _ed()
    records = [e.as_record() for e in chain]
    records.append({"seq": 2, "op": "add", "kind": "rogue",
                    "pubkey": pub.hex(), "algorithm": algo,
                    "prev": entry_hash(chain[-1]), "signatures": []})
    s = _store(tmp_path, {"chain": records})
    assert s.list_genesis_members_full() == {}
    assert "does not verify" in s.list_unreadable_genesis_members()["<chain>"]


def test_a_PRE_CHAIN_vault_still_reads_its_flat_members(tmp_path):
    """**THE ORPHAN GUARD, AGAIN.** The live vault was sealed before the chain
    existed: a flat `members` map, no chain. It must keep working untouched."""
    pub, _, _ = _ed()
    s = _store(tmp_path, {"members": {"passphrase": pub.hex()}, "stored_at_unix": 1})
    assert s.get_genesis_member("passphrase") == pub
    assert s.list_unreadable_genesis_members() == {}


def test_when_a_chain_exists_the_flat_map_is_not_consulted(tmp_path, two_member_chain):
    """One source of truth at any moment. A stale flat map left beside a chain
    must not resurrect a member the chain removed."""
    chain, *_ = two_member_chain
    ghost, _, _ = _ed()
    s = _store(tmp_path, {
        "chain": [e.as_record() for e in chain],
        "members": {"ghost": ghost.hex()},
    })
    assert "ghost" not in s.list_genesis_members_full()


# ---------------------------------------------------------------------------
# WHY UNANIMITY WAS REVERSED: A LOST MEMBER MUST BE RECOVERABLE
# ---------------------------------------------------------------------------

def _three_member_chain():
    pp_pub, pp_algo, pp_sign = _ed()
    pri_pub, pri_algo, pri_sign = _p256()
    rec_pub, rec_algo, rec_sign = _p256()
    chain = [_genesis(pp_pub, pp_algo)]
    chain.append(_next(chain, op="add", kind="primary", pubkey=pri_pub,
                       algorithm=pri_algo, signers=[pp_sign]))
    chain.append(_next(chain, op="add", kind="recovery", pubkey=rec_pub,
                       algorithm=rec_algo, signers=[pp_sign, pri_sign]))
    return chain, pp_sign, pri_sign, rec_sign, rec_pub


def test_a_majority_of_three_is_two():
    from recto.bootloader.genesis_chain import required_signatures
    assert [required_signatures(n) for n in (1, 2, 3, 4, 5)] == [1, 2, 2, 3, 3]


def test_three_members_are_reachable_and_replay_cleanly():
    chain, *_ = _three_member_chain()
    assert set(replay(chain)) == {"passphrase", "primary", "recovery"}


def test_TWO_of_three_can_drop_a_LOST_member(_=None):
    """**THE TEST THE REVERSAL EXISTS FOR.**

    Unanimity would have made this impossible: removing the lost phone would
    have required the lost phone's signature, freezing the roster forever --
    and a frozen roster cannot admit a replacement either. With a majority,
    the two surviving members recover.
    """
    chain, pp_sign, pri_sign, _, rec_pub = _three_member_chain()
    # `recovery` is lost. The passphrase and primary drop it WITHOUT it.
    chain.append(_next(chain, op="remove", kind="recovery", pubkey=rec_pub,
                       algorithm="ecdsa-p256", signers=[pp_sign, pri_sign]))
    assert set(replay(chain)) == {"passphrase", "primary"}


def test_the_replacement_can_then_be_admitted():
    """Recovery is only real if a new device can take the lost one's place."""
    chain, pp_sign, pri_sign, _, rec_pub = _three_member_chain()
    chain.append(_next(chain, op="remove", kind="recovery", pubkey=rec_pub,
                       algorithm="ecdsa-p256", signers=[pp_sign, pri_sign]))
    new_pub, new_algo, _ = _p256()
    chain.append(_next(chain, op="add", kind="recovery", pubkey=new_pub,
                       algorithm=new_algo, signers=[pp_sign, pri_sign]))
    members = replay(chain)
    assert set(members) == {"passphrase", "primary", "recovery"}
    assert members["recovery"].pubkey == new_pub, "the replacement did not take"


def test_ONE_of_three_still_cannot_change_the_roster():
    """Fault tolerance must not have cost single-compromise resistance."""
    chain, pp_sign, _, _, rec_pub = _three_member_chain()
    chain.append(_next(chain, op="remove", kind="recovery", pubkey=rec_pub,
                       algorithm="ecdsa-p256", signers=[pp_sign]))
    with pytest.raises(ChainError, match="requires 2"):
        replay(chain)
