"""Hard rule 14.7 -- the top plane needs the PASSPHRASE AND ONE OWNER DEVICE, every time.

The rule: the passphrase alone is refused, because a hijacked bootloader's sealed public key
could be attacked offline; devices alone - one or both - are refused, because a lost or stolen phone must never carry
the plane. Not k-of-N: the passphrase is MANDATORY and the devices are interchangeable.

Two layers carry it: `genesis_authority.verify_top_plane` (the gate an act asks) and the genesis chain's own
threshold (a roster change replays only under the same rule).
"""

from __future__ import annotations

import pathlib

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from recto.bootloader import genesis_authority as ga
from recto.bootloader.genesis_chain import ChainError, build_entry, entry_hash, replay, signing_bytes
from recto.bootloader.state import StateStore

ACT = b"recto-top-plane-test|owner-slot|primary|nonce-91c2"


def _ed25519():
    sk = Ed25519PrivateKey.generate()
    return sk.public_key().public_bytes_raw(), (lambda m: sk.sign(m))


def _p256():
    sk = ec.generate_private_key(ec.SECP256R1())
    nums = sk.public_key().public_numbers()
    pub = nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")

    def sign(m: bytes) -> bytes:
        r, s = decode_dss_signature(sk.sign(m, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    return pub, sign


@pytest.fixture
def plane(tmp_path):
    """The set the rule is written for: the passphrase + the recovery phone + the primary phone."""
    state = StateStore(state_dir=pathlib.Path(tmp_path))
    pp_pub, pp = _ed25519()
    rec_pub, rec = _p256()
    pri_pub, pri = _p256()
    state.put_genesis_member("passphrase", pp_pub, "ed25519")
    state.put_genesis_member("recovery-phone", rec_pub, "ecdsa-p256")
    state.put_genesis_member("primary-phone", pri_pub, "ecdsa-p256")
    return state, pp, rec, pri


# --- the gate -------------------------------------------------------------------------------------------------------

def test_the_passphrase_alone_is_refused(plane):
    state, pp, _, _ = plane
    r = ga.verify_top_plane(ACT, [pp(ACT)], state)
    assert r.met is False and r.passphrase is True and r.devices == frozenset()


def test_one_device_alone_is_refused(plane):
    state, _, rec, _ = plane
    assert ga.verify_top_plane(ACT, [rec(ACT)], state).met is False


def test_both_devices_without_the_passphrase_are_refused(plane):
    state, _, rec, pri = plane
    r = ga.verify_top_plane(ACT, [rec(ACT), pri(ACT)], state)
    assert r.met is False and r.passphrase is False and r.devices == {"recovery-phone", "primary-phone"}


def test_the_passphrase_and_the_primary_device_are_admitted(plane):
    state, pp, _, pri = plane
    r = ga.verify_top_plane(ACT, [pp(ACT), pri(ACT)], state)
    assert r.met is True and r.devices == {"primary-phone"}


def test_the_passphrase_and_the_recovery_device_are_admitted(plane):
    state, pp, rec, _ = plane
    r = ga.verify_top_plane(ACT, [rec(ACT), pp(ACT)], state)
    assert r.met is True and r.devices == {"recovery-phone"}


def test_a_signature_over_another_acts_bytes_is_refused(plane):
    state, pp, rec, _ = plane
    other = ACT.replace(b"primary", b"recovery")
    assert ga.verify_top_plane(ACT, [pp(other), rec(other)], state).met is False


def test_a_device_not_in_the_sealed_set_is_refused(plane):
    state, pp, _, _ = plane
    _, stranger = _p256()
    assert ga.verify_top_plane(ACT, [pp(ACT), stranger(ACT)], state).met is False


def test_one_devices_signature_twice_is_one_device_and_no_passphrase(plane):
    state, _, rec, _ = plane
    sig = rec(ACT)
    r = ga.verify_top_plane(ACT, [sig, sig, sig], state)
    assert r.met is False and r.devices == {"recovery-phone"}


def test_a_set_with_no_passphrase_cannot_act(tmp_path):
    state = StateStore(state_dir=pathlib.Path(tmp_path))
    rec_pub, rec = _p256()
    state.put_genesis_member("recovery-phone", rec_pub, "ecdsa-p256")
    with pytest.raises(ga.GenesisSetError, match="no passphrase"):
        ga.verify_top_plane(ACT, [rec(ACT)], state)


def test_a_set_with_no_device_cannot_act(tmp_path):
    state = StateStore(state_dir=pathlib.Path(tmp_path))
    pp_pub, pp = _ed25519()
    state.put_genesis_member("passphrase", pp_pub, "ed25519")
    with pytest.raises(ga.GenesisSetError, match="no device"):
        ga.verify_top_plane(ACT, [pp(ACT)], state)


def test_another_sealed_kind_is_not_an_owner_device_for_the_gate(tmp_path):
    """The gate's device leg is an OWNER device (recovery-phone / primary-phone); another sealed factor does not
    stand in for one there."""
    state = StateStore(state_dir=pathlib.Path(tmp_path))
    pp_pub, pp = _ed25519()
    hk_pub, hk = _p256()
    rec_pub, _ = _p256()
    state.put_genesis_member("passphrase", pp_pub, "ed25519")
    state.put_genesis_member("hardware-key", hk_pub, "ecdsa-p256")
    state.put_genesis_member("recovery-phone", rec_pub, "ecdsa-p256")
    assert ga.verify_top_plane(ACT, [pp(ACT), hk(ACT)], state).met is False


# --- the chain's own threshold ---------------------------------------------------------------------------------------

def _secp256k1_pub() -> bytes:
    """A real operator key: 64 bytes X||Y on secp256k1."""
    sk = ec.generate_private_key(ec.SECP256K1())
    nums = sk.public_key().public_numbers()
    return nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")


def _entry(chain, *, op, kind, pubkey, algorithm, signers):
    seq = len(chain)
    prev = entry_hash(chain[-1]) if chain else None
    msg = signing_bytes(seq=seq, op=op, kind=kind, pubkey=pubkey, algorithm=algorithm, prev=prev)
    return build_entry(seq=seq, op=op, kind=kind, pubkey=pubkey, algorithm=algorithm, prev=prev,
                       signatures=[s(msg) for s in signers])


@pytest.fixture
def chain2():
    """A chain whose first device entered under the passphrase alone: entry 0 the passphrase (unsigned genesis),
    entry 1 the recovery phone under the passphrase alone (the bootstrap: no device was sealed yet)."""
    pp_pub, pp = _ed25519()
    rec_pub, rec = _p256()
    chain = [_entry([], op="add", kind="passphrase", pubkey=pp_pub, algorithm="ed25519", signers=[])]
    chain.append(_entry(chain, op="add", kind="recovery-phone", pubkey=rec_pub, algorithm="ecdsa-p256",
                        signers=[pp]))
    return chain, pp, rec


def test_the_first_device_enters_under_the_passphrase_alone(chain2):
    chain, _, _ = chain2
    assert set(replay(chain)) == {"passphrase", "recovery-phone"}


def test_a_member_added_by_the_passphrase_and_one_device_replays(chain2):
    chain, pp, rec = chain2
    pri_pub, _ = _p256()
    chain.append(_entry(chain, op="add", kind="primary-phone", pubkey=pri_pub, algorithm="ecdsa-p256",
                        signers=[pp, rec]))
    assert set(replay(chain)) == {"passphrase", "recovery-phone", "primary-phone"}


def test_a_member_added_by_the_passphrase_alone_breaks_the_replay_once_a_device_is_sealed(chain2):
    chain, pp, _ = chain2
    pri_pub, _ = _p256()
    chain.append(_entry(chain, op="add", kind="primary-phone", pubkey=pri_pub, algorithm="ecdsa-p256",
                        signers=[pp]))
    with pytest.raises(ChainError, match="no device signature"):
        replay(chain)


def test_a_member_added_by_both_devices_without_the_passphrase_breaks_the_replay(chain2):
    chain, pp, rec = chain2
    pri_pub, pri = _p256()
    chain.append(_entry(chain, op="add", kind="primary-phone", pubkey=pri_pub, algorithm="ecdsa-p256",
                        signers=[pp, rec]))
    third_pub, _ = _p256()
    chain.append(_entry(chain, op="add", kind="spare-phone", pubkey=third_pub, algorithm="ecdsa-p256",
                        signers=[rec, pri]))
    with pytest.raises(ChainError, match="no valid passphrase signature"):
        replay(chain)


def test_the_passphrase_replaced_by_the_old_passphrase_and_a_device_replays(chain2):
    chain, pp, rec = chain2
    new_pp_pub, new_pp = _ed25519()
    chain.append(_entry(chain, op="add", kind="passphrase", pubkey=new_pp_pub, algorithm="ed25519",
                        signers=[pp, rec]))
    members = replay(chain)
    assert members["passphrase"].pubkey == new_pp_pub
    # and the OLD passphrase signs no later change
    pri_pub, _ = _p256()
    chain.append(_entry(chain, op="add", kind="primary-phone", pubkey=pri_pub, algorithm="ecdsa-p256",
                        signers=[pp, rec]))
    with pytest.raises(ChainError, match="no valid passphrase signature"):
        replay(chain)


def test_a_non_device_signature_is_never_the_device_leg_of_an_add(chain2):
    """The threshold's half of the device rule, on its own: a sealed member of another kind co-signing an ADD (no
    removal, so the last-device guard never runs) does not stand in for a device."""
    chain, pp, rec = chain2
    other_pub, other = _p256()
    chain.append(_entry(chain, op="add", kind="other", pubkey=other_pub, algorithm="ecdsa-p256", signers=[pp, rec]))
    pri_pub, _ = _p256()
    chain.append(_entry(chain, op="add", kind="primary-phone", pubkey=pri_pub, algorithm="ecdsa-p256",
                        signers=[pp, other]))
    with pytest.raises(ChainError, match="no device signature"):
        replay(chain)


def test_a_device_never_shares_the_passphrases_key(chain2):
    chain, pp, rec = chain2
    pp_pub = chain[0].pubkey
    chain.append(_entry(chain, op="add", kind="primary-phone", pubkey=pp_pub, algorithm="ed25519",
                        signers=[pp, rec]))
    with pytest.raises(ChainError, match="share its key"):
        replay(chain)


def test_a_lost_device_is_replaced_by_the_passphrase_and_the_other_device(chain2):
    """A lost device in a two-device set is replaced by the passphrase and the surviving device."""
    chain, pp, rec = chain2
    pri_pub, pri = _p256()
    chain.append(_entry(chain, op="add", kind="primary-phone", pubkey=pri_pub, algorithm="ecdsa-p256",
                        signers=[pp, rec]))
    new_rec_pub, _ = _p256()
    chain.append(_entry(chain, op="add", kind="recovery-phone", pubkey=new_rec_pub, algorithm="ecdsa-p256",
                        signers=[pp, pri]))
    assert replay(chain)["recovery-phone"].pubkey == new_rec_pub


# --- the sealed id, the digest form, rotation, reset (hard rule 14.7) ------------------------

from recto.bootloader.genesis_chain import act_message, canonical_meta, replay_state  # noqa: E402

SEALED_ID = "rb1-0123456789abcdef0123456789abcdef"
SEAL_OPERATOR = _secp256k1_pub()
SEAL_META = canonical_meta({"nonce": "n" * 32, "not_after": 1800000000, "operator_pubkey": SEAL_OPERATOR.hex(),
                           "identity_members": []})


def _act(chain, *, op, kind, pubkey, algorithm, signers, sealed_id, meta=None, extra_sigs=()):
    seq = len(chain)
    prev = entry_hash(chain[-1]) if chain else None
    msg = act_message(seq=seq, op=op, kind=kind, pubkey=pubkey, algorithm=algorithm, prev=prev, meta=meta,
                      sealed_id=sealed_id)
    return build_entry(seq=seq, op=op, kind=kind, pubkey=pubkey, algorithm=algorithm, prev=prev, meta=meta,
                       signatures=[s(msg) for s in signers] + list(extra_sigs))


def _sealed(chain2):
    chain, pp, rec = chain2
    chain.append(_act(chain, op="seal-id", kind="bootloader-id", pubkey=SEALED_ID.encode(), algorithm="none",
                      signers=[pp, rec], sealed_id=SEALED_ID, meta=SEAL_META))
    return chain, pp, rec


def test_a_seal_id_entry_commits_the_id_and_later_entries_sign_over_it(chain2):
    chain, pp, rec = _sealed(chain2)
    pri_pub, _ = _p256()
    chain.append(_act(chain, op="add", kind="primary-phone", pubkey=pri_pub, algorithm="ecdsa-p256",
                      signers=[pp, rec], sealed_id=SEALED_ID))
    st = replay_state(chain)
    assert st.sealed_id == SEALED_ID and set(st.members) == {"passphrase", "recovery-phone", "primary-phone"}
    # the act's message is 32 bytes - what a phone's card carries
    assert len(act_message(seq=4, op="add", kind="x", pubkey=b"k", algorithm="ed25519", prev=None,
                           sealed_id=SEALED_ID)) == 32


def test_after_the_seal_a_raw_form_signature_does_not_count(chain2):
    chain, pp, rec = _sealed(chain2)
    pri_pub, _ = _p256()
    chain.append(_act(chain, op="add", kind="primary-phone", pubkey=pri_pub, algorithm="ecdsa-p256",
                      signers=[pp, rec], sealed_id=None))  # signed in the pre-seal form
    with pytest.raises(ChainError, match="no valid passphrase signature"):
        replay(chain)


def test_a_chain_spliced_from_another_bootloader_does_not_replay(chain2):
    chain, pp, rec = _sealed(chain2)
    pri_pub, _ = _p256()
    chain.append(_act(chain, op="add", kind="primary-phone", pubkey=pri_pub, algorithm="ecdsa-p256",
                      signers=[pp, rec], sealed_id="rb1-another-bootloader"))
    with pytest.raises(ChainError):
        replay(chain)


def test_the_id_is_sealed_once(chain2):
    chain, pp, rec = _sealed(chain2)
    chain.append(_act(chain, op="seal-id", kind="bootloader-id", pubkey=b"rb1-second", algorithm="none",
                      signers=[pp, rec], sealed_id="rb1-second", meta=SEAL_META))
    with pytest.raises(ChainError, match="second time"):
        replay(chain)


def test_a_seal_id_by_the_passphrase_alone_is_refused_once_a_device_exists(chain2):
    chain, pp, _ = chain2
    chain.append(_act(chain, op="seal-id", kind="bootloader-id", pubkey=SEALED_ID.encode(), algorithm="none",
                      signers=[pp], sealed_id=SEALED_ID, meta=SEAL_META))
    with pytest.raises(ChainError, match="no device signature"):
        replay(chain)


def test_a_seal_id_with_no_device_sealed_refuses_on_replay():
    """The seal is a top-plane act: on a chain holding the passphrase alone, a seal signed by the passphrase alone
    does not replay - a device is sealed first."""
    pp_pub, pp = _ed25519()
    chain = [_entry([], op="add", kind="passphrase", pubkey=pp_pub, algorithm="ed25519", signers=[])]
    chain.append(_act(chain, op="seal-id", kind="bootloader-id", pubkey=SEALED_ID.encode(), algorithm="none",
                      signers=[pp], sealed_id=SEALED_ID, meta=SEAL_META))
    with pytest.raises(ChainError, match="no device sealed"):
        replay(chain)


def test_the_seal_records_the_operator_key(chain2):
    st = replay_state(_sealed(chain2)[0])
    assert st.sealed_operator_pubkey == SEAL_OPERATOR and st.operator_pubkey is None
    assert st.current_operator_pubkey == SEAL_OPERATOR


def test_a_seal_without_the_operator_key_refuses_on_replay(chain2):
    chain, pp, rec = chain2
    chain.append(_act(chain, op="seal-id", kind="bootloader-id", pubkey=SEALED_ID.encode(), algorithm="none",
                      signers=[pp, rec], sealed_id=SEALED_ID, meta=canonical_meta({"nonce": "n" * 32})))
    with pytest.raises(ChainError, match="records the operator key"):
        replay(chain)


def test_a_removal_under_another_members_key_refuses_on_replay(chain2):
    """A removal names the member it removes by that member's own key: one carrying another key never replays, so
    the chain and the registry always drop the same device."""
    chain, pp, rec = _sealed(chain2)
    pri_pub, pri = _p256()
    chain.append(_act(chain, op="add", kind="primary-phone", pubkey=pri_pub, algorithm="ecdsa-p256",
                      signers=[pp, rec], sealed_id=SEALED_ID))
    other_pub, _ = _p256()
    chain.append(_act(chain, op="remove", kind="primary-phone", pubkey=other_pub, algorithm="ecdsa-p256",
                      signers=[pp, rec], sealed_id=SEALED_ID))
    with pytest.raises(ChainError, match="not that member's own"):
        replay(chain)


def test_operator_rotation_is_recorded_and_the_latest_key_is_the_chains(chain2):
    chain, pp, rec = _sealed(chain2)
    k1, k2 = _secp256k1_pub(), _secp256k1_pub()
    chain.append(_act(chain, op="rotate-operator", kind="operator", pubkey=k1, algorithm="none",
                      signers=[pp, rec], sealed_id=SEALED_ID))
    chain.append(_act(chain, op="rotate-operator", kind="operator", pubkey=k2, algorithm="none",
                      signers=[rec, pp], sealed_id=SEALED_ID))
    st = replay_state(chain)
    assert st.operator_pubkey == k2 and st.sealed_id == SEALED_ID


def test_operator_rotation_without_the_passphrase_is_refused(chain2):
    chain, _, rec = _sealed(chain2)
    chain.append(_act(chain, op="rotate-operator", kind="operator", pubkey=_secp256k1_pub(), algorithm="none",
                      signers=[rec], sealed_id=SEALED_ID))
    with pytest.raises(ChainError, match="no valid passphrase signature"):
        replay(chain)


def _reset_meta(intent_id="intent-1", challenge=None):
    return canonical_meta({"intent_id": intent_id, "slot": "recovery", "lost": ["pk_x"],
                           "not_before": 1800000000,
                           "challenge": challenge or f"recto-reset-v1:{intent_id}:nonce-1"})


def test_a_reset_seats_the_fresh_device_under_the_passphrase_and_its_own_key(chain2):
    chain, pp, _ = _sealed(chain2)
    fresh_pub, fresh = _p256()
    meta = _reset_meta()
    challenge = json_challenge(meta)
    chain.append(_act(chain, op="reset", kind="recovery-phone", pubkey=fresh_pub, algorithm="ecdsa-p256",
                      signers=[pp], sealed_id=SEALED_ID, meta=meta, extra_sigs=[fresh(challenge)]))
    st = replay_state(chain)
    assert st.members["recovery-phone"].pubkey == fresh_pub and st.resets == ("intent-1",)


def test_a_reset_without_the_fresh_keys_signature_is_refused(chain2):
    chain, pp, rec = _sealed(chain2)
    fresh_pub, _ = _p256()
    chain.append(_act(chain, op="reset", kind="recovery-phone", pubkey=fresh_pub, algorithm="ecdsa-p256",
                      signers=[pp, rec], sealed_id=SEALED_ID, meta=_reset_meta()))
    with pytest.raises(ChainError, match="fresh device did not sign"):
        replay(chain)


def test_a_reset_without_the_passphrase_is_refused(chain2):
    chain, _, rec = _sealed(chain2)
    fresh_pub, fresh = _p256()
    meta = _reset_meta()
    chain.append(_act(chain, op="reset", kind="recovery-phone", pubkey=fresh_pub, algorithm="ecdsa-p256",
                      signers=[rec], sealed_id=SEALED_ID, meta=meta, extra_sigs=[fresh(json_challenge(meta))]))
    with pytest.raises(ChainError, match="no valid passphrase signature"):
        replay(chain)


def test_a_reset_whose_challenge_is_not_its_intents_is_refused(chain2):
    chain, pp, _ = _sealed(chain2)
    fresh_pub, fresh = _p256()
    meta = _reset_meta(challenge="recto-reset-v1:another-intent:nonce")
    chain.append(_act(chain, op="reset", kind="recovery-phone", pubkey=fresh_pub, algorithm="ecdsa-p256",
                      signers=[pp], sealed_id=SEALED_ID, meta=meta, extra_sigs=[fresh(json_challenge(meta))]))
    with pytest.raises(ChainError, match="not bound to its intent"):
        replay(chain)


def test_a_reset_before_the_seal_is_refused(chain2):
    chain, pp, _ = chain2
    fresh_pub, fresh = _p256()
    meta = _reset_meta()
    chain.append(_act(chain, op="reset", kind="recovery-phone", pubkey=fresh_pub, algorithm="ecdsa-p256",
                      signers=[pp], sealed_id=None, meta=meta, extra_sigs=[fresh(json_challenge(meta))]))
    with pytest.raises(ChainError, match="only after the bootloader id is sealed"):
        replay(chain)


def json_challenge(meta: str) -> bytes:
    import json as _json
    return _json.loads(meta)["challenge"].encode("ascii")


def test_a_rotation_whose_value_is_not_a_secp256k1_point_is_refused(chain2):
    chain, pp, rec = _sealed(chain2)
    for bad in (bytes(33), bytes([0x11]) * 64):
        with pytest.raises(ChainError, match="not a secp256k1 point"):
            _act(chain, op="rotate-operator", kind="operator", pubkey=bad, algorithm="none",
                 signers=[pp, rec], sealed_id=SEALED_ID)


def test_a_device_key_that_does_not_fit_its_algorithm_is_refused(chain2):
    """An Ed25519 key labelled ecdsa-p256 is a member that can never sign."""
    chain, pp, rec = chain2
    ed_pub, _ = _ed25519()
    with pytest.raises(ChainError, match="pubkey"):
        _entry(chain, op="add", kind="primary-phone", pubkey=ed_pub, algorithm="ecdsa-p256", signers=[pp, rec])


def test_a_reset_whose_slot_is_not_its_kinds_breaks_the_replay(chain2):
    chain, pp, _ = _sealed(chain2)
    fresh_pub, fresh = _p256()
    meta = _reset_meta()  # slot "recovery"
    chain.append(_act(chain, op="reset", kind="primary-phone", pubkey=fresh_pub, algorithm="ecdsa-p256",
                      signers=[pp], sealed_id=SEALED_ID, meta=meta, extra_sigs=[fresh(json_challenge(meta))]))
    with pytest.raises(ChainError, match="is not the slot of"):
        replay(chain)


def test_a_reset_intent_completes_once(chain2):
    chain, pp, _ = _sealed(chain2)
    for _ in range(2):
        fresh_pub, fresh = _p256()
        meta = _reset_meta()
        chain.append(_act(chain, op="reset", kind="recovery-phone", pubkey=fresh_pub, algorithm="ecdsa-p256",
                          signers=[pp], sealed_id=SEALED_ID, meta=meta, extra_sigs=[fresh(json_challenge(meta))]))
    with pytest.raises(ChainError, match="already seated"):
        replay(chain)


def test_a_removal_under_the_members_key_but_another_algorithm_refuses_on_replay(chain2):
    chain, pp, rec = _sealed(chain2)
    pri_pub, _ = _p256()
    chain.append(_act(chain, op="add", kind="primary-phone", pubkey=pri_pub, algorithm="ecdsa-p256",
                      signers=[pp, rec], sealed_id=SEALED_ID))
    chain.append(_act(chain, op="remove", kind="primary-phone", pubkey=pri_pub, algorithm="ed25519",
                      signers=[pp, rec], sealed_id=SEALED_ID))
    with pytest.raises(ChainError, match="not that member's own"):
        replay(chain)


def test_a_seal_whose_operator_key_is_not_a_point_refuses_on_replay(chain2):
    chain, pp, rec = chain2
    meta = canonical_meta({"nonce": "n" * 32, "not_after": 1800000000, "operator_pubkey": (bytes([0x11]) * 64).hex(),
                           "identity_members": []})
    chain.append(_act(chain, op="seal-id", kind="bootloader-id", pubkey=SEALED_ID.encode(), algorithm="none",
                      signers=[pp, rec], sealed_id=SEALED_ID, meta=meta))
    with pytest.raises(ChainError, match="not a secp256k1 point"):
        replay(chain)


@pytest.mark.parametrize("members", [None, "not-a-list", ["zz-not-hex"], {"ab": 1}, "", [12]])
def test_a_seal_without_well_formed_identity_members_refuses_on_replay(chain2, members):
    chain, pp, rec = chain2
    meta = {"nonce": "n" * 32, "not_after": 1800000000, "operator_pubkey": SEAL_OPERATOR.hex()}
    if members is not None:
        meta["identity_members"] = members
    chain.append(_act(chain, op="seal-id", kind="bootloader-id", pubkey=SEALED_ID.encode(), algorithm="none",
                      signers=[pp, rec], sealed_id=SEALED_ID, meta=canonical_meta(meta)))
    with pytest.raises(ChainError, match="identity members"):
        replay(chain)
