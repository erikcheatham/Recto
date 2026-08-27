"""GATE 5c-c: the genesis store learns which curve a member was sealed on.

WHAT THIS IS PROTECTING. The store used to hardcode "32 bytes, raw Ed25519".
That was true of the PASSPHRASE member and of nothing else, so a P-256
RECOVERY device could not be sealed at all. The tag is added now, while ONE
member exists, on the same reasoning that governed every other decision in
this gate: cheap while the set is small, expensive once a second member
depends on it.

THE TEST THAT MATTERS IS `test_a_member_sealed_BEFORE_the_tag_existed_still_loads`.
The passphrase member is ALREADY SEALED, in the untagged format, in a vault
whose entire purpose is that it cannot be re-created. A reader that only
understood the new shape would orphan it -- the same failure the derivation
pin test prevents, arriving through the storage layer instead.

THE POSITIVE CONTROL IS `test_seal_and_read_back_an_ed25519_member`: most of
what follows asserts a REFUSAL, and a store that refused everything would
satisfy those without storing anything.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from recto.bootloader.state import (
    GENESIS_ALGORITHMS,
    GENESIS_LEGACY_ALGORITHM,
    GenesisMember,
    StateStore,
    validate_genesis_pubkey,
)

def _real_ed25519() -> bytes:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return Ed25519PrivateKey.generate().public_key().public_bytes_raw()


def _real_p256() -> bytes:
    from cryptography.hazmat.primitives.asymmetric import ec

    n = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
    return n.x.to_bytes(32, "big") + n.y.to_bytes(32, "big")


# REAL KEYS, NOT BYTE PATTERNS -- and that is not fussiness. The store now
# loads every key through the verifier's decoder, so `bytes(range(1, 65))` is
# correctly REFUSED: it is 64 bytes and it is not a point on P-256. Using a
# pattern here would have tested the length check and nothing else.
ED = _real_ed25519()
P256 = _real_p256()
NOT_ON_CURVE = bytes(range(1, 65))  # right length, not a curve point


@pytest.fixture
def store(tmp_path):
    return StateStore(state_dir=pathlib.Path(tmp_path))


def _members_file(tmp_path) -> pathlib.Path:
    return pathlib.Path(tmp_path) / "genesis_members.json"


# ---------------------------------------------------------------------------
# THE POSITIVE CONTROL
# ---------------------------------------------------------------------------

def test_seal_and_read_back_an_ed25519_member(store):
    store.put_genesis_member("passphrase", ED, "ed25519")
    assert store.get_genesis_member("passphrase") == ED
    assert store.get_genesis_member_algorithm("passphrase") == "ed25519"
    full = store.list_genesis_members_full()["passphrase"]
    assert isinstance(full, GenesisMember)
    assert (full.kind, full.pubkey, full.algorithm) == ("passphrase", ED, "ed25519")


# ---------------------------------------------------------------------------
# THE ORPHAN GUARD
# ---------------------------------------------------------------------------

def test_a_member_sealed_BEFORE_the_tag_existed_still_loads(store, tmp_path):
    """**THE ONE THAT WOULD BE UNRECOVERABLE IF IT REGRESSED.**

    Writes the EXACT on-disk shape the old writer produced -- `kind -> hex
    string`, no algorithm anywhere -- and asserts it still reads. This is the
    format the live passphrase member is sealed in right now.
    """
    _members_file(tmp_path).write_text(
        json.dumps({"members": {"passphrase": ED.hex()}, "stored_at_unix": 1}),
        encoding="utf-8",
    )
    assert store.get_genesis_member("passphrase") == ED, "THE SEALED MEMBER WAS ORPHANED"
    assert store.get_genesis_member_algorithm("passphrase") == GENESIS_LEGACY_ALGORITHM


def test_legacy_and_tagged_members_coexist_in_one_file(store, tmp_path):
    """The state after enrolling a second member onto a vault sealed earlier."""
    _members_file(tmp_path).write_text(
        json.dumps({"members": {"passphrase": ED.hex()}, "stored_at_unix": 1}),
        encoding="utf-8",
    )
    store.put_genesis_member("recovery", P256, "ecdsa-p256")

    full = store.list_genesis_members_full()
    assert full["passphrase"].algorithm == "ed25519"
    assert full["passphrase"].pubkey == ED, "enrolling a second member moved the first"
    assert full["recovery"].algorithm == "ecdsa-p256"


def test_the_default_algorithm_keeps_the_existing_cli_call_working(store):
    """`cli.py` calls `put_genesis_member(kind, pubkey)` with two arguments.
    That call must keep meaning exactly what it meant before."""
    store.put_genesis_member("passphrase", ED)
    assert store.get_genesis_member_algorithm("passphrase") == "ed25519"


# ---------------------------------------------------------------------------
# THE POINT OF THE CHANGE: A NON-ED25519 MEMBER CAN NOW BE SEALED
# ---------------------------------------------------------------------------

def test_a_p256_member_seals(store):
    store.put_genesis_member("recovery", P256, "ecdsa-p256")
    assert store.get_genesis_member("recovery") == P256
    assert store.get_genesis_member_algorithm("recovery") == "ecdsa-p256"


def test_secp256k1_is_not_a_genesis_algorithm_at_all(store):
    """**THE ENTRY THAT WAS HERE, AND WHY IT LEFT.**

    secp256k1 was registered because the operator ROOT was assumed to be a
    tier-3 signer. The operator ruled on 2026-08-19 that it is not -- the set
    is the recovery phone and the passphrase, and the master key stays in
    custody rather than signing challenges online.

    A key with no signer is a verb with no caller. It also freed the store of
    a genuine hazard: `ecdsa-p256` is ALSO 64 raw bytes, so registering both
    would have put two different curves on one length. Not having the
    collision beats guarding it.
    """
    with pytest.raises(ValueError, match="unknown genesis member algorithm"):
        store.put_genesis_member("root", P256, "secp256k1")


def test_the_stored_bytes_are_never_re_encoded(store):
    """A store that normalises key material is a store that can change a
    pubkey. In byte for byte, out byte for byte."""
    store.put_genesis_member("recovery", P256, "ecdsa-p256")
    assert store.get_genesis_member("recovery") == P256
    assert len(store.get_genesis_member("recovery")) == 64


# ---------------------------------------------------------------------------
# REFUSALS
# ---------------------------------------------------------------------------

def test_an_ed25519_length_under_p256_is_refused(store):
    with pytest.raises(ValueError, match="64 bytes"):
        store.put_genesis_member("recovery", ED, "ecdsa-p256")


def test_a_p256_length_under_ed25519_is_refused(store):
    with pytest.raises(ValueError, match="32 bytes"):
        store.put_genesis_member("recovery", P256, "ed25519")


def test_an_unknown_algorithm_is_refused(store):
    with pytest.raises(ValueError, match="unknown genesis member algorithm"):
        store.put_genesis_member("recovery", ED, "ed448")


def test_a_refused_seal_writes_nothing(store, tmp_path):
    with pytest.raises(ValueError):
        store.put_genesis_member("recovery", ED, "ecdsa-p256")
    assert store.list_genesis_members() == {}
    assert not _members_file(tmp_path).exists()


@pytest.mark.parametrize("bad", ["", "  ", "has space", "sym!bol"])
def test_a_bad_kind_is_refused(store, bad):
    with pytest.raises(ValueError, match="alphanumeric"):
        store.put_genesis_member(bad, ED, "ed25519")


# ---------------------------------------------------------------------------
# CORRUPTION IS DROPPED, NEVER REPAIRED
# ---------------------------------------------------------------------------

def test_a_row_whose_length_contradicts_its_algorithm_is_DROPPED(store, tmp_path):
    """Repairing it would mean guessing which of the two fields is true, and a
    silently corrected member verifies against a key nobody chose."""
    _members_file(tmp_path).write_text(
        json.dumps({"members": {
            "good": {"pubkey": ED.hex(), "algorithm": "ed25519"},
            "liar": {"pubkey": ED.hex(), "algorithm": "ecdsa-p256"},
        }}),
        encoding="utf-8",
    )
    full = store.list_genesis_members_full()
    assert "good" in full
    assert "liar" not in full, "a contradictory member was repaired instead of dropped"


def test_garbage_entries_do_not_take_down_the_readable_ones(store, tmp_path):
    _members_file(tmp_path).write_text(
        json.dumps({"members": {
            "good": {"pubkey": ED.hex(), "algorithm": "ed25519"},
            "nothex": "zzzz",
            "wrongtype": 42,
            "nopubkey": {"algorithm": "ed25519"},
        }}),
        encoding="utf-8",
    )
    assert set(store.list_genesis_members_full()) == {"good"}


def test_an_unreadable_file_reads_as_empty_not_as_an_exception(store, tmp_path):
    _members_file(tmp_path).write_text("{not json", encoding="utf-8")
    assert store.list_genesis_members() == {}


# ---------------------------------------------------------------------------
# SHAPE + BACK-COMPAT
# ---------------------------------------------------------------------------

def test_list_genesis_members_still_returns_bytes(store):
    """Its return type was NOT widened -- callers keep working."""
    store.put_genesis_member("passphrase", ED, "ed25519")
    out = store.list_genesis_members()
    assert out == {"passphrase": ED}
    assert all(isinstance(v, bytes) for v in out.values())


def test_resealing_the_same_kind_replaces_key_and_algorithm(store):
    store.put_genesis_member("m", ED, "ed25519")
    store.put_genesis_member("m", P256, "ecdsa-p256")
    assert store.get_genesis_member("m") == P256
    assert store.get_genesis_member_algorithm("m") == "ecdsa-p256"


def test_missing_kinds_return_none_not_an_error(store):
    assert store.get_genesis_member("nope") is None
    assert store.get_genesis_member_algorithm("nope") is None


def test_the_algorithm_registry_is_explicit_about_lengths():
    """No length is shared between algorithms, so nothing here could be
    inferred from a key's size even if someone tried."""
    assert GENESIS_ALGORITHMS["ed25519"] == (32,)
    all_lengths = [n for lens in GENESIS_ALGORITHMS.values() for n in lens]
    assert len(all_lengths) == len(set(all_lengths)), "two algorithms share a length"


def test_the_registry_matches_WHAT_THE_VERIFIER_CAN_READ():
    """**THE CROSS-CHECK THAT WOULD HAVE CAUGHT THE SHIPPED BUG.**

    The test above only proves the registry is consistent WITH ITSELF -- it
    would pass just as happily on wrong numbers, and on 2026-08-19 it did: the
    registry carried SEC1's 33/65 for an hour because the expected value was
    the same literal as the code. **A test whose expectation restates the code
    is a copy, not a check.**

    This one ties the store to the thing that has to READ what it seals. A
    member sealed under an algorithm the verifier cannot handle is discovered
    at recovery and nowhere earlier, so these two lists -- in two different
    files -- must be the same list.
    """
    from recto.bootloader.sessions import SUPPORTED_ALGORITHMS

    assert set(GENESIS_ALGORITHMS) == set(SUPPORTED_ALGORITHMS), (
        f"store can seal {sorted(GENESIS_ALGORITHMS)} but the verifier reads "
        f"{sorted(SUPPORTED_ALGORITHMS)}"
    )


def test_a_right_length_key_that_is_NOT_ON_THE_CURVE_is_refused():
    """**THE GAP A LENGTH CHECK LEAVES, AND WHY THE STORE NOW CALLS THE
    VERIFIER.**

    `bytes(range(1, 65))` is exactly 64 bytes and is not a point on P-256. It
    passed every length check this file had, and `_public_key_from_b64u`
    refuses it -- so the store would have sealed a member that can never sign,
    and the operator would have discovered that at recovery.

    Sealable and verifiable are now ONE check rather than two lists that have
    to agree, which is the only version of this that cannot drift.
    """
    with pytest.raises(ValueError, match="not a usable ecdsa-p256 key"):
        validate_genesis_pubkey(NOT_ON_CURVE, "ecdsa-p256")


def test_the_store_refuses_to_seal_an_off_curve_key(store):
    with pytest.raises(ValueError, match="not a usable"):
        store.put_genesis_member("recovery", NOT_ON_CURVE, "ecdsa-p256")
    assert store.list_genesis_members() == {}


def test_a_real_p256_key_is_the_length_the_store_accepts():
    """End-to-end against a genuine curve point, not a byte pattern."""
    from cryptography.hazmat.primitives.asymmetric import ec

    nums = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
    xy = nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")
    assert validate_genesis_pubkey(xy, "ecdsa-p256") == "ecdsa-p256"


def test_validate_returns_the_normalised_algorithm():
    assert validate_genesis_pubkey(ED, "  ED25519 ") == "ed25519"
