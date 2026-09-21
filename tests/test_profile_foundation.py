"""
Tests for the recto.profile foundation modules — Phase 2.0.B.

Scope:
  - recto.profile.store: atomic write + load + corruption tolerance
  - recto.profile.manage: bootstrap_master + create_child_profile +
    list_profiles + get_profile_by_id + mark_profile_revoked +
    next-index logic + idempotency

These tests do NOT depend on the bootloader being running. They exercise
the foundation layer in isolation. The bootloader-side integration
(profile_create PendingRequest + endpoint + capability JWT
parent_profile field) lands in a follow-on sprint with its own
end-to-end tests.

Cross-references: recto/profile/SPEC.md Phase 2.0.B; ARCHITECTURE.md
"Multi-profile identity" ADR (2026-05-15 entry).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from recto.profile.manage import (
    CUSTOM_COIN_TYPE_FLOOR,
    PROFILE_BIP32_PURPOSE,
    PROFILE_COIN_TYPES,
    MasterAlreadyBootstrappedError,
    _resolve_coin_type,
    bootstrap_master,
    create_child_profile,
    get_master_pubkey_hex,
    get_profile_by_id,
    list_profiles,
    mark_profile_revoked,
    profile_revoke_device,
)
from recto.profile.store import (
    load_master_identity,
    master_identity_path,
    save_master_identity,
)
from recto.profile.types import (
    PROFILE_KIND_CONTRACTOR,
    PROFILE_KIND_PERSONAL_CHILD,
    PROFILE_KIND_PERSONAL_MASTER,
    PROFILE_KIND_SCHOOL,
    PROFILE_KIND_WORK,
    MasterIdentity,
    Profile,
    ProfileDerivationPath,
)


# A canonical 128-hex test pubkey. Not a real key; just a fixed string
# for deterministic test assertions.
TEST_PUBKEY_HEX = (
    "02" * 32 + "03" * 32  # 64 bytes = 128 hex chars
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def state_dir(tmp_path: Path) -> Path:
    """Isolated state directory per test. Mirrors how bootloader tests
    use tmp_path for state isolation."""
    sd = tmp_path / "recto-state"
    sd.mkdir(mode=0o700)
    return sd


# ===========================================================================
# recto.profile.store tests
# ===========================================================================


class TestStorePathResolution:
    def test_master_identity_path_appends_correct_filename(self, state_dir):
        path = master_identity_path(state_dir=state_dir)
        assert path.name == "master_identity.json"
        assert path.parent == state_dir


class TestStoreLoadEmpty:
    def test_load_returns_none_when_no_file(self, state_dir):
        result = load_master_identity(state_dir=state_dir)
        assert result is None


class TestStoreSaveAndLoad:
    def test_round_trip_master_only(self, state_dir):
        master_profile = Profile(
            profile_id="master-id-fixed",
            kind=PROFILE_KIND_PERSONAL_MASTER,
            display_name="Master",
            derivation=ProfileDerivationPath(
                purpose=PROFILE_BIP32_PURPOSE,
                profile_coin_type=0,
                profile_index=0,
            ),
            parent_profile_id=None,
            created_at_unix=1000,
        )
        mi = MasterIdentity(
            master_pubkey_hex=TEST_PUBKEY_HEX,
            master_profile_id="master-id-fixed",
            profiles=(master_profile,),
            label="Erik's master",
        )

        path = save_master_identity(mi, state_dir=state_dir)
        assert path.exists()

        loaded = load_master_identity(state_dir=state_dir)
        assert loaded is not None
        assert loaded.master_pubkey_hex == TEST_PUBKEY_HEX
        assert loaded.master_profile_id == "master-id-fixed"
        assert loaded.label == "Erik's master"
        assert len(loaded.profiles) == 1
        assert loaded.profiles[0].profile_id == "master-id-fixed"
        assert loaded.profiles[0].kind == PROFILE_KIND_PERSONAL_MASTER

    def test_round_trip_with_children(self, state_dir):
        bootstrap_master(TEST_PUBKEY_HEX, state_dir=state_dir)
        create_child_profile(
            kind=PROFILE_KIND_WORK,
            display_name="Work — Acme",
            state_dir=state_dir,
            theme_hint="blue",
            scim_provider="azure-ad:test-tenant",
            deny_actions_inherited=("treasury:transfer",),
        )

        loaded = load_master_identity(state_dir=state_dir)
        assert loaded is not None
        assert len(loaded.profiles) == 2

        work = next(p for p in loaded.profiles if p.kind == PROFILE_KIND_WORK)
        assert work.display_name == "Work — Acme"
        assert work.theme_hint == "blue"
        assert work.scim_provider == "azure-ad:test-tenant"
        assert work.deny_actions_inherited == ("treasury:transfer",)
        assert work.parent_profile_id == loaded.master_profile_id

    def test_save_creates_state_dir_if_missing(self, tmp_path):
        # state_dir explicitly does NOT exist yet
        nonexistent = tmp_path / "fresh-state"
        assert not nonexistent.exists()

        master_profile = _minimal_master_profile()
        mi = MasterIdentity(
            master_pubkey_hex=TEST_PUBKEY_HEX,
            master_profile_id=master_profile.profile_id,
            profiles=(master_profile,),
        )
        save_master_identity(mi, state_dir=nonexistent)
        assert nonexistent.exists()
        assert (nonexistent / "master_identity.json").exists()

    @pytest.mark.skipif(os.name != "posix", reason="POSIX file-mode check")
    def test_save_sets_owner_only_permissions_on_posix(self, state_dir):
        master_profile = _minimal_master_profile()
        mi = MasterIdentity(
            master_pubkey_hex=TEST_PUBKEY_HEX,
            master_profile_id=master_profile.profile_id,
            profiles=(master_profile,),
        )
        path = save_master_identity(mi, state_dir=state_dir)
        mode = path.stat().st_mode & 0o777
        # Owner read+write, no group/other access
        assert mode == 0o600, f"expected 0o600, got {oct(mode)}"


class TestStoreCorruption:
    def test_load_returns_none_and_moves_aside_on_bad_json(self, state_dir):
        path = master_identity_path(state_dir=state_dir)
        path.write_bytes(b"not valid json{{{")

        result = load_master_identity(state_dir=state_dir)
        assert result is None
        # Original file moved aside
        assert not path.exists()
        # A .corrupt-* sibling exists
        corrupts = list(state_dir.glob("master_identity.json.corrupt-*"))
        assert len(corrupts) == 1

    def test_load_returns_none_on_schema_violation(self, state_dir):
        path = master_identity_path(state_dir=state_dir)
        # Missing required master_pubkey_hex
        path.write_bytes(json.dumps({"profiles": []}).encode("utf-8"))

        result = load_master_identity(state_dir=state_dir)
        assert result is None

    def test_load_returns_none_when_pubkey_wrong_length(self, state_dir):
        path = master_identity_path(state_dir=state_dir)
        bad = {
            "schema_version": 1,
            "master_pubkey_hex": "abc",  # too short
            "master_profile_id": "mid",
            "profiles": [],
        }
        path.write_bytes(json.dumps(bad).encode("utf-8"))

        result = load_master_identity(state_dir=state_dir)
        assert result is None

    def test_load_returns_none_when_master_id_not_in_profiles(self, state_dir):
        path = master_identity_path(state_dir=state_dir)
        bad = {
            "schema_version": 1,
            "master_pubkey_hex": TEST_PUBKEY_HEX,
            "master_profile_id": "does-not-exist",
            "profiles": [
                {
                    "profile_id": "different-id",
                    "kind": PROFILE_KIND_PERSONAL_MASTER,
                    "display_name": "Master",
                    "derivation": {
                        "purpose": PROFILE_BIP32_PURPOSE,
                        "profile_coin_type": 0,
                        "profile_index": 0,
                    },
                },
            ],
        }
        path.write_bytes(json.dumps(bad).encode("utf-8"))

        result = load_master_identity(state_dir=state_dir)
        assert result is None


class TestStoreForwardCompat:
    def test_unknown_fields_in_blob_are_ignored(self, state_dir):
        path = master_identity_path(state_dir=state_dir)
        # Future schema_version=2 with an unknown field at root
        forward = {
            "schema_version": 2,
            "future_field": "ignore me",
            "master_pubkey_hex": TEST_PUBKEY_HEX,
            "master_profile_id": "mid",
            "profiles": [
                {
                    "profile_id": "mid",
                    "kind": PROFILE_KIND_PERSONAL_MASTER,
                    "display_name": "Master",
                    "derivation": {
                        "purpose": PROFILE_BIP32_PURPOSE,
                        "profile_coin_type": 0,
                        "profile_index": 0,
                    },
                    "another_future_field": "also ignore me",
                },
            ],
        }
        path.write_bytes(json.dumps(forward).encode("utf-8"))

        result = load_master_identity(state_dir=state_dir)
        assert result is not None
        assert result.master_pubkey_hex == TEST_PUBKEY_HEX
        assert len(result.profiles) == 1


# ===========================================================================
# recto.profile.manage tests
# ===========================================================================


class TestBootstrapMaster:
    def test_creates_master_identity_from_pubkey(self, state_dir):
        mi = bootstrap_master(TEST_PUBKEY_HEX, state_dir=state_dir)
        assert mi.master_pubkey_hex == TEST_PUBKEY_HEX
        assert len(mi.profiles) == 1
        assert mi.profiles[0].kind == PROFILE_KIND_PERSONAL_MASTER
        assert mi.profiles[0].profile_id == mi.master_profile_id
        assert mi.profiles[0].parent_profile_id is None
        assert mi.profiles[0].derivation.purpose == PROFILE_BIP32_PURPOSE
        assert mi.profiles[0].derivation.profile_index == 0

    def test_accepts_0x_prefix(self, state_dir):
        prefixed = "0x" + TEST_PUBKEY_HEX
        mi = bootstrap_master(prefixed, state_dir=state_dir)
        # Stored without the prefix
        assert mi.master_pubkey_hex == TEST_PUBKEY_HEX

    def test_accepts_sec1_uncompressed_prefix(self, state_dir):
        prefixed = "04" + TEST_PUBKEY_HEX
        mi = bootstrap_master(prefixed, state_dir=state_dir)
        # Stored without the SEC1 prefix
        assert mi.master_pubkey_hex == TEST_PUBKEY_HEX

    def test_accepts_uppercase_hex(self, state_dir):
        mi = bootstrap_master(TEST_PUBKEY_HEX.upper(), state_dir=state_dir)
        # Lowercased
        assert mi.master_pubkey_hex == TEST_PUBKEY_HEX

    def test_rejects_short_pubkey(self, state_dir):
        with pytest.raises(ValueError, match="128 hex chars"):
            bootstrap_master("abc", state_dir=state_dir)

    def test_rejects_non_hex_chars(self, state_dir):
        # 128 chars but with a 'g'
        bad = "g" + TEST_PUBKEY_HEX[1:]
        with pytest.raises(ValueError, match="non-hex"):
            bootstrap_master(bad, state_dir=state_dir)

    def test_refuses_overwrite_without_force(self, state_dir):
        bootstrap_master(TEST_PUBKEY_HEX, state_dir=state_dir)
        other = "ff" * 64
        with pytest.raises(MasterAlreadyBootstrappedError):
            bootstrap_master(other, state_dir=state_dir)

    def test_force_overwrites_existing(self, state_dir):
        bootstrap_master(TEST_PUBKEY_HEX, state_dir=state_dir)
        other = "ff" * 64
        mi = bootstrap_master(other, state_dir=state_dir, force=True)
        assert mi.master_pubkey_hex == other
        # Old master profile is GONE (rotation semantics — new tree)
        assert len(mi.profiles) == 1

    def test_label_defaults_to_display_name(self, state_dir):
        mi = bootstrap_master(
            TEST_PUBKEY_HEX,
            display_name="My Master",
            state_dir=state_dir,
        )
        assert mi.label == "My Master"

    def test_label_can_be_overridden(self, state_dir):
        mi = bootstrap_master(
            TEST_PUBKEY_HEX,
            display_name="Master",
            label="Erik (primary master)",
            state_dir=state_dir,
        )
        assert mi.label == "Erik (primary master)"


class TestCreateChildProfile:
    def test_creates_child_under_master(self, state_dir):
        bootstrap_master(TEST_PUBKEY_HEX, state_dir=state_dir)
        work = create_child_profile(
            kind=PROFILE_KIND_WORK,
            display_name="Work",
            state_dir=state_dir,
        )
        assert work.kind == PROFILE_KIND_WORK
        assert work.display_name == "Work"
        assert work.parent_profile_id is not None  # under master
        assert work.derivation.purpose == PROFILE_BIP32_PURPOSE
        assert work.derivation.profile_coin_type == PROFILE_COIN_TYPES[PROFILE_KIND_WORK]
        assert work.derivation.profile_index == 0  # first profile in work-slot

    def test_each_canonical_kind_uses_its_own_coin_type(self, state_dir):
        bootstrap_master(TEST_PUBKEY_HEX, state_dir=state_dir)
        pc = create_child_profile(
            kind=PROFILE_KIND_PERSONAL_CHILD,
            display_name="Pseudonym",
            state_dir=state_dir,
        )
        work = create_child_profile(
            kind=PROFILE_KIND_WORK,
            display_name="Work",
            state_dir=state_dir,
        )
        school = create_child_profile(
            kind=PROFILE_KIND_SCHOOL,
            display_name="School",
            state_dir=state_dir,
        )
        contractor = create_child_profile(
            kind=PROFILE_KIND_CONTRACTOR,
            display_name="Contractor",
            state_dir=state_dir,
        )
        assert pc.derivation.profile_coin_type == PROFILE_COIN_TYPES[PROFILE_KIND_PERSONAL_CHILD]
        assert work.derivation.profile_coin_type == PROFILE_COIN_TYPES[PROFILE_KIND_WORK]
        assert school.derivation.profile_coin_type == PROFILE_COIN_TYPES[PROFILE_KIND_SCHOOL]
        assert contractor.derivation.profile_coin_type == PROFILE_COIN_TYPES[PROFILE_KIND_CONTRACTOR]

    def test_custom_kind_uses_hashed_coin_type_above_floor(self, state_dir):
        bootstrap_master(TEST_PUBKEY_HEX, state_dir=state_dir)
        custom = create_child_profile(
            kind="custom:my-side-project",
            display_name="Side Project",
            state_dir=state_dir,
        )
        assert custom.derivation.profile_coin_type >= CUSTOM_COIN_TYPE_FLOOR

    def test_custom_kind_coin_type_is_deterministic(self):
        # Same kind string should always produce same coin_type
        ct1 = _resolve_coin_type("custom:foo")
        ct2 = _resolve_coin_type("custom:foo")
        assert ct1 == ct2

    def test_next_index_increments_within_same_coin_type(self, state_dir):
        bootstrap_master(TEST_PUBKEY_HEX, state_dir=state_dir)
        # Two work profiles
        w1 = create_child_profile(
            kind=PROFILE_KIND_WORK,
            display_name="Work Acme",
            state_dir=state_dir,
        )
        w2 = create_child_profile(
            kind=PROFILE_KIND_WORK,
            display_name="Work Beta",
            state_dir=state_dir,
        )
        assert w1.derivation.profile_index == 0
        assert w2.derivation.profile_index == 1

    def test_idempotent_on_same_kind_and_display_name(self, state_dir):
        bootstrap_master(TEST_PUBKEY_HEX, state_dir=state_dir)
        w1 = create_child_profile(
            kind=PROFILE_KIND_WORK,
            display_name="Work",
            state_dir=state_dir,
        )
        w2 = create_child_profile(
            kind=PROFILE_KIND_WORK,
            display_name="Work",
            state_dir=state_dir,
        )
        # Same profile, not a duplicate
        assert w1.profile_id == w2.profile_id
        mi = load_master_identity(state_dir=state_dir)
        assert len(mi.profiles) == 2  # master + one Work

    def test_different_display_name_makes_a_new_profile(self, state_dir):
        bootstrap_master(TEST_PUBKEY_HEX, state_dir=state_dir)
        w1 = create_child_profile(
            kind=PROFILE_KIND_WORK,
            display_name="Work Acme",
            state_dir=state_dir,
        )
        w2 = create_child_profile(
            kind=PROFILE_KIND_WORK,
            display_name="Work Beta",
            state_dir=state_dir,
        )
        assert w1.profile_id != w2.profile_id

    def test_rejects_master_kind(self, state_dir):
        bootstrap_master(TEST_PUBKEY_HEX, state_dir=state_dir)
        with pytest.raises(ValueError, match="bootstrap_master"):
            create_child_profile(
                kind=PROFILE_KIND_PERSONAL_MASTER,
                display_name="Another Master",
                state_dir=state_dir,
            )

    def test_rejects_empty_kind(self, state_dir):
        bootstrap_master(TEST_PUBKEY_HEX, state_dir=state_dir)
        with pytest.raises(ValueError):
            create_child_profile(
                kind="",
                display_name="Empty",
                state_dir=state_dir,
            )

    def test_rejects_empty_display_name(self, state_dir):
        bootstrap_master(TEST_PUBKEY_HEX, state_dir=state_dir)
        with pytest.raises(ValueError):
            create_child_profile(
                kind=PROFILE_KIND_WORK,
                display_name="",
                state_dir=state_dir,
            )
        with pytest.raises(ValueError):
            create_child_profile(
                kind=PROFILE_KIND_WORK,
                display_name="   ",
                state_dir=state_dir,
            )

    def test_raises_if_no_master_bootstrapped(self, state_dir):
        with pytest.raises(FileNotFoundError, match="bootstrap_master"):
            create_child_profile(
                kind=PROFILE_KIND_WORK,
                display_name="Work",
                state_dir=state_dir,
            )

    def test_profile_index_override(self, state_dir):
        bootstrap_master(TEST_PUBKEY_HEX, state_dir=state_dir)
        w = create_child_profile(
            kind=PROFILE_KIND_WORK,
            display_name="Work",
            state_dir=state_dir,
            profile_index_override=42,
        )
        assert w.derivation.profile_index == 42


class TestListAndGet:
    def test_list_returns_empty_when_no_master(self, state_dir):
        assert list_profiles(state_dir=state_dir) == []

    def test_list_returns_master_plus_children_ordered_by_creation(self, state_dir):
        mi = bootstrap_master(TEST_PUBKEY_HEX, state_dir=state_dir)
        c1 = create_child_profile(
            kind=PROFILE_KIND_WORK,
            display_name="Work",
            state_dir=state_dir,
        )
        c2 = create_child_profile(
            kind=PROFILE_KIND_SCHOOL,
            display_name="School",
            state_dir=state_dir,
        )

        profiles = list_profiles(state_dir=state_dir)
        # Order should be master, work, school (creation order)
        assert profiles[0].profile_id == mi.master_profile_id
        # Children may all share created_at_unix in fast tests; just
        # confirm both are present
        ids_after_master = {p.profile_id for p in profiles[1:]}
        assert {c1.profile_id, c2.profile_id} == ids_after_master

    def test_get_by_id_returns_match(self, state_dir):
        mi = bootstrap_master(TEST_PUBKEY_HEX, state_dir=state_dir)
        found = get_profile_by_id(mi.master_profile_id, state_dir=state_dir)
        assert found is not None
        assert found.profile_id == mi.master_profile_id

    def test_get_by_id_returns_none_on_no_match(self, state_dir):
        bootstrap_master(TEST_PUBKEY_HEX, state_dir=state_dir)
        assert get_profile_by_id("not-real", state_dir=state_dir) is None

    def test_get_by_id_returns_none_with_no_master(self, state_dir):
        assert get_profile_by_id("anything", state_dir=state_dir) is None

    def test_get_master_pubkey_hex_returns_pubkey_when_bootstrapped(self, state_dir):
        bootstrap_master(TEST_PUBKEY_HEX, state_dir=state_dir)
        assert get_master_pubkey_hex(state_dir=state_dir) == TEST_PUBKEY_HEX

    def test_get_master_pubkey_hex_returns_none_when_not_bootstrapped(self, state_dir):
        assert get_master_pubkey_hex(state_dir=state_dir) is None


class TestRevocation:
    def test_revoke_child_profile(self, state_dir):
        bootstrap_master(TEST_PUBKEY_HEX, state_dir=state_dir)
        w = create_child_profile(
            kind=PROFILE_KIND_WORK,
            display_name="Work",
            state_dir=state_dir,
        )
        assert not w.revoked

        revoked = mark_profile_revoked(w.profile_id, state_dir=state_dir)
        assert revoked.revoked
        assert revoked.profile_id == w.profile_id

        # Verify persisted
        loaded = get_profile_by_id(w.profile_id, state_dir=state_dir)
        assert loaded.revoked

    def test_revoke_raises_on_unknown_id(self, state_dir):
        bootstrap_master(TEST_PUBKEY_HEX, state_dir=state_dir)
        with pytest.raises(KeyError):
            mark_profile_revoked("not-real", state_dir=state_dir)

    def test_revoke_raises_with_no_master(self, state_dir):
        with pytest.raises(FileNotFoundError):
            mark_profile_revoked("anything", state_dir=state_dir)

    def test_refuses_to_revoke_master_while_children_exist(self, state_dir):
        mi = bootstrap_master(TEST_PUBKEY_HEX, state_dir=state_dir)
        create_child_profile(
            kind=PROFILE_KIND_WORK,
            display_name="Work",
            state_dir=state_dir,
        )
        with pytest.raises(ValueError, match="master-rotate"):
            mark_profile_revoked(mi.master_profile_id, state_dir=state_dir)

    def test_revoke_master_allowed_when_all_children_revoked(self, state_dir):
        mi = bootstrap_master(TEST_PUBKEY_HEX, state_dir=state_dir)
        w = create_child_profile(
            kind=PROFILE_KIND_WORK,
            display_name="Work",
            state_dir=state_dir,
        )
        mark_profile_revoked(w.profile_id, state_dir=state_dir)
        # Now all non-master profiles are revoked; revoking master OK
        revoked_master = mark_profile_revoked(
            mi.master_profile_id, state_dir=state_dir
        )
        assert revoked_master.revoked


# ===========================================================================
# Phase 2.0.C wave C.6 — revoke_quorum_k field + profile_revoke_device tests
# ===========================================================================


class TestRevokeQuorumK:
    """The revoke_quorum_k field on Profile + its serialization +
    its validation at create_child_profile time. Wave C.6 schema bump.
    """

    def test_default_value_is_one(self, state_dir):
        bootstrap_master(TEST_PUBKEY_HEX, state_dir=state_dir)
        p = create_child_profile(
            kind=PROFILE_KIND_PERSONAL_CHILD,
            display_name="Personal",
            state_dir=state_dir,
        )
        assert p.revoke_quorum_k == 1

    def test_custom_value_persists(self, state_dir):
        bootstrap_master(TEST_PUBKEY_HEX, state_dir=state_dir)
        p = create_child_profile(
            kind=PROFILE_KIND_WORK,
            display_name="Work",
            device_ids=("ph-1", "ph-2", "ph-3"),
            revoke_quorum_k=2,
            state_dir=state_dir,
        )
        assert p.revoke_quorum_k == 2
        # Verify round-trip via reload
        loaded = get_profile_by_id(p.profile_id, state_dir=state_dir)
        assert loaded.revoke_quorum_k == 2

    def test_rejected_when_zero(self, state_dir):
        bootstrap_master(TEST_PUBKEY_HEX, state_dir=state_dir)
        with pytest.raises(ValueError, match="revoke_quorum_k"):
            create_child_profile(
                kind=PROFILE_KIND_WORK,
                display_name="Work",
                revoke_quorum_k=0,
                state_dir=state_dir,
            )

    def test_rejected_when_negative(self, state_dir):
        bootstrap_master(TEST_PUBKEY_HEX, state_dir=state_dir)
        with pytest.raises(ValueError, match="revoke_quorum_k"):
            create_child_profile(
                kind=PROFILE_KIND_WORK,
                display_name="Work",
                revoke_quorum_k=-1,
                state_dir=state_dir,
            )

    def test_rejected_when_exceeds_device_ids(self, state_dir):
        """K=3 with only 2 devices is structurally impossible."""
        bootstrap_master(TEST_PUBKEY_HEX, state_dir=state_dir)
        with pytest.raises(ValueError, match="exceeds device_ids"):
            create_child_profile(
                kind=PROFILE_KIND_WORK,
                display_name="Work",
                device_ids=("ph-1", "ph-2"),
                revoke_quorum_k=3,
                state_dir=state_dir,
            )

    def test_allowed_when_equals_device_count(self, state_dir):
        """K=N (all devices must sign) is the upper bound."""
        bootstrap_master(TEST_PUBKEY_HEX, state_dir=state_dir)
        p = create_child_profile(
            kind=PROFILE_KIND_WORK,
            display_name="Work",
            device_ids=("ph-1", "ph-2"),
            revoke_quorum_k=2,
            state_dir=state_dir,
        )
        assert p.revoke_quorum_k == 2

    def test_empty_device_ids_skips_upper_bound_check(self, state_dir):
        """K is validated >=1 even when device_ids is empty (devices
        get added later via profile_add_device + the quorum must be
        satisfiable by then)."""
        bootstrap_master(TEST_PUBKEY_HEX, state_dir=state_dir)
        # K=5 with empty device_ids should succeed (no upper bound to check)
        p = create_child_profile(
            kind=PROFILE_KIND_WORK,
            display_name="Work",
            revoke_quorum_k=5,
            state_dir=state_dir,
        )
        assert p.revoke_quorum_k == 5

    def test_serializer_omits_when_default(self, state_dir):
        """Round-trip byte-compat: K=1 (default) is OMITTED from the
        on-disk JSON so v2.0.B / v2.0.C-pre-C.6 era rows stay
        identical."""
        bootstrap_master(TEST_PUBKEY_HEX, state_dir=state_dir)
        create_child_profile(
            kind=PROFILE_KIND_WORK,
            display_name="Work",
            state_dir=state_dir,
        )
        raw = json.loads(master_identity_path(state_dir=state_dir).read_text())
        work_dict = next(
            p for p in raw["profiles"]
            if p.get("kind") == PROFILE_KIND_WORK
        )
        assert "revoke_quorum_k" not in work_dict

    def test_serializer_emits_when_non_default(self, state_dir):
        bootstrap_master(TEST_PUBKEY_HEX, state_dir=state_dir)
        create_child_profile(
            kind=PROFILE_KIND_WORK,
            display_name="Work",
            device_ids=("ph-1", "ph-2"),
            revoke_quorum_k=2,
            state_dir=state_dir,
        )
        raw = json.loads(master_identity_path(state_dir=state_dir).read_text())
        work_dict = next(
            p for p in raw["profiles"]
            if p.get("kind") == PROFILE_KIND_WORK
        )
        assert work_dict["revoke_quorum_k"] == 2


class TestProfileRevokeDevice:
    """Storage-mutation primitive for the profile_revoke_device flow.
    Wave C.6 (v1 = K=1, K-of-N aggregation deferred to v1.1)."""

    def test_happy_path_removes_phone(self, state_dir):
        bootstrap_master(TEST_PUBKEY_HEX, state_dir=state_dir)
        p = create_child_profile(
            kind=PROFILE_KIND_WORK,
            display_name="Work",
            device_ids=("ph-master", "ph-laptop", "ph-pixel"),
            state_dir=state_dir,
        )
        assert "ph-laptop" in p.device_ids

        updated = profile_revoke_device(
            profile_id=p.profile_id,
            phone_id_to_revoke="ph-laptop",
            state_dir=state_dir,
        )
        assert "ph-laptop" not in updated.device_ids
        assert "ph-master" in updated.device_ids
        assert "ph-pixel" in updated.device_ids
        assert len(updated.device_ids) == 2

        # Verify persisted
        loaded = get_profile_by_id(p.profile_id, state_dir=state_dir)
        assert "ph-laptop" not in loaded.device_ids

    def test_idempotent_not_a_member(self, state_dir):
        """Revoking a phone that wasn't in device_ids returns the
        profile unchanged (no exception, no mutation)."""
        bootstrap_master(TEST_PUBKEY_HEX, state_dir=state_dir)
        p = create_child_profile(
            kind=PROFILE_KIND_WORK,
            display_name="Work",
            device_ids=("ph-master", "ph-laptop"),
            state_dir=state_dir,
        )
        before = tuple(p.device_ids)
        updated = profile_revoke_device(
            profile_id=p.profile_id,
            phone_id_to_revoke="ph-never-added",
            state_dir=state_dir,
        )
        assert tuple(updated.device_ids) == before

    def test_last_device_guard(self, state_dir):
        """Cannot revoke the only device — would make profile unreachable."""
        bootstrap_master(TEST_PUBKEY_HEX, state_dir=state_dir)
        p = create_child_profile(
            kind=PROFILE_KIND_WORK,
            display_name="Work",
            device_ids=("ph-only",),
            state_dir=state_dir,
        )
        with pytest.raises(ValueError, match="last device"):
            profile_revoke_device(
                profile_id=p.profile_id,
                phone_id_to_revoke="ph-only",
                state_dir=state_dir,
            )

    def test_revoked_profile_rejected(self, state_dir):
        """Profile-level revocation precludes device-set mutations."""
        bootstrap_master(TEST_PUBKEY_HEX, state_dir=state_dir)
        p = create_child_profile(
            kind=PROFILE_KIND_WORK,
            display_name="Work",
            device_ids=("ph-1", "ph-2"),
            state_dir=state_dir,
        )
        mark_profile_revoked(p.profile_id, state_dir=state_dir)
        with pytest.raises(ValueError, match="revoked profile"):
            profile_revoke_device(
                profile_id=p.profile_id,
                phone_id_to_revoke="ph-1",
                state_dir=state_dir,
            )

    def test_unknown_profile_raises_keyerror(self, state_dir):
        bootstrap_master(TEST_PUBKEY_HEX, state_dir=state_dir)
        with pytest.raises(KeyError):
            profile_revoke_device(
                profile_id="00000000-0000-0000-0000-000000000000",
                phone_id_to_revoke="ph-1",
                state_dir=state_dir,
            )

    def test_no_master_raises_filenotfound(self, state_dir):
        with pytest.raises(FileNotFoundError):
            profile_revoke_device(
                profile_id="anything",
                phone_id_to_revoke="ph-1",
                state_dir=state_dir,
            )

    def test_empty_profile_id_rejected(self, state_dir):
        bootstrap_master(TEST_PUBKEY_HEX, state_dir=state_dir)
        with pytest.raises(ValueError, match="profile_id"):
            profile_revoke_device(
                profile_id="",
                phone_id_to_revoke="ph-1",
                state_dir=state_dir,
            )

    def test_empty_phone_id_rejected(self, state_dir):
        bootstrap_master(TEST_PUBKEY_HEX, state_dir=state_dir)
        with pytest.raises(ValueError, match="phone_id_to_revoke"):
            profile_revoke_device(
                profile_id="p-target",
                phone_id_to_revoke="",
                state_dir=state_dir,
            )


# ===========================================================================
# Helpers
# ===========================================================================


def _minimal_master_profile() -> Profile:
    """Build a minimal valid master profile for tests that construct
    MasterIdentity directly (bypassing bootstrap_master)."""
    return Profile(
        profile_id="test-master-id",
        kind=PROFILE_KIND_PERSONAL_MASTER,
        display_name="Master",
        derivation=ProfileDerivationPath(
            purpose=PROFILE_BIP32_PURPOSE,
            profile_coin_type=0,
            profile_index=0,
        ),
        parent_profile_id=None,
        created_at_unix=1000,
    )
