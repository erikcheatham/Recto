"""
Tests for PendingRequest.new_profile_create + ProfileCreateResult +
StateStore methods (Phase 2.0.B integration — state.py extension only).

This module covers the state-layer extension. The server-side endpoint
+ respond handler + CLI integration + fake_phone end-to-end smoke land
in tests/test_bootloader_profile_create.py in a follow-on commit.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from recto.bootloader.state import (
    PendingRequest,
    ProfileCreateResult,
    StateStore,
)


# A canonical valid payload_hash_b64u (matches the existing
# bootloader test conventions — 32 raw bytes -> 43 base64url chars
# without padding).
TEST_PAYLOAD_HASH_B64U = "A" * 43


def _valid_new_profile_create_kwargs(**overrides) -> dict:
    """Build a kwargs dict for new_profile_create with all required
    fields filled in. Tests override individual fields to exercise
    validation paths."""
    base = {
        "service": "test-service",
        "secret": "test-secret",
        "phone_id": "phone-fixed-1",
        "operation_description": "Create child profile 'Work'",
        "payload_hash_b64u": TEST_PAYLOAD_HASH_B64U,
        "child_pid": 1234,
        "child_argv0": "python.exe",
        "candidate_profile_id": "profile-fixed-1",
        "candidate_kind": "work",
        "candidate_display_name": "Work — Acme",
        "candidate_derivation_purpose": 0x72656374,
        "candidate_derivation_coin_type": 2,
        "candidate_derivation_index": 0,
    }
    base.update(overrides)
    return base


class TestNewProfileCreateHappyPath:
    def test_constructs_with_all_required_fields(self):
        req = PendingRequest.new_profile_create(
            **_valid_new_profile_create_kwargs()
        )
        assert req.kind == "profile_create"
        assert req.candidate_profile_id == "profile-fixed-1"
        assert req.candidate_kind == "work"
        assert req.candidate_display_name == "Work — Acme"
        assert req.candidate_derivation_purpose == 0x72656374
        assert req.candidate_derivation_coin_type == 2
        assert req.candidate_derivation_index == 0
        assert req.candidate_theme_hint is None
        assert req.candidate_scim_provider is None
        assert req.payload_hash_b64u == TEST_PAYLOAD_HASH_B64U

    def test_optional_metadata_fields_pass_through(self):
        req = PendingRequest.new_profile_create(
            **_valid_new_profile_create_kwargs(
                candidate_theme_hint="blue",
                candidate_scim_provider="azure-ad:tenant-id",
            )
        )
        assert req.candidate_theme_hint == "blue"
        assert req.candidate_scim_provider == "azure-ad:tenant-id"

    def test_default_ttl_is_600_seconds(self):
        before = int(time.time())
        req = PendingRequest.new_profile_create(
            **_valid_new_profile_create_kwargs()
        )
        elapsed = req.expires_at_unix - req.requested_at_unix
        assert elapsed == 600

    def test_custom_ttl_honored(self):
        req = PendingRequest.new_profile_create(
            **_valid_new_profile_create_kwargs(ttl_seconds=1200)
        )
        elapsed = req.expires_at_unix - req.requested_at_unix
        assert elapsed == 1200

    def test_display_name_stripped(self):
        req = PendingRequest.new_profile_create(
            **_valid_new_profile_create_kwargs(
                candidate_display_name="  Work — Acme  "
            )
        )
        assert req.candidate_display_name == "Work — Acme"

    def test_request_id_is_uuid_per_call(self):
        r1 = PendingRequest.new_profile_create(
            **_valid_new_profile_create_kwargs()
        )
        r2 = PendingRequest.new_profile_create(
            **_valid_new_profile_create_kwargs()
        )
        assert r1.request_id != r2.request_id


class TestNewProfileCreateValidation:
    def test_rejects_empty_candidate_profile_id(self):
        with pytest.raises(ValueError, match="candidate_profile_id"):
            PendingRequest.new_profile_create(
                **_valid_new_profile_create_kwargs(candidate_profile_id="")
            )

    def test_rejects_empty_candidate_kind(self):
        with pytest.raises(ValueError, match="candidate_kind"):
            PendingRequest.new_profile_create(
                **_valid_new_profile_create_kwargs(candidate_kind="")
            )

    def test_rejects_empty_candidate_display_name(self):
        with pytest.raises(ValueError, match="candidate_display_name"):
            PendingRequest.new_profile_create(
                **_valid_new_profile_create_kwargs(candidate_display_name="")
            )
        with pytest.raises(ValueError, match="candidate_display_name"):
            PendingRequest.new_profile_create(
                **_valid_new_profile_create_kwargs(
                    candidate_display_name="   "
                )
            )

    def test_rejects_negative_derivation_purpose(self):
        with pytest.raises(ValueError, match="candidate_derivation_purpose"):
            PendingRequest.new_profile_create(
                **_valid_new_profile_create_kwargs(
                    candidate_derivation_purpose=-1
                )
            )

    def test_rejects_negative_coin_type(self):
        with pytest.raises(ValueError, match="candidate_derivation_coin_type"):
            PendingRequest.new_profile_create(
                **_valid_new_profile_create_kwargs(
                    candidate_derivation_coin_type=-1
                )
            )

    def test_rejects_negative_index(self):
        with pytest.raises(ValueError, match="candidate_derivation_index"):
            PendingRequest.new_profile_create(
                **_valid_new_profile_create_kwargs(
                    candidate_derivation_index=-1
                )
            )

    def test_rejects_empty_payload_hash(self):
        with pytest.raises(ValueError, match="payload_hash_b64u"):
            PendingRequest.new_profile_create(
                **_valid_new_profile_create_kwargs(payload_hash_b64u="")
            )


class TestProfileCreateResultDataclass:
    def test_constructs_approved_result(self):
        result = ProfileCreateResult(
            request_id="req-1",
            status="approved",
            profile_id="profile-new-1",
            reason=None,
            resolved_at_unix=1000,
            expires_at_unix=2000,
        )
        assert result.status == "approved"
        assert result.profile_id == "profile-new-1"
        assert result.reason is None

    def test_constructs_denied_result(self):
        result = ProfileCreateResult(
            request_id="req-2",
            status="denied",
            profile_id=None,
            reason="operator rejected: wrong kind",
            resolved_at_unix=1000,
            expires_at_unix=2000,
        )
        assert result.status == "denied"
        assert result.profile_id is None
        assert "wrong kind" in result.reason

    def test_constructs_signature_error_result(self):
        result = ProfileCreateResult(
            request_id="req-3",
            status="signature_error",
            profile_id=None,
            reason="attestation signature did not verify against operator pubkey",
            resolved_at_unix=1000,
            expires_at_unix=2000,
        )
        assert result.status == "signature_error"
        assert result.profile_id is None
        assert "signature" in result.reason

    def test_is_expired_returns_false_when_in_future(self):
        future = int(time.time()) + 1000
        result = ProfileCreateResult(
            request_id="req-4",
            status="approved",
            profile_id="p1",
            reason=None,
            resolved_at_unix=int(time.time()),
            expires_at_unix=future,
        )
        assert not result.is_expired

    def test_is_expired_returns_true_when_past(self):
        past = int(time.time()) - 1000
        result = ProfileCreateResult(
            request_id="req-5",
            status="approved",
            profile_id="p1",
            reason=None,
            resolved_at_unix=int(time.time()) - 2000,
            expires_at_unix=past,
        )
        assert result.is_expired


class TestStateStoreProfileCreateResultMethods:
    def test_put_get_round_trip(self, tmp_path):
        store = StateStore(state_dir=tmp_path)
        result = ProfileCreateResult(
            request_id="req-rt",
            status="approved",
            profile_id="profile-rt",
            reason=None,
            resolved_at_unix=int(time.time()),
            expires_at_unix=int(time.time()) + 600,
        )
        store.put_profile_create_result(result)

        fetched = store.get_profile_create_result("req-rt")
        assert fetched is not None
        assert fetched.profile_id == "profile-rt"
        assert fetched.status == "approved"

    def test_get_returns_none_for_unknown(self, tmp_path):
        store = StateStore(state_dir=tmp_path)
        assert store.get_profile_create_result("never-existed") is None

    def test_take_is_single_use(self, tmp_path):
        store = StateStore(state_dir=tmp_path)
        result = ProfileCreateResult(
            request_id="req-take",
            status="approved",
            profile_id="profile-take",
            reason=None,
            resolved_at_unix=int(time.time()),
            expires_at_unix=int(time.time()) + 600,
        )
        store.put_profile_create_result(result)

        first_take = store.take_profile_create_result("req-take")
        assert first_take is not None
        assert first_take.profile_id == "profile-take"

        # Second take returns None — single-use semantics
        second_take = store.take_profile_create_result("req-take")
        assert second_take is None

    def test_get_after_take_returns_none(self, tmp_path):
        store = StateStore(state_dir=tmp_path)
        result = ProfileCreateResult(
            request_id="req-gt",
            status="approved",
            profile_id="profile-gt",
            reason=None,
            resolved_at_unix=int(time.time()),
            expires_at_unix=int(time.time()) + 600,
        )
        store.put_profile_create_result(result)
        store.take_profile_create_result("req-gt")
        assert store.get_profile_create_result("req-gt") is None

    def test_expired_results_purged_on_read(self, tmp_path):
        store = StateStore(state_dir=tmp_path)
        # Store an already-expired result
        expired = ProfileCreateResult(
            request_id="req-expired",
            status="approved",
            profile_id="profile-expired",
            reason=None,
            resolved_at_unix=int(time.time()) - 1000,
            expires_at_unix=int(time.time()) - 500,  # 500s in past
        )
        store.put_profile_create_result(expired)

        # Add a fresh one — purge fires during the put
        fresh = ProfileCreateResult(
            request_id="req-fresh",
            status="approved",
            profile_id="profile-fresh",
            reason=None,
            resolved_at_unix=int(time.time()),
            expires_at_unix=int(time.time()) + 600,
        )
        store.put_profile_create_result(fresh)

        assert store.get_profile_create_result("req-expired") is None
        assert store.get_profile_create_result("req-fresh") is not None

    def test_profile_create_results_independent_of_capability_results(self, tmp_path):
        """Storing a profile_create_result with the same request_id as
        a capability_result should not collide — they live in separate
        dicts on the StateStore."""
        from recto.bootloader.state import CapabilityResult

        store = StateStore(state_dir=tmp_path)
        same_id = "shared-id"

        cap_result = CapabilityResult(
            request_id=same_id,
            status="approved",
            capability_jws="header.payload.sig",
            reason=None,
            agent_id="agent-1",
            resolved_at_unix=int(time.time()),
            expires_at_unix=int(time.time()) + 600,
        )
        store.put_capability_result(cap_result)

        prof_result = ProfileCreateResult(
            request_id=same_id,
            status="approved",
            profile_id="profile-shared",
            reason=None,
            resolved_at_unix=int(time.time()),
            expires_at_unix=int(time.time()) + 600,
        )
        store.put_profile_create_result(prof_result)

        # Both retrievable independently
        assert store.get_capability_result(same_id) is not None
        assert store.get_profile_create_result(same_id) is not None
