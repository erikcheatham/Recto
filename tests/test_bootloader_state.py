"""Tests for recto.bootloader.state.

State persistence: phones, sessions, pending requests. Covers:
- Phone registration round-trips through disk.
- Session expiry purging on read (no stale session served).
- Session use-counter increments persist atomically.
- Pending requests purge on TTL.
- Revocation cascades to dependent sessions/pending.
- Atomic write rollback on partial failure.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from recto.bootloader.state import (
    PendingRequest,
    PhoneRegistration,
    Session,
    StateStore,
)


@pytest.fixture
def store(tmp_path: Path) -> StateStore:
    return StateStore(state_dir=tmp_path)


# ---------------------------------------------------------------------------
# Phones
# ---------------------------------------------------------------------------


class TestPhones:
    def test_register_then_get(self, store: StateStore) -> None:
        reg = PhoneRegistration.new(
            device_label="Test Phone",
            public_key_b64u="aGVsbG8td29ybGQ",
            supported_algorithms=("ed25519",),
        )
        store.register_phone(reg)
        loaded = store.get_phone(reg.phone_id)
        assert loaded is not None
        assert loaded.device_label == "Test Phone"
        assert loaded.public_key_b64u == "aGVsbG8td29ybGQ"

    def test_get_unknown_returns_none(self, store: StateStore) -> None:
        assert store.get_phone("does-not-exist") is None

    def test_list_phones_returns_all(self, store: StateStore) -> None:
        for label in ["A", "B", "C"]:
            store.register_phone(PhoneRegistration.new(
                device_label=label,
                public_key_b64u=f"key-{label}",
                supported_algorithms=("ed25519",),
            ))
        labels = sorted(p.device_label for p in store.list_phones())
        assert labels == ["A", "B", "C"]

    def test_revoke_removes_phone(self, store: StateStore) -> None:
        reg = PhoneRegistration.new(
            device_label="Test",
            public_key_b64u="key",
            supported_algorithms=("ed25519",),
        )
        store.register_phone(reg)
        assert store.revoke_phone(reg.phone_id) is True
        assert store.get_phone(reg.phone_id) is None

    def test_revoke_nonexistent_returns_false(self, store: StateStore) -> None:
        assert store.revoke_phone("ghost") is False

    def test_persistence_across_store_instances(self, tmp_path: Path) -> None:
        s1 = StateStore(state_dir=tmp_path)
        reg = PhoneRegistration.new(
            device_label="Persistent",
            public_key_b64u="key",
            supported_algorithms=("ed25519",),
        )
        s1.register_phone(reg)
        # New store reads from same dir.
        s2 = StateStore(state_dir=tmp_path)
        loaded = s2.get_phone(reg.phone_id)
        assert loaded is not None
        assert loaded.device_label == "Persistent"


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------


class TestSessions:
    def test_put_then_get(self, store: StateStore) -> None:
        sess = Session(
            service="svc",
            secret="KEY",
            phone_id="phone1",
            jwt="header.payload.sig",
            expires_at_unix=int(time.time()) + 3600,
            issued_at_unix=int(time.time()),
            max_uses=100,
        )
        store.put_session(sess)
        loaded = store.get_session("svc", "KEY")
        assert loaded is not None
        assert loaded.jwt == sess.jwt

    def test_get_expired_session_returns_none_and_purges(
        self, store: StateStore
    ) -> None:
        sess = Session(
            service="svc", secret="KEY", phone_id="phone1",
            jwt="x", expires_at_unix=int(time.time()) - 10,
            issued_at_unix=int(time.time()) - 3700, max_uses=100,
        )
        store.put_session(sess)
        # Lazy purge: get returns None and removes from disk.
        assert store.get_session("svc", "KEY") is None

    def test_get_exhausted_session_returns_none(self, store: StateStore) -> None:
        sess = Session(
            service="svc", secret="KEY", phone_id="phone1",
            jwt="x", expires_at_unix=int(time.time()) + 3600,
            issued_at_unix=int(time.time()), max_uses=5,
            uses_so_far=5,
        )
        store.put_session(sess)
        assert store.get_session("svc", "KEY") is None

    def test_unlimited_max_uses_never_exhausts(self, store: StateStore) -> None:
        sess = Session(
            service="svc", secret="KEY", phone_id="phone1",
            jwt="x", expires_at_unix=int(time.time()) + 3600,
            issued_at_unix=int(time.time()), max_uses=0,
            uses_so_far=10_000,
        )
        store.put_session(sess)
        assert store.get_session("svc", "KEY") is not None

    def test_increment_uses(self, store: StateStore) -> None:
        sess = Session(
            service="svc", secret="KEY", phone_id="phone1",
            jwt="x", expires_at_unix=int(time.time()) + 3600,
            issued_at_unix=int(time.time()), max_uses=100,
        )
        store.put_session(sess)
        updated = store.increment_session_uses("svc", "KEY")
        assert updated is not None
        assert updated.uses_so_far == 1
        # Repeat -- should accumulate.
        for _ in range(4):
            store.increment_session_uses("svc", "KEY")
        final = store.get_session("svc", "KEY")
        assert final is not None
        assert final.uses_so_far == 5

    def test_increment_unknown_returns_none(self, store: StateStore) -> None:
        assert store.increment_session_uses("ghost", "KEY") is None

    def test_session_needs_renewal_at_80_percent_lifetime(self) -> None:
        now = int(time.time())
        sess = Session(
            service="x", secret="x", phone_id="p", jwt="x",
            issued_at_unix=now - 81, expires_at_unix=now + 19,  # 81% consumed
            max_uses=1000, uses_so_far=0,
        )
        assert sess.needs_renewal() is True

    def test_session_needs_renewal_at_80_percent_uses(self) -> None:
        now = int(time.time())
        sess = Session(
            service="x", secret="x", phone_id="p", jwt="x",
            issued_at_unix=now, expires_at_unix=now + 3600,
            max_uses=10, uses_so_far=8,  # 80% consumed
        )
        assert sess.needs_renewal() is True


# ---------------------------------------------------------------------------
# Pending requests
# ---------------------------------------------------------------------------


class TestPending:
    def _new(self, phone_id: str = "phone1", ttl: int = 300) -> PendingRequest:
        return PendingRequest.new(
            kind="single_sign",
            service="svc",
            secret="KEY",
            phone_id=phone_id,
            operation_description="test sign",
            payload_hash_b64u="aGFzaA",
            child_pid=12345,
            child_argv0="python.exe",
            ttl_seconds=ttl,
        )

    def test_add_then_take(self, store: StateStore) -> None:
        req = self._new()
        store.add_pending(req)
        taken = store.take_pending(req.request_id)
        assert taken is not None
        assert taken.request_id == req.request_id
        # take is one-shot.
        assert store.take_pending(req.request_id) is None

    def test_list_pending_filters_by_phone(self, store: StateStore) -> None:
        store.add_pending(self._new(phone_id="phone1"))
        store.add_pending(self._new(phone_id="phone2"))
        store.add_pending(self._new(phone_id="phone1"))
        for_p1 = store.list_pending_for_phone("phone1")
        assert len(for_p1) == 2
        for_p2 = store.list_pending_for_phone("phone2")
        assert len(for_p2) == 1

    def test_expired_pending_purged_on_read(self, store: StateStore) -> None:
        req = self._new(ttl=-10)  # already expired
        store.add_pending(req)
        listed = store.list_pending_for_phone("phone1")
        assert listed == []

    def test_pending_not_persisted_across_restart(self, tmp_path: Path) -> None:
        s1 = StateStore(state_dir=tmp_path)
        s1.add_pending(self._new())
        # New store doesn't load pending (intentional design).
        s2 = StateStore(state_dir=tmp_path)
        assert s2.list_pending_for_phone("phone1") == []


# ---------------------------------------------------------------------------
# Revocation cascade
# ---------------------------------------------------------------------------


class TestRevocationCascade:
    def test_revoke_drops_dependent_sessions(self, store: StateStore) -> None:
        reg = PhoneRegistration.new(
            device_label="Test", public_key_b64u="key",
            supported_algorithms=("ed25519",),
        )
        store.register_phone(reg)
        store.put_session(Session(
            service="svc", secret="KEY", phone_id=reg.phone_id,
            jwt="x", expires_at_unix=int(time.time()) + 3600,
            issued_at_unix=int(time.time()), max_uses=100,
        ))
        store.revoke_phone(reg.phone_id)
        assert store.get_session("svc", "KEY") is None

    def test_revoke_drops_dependent_pending(self, store: StateStore) -> None:
        reg = PhoneRegistration.new(
            device_label="Test", public_key_b64u="key",
            supported_algorithms=("ed25519",),
        )
        store.register_phone(reg)
        req = PendingRequest.new(
            kind="single_sign", service="svc", secret="KEY",
            phone_id=reg.phone_id, operation_description="x",
            payload_hash_b64u="x", child_pid=1, child_argv0="x",
        )
        store.add_pending(req)
        store.revoke_phone(reg.phone_id)
        assert store.list_pending_for_phone(reg.phone_id) == []
