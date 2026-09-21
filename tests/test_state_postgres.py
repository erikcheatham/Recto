"""Contract tests for StateStoreBase backends -- file AND postgres.

One shared behavioral suite parametrized over both implementations:

- ``file`` -- the local-JSON ``StateStore``. Always runs (tmp_path);
  doubles as a regression pin on the file backend's semantics so the
  two backends can never drift apart silently.
- ``postgres`` -- ``PostgresStateStore``. Runs only when the
  ``RECTO_TEST_POSTGRES_DSN`` environment variable points at a
  disposable database AND ``recto[postgres]`` is installed; skips
  cleanly otherwise (CI without a database stays green). Each test gets
  a fresh randomly-named schema, dropped on teardown.

Run the postgres arm locally with e.g.::

    RECTO_TEST_POSTGRES_DSN="postgresql://user:pass@localhost:5432/recto_test" \
        pytest tests/test_state_postgres.py -v

The suite exercises the full StateStoreBase contract: phone CRUD +
revoke-cascade, session put/get/increment/expiry/exhaustion, pending
add/list/take (+ AppContext round-trip, single-use take), all four
result families (put/get/take single-use + TTL), vault-root pubkey
persistence, and revocation add/check/prune.
"""

from __future__ import annotations

import os
import time
import uuid

import pytest

from recto.bootloader.state import (
    AppContext,
    CapabilityResult,
    PendingRequest,
    PhoneRegistration,
    ProfileAddDeviceResult,
    ProfileCreateResult,
    ProfileRevokeDeviceResult,
    RevocationEntry,
    Session,
    StateStore,
)

PG_DSN = os.environ.get("RECTO_TEST_POSTGRES_DSN")


def _make_pg_store():
    if not PG_DSN:
        pytest.skip("RECTO_TEST_POSTGRES_DSN not set -- postgres arm skipped")
    pytest.importorskip("psycopg", reason="recto[postgres] not installed")
    from recto.bootloader.state_postgres import PostgresStateStore

    schema = f"recto_test_{uuid.uuid4().hex[:12]}"
    store = PostgresStateStore(PG_DSN, schema=schema)
    return store, schema


@pytest.fixture(params=["file", "postgres"])
def store(request, tmp_path):
    """Yield a fresh store of each backend flavor per test."""
    if request.param == "file":
        yield StateStore(state_dir=tmp_path)
        return
    pg, schema = _make_pg_store()
    try:
        yield pg
    finally:
        with pg._pool.connection() as conn:  # noqa: SLF001 - test teardown
            conn.execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")
        pg.close()


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def _phone(label: str = "test-phone") -> PhoneRegistration:
    return PhoneRegistration.new(
        device_label=label,
        public_key_b64u="AAAA_test_pubkey_b64u",
        supported_algorithms=("ed25519", "ecdsa-p256"),
    )


def _session(
    service: str = "svc",
    secret: str = "sec",
    phone_id: str = "p1",
    *,
    ttl: int = 3600,
    max_uses: int = 5,
    uses_so_far: int = 0,
) -> Session:
    now = int(time.time())
    return Session(
        service=service,
        secret=secret,
        phone_id=phone_id,
        jwt="header.payload.signature",
        expires_at_unix=now + ttl,
        issued_at_unix=now,
        max_uses=max_uses,
        uses_so_far=uses_so_far,
    )


def _pending(
    request_id: str,
    phone_id: str = "p1",
    *,
    ttl: int = 600,
    app_context: AppContext | None = None,
) -> PendingRequest:
    now = int(time.time())
    return PendingRequest(
        request_id=request_id,
        kind="single_sign",
        service="svc",
        secret="sec",
        phone_id=phone_id,
        operation_description="test op",
        payload_hash_b64u="cGF5bG9hZC1oYXNo",
        child_pid=1234,
        child_argv0="test-child",
        requested_at_unix=now,
        expires_at_unix=now + ttl,
        app_context=app_context,
    )


def _cap_result(request_id: str, *, ttl: int = 600) -> CapabilityResult:
    now = int(time.time())
    return CapabilityResult(
        request_id=request_id,
        status="approved",
        capability_jws="h.p.s",
        reason=None,
        agent_id="agent-1",
        resolved_at_unix=now,
        expires_at_unix=now + ttl,
    )


# ----------------------------------------------------------------------
# Phones
# ----------------------------------------------------------------------

def test_phone_register_get_list(store):
    p1, p2 = _phone("one"), _phone("two")
    store.register_phone(p1)
    store.register_phone(p2)

    got = store.get_phone(p1.phone_id)
    assert got == p1
    assert isinstance(got.supported_algorithms, tuple)
    assert {p.phone_id for p in store.list_phones()} == {
        p1.phone_id,
        p2.phone_id,
    }


def test_phone_register_is_upsert(store):
    p = _phone("before")
    store.register_phone(p)
    updated = PhoneRegistration(
        phone_id=p.phone_id,
        device_label="after",
        public_key_b64u=p.public_key_b64u,
        supported_algorithms=p.supported_algorithms,
        registered_at_unix=p.registered_at_unix,
        last_seen_unix=p.last_seen_unix + 5,
    )
    store.register_phone(updated)
    assert store.get_phone(p.phone_id).device_label == "after"
    assert len(store.list_phones()) == 1


def test_phone_get_unknown_returns_none(store):
    assert store.get_phone("nope") is None


def test_revoke_phone_cascades_sessions_and_pending(store):
    p = _phone()
    store.register_phone(p)
    store.put_session(_session("svc", "sec", phone_id=p.phone_id))
    store.add_pending(_pending("req-1", phone_id=p.phone_id))

    assert store.revoke_phone(p.phone_id) is True
    assert store.get_phone(p.phone_id) is None
    assert store.get_session("svc", "sec") is None
    assert store.list_pending_for_phone(p.phone_id) == []
    # Second revoke: already gone.
    assert store.revoke_phone(p.phone_id) is False


# ----------------------------------------------------------------------
# Sessions
# ----------------------------------------------------------------------

def test_session_put_get_roundtrip(store):
    s = _session()
    store.put_session(s)
    assert store.get_session("svc", "sec") == s


def test_session_expired_is_lazily_purged(store):
    s = _session(ttl=-10)
    store.put_session(s)
    assert store.get_session("svc", "sec") is None


def test_session_exhausted_is_lazily_purged(store):
    s = _session(max_uses=3, uses_so_far=3)
    store.put_session(s)
    assert store.get_session("svc", "sec") is None


def test_increment_session_uses(store):
    store.put_session(_session(max_uses=5))
    updated = store.increment_session_uses("svc", "sec")
    assert updated is not None
    assert updated.uses_so_far == 1
    updated = store.increment_session_uses("svc", "sec")
    assert updated.uses_so_far == 2
    # Unknown session increments to None.
    assert store.increment_session_uses("svc", "missing") is None


# ----------------------------------------------------------------------
# Pending requests
# ----------------------------------------------------------------------

def test_pending_add_list_take(store):
    ctx = AppContext(
        app_id="test-app",
        app_name="Test App",
        app_description="An app under test",
    )
    r1 = _pending("req-a", phone_id="p1", app_context=ctx)
    r2 = _pending("req-b", phone_id="p1")
    r3 = _pending("req-c", phone_id="p2")
    for r in (r1, r2, r3):
        store.add_pending(r)

    listed = store.list_pending_for_phone("p1")
    assert {r.request_id for r in listed} == {"req-a", "req-b"}
    got_a = next(r for r in listed if r.request_id == "req-a")
    assert isinstance(got_a.app_context, AppContext)
    assert got_a.app_context.app_name == "Test App"

    taken = store.take_pending("req-a")
    assert taken is not None and taken.request_id == "req-a"
    # Single-use: second take misses.
    assert store.take_pending("req-a") is None
    assert {r.request_id for r in store.list_pending_for_phone("p1")} == {
        "req-b"
    }


def test_pending_expired_not_listed_and_purged_by_list(store):
    """Expired pending requests never surface in a phone's list, and the
    list-time purge removes them entirely (a subsequent take misses).

    NOTE the contract nuance pinned here: ``take_pending`` itself is a
    bare pop -- it does NOT filter expiry (the server's respond path
    owns expired-request interpretation). Purging happens at list time.
    Both backends must agree on that ordering semantics.
    """
    store.add_pending(_pending("req-old", ttl=-5))
    assert store.list_pending_for_phone("p1") == []
    assert store.take_pending("req-old") is None


# ----------------------------------------------------------------------
# Result stores (all four families share semantics; capability is
# exercised fully, the profile families are pinned per-family)
# ----------------------------------------------------------------------

def test_capability_result_put_get_take(store):
    res = _cap_result("req-1")
    store.put_capability_result(res)
    # get does NOT consume.
    assert store.get_capability_result("req-1") == res
    assert store.get_capability_result("req-1") == res
    # take consumes -- single-use.
    assert store.take_capability_result("req-1") == res
    assert store.take_capability_result("req-1") is None
    assert store.get_capability_result("req-1") is None


def test_capability_result_expiry(store):
    now = int(time.time())
    store.put_capability_result(
        CapabilityResult(
            request_id="req-exp",
            status="approved",
            capability_jws="h.p.s",
            reason=None,
            agent_id="a",
            resolved_at_unix=now - 100,
            expires_at_unix=now - 10,
        )
    )
    assert store.get_capability_result("req-exp") is None
    assert store.take_capability_result("req-exp") is None


def test_profile_create_result_roundtrip(store):
    now = int(time.time())
    res = ProfileCreateResult(
        request_id="pc-1",
        status="approved",
        profile_id="prof-123",
        reason=None,
        resolved_at_unix=now,
        expires_at_unix=now + 600,
    )
    store.put_profile_create_result(res)
    assert store.get_profile_create_result("pc-1") == res
    assert store.take_profile_create_result("pc-1") == res
    assert store.take_profile_create_result("pc-1") is None


def test_profile_add_device_result_roundtrip(store):
    now = int(time.time())
    res = ProfileAddDeviceResult(
        request_id="ad-1",
        status="approved",
        profile_id="prof-123",
        new_phone_id="p9",
        reason=None,
        resolved_at_unix=now,
        expires_at_unix=now + 600,
    )
    store.put_profile_add_device_result(res)
    assert store.get_profile_add_device_result("ad-1") == res
    assert store.take_profile_add_device_result("ad-1") == res
    assert store.take_profile_add_device_result("ad-1") is None


def test_profile_revoke_device_result_roundtrip(store):
    now = int(time.time())
    res = ProfileRevokeDeviceResult(
        request_id="rd-1",
        status="approved",
        profile_id="prof-123",
        phone_id_revoked="p9",
        reason=None,
        resolved_at_unix=now,
        expires_at_unix=now + 600,
    )
    store.put_profile_revoke_device_result(res)
    assert store.get_profile_revoke_device_result("rd-1") == res
    assert store.take_profile_revoke_device_result("rd-1") == res
    assert store.take_profile_revoke_device_result("rd-1") is None


def test_result_families_do_not_collide(store):
    """Same request_id across families must stay independent."""
    now = int(time.time())
    store.put_capability_result(_cap_result("shared-id"))
    store.put_profile_create_result(
        ProfileCreateResult(
            request_id="shared-id",
            status="denied",
            profile_id=None,
            reason="operator declined",
            resolved_at_unix=now,
            expires_at_unix=now + 600,
        )
    )
    assert store.take_capability_result("shared-id").status == "approved"
    # Capability take must not have consumed the profile-create result.
    assert store.get_profile_create_result("shared-id").status == "denied"


# ----------------------------------------------------------------------
# Vault root
# ----------------------------------------------------------------------

def test_operator_pubkey_roundtrip(store):
    assert store.is_vault_bootstrapped() is False
    assert store.get_operator_pubkey() is None
    key = bytes(range(64))
    store.put_operator_pubkey(key)
    assert store.is_vault_bootstrapped() is True
    assert store.get_operator_pubkey() == key
    # Overwrite (rotation) is allowed at the store layer.
    key2 = bytes(reversed(range(64)))
    store.put_operator_pubkey(key2)
    assert store.get_operator_pubkey() == key2


def test_operator_pubkey_rejects_wrong_length(store):
    with pytest.raises(ValueError):
        store.put_operator_pubkey(b"\x00" * 63)
    with pytest.raises(ValueError):
        store.put_operator_pubkey(b"\x00" * 65)


# ----------------------------------------------------------------------
# Revocations
# ----------------------------------------------------------------------

def test_revocation_add_check_list(store):
    now = int(time.time())
    e = RevocationEntry(
        jti="jti-1",
        revoked_at_unix=now,
        original_exp_unix=now + 3600,
        reason="compromised",
    )
    store.add_revocation(e)
    assert store.is_revoked("jti-1") is True
    assert store.is_revoked("jti-other") is False
    assert store.list_revocations() == [e]
    # Idempotent re-add.
    store.add_revocation(e)
    assert len(store.list_revocations()) == 1


def test_revocation_auto_prunes_past_original_exp(store):
    now = int(time.time())
    store.add_revocation(
        RevocationEntry(
            jti="jti-old",
            revoked_at_unix=now - 100,
            original_exp_unix=now - 10,
        )
    )
    assert store.is_revoked("jti-old") is False
    assert store.list_revocations() == []


# ----------------------------------------------------------------------
# One-time challenges (registration challenges + pairing codes)
# ----------------------------------------------------------------------

def test_challenge_issue_and_single_use_consume(store):
    c, exp = store.issue_challenge(ttl_seconds=60)
    assert isinstance(c, str) and len(c) >= 40  # 32 bytes b64u, no padding
    assert exp > int(time.time())
    assert store.consume_challenge(c) is True
    # Single-use: second consume fails.
    assert store.consume_challenge(c) is False


def test_challenge_unknown_value_fails(store):
    assert store.consume_challenge("no-such-challenge") is False


def test_challenge_expired_fails(store):
    c, _ = store.issue_challenge(ttl_seconds=-1)
    assert store.consume_challenge(c) is False


def test_pairing_code_issue_and_single_use_consume(store):
    code, exp = store.issue_pairing_code(ttl_seconds=300)
    assert len(code) == 6 and code.isdigit()
    assert exp > int(time.time())
    assert store.consume_pairing_code(code) is True
    assert store.consume_pairing_code(code) is False


def test_pairing_code_expired_fails(store):
    code, _ = store.issue_pairing_code(ttl_seconds=-1)
    assert store.consume_pairing_code(code) is False


def test_challenge_kinds_are_isolated(store):
    """A pairing code must not be consumable as a registration
    challenge (and vice versa) even if the raw values collided."""
    code, _ = store.issue_pairing_code(ttl_seconds=300)
    assert store.consume_challenge(code) is False
    # Still consumable under the right kind.
    assert store.consume_pairing_code(code) is True


def test_challenge_store_adapter_delegates_to_state(store):
    """Regression pin for the 2026-07-20 prod finding: a ChallengeStore
    constructed WITH a state store must share challenge visibility with
    the store itself (and thus with sibling instances on a shared
    backend). A bare in-memory shadow fails this cross-object check."""
    from recto.bootloader.server import ChallengeStore

    cs = ChallengeStore(state=store)
    code, _ = cs.issue_pairing_code(ttl_seconds=300)
    # Consume via the STORE directly -- proves delegation, no shadow.
    assert store.consume_pairing_code(code) is True
    # And the reverse direction.
    c, _ = store.issue_challenge(ttl_seconds=60)
    assert cs.consume_challenge(c) is True
