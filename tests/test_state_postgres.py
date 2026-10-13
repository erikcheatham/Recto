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

def _phone(label: str = "test-phone", pubkey: str = "AAAA_test_pubkey_b64u") -> PhoneRegistration:
    # The key IS the identity (hard rule 14.1): two phones need two keys.
    return PhoneRegistration.new(
        device_label=label,
        public_key_b64u=pubkey,
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
    p1, p2 = _phone("one", "AAAA_test_pubkey_one"), _phone("two", "AAAA_test_pubkey_two")
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


# THE MEMBER PLANE (2026-09-30): a consumer's member codes + challenges are their own kinds, on both backends.

def test_member_pairing_code_issue_and_single_use_consume(store):
    code, exp = store.issue_member_pairing_code(ttl_seconds=300)
    assert len(code) == 6 and code.isdigit() and exp > int(time.time())
    assert store.consume_member_pairing_code(code) is True
    assert store.consume_member_pairing_code(code) is False


def test_member_and_owner_codes_are_isolated(store):
    """A member code never buys an owner challenge, and an owner code is never a member one."""
    member, _ = store.issue_member_pairing_code(ttl_seconds=300)
    owner, _ = store.issue_pairing_code(ttl_seconds=300)
    assert store.consume_pairing_code(member) is False
    assert store.consume_member_pairing_code(owner) is False
    assert store.consume_member_pairing_code(member) is True
    assert store.consume_pairing_code(owner) is True


def test_member_challenge_peek_never_consumes_and_kinds_are_isolated(store):
    c, _ = store.issue_member_challenge(ttl_seconds=60)
    owner_c, _ = store.issue_challenge(ttl_seconds=60)
    assert store.is_member_challenge(c) is True
    assert store.is_member_challenge(c) is True, "the peek consumed the challenge"
    assert store.is_member_challenge(owner_c) is False
    assert store.consume_challenge(c) is False, "a member challenge answered as an owner one"
    assert store.consume_member_challenge(c) is True
    assert store.is_member_challenge(c) is False
    assert store.consume_member_challenge(c) is False


def test_member_challenge_expired_is_not_a_member_challenge(store):
    c, _ = store.issue_member_challenge(ttl_seconds=-1)
    assert store.is_member_challenge(c) is False
    assert store.consume_member_challenge(c) is False


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


# ----------------------------------------------------------------------
# THE OWNER SLOTS (hard rule 14.4, amended)
# ----------------------------------------------------------------------

def test_owner_challenge_peek_never_consumes_and_kinds_are_isolated(store):
    c, _ = store.issue_owner_challenge(ttl_seconds=60)
    plain, _ = store.issue_challenge(ttl_seconds=60)
    member, _ = store.issue_member_challenge(ttl_seconds=60)
    assert store.is_owner_challenge(c) is True
    assert store.is_owner_challenge(c) is True, "the peek consumed the challenge"
    assert store.is_owner_challenge(plain) is False, "a codeless challenge answered as an owner one"
    assert store.is_owner_challenge(member) is False
    assert store.consume_challenge(c) is False
    assert store.consume_member_challenge(c) is False
    assert store.consume_owner_challenge(plain) is False
    assert store.consume_owner_challenge(c) is True
    assert store.consume_owner_challenge(c) is False


def test_owner_challenge_expired_is_not_an_owner_challenge(store):
    c, _ = store.issue_owner_challenge(ttl_seconds=-1)
    assert store.is_owner_challenge(c) is False
    assert store.consume_owner_challenge(c) is False


def test_owner_genesis_marker_round_trip(store):
    assert store.get_owner_genesis() is None
    store.set_owner_genesis("open")
    assert store.get_owner_genesis() == "open"
    store.set_owner_genesis("closed")
    assert store.get_owner_genesis() == "closed"
    with pytest.raises(ValueError):
        store.set_owner_genesis("ajar")
    assert store.get_owner_genesis() == "closed"


def test_owner_genesis_marker_survives_a_new_file_store(tmp_path):
    StateStore(state_dir=tmp_path).set_owner_genesis("closed")
    assert StateStore(state_dir=tmp_path).get_owner_genesis() == "closed"


def test_owner_enroll_records_put_get_list_take_and_expire(store):
    now = int(time.time())
    live = {"request_id": "r-live", "slot": "recovery", "state": "pending", "cards": {"c1": "pk_a"},
            "expires_at_unix": now + 300}
    dead = {"request_id": "r-dead", "slot": "primary", "state": "pending", "cards": {},
            "expires_at_unix": now - 1}
    store.put_owner_enroll(live)
    store.put_owner_enroll(dead)
    assert store.get_owner_enroll("r-live")["cards"] == {"c1": "pk_a"}
    assert store.get_owner_enroll("r-dead") is None
    assert [r["request_id"] for r in store.list_owner_enrolls()] == ["r-live"]
    store.put_owner_enroll({**live, "state": "approved"})
    assert store.get_owner_enroll("r-live")["state"] == "approved"
    assert store.delete_owner_enroll("r-live")["request_id"] == "r-live"
    assert store.delete_owner_enroll("r-live") is None
    assert store.list_owner_enrolls() == []


def test_update_phone_push_updates_only_a_held_phone(store):
    p = _phone("pusher", pubkey="push_key_b64u")
    from dataclasses import replace
    p = replace(p, slot="recovery")
    store.register_phone(p)
    assert store.update_phone_push(p.phone_id, "tok-1", "fcm") is True
    got = store.get_phone(p.phone_id)
    assert (got.push_token, got.push_platform, got.slot) == ("tok-1", "fcm", "recovery")
    assert store.revoke_phone(p.phone_id) is True
    assert store.update_phone_push(p.phone_id, "tok-2", "apns") is False
    assert store.get_phone(p.phone_id) is None, "the push update re-inserted a removed phone"


def test_has_any_session(store):
    assert store.has_any_session() is False
    store.put_session(_session())
    assert store.has_any_session() is True


def test_registry_lock_is_reentrant(store):
    import threading

    done = threading.Event()

    def nested():
        with store.registry_lock():
            with store.registry_lock():
                store.register_phone(_phone("locked", pubkey="lock_key_b64u"))
        done.set()

    worker = threading.Thread(target=nested, daemon=True)
    worker.start()
    worker.join(timeout=10)
    assert done.is_set(), "a nested registry_lock waited on itself"
    assert store.get_phone(_phone("x", pubkey="lock_key_b64u").phone_id) is not None


def test_owner_and_member_codes_never_collide(store, monkeypatch):
    import secrets

    draws = iter([123456, 123456, 654321, 111111, 111111, 222222])
    monkeypatch.setattr(secrets, "randbelow", lambda n: next(draws))
    member, _ = store.issue_member_pairing_code(ttl_seconds=300)
    owner, _ = store.issue_pairing_code(ttl_seconds=300)
    assert (member, owner) == ("123456", "654321"), "an owner code drawn equal to a live member code"
    owner2, _ = store.issue_pairing_code(ttl_seconds=300)
    member2, _ = store.issue_member_pairing_code(ttl_seconds=300)
    assert (owner2, member2) == ("111111", "222222"), "a member code equal to a live owner code would buy an OWNER challenge"


def test_a_plain_challenge_survives_a_flood(store):
    """A codeless challenge serves revoke; no flood of them evicts a phone's revoke challenge."""
    first, _ = store.issue_challenge(ttl_seconds=600)
    for _ in range(1100):
        store.issue_challenge(ttl_seconds=600)
    assert store.consume_challenge(first) is True


def _slotted(label: str, pubkey: str, slot: str) -> PhoneRegistration:
    return PhoneRegistration.new(device_label=label, public_key_b64u=pubkey, supported_algorithms=("ed25519",),
                                 slot=slot)


def test_replace_phone_swaps_the_occupant_in_one_act(store):
    occupant = store.register_phone(_slotted("old", "occupant_key_b64u", "primary"))
    other = store.register_phone(_slotted("other", "other_key_b64u", "recovery"))
    store.put_session(_session(phone_id=occupant.phone_id))
    store.add_pending(_pending("occupant-card", phone_id=occupant.phone_id))
    store.add_pending(_pending("other-card", phone_id=other.phone_id))
    stored = store.replace_phone(occupant.phone_id, _slotted("new", "incoming_key_b64u", "primary"))
    assert stored is not None and stored.slot == "primary"
    assert {p.phone_id for p in store.list_phones()} == {stored.phone_id, other.phone_id}
    assert store.get_phone(occupant.phone_id) is None
    assert store.has_any_session() is False, "the displaced phone's session survived"
    assert store.list_pending_for_phone(occupant.phone_id) == []
    assert [p.request_id for p in store.list_pending_for_phone(other.phone_id)] == ["other-card"]


def test_replace_phone_that_fails_midway_keeps_the_occupant(store, monkeypatch):
    """The displacement is one act: when building the incoming row fails after the occupant's rows would have gone,
    the occupant, its session and its queue are all still there (Postgres: the transaction rolled back)."""
    import recto.bootloader.state as state_module

    occupant = store.register_phone(_slotted("old", "occupant_key_b64u", "primary"))
    store.put_session(_session(phone_id=occupant.phone_id))
    store.add_pending(_pending("occupant-card", phone_id=occupant.phone_id))

    def broken(*_a, **_k):
        raise RuntimeError("the incoming row could not be built")

    monkeypatch.setattr(state_module, "_merge_onto_existing", broken)
    if not isinstance(store, StateStore):
        import recto.bootloader.state_postgres as pg_module
        monkeypatch.setattr(pg_module, "_merge_onto_existing", broken)
    with pytest.raises(RuntimeError):
        store.replace_phone(occupant.phone_id, _slotted("new", "incoming_key_b64u", "primary"))
    monkeypatch.undo()
    assert [p.phone_id for p in store.list_phones()] == [occupant.phone_id]
    assert store.has_any_session() is True
    assert [p.request_id for p in store.list_pending_for_phone(occupant.phone_id)] == ["occupant-card"]


# 4 is past the three writes a one-act replace makes: it injects nothing on correct code, and turns a revoke-then-register
# (two-act) displacement red.
@pytest.mark.parametrize("fail_at", [1, 2, 3, 4])
def test_replace_phone_never_leaves_the_slot_empty_or_doubled_on_a_failed_write(tmp_path, monkeypatch, fail_at):
    """File store: whichever write fails, the primary slot holds exactly one key - the occupant's or the incoming
    one - and memory agrees with disk."""
    store = StateStore(state_dir=tmp_path)
    occupant = store.register_phone(_slotted("old", "occupant_key_b64u", "primary"))
    store.put_session(_session(phone_id=occupant.phone_id))
    store.add_pending(_pending("occupant-card", phone_id=occupant.phone_id))
    real, calls = store._atomic_write, [0]

    def failing(path, body):
        calls[0] += 1
        if calls[0] == fail_at:
            raise OSError(28, "no space left on device")
        return real(path, body)

    monkeypatch.setattr(store, "_atomic_write", failing)
    try:
        store.replace_phone(occupant.phone_id, _slotted("new", "incoming_key_b64u", "primary"))
    except OSError:
        pass
    monkeypatch.undo()
    in_memory = [p.public_key_b64u for p in store.list_phones() if p.slot == "primary"]
    on_disk = [p.public_key_b64u for p in StateStore(state_dir=tmp_path).list_phones() if p.slot == "primary"]
    assert in_memory in (["occupant_key_b64u"], ["incoming_key_b64u"]), in_memory
    assert on_disk == in_memory


def test_replace_phone_changes_nothing_when_the_occupant_is_gone(store):
    other = store.register_phone(_slotted("other", "other_key_b64u", "recovery"))
    assert store.replace_phone("pk_0000000000000000", _slotted("new", "incoming_key_b64u", "primary")) is None
    assert [p.phone_id for p in store.list_phones()] == [other.phone_id]


@pytest.mark.parametrize("store", ["postgres"], indirect=True)   # no [file] item: the Postgres job skips nothing
def test_postgres_owner_genesis_refuses_an_unknown_value(store):
    from psycopg.types.json import Jsonb
    with store._pool.connection() as conn:  # noqa: SLF001 - a corrupted row, written behind the store's back
        conn.execute(store._q("INSERT INTO {schema}.registry_meta (key, value) VALUES ('owner_genesis', %s)"),
                     (Jsonb({"state": "ajar"}),))
    with pytest.raises(ValueError):
        store.get_owner_genesis()


@pytest.mark.parametrize("store", ["postgres"], indirect=True)
def test_postgres_registry_lock_serializes_two_instances(store):
    import threading
    from typing import Any

    from recto.bootloader.state_postgres import PostgresStateStore

    second = PostgresStateStore(PG_DSN, schema=store._schema)  # noqa: SLF001
    key = store._registry_lock_key  # noqa: SLF001
    try:
        with second._pool.connection() as probe_conn:  # noqa: SLF001 - a probe that never blocks
            probe_conn.autocommit = True

            def free() -> bool:
                return probe_conn.execute("SELECT pg_try_advisory_xact_lock(%s)", (key,)).fetchone()[0]

            outcome: dict[str, Any] = {}

            def held_twice() -> None:
                with store.registry_lock():
                    with store.registry_lock():          # nested on one thread: one hold, no self-deadlock
                        outcome["inner"] = free()
                    outcome["after_inner"] = free()
                outcome["after_outer"] = free()

            worker = threading.Thread(target=held_twice, daemon=True)
            worker.start()
            worker.join(timeout=10)
            assert not worker.is_alive(), "registry_lock hung (a nested hold waited on itself?)"
            assert outcome == {"inner": False, "after_inner": False, "after_outer": True}, outcome
    finally:
        second.close()


@pytest.mark.parametrize("act", ["register-new", "register-merge", "revoke", "push", "replace"])
def test_a_failed_phones_write_changes_neither_memory_nor_disk(tmp_path, monkeypatch, act):
    """File store: phones.json is written first and memory follows only once it lands, for every act that changes it."""
    store = StateStore(state_dir=tmp_path)
    occupant = store.register_phone(_slotted("old", "occupant_key_b64u", "primary"))
    other = store.register_phone(_slotted("other", "other_key_b64u", "recovery"))
    before = store.list_phones()
    real = store._atomic_write

    def failing(path, body):
        if os.path.basename(str(path)) == "phones.json":
            raise OSError(28, "no space left on device")
        return real(path, body)

    monkeypatch.setattr(store, "_atomic_write", failing)
    with pytest.raises(OSError):
        if act == "register-new":
            store.register_phone(_slotted("new", "new_key_b64u", "primary"))
        elif act == "register-merge":
            store.register_phone(_slotted("renamed", "other_key_b64u", "recovery"))
        elif act == "revoke":
            store.revoke_phone(occupant.phone_id)
        elif act == "push":
            store.update_phone_push(other.phone_id, "tok", "fcm")
        else:
            store.replace_phone(occupant.phone_id, _slotted("new", "new_key_b64u", "primary"))
    monkeypatch.undo()
    assert store.list_phones() == StateStore(state_dir=tmp_path).list_phones() == before


@pytest.mark.parametrize("bad", ["sessions.json", "pending.json"])
def test_a_phone_change_that_landed_is_done_when_a_later_file_fails(tmp_path, monkeypatch, caplog, bad):
    """Once phones.json has landed, a failed sessions/pending write is logged and the act reports done."""
    store = StateStore(state_dir=tmp_path)
    occupant = store.register_phone(_slotted("old", "occupant_key_b64u", "primary"))
    other = store.register_phone(_slotted("other", "other_key_b64u", "recovery"))
    store.put_session(_session(phone_id=occupant.phone_id))
    store.add_pending(_pending("occupant-card", phone_id=occupant.phone_id))
    real = store._atomic_write

    def failing(path, body):
        if os.path.basename(str(path)) == bad:
            raise OSError(28, "no space left on device")
        return real(path, body)

    monkeypatch.setattr(store, "_atomic_write", failing)
    assert store.revoke_phone(other.phone_id) is True
    stored = store.replace_phone(occupant.phone_id, _slotted("new", "new_key_b64u", "primary"))
    assert stored is not None
    monkeypatch.undo()
    assert [p.phone_id for p in store.list_phones()] == [stored.phone_id]
    assert [p.phone_id for p in StateStore(state_dir=tmp_path).list_phones()] == [stored.phone_id]
    said = [r.getMessage() for r in caplog.records if r.name == "recto.bootloader.state"]
    assert len(said) == 2 and all(m.startswith(f"{bad} not written after a phone change") for m in said), said


@pytest.mark.parametrize("name", ["phones.json", "sessions.json", "owner_genesis.json", "revocations.json"])
def test_a_corrupt_store_file_is_named(tmp_path, name):
    (tmp_path / name).write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError, match=name.replace(".", r"\.")):
        StateStore(state_dir=tmp_path)


def test_a_store_file_of_the_wrong_shape_is_named(tmp_path):
    (tmp_path / "phones.json").write_text('{"phones": [{"no_such_field": 1}]}', encoding="utf-8")
    with pytest.raises(ValueError, match="phones.json"):
        StateStore(state_dir=tmp_path)


def test_replace_phone_writes_each_file_once(tmp_path, monkeypatch):
    store = StateStore(state_dir=tmp_path)
    occupant = store.register_phone(_slotted("old", "occupant_key_b64u", "primary"))
    store.put_session(_session(phone_id=occupant.phone_id))
    store.add_pending(_pending("occupant-card", phone_id=occupant.phone_id))
    real, written = store._atomic_write, []

    def spy(path, body):
        written.append(os.path.basename(str(path)))
        return real(path, body)

    monkeypatch.setattr(store, "_atomic_write", spy)
    store.replace_phone(occupant.phone_id, _slotted("new", "incoming_key_b64u", "primary"))
    assert written == ["phones.json", "sessions.json", "pending.json"], written


def test_the_cli_never_creates_a_mistyped_schema(monkeypatch):
    """The host CLI probes before it constructs the store (whose DDL would CREATE a mistyped schema, empty)."""
    if not PG_DSN:
        pytest.skip("RECTO_TEST_POSTGRES_DSN not set -- postgres arm skipped")
    psycopg = pytest.importorskip("psycopg", reason="recto[postgres] not installed")
    import io

    from recto.cli import main

    schema = f"recto_missing_{uuid.uuid4().hex[:12]}"
    monkeypatch.setenv("RECTO_STATE_BACKEND", "postgres")
    monkeypatch.setenv("RECTO_POSTGRES_DSN", PG_DSN)
    monkeypatch.setenv("RECTO_POSTGRES_SCHEMA", schema)
    out, err = io.StringIO(), io.StringIO()
    assert main(["bootloader", "owner-slots"], stdout=out, stderr=err) == 1
    assert "no bootloader registry" in err.getvalue()
    with psycopg.connect(PG_DSN) as conn:
        assert conn.execute("SELECT 1 FROM information_schema.schemata WHERE schema_name = %s",
                            (schema,)).fetchone() is None, "the refused command created the schema"


@pytest.mark.parametrize("store", ["postgres"], indirect=True)
def test_postgres_registry_lock_refuses_by_name_when_another_session_holds_it(store, monkeypatch):
    """A real contention: a session lock on the key held outside the store; registry_lock refuses by name within its
    bound, then is granted once the holder lets go (the refused attempt rolled back and returned its connection)."""
    import threading

    import psycopg
    import recto.bootloader.state_postgres as spg
    from recto.bootloader.state import RegistryLockUnavailable

    monkeypatch.setattr(spg, "REGISTRY_LOCK_WAIT_SECONDS", 1)
    key = store._registry_lock_key  # noqa: SLF001
    with psycopg.connect(PG_DSN, autocommit=True) as holder:
        holder.execute("SELECT pg_advisory_lock(%s)", (key,))
        outcome: dict = {}

        def attempt() -> None:
            try:
                with store.registry_lock():
                    outcome["granted"] = True
            except RegistryLockUnavailable as exc:
                outcome["refused"] = str(exc)

        worker = threading.Thread(target=attempt, daemon=True)
        worker.start()
        worker.join(timeout=10)
        assert not worker.is_alive(), "registry_lock waited past its bound"
        assert "refused" in outcome, outcome
        holder.execute("SELECT pg_advisory_unlock(%s)", (key,))
    with store.registry_lock():
        pass


@pytest.mark.parametrize("store", ["postgres"], indirect=True)
def test_postgres_registry_lock_outlasts_a_roles_statement_timeout(store, monkeypatch):
    """A connection whose role cancels statements after 1 s still waits the lock's own bound and refuses by name -
    never QueryCanceled (57014)."""
    import threading

    import psycopg
    from psycopg.conninfo import make_conninfo

    import recto.bootloader.state_postgres as spg
    from recto.bootloader.state import RegistryLockUnavailable

    monkeypatch.setattr(spg, "REGISTRY_LOCK_WAIT_SECONDS", 3)
    impatient = spg.PostgresStateStore(make_conninfo(PG_DSN, options="-c statement_timeout=1000"),
                                       schema=store._schema)  # noqa: SLF001
    key = store._registry_lock_key  # noqa: SLF001
    try:
        with psycopg.connect(PG_DSN, autocommit=True) as holder:
            holder.execute("SELECT pg_advisory_lock(%s)", (key,))
            outcome: dict = {}

            def attempt() -> None:
                try:
                    with impatient.registry_lock():
                        outcome["granted"] = True
                except RegistryLockUnavailable:
                    outcome["refused"] = True
                except Exception as exc:  # noqa: BLE001
                    outcome["other"] = type(exc).__name__

            worker = threading.Thread(target=attempt, daemon=True)
            worker.start()
            worker.join(timeout=15)
            assert not worker.is_alive() and outcome == {"refused": True}, outcome
            holder.execute("SELECT pg_advisory_unlock(%s)", (key,))
    finally:
        impatient.close()
