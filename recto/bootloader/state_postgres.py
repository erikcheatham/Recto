"""PostgresStateStore -- the production-scale StateStoreBase backend.

Implements the ``StateStoreBase`` contract (recto.bootloader.state) on
PostgreSQL via psycopg3 + a connection pool, so N bootloader instances
behind a load balancer observe ONE shared state surface:

- a consumer's server POSTs a capability request to instance A; the
  phone polls (or is push-woken through) instance B and sees it;
- single-use ``take_*`` semantics become ``DELETE ... RETURNING`` --
  atomic across instances by construction, and durable across restarts
  (strictly stronger than the file backend's in-memory result stores);
- caller-authored idempotency keys (request ids, jti) become primary
  keys, DB-enforcing the partial-failure discipline the file backend
  enforces in code.

The file-backed ``StateStore`` remains the zero-setup default (Hard
Rule #4 -- single-file-runnable); this backend is opt-in production
config. Install with ``pip install recto[postgres]``.

Wire-up::

    from recto.bootloader.state_postgres import PostgresStateStore
    store = PostgresStateStore(dsn)   # DSN resolved via a SecretSource,
                                      # never a plaintext config literal
    cfg = BootloaderConfig(..., state=store)

Serialization: every record round-trips through the SAME
``dataclasses.asdict`` shape the file backend persists, stored as one
JSONB document per row plus the handful of columns queries filter on
(ids, phone_id, expiry). Schema evolution therefore tracks the
dataclasses automatically -- adding an optional field needs no
migration, exactly like the JSON files.

Expiry: purge-on-read parity with the file backend (each read op
deletes that table's expired rows first), with the ``expires_at_unix``
guard also in every WHERE clause so two instances racing a purge stay
correct.

Known bounded gap: multi-profile master-identity state
(``master_identity.json`` via ``recto.profile``) is file-based and NOT
part of the StateStoreBase contract; ``state_dir`` on this class points
at a local directory for that compat surface. Deployments using
profiles multi-instance need the profile store moved behind the seam
first (banked follow-on in docs/production-scale-brief.md).
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Any, Iterator

from recto.bootloader.state import (
    GENESIS_LEGACY_ALGORITHM,
    OWNER_GENESIS_STATES,
    AppContext,
    RegistryLockUnavailable,
    CapabilityResult,
    GenesisMember,
    PendingRequest,
    PhoneRegistration,
    ProfileAddDeviceResult,
    ProfileCreateResult,
    ProfileRevokeDeviceResult,
    RevocationEntry,
    Session,
    StateStoreBase,
    _merge_onto_existing,
    default_state_dir,
    member_bindings_from_doc,
    validate_genesis_pubkey,
)

try:  # optional dependency -- recto[postgres]
    import psycopg
    from psycopg.types.json import Jsonb
    from psycopg_pool import ConnectionPool
except ImportError as _exc:  # pragma: no cover - exercised via skip in tests
    psycopg = None  # type: ignore[assignment]
    Jsonb = None  # type: ignore[assignment]
    ConnectionPool = None  # type: ignore[assignment]
    _IMPORT_ERROR: ImportError | None = _exc
else:
    _IMPORT_ERROR = None


_DDL = """
CREATE SCHEMA IF NOT EXISTS {schema};

CREATE TABLE IF NOT EXISTS {schema}.phones (
    phone_id   text PRIMARY KEY,
    doc        jsonb NOT NULL
);

CREATE TABLE IF NOT EXISTS {schema}.sessions (
    service    text NOT NULL,
    secret     text NOT NULL,
    doc        jsonb NOT NULL,
    expires_at_unix bigint NOT NULL,
    PRIMARY KEY (service, secret)
);

CREATE TABLE IF NOT EXISTS {schema}.pending (
    request_id text PRIMARY KEY,
    phone_id   text NOT NULL,
    doc        jsonb NOT NULL,
    expires_at_unix bigint NOT NULL
);
CREATE INDEX IF NOT EXISTS pending_phone_idx
    ON {schema}.pending (phone_id);

CREATE TABLE IF NOT EXISTS {schema}.results (
    kind       text NOT NULL,
    request_id text NOT NULL,
    doc        jsonb NOT NULL,
    expires_at_unix bigint NOT NULL,
    PRIMARY KEY (kind, request_id)
);

CREATE TABLE IF NOT EXISTS {schema}.vault_root (
    id         int PRIMARY KEY CHECK (id = 1),
    pubkey_hex text NOT NULL
);

CREATE TABLE IF NOT EXISTS {schema}.genesis_members (
    kind        TEXT PRIMARY KEY,
    pubkey_hex  TEXT NOT NULL
);
-- GATE 5c-c: the curve a member was sealed on, added additively so an
-- existing row keeps its meaning. DEFAULT 'ed25519' is a recorded fact, not
-- a fallback: the writer that created any pre-tag row refused every length
-- but 32, so such a row cannot be anything else.
ALTER TABLE {schema}.genesis_members
    ADD COLUMN IF NOT EXISTS algorithm TEXT NOT NULL DEFAULT 'ed25519';
CREATE TABLE IF NOT EXISTS {schema}.revocations (
    jti        text PRIMARY KEY,
    doc        jsonb NOT NULL,
    original_exp_unix bigint NOT NULL
);

CREATE TABLE IF NOT EXISTS {schema}.challenges (
    kind       text NOT NULL,
    value      text NOT NULL,
    expires_at_unix bigint NOT NULL,
    PRIMARY KEY (kind, value)
);
-- THE MEMBER BINDING (2026-10-17, hard rule 15.n): a member code and the challenge it buys carry the
-- (consumer, subject) they were minted for. Additive; NULL on every other kind. The subject is an opaque handle.
ALTER TABLE {schema}.challenges
    ADD COLUMN IF NOT EXISTS binding jsonb;

-- THE USER-VAULT GRANTS (2026-10-17, R-series step 2): one live grant per (consumer, subject, agent_handle, key).
-- The subject and the agent are opaque handles; doc holds the signed record, the signature and the signer's ref.
CREATE TABLE IF NOT EXISTS {schema}.user_vault_grants (
    grant_id     text PRIMARY KEY,
    consumer     text NOT NULL,
    subject      text NOT NULL,
    agent_handle text NOT NULL,
    key          text NOT NULL,
    not_after    bigint NOT NULL,
    doc          jsonb NOT NULL,
    UNIQUE (consumer, subject, agent_handle, key)
);

-- THE OWNER SLOTS (hard rule 14.4, amended): small registry facts, one row each (the owner-genesis marker).
CREATE TABLE IF NOT EXISTS {schema}.registry_meta (
    key        text PRIMARY KEY,
    value      jsonb NOT NULL
);
"""

# Result-table ``kind`` discriminators. One table, four result families
# -- the families share identical storage semantics (put / get / take /
# TTL purge), differing only in dataclass shape, which the JSONB doc
# carries.
_KIND_CAPABILITY = "capability"
_KIND_PROFILE_CREATE = "profile_create"
_KIND_PROFILE_ADD_DEVICE = "profile_add_device"
_KIND_PROFILE_REVOKE_DEVICE = "profile_revoke_device"
# THE OWNER SLOTS: an approval card's record (what it binds and where it stands) - the results table's TTL and its
# DELETE ... RETURNING take serve it unchanged.
# How long registry_lock waits for the lock - for another thread of this process and another instance together, one
# deadline - before it refuses. (Checking out the lock's pooled connection may add the pool's own timeout.)
REGISTRY_LOCK_WAIT_SECONDS = 30
_KIND_OWNER_ENROLL = "owner_enroll"
_META_OWNER_GENESIS = "owner_genesis"


class PostgresStateStore(StateStoreBase):
    """StateStoreBase on PostgreSQL (psycopg3 + connection pool).

    Thread-safe by construction: every operation borrows a pooled
    connection and runs in its own transaction. Safe to share across the
    ThreadingHTTPServer's request threads AND across bootloader instances
    pointed at the same database. The one exception is registry_lock():
    a process lock plus a transaction-scoped advisory lock held in one
    pooled connection's open transaction for the length of an owner-slot
    decision. The DSN may be a direct connection or a session-mode pooler;
    a transaction-mode pooler (PgBouncer, Supavisor) needs prepared-
    statement support (PgBouncer 1.21+ with max_prepared_statements > 0).
    The lock is waited for at most REGISTRY_LOCK_WAIT_SECONDS - in this
    process and in the database, one deadline - then refused
    (RegistryLockUnavailable). The lock connection overrides a role's
    statement, idle-in-transaction and transaction timeouts for its own
    transaction only. A holder whose host vanished keeps it until
    the server ends that session: it shows in pg_locks (locktype
    'advisory') and in pg_stat_activity as 'idle in transaction', and
    pg_terminate_backend(pid) frees it. A LIVE holder also shows 'idle in
    transaction': before pg_terminate_backend, check that
    pg_stat_activity.xact_start is far older than any act, or stop the
    servers first - terminating a live holder frees the lock while its act
    continues on other connections.
    """

    #: Identifier-safe schema name guard -- the schema is interpolated
    #: into DDL/DML strings (it cannot be a bind parameter), so it is
    #: restricted to a conservative identifier alphabet.
    _SCHEMA_ALPHABET = set("abcdefghijklmnopqrstuvwxyz0123456789_")

    def __init__(
        self,
        dsn: str,
        *,
        schema: str = "recto_bootloader",
        state_dir: Path | None = None,
        pool_min: int = 1,
        pool_max: int = 8,
        connect_timeout_seconds: float = 10.0,
    ):
        if _IMPORT_ERROR is not None:
            raise ImportError(
                "PostgresStateStore requires the optional postgres extra: "
                "pip install recto[postgres]"
            ) from _IMPORT_ERROR
        if not schema or not set(schema) <= self._SCHEMA_ALPHABET:
            raise ValueError(
                "schema must be a lowercase identifier "
                f"([a-z0-9_]); got {schema!r}"
            )
        self._schema = schema
        self._dir = state_dir if state_dir is not None else default_state_dir()
        self._registry_rlock = threading.RLock()
        # registry_lock's own state, touched only while _registry_rlock is held: the nesting depth and the pooled
        # connection whose open transaction holds the advisory lock for the outermost holder.
        self._registry_depth = 0
        self._registry_conn_cm: Any = None
        # One advisory-lock key per schema: instances on the same schema share it, other schemas never contend.
        self._registry_lock_key = int.from_bytes(
            hashlib.sha256(f"recto-registry:{schema}".encode("ascii")).digest()[:8], "big", signed=True)
        self._pool = ConnectionPool(
            dsn,
            min_size=pool_min,
            max_size=pool_max,
            open=True,
            timeout=connect_timeout_seconds,
        )
        # Fail-fast: surface an unreachable / misconfigured database at
        # construction time (launcher fail-loud posture), not 30s into
        # the first request. wait() blocks until min_size connections
        # are live or raises PoolTimeout.
        try:
            self._pool.wait(timeout=connect_timeout_seconds)
            self._ensure_schema()
        except BaseException:
            self._pool.close()   # a store that failed to open leaves no pool behind
            raise

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the connection pool. Idempotent."""
        self._pool.close()

    def __enter__(self) -> PostgresStateStore:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _ensure_schema(self) -> None:
        with self._pool.connection() as conn:
            conn.execute(_DDL.format(schema=self._schema))

    def _q(self, sql: str) -> str:
        return sql.format(schema=self._schema)

    @property
    def state_dir(self) -> Path:
        """Local directory for file-based compat surfaces (profile
        master-identity). NOT where this backend persists its own
        state -- see the module docstring's known-bounded-gap note."""
        return self._dir

    # ------------------------------------------------------------------
    # Phones
    # ------------------------------------------------------------------

    @staticmethod
    def _phone_to_doc(p: PhoneRegistration) -> dict[str, Any]:
        d = asdict(p)
        d["supported_algorithms"] = list(d["supported_algorithms"])
        return d

    @staticmethod
    def _phone_from_doc(d: dict[str, Any]) -> PhoneRegistration:
        d = dict(d)
        d["supported_algorithms"] = tuple(d.get("supported_algorithms") or ())
        d["member_bindings"] = member_bindings_from_doc(d.get("member_bindings"))
        return PhoneRegistration(**d)

    def register_phone(self, reg: PhoneRegistration) -> PhoneRegistration:
        # THE KEY IS THE IDENTITY (2026-09-21): the same rule as the file store,
        # in one transaction -- a key already held keeps its row's id.
        with self._pool.connection() as conn:
            row = conn.execute(
                self._q(
                    "SELECT doc FROM {schema}.phones "
                    "WHERE doc->>'public_key_b64u' = %s LIMIT 1"
                ),
                (reg.public_key_b64u,),
            ).fetchone()
            existing = self._phone_from_doc(row[0]) if row else None
            stored = _merge_onto_existing(existing, reg)
            conn.execute(
                self._q(
                    "INSERT INTO {schema}.phones (phone_id, doc) "
                    "VALUES (%s, %s) "
                    "ON CONFLICT (phone_id) DO UPDATE SET doc = EXCLUDED.doc"
                ),
                (stored.phone_id, Jsonb(self._phone_to_doc(stored))),
            )
        return stored

    def get_phone(self, phone_id: str) -> PhoneRegistration | None:
        with self._pool.connection() as conn:
            row = conn.execute(
                self._q("SELECT doc FROM {schema}.phones WHERE phone_id = %s"),
                (phone_id,),
            ).fetchone()
        return self._phone_from_doc(row[0]) if row else None

    def list_phones(self) -> list[PhoneRegistration]:
        with self._pool.connection() as conn:
            rows = conn.execute(
                self._q("SELECT doc FROM {schema}.phones ORDER BY phone_id")
            ).fetchall()
        return [self._phone_from_doc(r[0]) for r in rows]

    def revoke_phone(self, phone_id: str) -> bool:
        """Delete the phone AND cascade its sessions + pending requests
        (parity with the file backend's revoke semantics)."""
        with self._pool.connection() as conn:
            deleted = conn.execute(
                self._q(
                    "DELETE FROM {schema}.phones WHERE phone_id = %s "
                    "RETURNING phone_id"
                ),
                (phone_id,),
            ).fetchone()
            if deleted is None:
                return False
            conn.execute(
                self._q(
                    "DELETE FROM {schema}.sessions "
                    "WHERE doc->>'phone_id' = %s"
                ),
                (phone_id,),
            )
            conn.execute(
                self._q("DELETE FROM {schema}.pending WHERE phone_id = %s"),
                (phone_id,),
            )
            return True

    # ------------------------------------------------------------------
    # Sessions
    # ------------------------------------------------------------------

    def get_session(self, service: str, secret: str) -> Session | None:
        with self._pool.connection() as conn:
            row = conn.execute(
                self._q(
                    "SELECT doc FROM {schema}.sessions "
                    "WHERE service = %s AND secret = %s"
                ),
                (service, secret),
            ).fetchone()
            if row is None:
                return None
            sess = Session(**row[0])
            if sess.is_expired or sess.is_exhausted:
                # Lazy purge -- parity with the file backend: expiry /
                # exhaustion is normal, the caller re-issues.
                conn.execute(
                    self._q(
                        "DELETE FROM {schema}.sessions "
                        "WHERE service = %s AND secret = %s"
                    ),
                    (service, secret),
                )
                return None
            return sess

    def put_session(self, sess: Session) -> None:
        with self._pool.connection() as conn:
            conn.execute(
                self._q(
                    "INSERT INTO {schema}.sessions "
                    "(service, secret, doc, expires_at_unix) "
                    "VALUES (%s, %s, %s, %s) "
                    "ON CONFLICT (service, secret) DO UPDATE "
                    "SET doc = EXCLUDED.doc, "
                    "    expires_at_unix = EXCLUDED.expires_at_unix"
                ),
                (
                    sess.service,
                    sess.secret,
                    Jsonb(asdict(sess)),
                    sess.expires_at_unix,
                ),
            )

    def increment_session_uses(
        self, service: str, secret: str
    ) -> Session | None:
        """Atomic single-statement increment -- correct under N
        concurrent instances without SELECT FOR UPDATE."""
        with self._pool.connection() as conn:
            row = conn.execute(
                self._q(
                    "UPDATE {schema}.sessions "
                    "SET doc = jsonb_set(doc, '{{uses_so_far}}', "
                    "    to_jsonb(((doc->>'uses_so_far')::int) + 1)) "
                    "WHERE service = %s AND secret = %s "
                    "RETURNING doc"
                ),
                (service, secret),
            ).fetchone()
        return Session(**row[0]) if row else None

    # ------------------------------------------------------------------
    # Pending requests
    # ------------------------------------------------------------------

    @staticmethod
    def _pending_from_doc(d: dict[str, Any]) -> PendingRequest:
        d = dict(d)
        ac = d.get("app_context")
        if isinstance(ac, dict):
            d["app_context"] = AppContext(**ac)
        return PendingRequest(**d)

    def _purge_expired(self, conn: Any, table: str) -> None:
        conn.execute(
            self._q(
                "DELETE FROM {schema}." + table + " WHERE expires_at_unix <= %s"
            ),
            (int(time.time()),),
        )

    def add_pending(self, req: PendingRequest) -> None:
        with self._pool.connection() as conn:
            conn.execute(
                self._q(
                    "INSERT INTO {schema}.pending "
                    "(request_id, phone_id, doc, expires_at_unix) "
                    "VALUES (%s, %s, %s, %s) "
                    "ON CONFLICT (request_id) DO UPDATE "
                    "SET phone_id = EXCLUDED.phone_id, "
                    "    doc = EXCLUDED.doc, "
                    "    expires_at_unix = EXCLUDED.expires_at_unix"
                ),
                (
                    req.request_id,
                    req.phone_id,
                    Jsonb(asdict(req)),
                    req.expires_at_unix,
                ),
            )

    def list_pending_for_phone(self, phone_id: str) -> list[PendingRequest]:
        with self._pool.connection() as conn:
            self._purge_expired(conn, "pending")
            rows = conn.execute(
                self._q(
                    "SELECT doc FROM {schema}.pending "
                    "WHERE phone_id = %s "
                    "ORDER BY (doc->>'requested_at_unix')::bigint"
                ),
                (phone_id,),
            ).fetchall()
        return [self._pending_from_doc(r[0]) for r in rows]

    def take_pending(self, request_id: str) -> PendingRequest | None:
        """Bare pop -- deliberately NO expiry guard, matching the file
        backend: the server's respond path interprets an expired
        request itself (distinct error from not-found). Expired rows
        are purged at list time."""
        with self._pool.connection() as conn:
            row = conn.execute(
                self._q(
                    "DELETE FROM {schema}.pending "
                    "WHERE request_id = %s "
                    "RETURNING doc"
                ),
                (request_id,),
            ).fetchone()
        return self._pending_from_doc(row[0]) if row else None

    # ------------------------------------------------------------------
    # Result stores (one table, four families)
    # ------------------------------------------------------------------

    def _put_result(self, kind: str, request_id: str, result: Any) -> None:
        with self._pool.connection() as conn:
            conn.execute(
                self._q(
                    "INSERT INTO {schema}.results "
                    "(kind, request_id, doc, expires_at_unix) "
                    "VALUES (%s, %s, %s, %s) "
                    "ON CONFLICT (kind, request_id) DO UPDATE "
                    "SET doc = EXCLUDED.doc, "
                    "    expires_at_unix = EXCLUDED.expires_at_unix"
                ),
                (kind, request_id, Jsonb(asdict(result)), result.expires_at_unix),
            )

    def _get_result(self, kind: str, request_id: str) -> dict[str, Any] | None:
        with self._pool.connection() as conn:
            self._purge_expired(conn, "results")
            row = conn.execute(
                self._q(
                    "SELECT doc FROM {schema}.results "
                    "WHERE kind = %s AND request_id = %s"
                ),
                (kind, request_id),
            ).fetchone()
        return row[0] if row else None

    def _take_result(self, kind: str, request_id: str) -> dict[str, Any] | None:
        """Single-use take: atomic DELETE ... RETURNING. The expiry
        guard keeps a raced purge correct across instances."""
        with self._pool.connection() as conn:
            row = conn.execute(
                self._q(
                    "DELETE FROM {schema}.results "
                    "WHERE kind = %s AND request_id = %s "
                    "  AND expires_at_unix > %s "
                    "RETURNING doc"
                ),
                (kind, request_id, int(time.time())),
            ).fetchone()
        return row[0] if row else None

    # Capability results
    def put_capability_result(self, result: CapabilityResult) -> None:
        self._put_result(_KIND_CAPABILITY, result.request_id, result)

    def get_capability_result(self, request_id: str) -> CapabilityResult | None:
        d = self._get_result(_KIND_CAPABILITY, request_id)
        return CapabilityResult(**d) if d else None

    def take_capability_result(self, request_id: str) -> CapabilityResult | None:
        d = self._take_result(_KIND_CAPABILITY, request_id)
        return CapabilityResult(**d) if d else None

    # Profile-create results
    def put_profile_create_result(self, result: ProfileCreateResult) -> None:
        self._put_result(_KIND_PROFILE_CREATE, result.request_id, result)

    def get_profile_create_result(
        self, request_id: str
    ) -> ProfileCreateResult | None:
        d = self._get_result(_KIND_PROFILE_CREATE, request_id)
        return ProfileCreateResult(**d) if d else None

    def take_profile_create_result(
        self, request_id: str
    ) -> ProfileCreateResult | None:
        d = self._take_result(_KIND_PROFILE_CREATE, request_id)
        return ProfileCreateResult(**d) if d else None

    # Profile-add-device results
    def put_profile_add_device_result(
        self, result: ProfileAddDeviceResult
    ) -> None:
        self._put_result(_KIND_PROFILE_ADD_DEVICE, result.request_id, result)

    def get_profile_add_device_result(
        self, request_id: str
    ) -> ProfileAddDeviceResult | None:
        d = self._get_result(_KIND_PROFILE_ADD_DEVICE, request_id)
        return ProfileAddDeviceResult(**d) if d else None

    def take_profile_add_device_result(
        self, request_id: str
    ) -> ProfileAddDeviceResult | None:
        d = self._take_result(_KIND_PROFILE_ADD_DEVICE, request_id)
        return ProfileAddDeviceResult(**d) if d else None

    # Profile-revoke-device results
    def put_profile_revoke_device_result(
        self, result: ProfileRevokeDeviceResult
    ) -> None:
        self._put_result(_KIND_PROFILE_REVOKE_DEVICE, result.request_id, result)

    def get_profile_revoke_device_result(
        self, request_id: str
    ) -> ProfileRevokeDeviceResult | None:
        d = self._get_result(_KIND_PROFILE_REVOKE_DEVICE, request_id)
        return ProfileRevokeDeviceResult(**d) if d else None

    def take_profile_revoke_device_result(
        self, request_id: str
    ) -> ProfileRevokeDeviceResult | None:
        d = self._take_result(_KIND_PROFILE_REVOKE_DEVICE, request_id)
        return ProfileRevokeDeviceResult(**d) if d else None

    # ------------------------------------------------------------------
    # Operator pubkey / vault root
    # ------------------------------------------------------------------

    def put_operator_pubkey(self, pubkey: bytes) -> None:
        if pubkey is None or len(pubkey) != 64:
            raise ValueError(
                f"operator pubkey must be 64 bytes (uncompressed X||Y); "
                f"got {len(pubkey) if pubkey is not None else 0}"
            )
        with self._pool.connection() as conn:
            conn.execute(
                self._q(
                    "INSERT INTO {schema}.vault_root (id, pubkey_hex) "
                    "VALUES (1, %s) "
                    "ON CONFLICT (id) DO UPDATE "
                    "SET pubkey_hex = EXCLUDED.pubkey_hex"
                ),
                (pubkey.hex(),),
            )

    # ------------------------------------------------------------------
    # Genesis members (5c).
    # ------------------------------------------------------------------
    #
    # NOTE FOR WHOEVER TOUCHES THIS: the Postgres arm of this seam has NEVER
    # RUN IN CI (24 of the suite's 41 skips are `RECTO_TEST_POSTGRES_DSN not
    # set`, measured 2026-08-18). These three methods mirror the file backend
    # and are covered by tests only on the file side. **Treat that as an
    # untested path until a Postgres arm exists**, and do not read a green
    # suite as evidence they work.

    def put_genesis_member(
        self, kind: str, pubkey: bytes, algorithm: str = GENESIS_LEGACY_ALGORITHM
    ) -> None:
        kind = (kind or "").strip().lower()
        if not kind or not kind.replace("-", "").isalnum():
            raise ValueError(f"genesis member kind must be alphanumeric; got {kind!r}")
        algo = validate_genesis_pubkey(pubkey, algorithm)
        with self._pool.connection() as conn:
            conn.execute(
                self._q(
                    "INSERT INTO {schema}.genesis_members "
                    "(kind, pubkey_hex, algorithm) "
                    "VALUES (%s, %s, %s) "
                    "ON CONFLICT (kind) DO UPDATE "
                    "SET pubkey_hex = EXCLUDED.pubkey_hex, "
                    "    algorithm  = EXCLUDED.algorithm"
                ),
                (kind, pubkey.hex(), algo),
            )

    def get_genesis_member(self, kind: str) -> bytes | None:
        return self.list_genesis_members().get((kind or "").strip().lower())

    def get_genesis_member_algorithm(self, kind: str) -> str | None:
        m = self.list_genesis_members_full().get((kind or "").strip().lower())
        return m.algorithm if m else None

    def list_genesis_members(self) -> dict[str, bytes]:
        return {k: m.pubkey for k, m in self.list_genesis_members_full().items()}

    def list_genesis_members_full(self) -> dict[str, GenesisMember]:
        return self._read_genesis_members()[0]

    def list_unreadable_genesis_members(self) -> dict[str, str]:
        return self._read_genesis_members()[1]

    def _read_genesis_members(
        self,
    ) -> tuple[dict[str, GenesisMember], dict[str, str]]:
        with self._pool.connection() as conn:
            rows = conn.execute(
                self._q(
                    "SELECT kind, pubkey_hex, algorithm "
                    "FROM {schema}.genesis_members"
                )
            ).fetchall()
        good: dict[str, GenesisMember] = {}
        bad: dict[str, str] = {}
        for kind, hexed, algo in rows or []:
            try:
                pk = bytes.fromhex(hexed)
            except (ValueError, TypeError):
                bad[kind] = "stored pubkey is not valid hex"
                continue
            # Same rule as the file backend: a row whose length contradicts
            # its algorithm is NOT repaired -- repairing means guessing which
            # field is true. It is RECORDED, because an unreadable member is
            # a different fact from an absent one.
            try:
                algo = validate_genesis_pubkey(pk, algo or GENESIS_LEGACY_ALGORITHM)
            except ValueError as exc:
                bad[kind] = str(exc)
                continue
            good[kind] = GenesisMember(kind=kind, pubkey=pk, algorithm=algo)
        return good, bad

    def get_operator_pubkey(self) -> bytes | None:
        with self._pool.connection() as conn:
            row = conn.execute(
                self._q("SELECT pubkey_hex FROM {schema}.vault_root WHERE id = 1")
            ).fetchone()
        return bytes.fromhex(row[0]) if row else None

    def is_vault_bootstrapped(self) -> bool:
        return self.get_operator_pubkey() is not None

    # ------------------------------------------------------------------
    # Capability revocations
    # ------------------------------------------------------------------

    def add_revocation(self, entry: RevocationEntry) -> None:
        with self._pool.connection() as conn:
            conn.execute(
                self._q(
                    "INSERT INTO {schema}.revocations "
                    "(jti, doc, original_exp_unix) "
                    "VALUES (%s, %s, %s) "
                    "ON CONFLICT (jti) DO UPDATE "
                    "SET doc = EXCLUDED.doc, "
                    "    original_exp_unix = EXCLUDED.original_exp_unix"
                ),
                (entry.jti, Jsonb(asdict(entry)), entry.original_exp_unix),
            )

    def _purge_expired_revocations(self, conn: Any) -> None:
        # A revocation entry ages out once the original JWT's exp has
        # passed -- verify_jws already rejects such a JWT for being
        # expired, so the entry is no longer load-bearing.
        conn.execute(
            self._q(
                "DELETE FROM {schema}.revocations "
                "WHERE original_exp_unix <= %s"
            ),
            (int(time.time()),),
        )

    def is_revoked(self, jti: str) -> bool:
        with self._pool.connection() as conn:
            self._purge_expired_revocations(conn)
            row = conn.execute(
                self._q("SELECT 1 FROM {schema}.revocations WHERE jti = %s"),
                (jti,),
            ).fetchone()
        return row is not None

    def list_revocations(self) -> list[RevocationEntry]:
        with self._pool.connection() as conn:
            self._purge_expired_revocations(conn)
            rows = conn.execute(
                self._q("SELECT doc FROM {schema}.revocations ORDER BY jti")
            ).fetchall()
        return [RevocationEntry(**r[0]) for r in rows]

    # ------------------------------------------------------------------
    # One-time challenges (SQL-backed; DELETE ... RETURNING take
    # semantics so consumption is multi-instance-atomic and a pairing
    # code survives replica death -- the 2026-07-20 field lesson)
    # ------------------------------------------------------------------

    _CHALLENGE_KIND_REGISTRATION = "registration"
    _CHALLENGE_KIND_PAIRING_CODE = "pairing_code"
    # THE MEMBER PLANE (2026-09-30): the same table, two more kinds - no schema change.
    _CHALLENGE_KIND_MEMBER_PAIRING_CODE = "member_pairing_code"
    _CHALLENGE_KIND_MEMBER_REGISTRATION = "member_registration"
    _CHALLENGE_KIND_OWNER_REGISTRATION = "owner_registration"

    def _issue_one_time(self, kind: str, value: str, ttl_seconds: int) -> int:
        exp = int(time.time()) + ttl_seconds
        with self._pool.connection() as conn:
            self._purge_expired_challenges(conn)
            # ON CONFLICT refreshes expiry -- matches the file backend,
            # where re-issuing an identical 6-digit code overwrites the
            # dict entry (collision acceptable for personal-use).
            conn.execute(
                self._q(
                    "INSERT INTO {schema}.challenges "
                    "(kind, value, expires_at_unix) VALUES (%s, %s, %s) "
                    "ON CONFLICT (kind, value) DO UPDATE "
                    "SET expires_at_unix = EXCLUDED.expires_at_unix"
                ),
                (kind, value, exp),
            )
        return exp

    def _consume_one_time(self, kind: str, value: str) -> bool:
        now = int(time.time())
        with self._pool.connection() as conn:
            row = conn.execute(
                self._q(
                    "DELETE FROM {schema}.challenges "
                    "WHERE kind = %s AND value = %s "
                    "RETURNING expires_at_unix"
                ),
                (kind, value),
            ).fetchone()
        return row is not None and now < row[0]

    def _purge_expired_challenges(self, conn: Any) -> None:
        conn.execute(
            self._q(
                "DELETE FROM {schema}.challenges WHERE expires_at_unix <= %s"
            ),
            (int(time.time()),),
        )

    def issue_challenge(self, ttl_seconds: int = 60) -> tuple[str, int]:
        c = (
            base64.urlsafe_b64encode(secrets.token_bytes(32))
            .rstrip(b"=")
            .decode("ascii")
        )
        exp = self._issue_one_time(
            self._CHALLENGE_KIND_REGISTRATION, c, ttl_seconds
        )
        return c, exp

    def consume_challenge(self, challenge: str) -> bool:
        return self._consume_one_time(
            self._CHALLENGE_KIND_REGISTRATION, challenge
        )

    def issue_pairing_code(self, ttl_seconds: int = 300) -> tuple[str, int]:
        code = self._unique_code()
        exp = self._issue_one_time(
            self._CHALLENGE_KIND_PAIRING_CODE, code, ttl_seconds
        )
        return code, exp

    def _unique_code(self) -> str:
        # Owner and member codes share one 6-digit space and the challenge GET tries the owner code first: a new code
        # is unique across both live kinds.
        now = int(time.time())
        with self._pool.connection() as conn:
            for _ in range(64):
                code = f"{secrets.randbelow(1_000_000):06d}"
                row = conn.execute(
                    self._q(
                        "SELECT 1 FROM {schema}.challenges WHERE value = %s AND kind IN (%s, %s) "
                        "AND expires_at_unix > %s"
                    ),
                    (code, self._CHALLENGE_KIND_PAIRING_CODE, self._CHALLENGE_KIND_MEMBER_PAIRING_CODE, now),
                ).fetchone()
                if row is None:
                    return code
        raise RuntimeError("no free pairing code after 64 draws")

    def consume_pairing_code(self, code: str) -> bool:
        return self._consume_one_time(
            self._CHALLENGE_KIND_PAIRING_CODE, code
        )

    def issue_member_pairing_code(
        self, ttl_seconds: int = 300, binding: tuple[str, str] | None = None
    ) -> tuple[str, int]:
        code = self._unique_code()
        return code, self._issue_bound(self._CHALLENGE_KIND_MEMBER_PAIRING_CODE, code, ttl_seconds, binding)

    def consume_member_pairing_code(self, code: str) -> tuple[str, str] | None:
        return self._consume_bound(self._CHALLENGE_KIND_MEMBER_PAIRING_CODE, code)

    def issue_member_challenge(
        self, ttl_seconds: int = 60, binding: tuple[str, str] | None = None
    ) -> tuple[str, int]:
        c = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
        return c, self._issue_bound(self._CHALLENGE_KIND_MEMBER_REGISTRATION, c, ttl_seconds, binding)

    def _issue_bound(self, kind: str, value: str, ttl_seconds: int, binding: tuple[str, str] | None) -> int:
        """A one-time value that carries its member binding (consumer, subject) in the same row."""
        exp = int(time.time()) + ttl_seconds
        doc = None if binding is None else json.dumps({"consumer": binding[0], "subject": binding[1]})
        with self._pool.connection() as conn:
            self._purge_expired_challenges(conn)
            conn.execute(
                self._q(
                    "INSERT INTO {schema}.challenges (kind, value, expires_at_unix, binding) "
                    "VALUES (%s, %s, %s, %s::jsonb) "
                    "ON CONFLICT (kind, value) DO UPDATE "
                    "SET expires_at_unix = EXCLUDED.expires_at_unix, binding = EXCLUDED.binding"
                ),
                (kind, value, exp, doc),
            )
        return exp

    def _consume_bound(self, kind: str, value: str) -> tuple[str, str] | None:
        """Spend a one-time value; its binding if it was live, else None."""
        now = int(time.time())
        with self._pool.connection() as conn:
            row = conn.execute(
                self._q(
                    "DELETE FROM {schema}.challenges WHERE kind = %s AND value = %s "
                    "RETURNING expires_at_unix, binding"
                ),
                (kind, value),
            ).fetchone()
        if row is None or now >= row[0] or not row[1]:
            return None
        b = row[1] if isinstance(row[1], dict) else json.loads(row[1])
        return (str(b["consumer"]), str(b["subject"]))

    def is_member_challenge(self, challenge: str) -> bool:
        now = int(time.time())
        with self._pool.connection() as conn:
            row = conn.execute(
                self._q("SELECT expires_at_unix FROM {schema}.challenges WHERE kind = %s AND value = %s"),
                (self._CHALLENGE_KIND_MEMBER_REGISTRATION, challenge),
            ).fetchone()
        return row is not None and now < row[0]

    def consume_member_challenge(self, challenge: str) -> tuple[str, str] | None:
        return self._consume_bound(self._CHALLENGE_KIND_MEMBER_REGISTRATION, challenge)

    # THE OWNER SLOTS (hard rule 14.4, amended): an owner code's challenge is its own kind - the same table, no schema
    # change. The genesis marker lives in registry_meta; the owner-enroll records in results (kind owner_enroll).
    def issue_owner_challenge(self, ttl_seconds: int = 60) -> tuple[str, int]:
        c = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
        return c, self._issue_one_time(self._CHALLENGE_KIND_OWNER_REGISTRATION, c, ttl_seconds)

    def is_owner_challenge(self, challenge: str) -> bool:
        now = int(time.time())
        with self._pool.connection() as conn:
            row = conn.execute(
                self._q("SELECT expires_at_unix FROM {schema}.challenges WHERE kind = %s AND value = %s"),
                (self._CHALLENGE_KIND_OWNER_REGISTRATION, challenge),
            ).fetchone()
        return row is not None and now < row[0]

    def consume_owner_challenge(self, challenge: str) -> bool:
        return self._consume_one_time(self._CHALLENGE_KIND_OWNER_REGISTRATION, challenge)

    def get_owner_genesis(self) -> str | None:
        with self._pool.connection() as conn:
            row = conn.execute(
                self._q("SELECT value->>'state' FROM {schema}.registry_meta WHERE key = %s"),
                (_META_OWNER_GENESIS,),
            ).fetchone()
        if row is None:
            return None
        if row[0] not in OWNER_GENESIS_STATES:
            raise ValueError(f"registry_meta owner_genesis holds {row[0]!r}; expected one of {OWNER_GENESIS_STATES}")
        return row[0]

    def set_owner_genesis(self, state: str) -> None:
        if state not in OWNER_GENESIS_STATES:
            raise ValueError(f"owner genesis must be one of {OWNER_GENESIS_STATES}; got {state!r}")
        with self._pool.connection() as conn:
            conn.execute(
                self._q(
                    "INSERT INTO {schema}.registry_meta (key, value) VALUES (%s, %s) "
                    "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
                ),
                (_META_OWNER_GENESIS, Jsonb({"state": state})),
            )

    def put_owner_enroll(self, record: dict[str, Any]) -> None:
        with self._pool.connection() as conn:
            conn.execute(
                self._q(
                    "INSERT INTO {schema}.results (kind, request_id, doc, expires_at_unix) "
                    "VALUES (%s, %s, %s, %s) "
                    "ON CONFLICT (kind, request_id) DO UPDATE "
                    "SET doc = EXCLUDED.doc, expires_at_unix = EXCLUDED.expires_at_unix"
                ),
                (_KIND_OWNER_ENROLL, record["request_id"], Jsonb(dict(record)), int(record["expires_at_unix"])),
            )

    def get_owner_enroll(self, request_id: str) -> dict[str, Any] | None:
        return self._get_result(_KIND_OWNER_ENROLL, request_id)

    def list_owner_enrolls(self) -> list[dict[str, Any]]:
        with self._pool.connection() as conn:
            self._purge_expired(conn, "results")
            rows = conn.execute(
                self._q("SELECT doc FROM {schema}.results WHERE kind = %s ORDER BY request_id"),
                (_KIND_OWNER_ENROLL,),
            ).fetchall()
        return [r[0] for r in rows]

    def delete_owner_enroll(self, request_id: str) -> dict[str, Any] | None:
        return self._take_result(_KIND_OWNER_ENROLL, request_id)

    def update_phone_push(self, phone_id: str, push_token: str, push_platform: str) -> bool:
        # One UPDATE on a row that exists: a removed phone is never written back (the INSERT ... ON CONFLICT upsert
        # register_phone does would re-insert it).
        with self._pool.connection() as conn:
            row = conn.execute(
                self._q(
                    "UPDATE {schema}.phones SET doc = doc || %s WHERE phone_id = %s RETURNING phone_id"
                ),
                (Jsonb({"push_token": push_token, "push_platform": push_platform,
                        "last_seen_unix": int(time.time())}), phone_id),
            ).fetchone()
        return row is not None

    def replace_phone(self, occupant_phone_id: str, reg: PhoneRegistration) -> PhoneRegistration | None:
        # The displacement in ONE transaction: the occupant's row, sessions and queue go and the incoming row lands, or
        # nothing changes.
        with self._pool.connection() as conn:
            with conn.transaction():
                deleted = conn.execute(
                    self._q("DELETE FROM {schema}.phones WHERE phone_id = %s RETURNING phone_id"),
                    (occupant_phone_id,),
                ).fetchone()
                if deleted is None:
                    return None
                conn.execute(self._q("DELETE FROM {schema}.sessions WHERE doc->>'phone_id' = %s"), (occupant_phone_id,))
                conn.execute(self._q("DELETE FROM {schema}.pending WHERE phone_id = %s"), (occupant_phone_id,))
                row = conn.execute(
                    self._q("SELECT doc FROM {schema}.phones WHERE doc->>'public_key_b64u' = %s LIMIT 1"),
                    (reg.public_key_b64u,),
                ).fetchone()
                stored = _merge_onto_existing(self._phone_from_doc(row[0]) if row else None, reg)
                conn.execute(
                    self._q(
                        "INSERT INTO {schema}.phones (phone_id, doc) VALUES (%s, %s) "
                        "ON CONFLICT (phone_id) DO UPDATE SET doc = EXCLUDED.doc"
                    ),
                    (stored.phone_id, Jsonb(self._phone_to_doc(stored))),
                )
        return stored

    def has_any_session(self) -> bool:
        with self._pool.connection() as conn:
            row = conn.execute(self._q("SELECT 1 FROM {schema}.sessions LIMIT 1")).fetchone()
        return row is not None

    # THE USER-VAULT GRANTS (Postgres backend).
    def put_user_vault_grant(self, grant: dict[str, Any]) -> None:
        r = grant["record"]
        with self._pool.connection() as conn:
            conn.execute(
                self._q("DELETE FROM {schema}.user_vault_grants WHERE not_after <= %s"), (int(time.time()),))
            conn.execute(
                self._q(
                    "INSERT INTO {schema}.user_vault_grants "
                    "(grant_id, consumer, subject, agent_handle, key, not_after, doc) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s) "
                    "ON CONFLICT (consumer, subject, agent_handle, key) DO UPDATE "
                    "SET grant_id = EXCLUDED.grant_id, not_after = EXCLUDED.not_after, doc = EXCLUDED.doc"
                ),
                (grant["grant_id"], r["consumer"], r["subject"], r["agent_handle"], r["key"],
                 int(r["not_after"]), Jsonb(dict(grant))),
            )

    def get_user_vault_grant(self, grant_id: str) -> dict[str, Any] | None:
        with self._pool.connection() as conn:
            row = conn.execute(
                self._q("SELECT doc FROM {schema}.user_vault_grants WHERE grant_id = %s"), (grant_id,)).fetchone()
        return None if row is None else dict(row[0])

    def list_user_vault_grants(self, consumer: str, subject: str) -> list[dict[str, Any]]:
        with self._pool.connection() as conn:
            rows = conn.execute(
                self._q("SELECT doc FROM {schema}.user_vault_grants WHERE consumer = %s AND subject = %s "
                        "ORDER BY grant_id"),
                (consumer, subject),
            ).fetchall()
        return [dict(r[0]) for r in rows]

    @contextmanager
    def registry_lock(self) -> Iterator[None]:
        # The process lock first; then, for the OUTERMOST holder only, one pooled connection opens a transaction and
        # takes a transaction-scoped advisory lock on the schema's key, so every instance sharing the database
        # serializes. The lock ends with that transaction - at commit or rollback, or when the server ends the session
        # - so no unlock statement can miss or land on another server session behind a pooler. The locked work runs on
        # its own pooled connections, never inside this transaction. Nested holds on the same thread reuse the one
        # hold: a second connection would wait on the first for ever. Both waits are bounded.
        deadline = time.monotonic() + REGISTRY_LOCK_WAIT_SECONDS
        if not self._registry_rlock.acquire(timeout=REGISTRY_LOCK_WAIT_SECONDS):
            raise RegistryLockUnavailable(
                f"the registry lock of schema {self._schema!r} is held by another thread of this process")
        try:
            if self._registry_depth == 0:
                # What is left of the one deadline, in milliseconds. Never 0: in Postgres a lock_timeout of 0 means
                # no timeout at all.
                left_ms = int((deadline - time.monotonic()) * 1000)
                if left_ms < 1:
                    raise RegistryLockUnavailable(
                        f"the registry lock of schema {self._schema!r} is held by another thread of this process")
                cm = self._pool.connection()
                conn = cm.__enter__()
                try:
                    # This transaction is idle by design while the body works, and its one statement may wait: no
                    # role timeout cuts it off - lock_timeout is the only bound on the wait.
                    conn.execute("SET LOCAL idle_in_transaction_session_timeout = 0")
                    conn.execute("SET LOCAL statement_timeout = 0")
                    if conn.info.server_version >= 170000:
                        conn.execute("SET LOCAL transaction_timeout = 0")
                    conn.execute(f"SET LOCAL lock_timeout = '{left_ms}ms'")
                    conn.execute("SELECT pg_advisory_xact_lock(%s)", (self._registry_lock_key,))
                except BaseException as exc:
                    cm.__exit__(*sys.exc_info())   # rolls back (ending any lock taken) and returns the connection
                    if getattr(exc, "sqlstate", None) == "55P03":   # lock_not_available
                        raise RegistryLockUnavailable(
                            f"the registry lock of schema {self._schema!r} was not granted within "
                            f"{REGISTRY_LOCK_WAIT_SECONDS} s - another holder keeps it (see pg_locks)") from exc
                    raise
                self._registry_conn_cm = cm
            self._registry_depth += 1
            try:
                yield
            finally:
                self._registry_depth -= 1
                if self._registry_depth == 0:
                    cm, self._registry_conn_cm = self._registry_conn_cm, None
                    try:
                        cm.__exit__(None, None, None)   # commits: the lock ends with the transaction
                    except Exception:
                        # The locked work already landed on its own connections.
                        logging.getLogger("recto.bootloader.state").error(
                            "registry lock: ending the lock's transaction failed - the lock is held until the server "
                            "ends that session (at once after a rollback or a clean close; later if the server has "
                            "not noticed a lost client)", exc_info=True)
        finally:
            self._registry_rlock.release()
