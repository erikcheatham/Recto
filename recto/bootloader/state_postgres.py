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
import secrets
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

from recto.bootloader.state import (
    GENESIS_LEGACY_ALGORITHM,
    AppContext,
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
    default_state_dir,
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
"""

# Result-table ``kind`` discriminators. One table, four result families
# -- the families share identical storage semantics (put / get / take /
# TTL purge), differing only in dataclass shape, which the JSONB doc
# carries.
_KIND_CAPABILITY = "capability"
_KIND_PROFILE_CREATE = "profile_create"
_KIND_PROFILE_ADD_DEVICE = "profile_add_device"
_KIND_PROFILE_REVOKE_DEVICE = "profile_revoke_device"


class PostgresStateStore(StateStoreBase):
    """StateStoreBase on PostgreSQL (psycopg3 + connection pool).

    Thread-safe by construction: every operation borrows a pooled
    connection and runs in its own transaction; no process-level lock.
    Safe to share across the ThreadingHTTPServer's request threads AND
    across bootloader instances pointed at the same database.
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
        self._pool.wait(timeout=connect_timeout_seconds)
        self._ensure_schema()

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
        return PhoneRegistration(**d)

    def register_phone(self, reg: PhoneRegistration) -> None:
        with self._pool.connection() as conn:
            conn.execute(
                self._q(
                    "INSERT INTO {schema}.phones (phone_id, doc) "
                    "VALUES (%s, %s) "
                    "ON CONFLICT (phone_id) DO UPDATE SET doc = EXCLUDED.doc"
                ),
                (reg.phone_id, Jsonb(self._phone_to_doc(reg))),
            )

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
        code = f"{secrets.randbelow(1_000_000):06d}"
        exp = self._issue_one_time(
            self._CHALLENGE_KIND_PAIRING_CODE, code, ttl_seconds
        )
        return code, exp

    def consume_pairing_code(self, code: str) -> bool:
        return self._consume_one_time(
            self._CHALLENGE_KIND_PAIRING_CODE, code
        )
