"""HTTPS server for the v0.4 bootloader.

Implements the endpoint set defined in `docs/v0.4-protocol.md`:

- POST /v0.4/register
- GET  /v0.4/registration_challenge
- POST /v0.4/issue_session
- GET  /v0.4/pending?phone_id=<id>
- POST /v0.4/respond/<request_id>

Uses stdlib `http.server.ThreadingHTTPServer` + `ssl.SSLContext`. No
extra HTTP-framework dependency. The server is single-process (one
bootloader per service, owned by the launcher); concurrency comes from
the threading mixin handling each request on its own thread.

State access is delegated to `recto.bootloader.state.StateStore`, which
is internally thread-safe. The handler holds a reference to the store
and a few config values via class attributes set at server creation.

Threat model notes are in module docstrings of `state.py` and
`sessions.py`. This module enforces the wire-protocol contract; it does
NOT do rate limiting, brute-force defense, or replay protection beyond
the JWT `jti` and challenge expiry. Production hardening is followup
work tracked in the v0.4 deferred-items list.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
import threading
import time
import uuid
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse
import urllib.error
import urllib.request

from recto.bootloader.clusters import ClusterRegistry, ClusterRegistryError

from recto.bootloader import (
    BootloaderError,
    PendingRequestNotFoundError,
    RegistrationExpiredError,
    UnknownPhoneError,
)
from recto import __version__
from recto.bootloader.sessions import (
    SUPPORTED_ALGORITHMS,
    build_session_issuance_payload,
    verify_jwt,
    verify_signature,
)
from recto.bootloader.state import (
    AppContext,
    CapabilityResult,
    PendingRequest,
    PhoneRegistration,
    ProfileCreateResult,
    RevocationEntry,
    Session,
    StateStore,
    StateStoreBase,
)

__all__ = [
    "BootloaderHandler",
    "BootloaderConfig",
    "ChallengeStore",
    "create_server",
]

PROTOCOL_VERSION = 1

# Signed-poll protocol (2026-08-13, "phone_id split: reference vs
# capability"). The phone signs the ASCII string
#   recto-poll-v1|{phone_id}|{ts}|{path}
# with its enclave key (ts = unix seconds, path = URL path only, e.g.
# "/v0.4/pending") and sends the signature + timestamp as headers on
# every possession-of-phone_id read. Freshness window is +/- this many
# seconds around the server clock.
POLL_SIG_PREFIX = "recto-poll-v1"
POLL_SIG_HEADER = "X-Recto-Phone-Sig"
POLL_SIG_TS_HEADER = "X-Recto-Phone-Ts"
POLL_SIG_FRESHNESS_SECONDS = 120

# The three legal signed_poll_mode values. "advisory" is the DEFAULT:
# Build 12 phones in both stores poll bare, so a hard require would
# brick the shipped app (Hard Rule #1 back-compat). Advisory allows
# every poll and logs the per-poll verdict (signed-valid /
# signed-invalid / unsigned) so an operator can watch the evidence
# window before flipping to "required" (the RECURVE ceremony:
# advisory -> evidence window -> flip -> single redeploy).
SIGNED_POLL_MODES = ("off", "advisory", "required")


def _phone_ref(public_key_b64u: str) -> str:
    """Derive the phone's public reference id from its pubkey.

    ``"pk_" + first 16 hex chars of sha256(raw pubkey bytes)`` where the
    raw bytes are the base64url-DECODED public key. This is the pure
    REFERENCE half of the phone_id split: it names the keypair (the
    actual identity) without being usable as any kind of credential,
    and it is derivable by anyone who holds the public key. Additive
    today; re-keying registries onto it is deferred until
    signed_poll_mode flips to "required".

    Falls back to hashing the ASCII bytes of the string itself when the
    value is not decodable base64url (defensive: registrations are
    validated at pairing time, but test fixtures and pre-validation
    blobs may carry arbitrary strings; a reference derivation must
    never raise).
    """
    try:
        padding = "=" * (-len(public_key_b64u) % 4)
        raw = base64.urlsafe_b64decode(public_key_b64u + padding)
    except Exception:  # noqa: BLE001 - reference derivation never raises
        raw = public_key_b64u.encode("utf-8", errors="replace")
    return "pk_" + hashlib.sha256(raw).hexdigest()[:16]


def _constant_time_compare(a: str, b: str) -> bool:
    """Constant-time string compare for the X-Recto-Agent-Token header
    check. Defends against timing-based agent-token guessing."""
    if len(a) != len(b):
        # Still walk the string to keep the timing roughly constant
        # for length probes; the caller treats the result as boolean.
        result = 1
    else:
        result = 0
    for x, y in zip(a.encode("utf-8"), b.encode("utf-8")):
        result |= x ^ y
    return result == 0


def _connection_key_matches(pattern: str, key: str) -> bool:
    """Does one allowlist pattern admit one (already normalized) key?

    Three shapes, deliberately no regex and no general globbing -- an ACL
    is only as good as the operator's ability to read it at a glance:
      - ``"*"``          -> allow every key (the migration escape hatch)
      - ``"prefix-*"``   -> allow keys starting with ``prefix-``
      - ``"anthropic"``  -> exact match

    Patterns are compared case-insensitively because keys normalize to
    lowercase; an empty or whitespace-only pattern matches nothing.
    """
    pat = (pattern or "").strip().lower()
    if not pat:
        return False
    if pat == "*":
        return True
    if pat.endswith("*"):
        prefix = pat[:-1]
        # A bare "*" is handled above, so prefix is non-empty here.
        return key.startswith(prefix)
    return key == pat


def _registered_algorithm(reg: Any, who: str) -> str:
    """The algorithm a REGISTERED phone signs with, from its stored list.

    GATE 2a (2026-08-17). Four sites read this and each re-implemented the same
    `[0] if list else "ed25519"` fallback -- one value, five places, every copy
    resolving silence to the software path.

    WHY THIS WARNS INSTEAD OF REFUSING, and the distinction is the whole design:
    enrollment now REFUSES an absent or empty list, which binds only phones that
    have not registered yet. This function reads phones that ALREADY EXIST. A
    legacy row with an empty list belongs to a real device -- possibly the
    operator's, which is the root of trust -- and making this fatal would lock
    it out to fix a record-keeping gap. That trade is not worth taking blind.

    So it stays permissive AND becomes VISIBLE, which is the same order that
    worked for the connections ACL today: emit the evidence, watch a window,
    make it fatal once the window is silent. A gate flipped before its evidence
    exists is a gate flipped on a guess.

    WARNING, not INFO, deliberately: this is a defect in stored state, not
    routine traffic, and it must survive a log level set to suppress the ACL
    audit line.
    """
    algos = getattr(reg, "supported_algorithms", None)
    if algos:
        return algos[0]
    logging.getLogger("recto.bootloader.enrollment").warning(
        "registered phone %r has an EMPTY supported_algorithms list; assuming "
        "'ed25519' to keep it working. This row predates the GATE 2a enrollment "
        "refusal (2026-08-17) -- new registrations cannot produce it. Re-enroll "
        "the device to state its algorithm explicitly. While any of these lines "
        "appear, the read path CANNOT be made fatal.",
        who,
    )
    return "ed25519"


# --------------------------------------------------------------------------
# GATE 5b -- bootloader identity derived from the operator key set.
# --------------------------------------------------------------------------

BOOTLOADER_ID_DERIVATION_V1 = "recto-bootloader-id-v1"
BOOTLOADER_ID_PREFIX = "rb1-"

# CROSS-LANGUAGE PARITY PIN. The phone MUST be able to recompute this, and the
# phone is C#. Any reimplementation must reproduce these bytes exactly; the
# repo already uses this pattern for the pair deep-link (see
# recto/qr/pair.py CANONICAL_DEMO_PAIR_URL and its C# sister test).
#   operator pubkey = bytes(range(64))  ->  the value pinned in
#   tests/test_bootloader_identity.py::test_the_cross_language_parity_pin
# Do not "fix" a parity mismatch by editing the pin. The pin is the contract.


def derive_bootloader_id(
    operator_pubkey: bytes | None,
    member_pubkeys: "tuple[bytes, ...] | list[bytes]" = (),
) -> str:
    """Derive a bootloader id from the operator key set.

    WHY THIS EXISTS. `bootloader_id` is the JWT audience. Configured or random,
    it is a NAME THE PHONE IS TOLD -- so a look-alike deployment at any
    hostname can claim any id, and the phone signs against it. Derived, the id
    becomes a CLAIM THE PHONE CAN CHECK: recompute it from the key set and a
    mismatch is arithmetic, not a hostname the operator has to eyeball.

    THE THREE PROPERTIES, each load-bearing:

    * DOMAIN SEPARATED. The hash is prefixed with a version string, so this
      digest can never collide with some other SHA-256 over the same keys.
      Bumping the string is how a v2 derivation stays distinguishable.
    * ORDER INDEPENDENT. Keys are de-duplicated and sorted, so the id depends
      on the SET, not on enumeration order -- which is not stable across
      backends (file vs postgres) and must not change the identity.
    * LENGTH PREFIXED. Each key is preceded by its 4-byte big-endian length.
      Without this, {AB, C} and {A, BC} hash identically -- a concatenation
      ambiguity that is a real (if here unlikely) forgery primitive.

    Returns `rb1-<32 hex chars>` (128 bits). Truncation is deliberate: this is
    an identifier to be compared, displayed, and typed, not a MAC. 128 bits is
    far beyond collision reach for a set of operator keys.

    Raises ValueError if there is no operator pubkey -- an unsealed bootloader
    HAS no derived identity, and returning a plausible-looking string for one
    would be worse than refusing.
    """
    if not operator_pubkey:
        raise ValueError(
            "cannot derive a bootloader id with no operator pubkey: an "
            "unsealed bootloader has no derived identity"
        )
    keys = sorted({bytes(operator_pubkey)} | {bytes(k) for k in member_pubkeys})
    h = hashlib.sha256()
    h.update(BOOTLOADER_ID_DERIVATION_V1.encode("ascii"))
    for k in keys:
        h.update(len(k).to_bytes(4, "big"))
        h.update(k)
    return BOOTLOADER_ID_PREFIX + h.hexdigest()[:32]


# WHICH SEALED MEMBERS ARE PART OF THE IDENTITY -- AN ALLOWLIST, DELIBERATELY.
#
# The bootloader's identity is the DEVICE set: the keys a phone can be shown
# and can check at pairing. The passphrase member is a QUORUM member (tier 3)
# and is deliberately NOT identity: quorum answers "who may authorise", the
# id answers "which bootloader is this", and folding one into the other would
# make sealing a phrase rename the bootloader.
#
# An allowlist rather than an exclusion: a NEW member kind entering the
# identity derivation changes the id of every deployment that seals one --
# that is a decision to make loudly (add the kind here, with a reason), never
# a default inherited by whatever kind someone seals next. Excluded kinds are
# logged at startup so the omission is visible, not silent.
IDENTITY_MEMBER_KINDS = frozenset({"recovery-phone"})


def collect_identity_member_pubkeys(
    members: "Mapping[str, Any]",
) -> "tuple[list[bytes], list[str]]":
    """Split sealed members into (identity pubkeys, excluded kinds).

    `members` is the mapping from `StateStoreBase.list_genesis_members_full`
    (kind -> GenesisMember). Returns the pubkeys of allowlisted kinds in
    sorted-kind order (the derivation re-sorts by key bytes anyway) plus the
    excluded kind names for the startup log.
    """
    identity: list[bytes] = []
    excluded: list[str] = []
    for kind in sorted(members):
        if kind in IDENTITY_MEMBER_KINDS:
            identity.append(bytes(members[kind].pubkey))
        else:
            excluded.append(kind)
    return identity, excluded


class BootloaderConfig:
    """Server-side config values shared across requests.

    Lives on the handler class as a class attribute (set by
    `create_server`). Threading.local would be overkill -- these
    values don't change during the bootloader's lifetime."""

    bootloader_id: str = ""
    # GATE 5b phone-recomputation half: the EXACT inputs that produced the
    # derived `bootloader_id`, snapshotted at the same moment the id was
    # derived (create_server). Emitted to phones at registration as the
    # additive `bootloader_identity` field so the id becomes a claim the
    # phone RECOMPUTES rather than a name it is told. None when the id is
    # not derived (unsealed bootloader) -- the field is then omitted and
    # the phone has no claim to check. Snapshot, not a live read: id and
    # inputs must never disagree, and a member sealed mid-life takes
    # effect at restart exactly like the id itself.
    bootloader_identity_inputs: "dict[str, Any] | None" = None
    # Typed against the seam (StateStoreBase), not the file-backed
    # concrete class -- any backend implementing the contract slots in
    # (file-backed StateStore for single-host installs,
    # PostgresStateStore for load-balanced multi-instance deployments).
    state: StateStoreBase | None = None
    # Silent-push wake dispatcher (recto.bootloader.push.PushDispatcher,
    # production-scale wave C). None = poll-only (current default).
    # When set, every queued PendingRequest fires a best-effort silent
    # wake push to the target phone's registered token; polling stays
    # the fallback path.
    push_dispatcher: Any = None
    # Public URL list emitted to phones at registration as
    # `bootloader_urls` (primary first). Empty = field omitted (v1
    # behavior). Phones persist the list so a future multi-region /
    # failover deployment can move hosts without re-pairing -- the
    # banked multi-bootloader-per-pairing wire extension.
    public_urls: tuple[str, ...] = ()
    challenges: "ChallengeStore | None" = None
    default_session_lifetime_seconds: int = 86400  # 24h
    default_session_max_uses: int = 1000
    # Phase 5 Wave B: pre-shared bearer tokens for external agents
    # submitting capability requests. Map of agent_id -> token; the
    # capability-request endpoint requires both X-Recto-Agent-Id and
    # X-Recto-Agent-Token headers and rejects 401 if they don't match
    # an entry here. Empty dict (default) disables the endpoint
    # entirely — bootloaders that don't issue capabilities to external
    # agents leave it empty, and the endpoint returns 404.
    capability_agent_tokens: dict[str, str] = {}
    # Per-agent REQUESTABLE-action policy, evaluated BEFORE a request
    # is queued for approval. Map of agent_id -> list of action keys
    # that agent may ask for. An agent WITH an entry is deny-by-default:
    # a capability request whose effective action set (groups expanded
    # via the manifest + allow_actions, deny_actions subtracted — the
    # same resolution verifiers use) contains any action outside its
    # list is refused 403 and never reaches the approval queue. An
    # agent WITHOUT an entry is unrestricted at this layer (legacy
    # behavior — the operator's approval remains the gate). This is a
    # pre-carding filter on what may be ASKED, not a grant of anything:
    # nothing here mints authority, it only narrows which requests are
    # allowed to spend the operator's attention.
    capability_agent_requestable: dict[str, list[str]] = {}
    # Operator's expected secp256k1 public key (uncompressed, 64 raw
    # bytes — X || Y, no 0x04 prefix). When set, the bootloader
    # verifies the phone's capability signature recovers to this key
    # before storing the assembled JWS. When None, only the Ed25519
    # paired-phone envelope is checked (development convenience —
    # production deployments MUST set this).
    capability_operator_pubkey: bytes | None = None
    # Default TTL for the resolved CapabilityResult. After resolution,
    # the agent has this long to poll the result endpoint before the
    # JWT is purged. 600s (10 min) is generous for synchronous chat-
    # style flows; bursty fan-outs may need longer.
    capability_result_ttl_seconds: int = 600
    # Phase 5 Wave C part 1: capability action manifest the bootloader
    # serves at GET /v0.4/capability/manifest. Loaded at startup via
    # `recto.capability.manifest.load_manifest`. None means the
    # manifest endpoint returns 404 (bootloaders that don't broker
    # capability auth leave this unset).
    capability_manifest: object | None = None  # ActionManifest | None
    # Phase 5 Wave C part 1: pre-populated map of vault-readable
    # secrets keyed by (service, secret_name) tuple. The
    # `/v0.4/secrets/read` endpoint looks up secrets here after
    # verifying the caller's capability JWT and evaluating the
    # `secret:read` action against the JWT's scope. Operator
    # populates at create_server time from whichever SecretSource
    # backend their deployment uses (dpapi-machine in production,
    # env in dev). Empty dict (default) disables the endpoint --
    # returns 404 -- so bootloaders that don't expose vault secrets
    # via HTTP have zero attack surface. v2 will wire the bootloader
    # directly to recto.secrets.SecretSource implementations for
    # on-demand resolution; v1 keeps the secret-resolution chain
    # in the launcher's existing flow and the bootloader stays a
    # simple authorization layer.
    capability_vault_secrets: dict[tuple[str, str], str] = {}
    # Phase 5 Wave C part 1: revocation list seed for testing. v1
    # accepted in-memory revocation entries via this kwarg; v2 (Wave
    # C part 2) moves the source-of-truth to the StateStore's
    # persistent revocation list (revocations.json under the state
    # dir). This kwarg now seeds the StateStore at create_server
    # time so existing tests keep passing -- production deployments
    # add revocations via POST /v0.4/capability/revoke instead, and
    # they survive bootloader restart.
    capability_revocation_jtis: set[str] = set()
    # Phase 5 Wave C part 2: pre-shared operator token for the
    # POST /v0.4/capability/revoke endpoint. When set, the endpoint
    # requires an `X-Recto-Operator-Token` header with this exact
    # value. When None / empty, the revoke endpoint returns 404 --
    # bootloaders that don't expose revocation via HTTP can run
    # revocation entirely operator-side via direct StateStore writes
    # (or via Wave D's phone-mediated revocation flow when that
    # ships). v1 uses a pre-shared token rather than capability-JWT
    # gating because revocation needs to work for the chicken-and-
    # egg case of "revoke a compromised JWT" -- gating revocation
    # itself behind a JWT would create a cycle. Future iteration
    # may layer capability:revoke-other tier-3 enforcement ON TOP
    # of the operator token (revocation requires BOTH), but v1
    # keeps it simple.
    capability_operator_token: str | None = None
    # Phase 5 Wave C part 3: operator-administered registry of
    # AppContext entries keyed by principal-id. The bootloader injects
    # the matching AppContext into every PendingRequest at queue time
    # so the phone can show the app's icon + name + description at
    # the top of every approval card.
    #
    # Lookup order in the queue handlers:
    #   1. cap_agent_id when set (capability_request flow) -- the
    #      X-Recto-Agent-Id header value identifies which app sent
    #      the request.
    #   2. service when cap_agent_id is None (other phone-rendered
    #      request kinds) -- the supervised child's service name from
    #      service.yaml is the app identifier for non-capability flows.
    #
    # Empty / unset means no AppContext is injected; PendingRequests
    # carry app_context=None and the phone renders an "Unknown app"
    # warning banner. Operator-side discipline is to register every
    # consumer's AppContext at deploy time so operators never see the
    # warning in production.
    principal_apps: dict[str, AppContext] = {}

    # Phase H end-user device pairing (2026-05-19). Map of consumer
    # base URLs (e.g. "https://consumer.example.com") -> the webhook
    # token the consumer's /api/v1/devices/pairing/complete endpoint
    # requires in its X-Openclaw-Token header. The bootloader's new
    # POST /v0.4/devices/pair endpoint is a thin relay: it takes the
    # user-supplied {consumer_base_url, pairing_code, user_pubkey_hex,
    # user_jws}, looks up the matching webhook token in this dict, and
    # forwards the payload to the consumer's /complete endpoint with
    # the token applied.
    #
    # Empty dict (default) disables the endpoint entirely -- bootloaders
    # that don't broker end-user device pairing for any consumer leave
    # it empty, and POST /v0.4/devices/pair returns 404. Sister of
    # capability_agent_tokens / capability_vault_secrets patterns:
    # consumers register their webhook tokens at deploy time, the
    # bootloader stays a thin authorization layer.
    #
    # Security posture: this dict holds OPERATOR-LEVEL secrets (each
    # consumer's webhook secret authorizes the bootloader to bind ANY
    # user's master pubkey to ANY pairing code on that consumer). The
    # user's JWS self-attestation (verified at the consumer's /complete
    # endpoint) is the load-bearing trust gate that prevents the
    # bootloader from binding pubkeys it doesn't actually hold the
    # signing keys for; the X-Openclaw-Token here is defense-in-depth
    # ("the request came through THIS authorized bootloader").
    devices_pair_consumer_webhook_tokens: dict[str, str] = {}

    # Optional relay-URL overrides.  When a consumer's ``relay_url`` is
    # set in the manifest, the bootloader forwards to that URL instead of
    # ``base_url``.  The phone still sends the original ``base_url`` as
    # ``consumer_base_url`` in the request body, so the lookup key stays
    # the same; only the outbound HTTP target changes.  Motivation:
    # three-zone architecture (commitment #17) — the phone knows the
    # .com user-zone URL, but server-to-server relay must traverse the
    # .ai agent-zone hostname to bypass the WAF.
    devices_pair_consumer_relay_urls: dict[str, str] = {}

    # Phase H optional: per-call timeout (seconds) for the bootloader's
    # outbound request to the consumer's /complete endpoint. 15s is
    # generous for a single DB write + JWS verify; bumps if a future
    # consumer's /complete grows slower (e.g. on-chain attestation
    # writeback).
    devices_pair_consumer_timeout_seconds: float = 15.0

    # Recto Connections Substrate (2026-06-13). Path to the connections
    # metadata sidecar JSON (sister of phones.json under the state dir).
    # When None (default), ALL /v0.4/connections/* endpoints return 404 --
    # the substrate is opt-in, so bootloaders that don't broker connection
    # management for any consumer carry zero attack surface.
    connections_path: str | None = None
    # Map of agent_id -> the connections SERVICE that agent may READ. A
    # consuming app (identified by its X-Recto-Agent-Id header) can read
    # only the service it's mapped to here, so one consumer's agent can't
    # read another consumer's provider keys, and vice versa. Reads (list
    # metadata + fetch a
    # secret value) are agent-token-gated AND service-scoped via this map.
    # Writes (upsert/rotate/enable/delete) are OPERATOR-gated via
    # capability_operator_token and may target any service, so they do NOT
    # consult this map. Empty (default) means no agent may read connections
    # even when connections_path is set -- the operator must register each
    # consumer's agent->service mapping at deploy time.
    connections_agent_services: dict[str, str] = {}
    # Map of agent_id -> the KEY PATTERNS that agent may read the VALUE of
    # (2026-07-28). The service map above answers "whose keys?"; this map
    # answers "which of them?" -- without it, an agent token mapped to a
    # service is a skeleton key to EVERY secret in that service's
    # namespace (`secret?key=<anything>`), which for a platform service
    # means its AI-provider, payment, edge and push credentials all at
    # once. Patterns are exact keys ("anthropic"), trailing-`*` prefixes
    # ("media-*"), or the bare wildcard "*" (allow-all -- an explicit,
    # logged migration escape hatch, never a default).
    #
    # DEFAULT-DENY: an agent with no entry here reads no secret values at
    # all. Reads of secret-free METADATA (GET /v0.4/connections) are
    # deliberately NOT filtered by this map -- discovery stays whole so a
    # consumer can still see which connections exist and whether they
    # carry a value; only the VALUE read is gated.
    connections_agent_keys: dict[str, list[str]] = {}
    # Enforcement switch for the allowlist above. TRUE BY DEFAULT (flipped
    # 2026-08-09): an unlisted key is refused with 403 key_not_allowed.
    #
    # Set False to run the gate in AUDIT mode: every would-be denial is
    # logged at WARNING with the agent, service and key, and the read still
    # SUCCEEDS. That mode exists for a real reason -- it lets an operator
    # discover the live key set from logs, including keys that are not
    # statically enumerable in the consuming app (connection keys carried in
    # DB-driven media-source configs, say) -- and it remains available. What
    # changed is which way the switch points when nobody has touched it.
    #
    # Why it was flipped: audit was the DEFAULT, so a deployment that never
    # read this docstring served every unlisted secret and logged a warning
    # nobody was watching. A boundary whose default is open is a boundary
    # that is open, and the per-key allowlist is the VAULT role's entire
    # crossing test -- a fetch with a valid token but an unlisted key must
    # return refusal, not the secret. It could not pass while this was False.
    #
    # The migration cost is real and is deliberately paid on the safe side:
    # an existing deployment that never set this flag and relies on unlisted
    # keys will start getting 403s. That is a loud, legible failure naming
    # the exact key, which is recoverable in one config edit -- as against
    # the quiet failure it replaces, which was indistinguishable from working.
    # With the allowlist empty, default-deny means NOTHING is readable; the
    # startup posture log says so at WARNING rather than letting a fresh
    # install look mysteriously broken.
    connections_key_acl_enforce: bool = True
    # Injectable secret backend factory (service_name -> WritableSecretSource)
    # for the connections substrate. None (default) means the handlers use
    # recto.connections.manage's production DpapiMachineSource factory -- the
    # right backend on the Windows bootloader host. Tests inject an in-memory
    # double so the connections endpoints exercise on a non-Windows box.
    connections_secret_source_factory: Any = None

    # Recto User Vault Substrate (2026-07-25). Per-USER secret storage
    # ("bring your own key") -- the user-tier sister of the connections
    # substrate. Path to the user-vault metadata sidecar JSON (sister of
    # connections.json under the state dir). When None (default), ALL
    # /v0.4/user-vault/* endpoints return 404 -- opt-in, zero attack
    # surface for bootloaders that don't broker user keys.
    user_vault_path: str | None = None
    # Map of agent_id -> the PLATFORM namespace that agent may operate
    # on. A consuming platform (identified by its X-Recto-Agent-Id
    # header) reads/writes user entries only within the platform it's
    # mapped to here, always further scoped by the X-Recto-User-Id claim
    # it supplies. ALL FOUR user-vault verbs are agent-gated (divergence
    # from connections, where writes are operator-gated): user-vault
    # writes are the platform acting for its own user at runtime.
    user_vault_agent_platforms: dict[str, str] = {}
    # Injectable secret backend factory for user-vault values. Same seam
    # as connections_secret_source_factory: None means DpapiMachineSource
    # (Windows host); containers inject a file-backed factory; tests
    # inject an in-memory double.
    user_vault_secret_source_factory: Any = None

    # Signed-poll enforcement mode (2026-08-13, phone_id split). Gates
    # every possession-of-phone_id read surface (GET /v0.4/pending,
    # GET /v0.4/manage/phones, POST /v0.4/manage/push_token):
    #   - "off":      no signature processing at all (pre-split shape).
    #   - "advisory": DEFAULT. All polls allowed; each one is logged as
    #                 signed-valid / signed-invalid / unsigned (verdicts
    #                 only -- never header values). The evidence window.
    #   - "required": unsigned polls 401 poll_signature_required; polls
    #                 with a bad/stale/wrong-key signature 401
    #                 poll_signature_invalid. Possession of the
    #                 phone_id string alone no longer reads anything.
    # Default is advisory, NOT required: Build 12 phones in both stores
    # poll bare (Hard Rule #1 back-compat) -- the flip to required is an
    # operator ceremony after the advisory evidence window shows every
    # live phone signing (RECURVE pattern).
    signed_poll_mode: str = "advisory"


class ChallengeStore:
    """Store of one-time challenges.

    Two challenge types share the same TTL store:
    - Registration challenges (60s TTL, single use).
    - Pairing codes (300s TTL, single use, 6-digit human-readable).

    Since 2026-07 this is a thin adapter over the injected
    ``StateStoreBase`` (which owns challenge persistence semantics per
    backend): the file backend keeps challenges in-memory (restart
    invalidates -- re-run `recto v0.4 register` for a fresh code), the
    postgres backend persists them so a pairing code survives replica
    restarts and works across instances behind a load balancer.

    Constructed without a state store (legacy/test paths), it falls
    back to its original self-contained in-memory dicts.
    """

    def __init__(self, state: "StateStoreBase | None" = None) -> None:
        self._state = state
        self._challenges: dict[str, int] = {}  # value -> expires_at_unix
        self._pairing_codes: dict[str, int] = {}  # code -> expires_at_unix

    def issue_challenge(self, ttl_seconds: int = 60) -> tuple[str, int]:
        if self._state is not None:
            return self._state.issue_challenge(ttl_seconds)
        c = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
        exp = int(time.time()) + ttl_seconds
        self._challenges[c] = exp
        return c, exp

    def consume_challenge(self, c: str) -> bool:
        """Return True if the challenge exists and is unexpired; remove
        it on success (single-use)."""
        if self._state is not None:
            return self._state.consume_challenge(c)
        self._purge()
        exp = self._challenges.pop(c, None)
        return exp is not None and time.time() < exp

    def issue_pairing_code(self, ttl_seconds: int = 300) -> tuple[str, int]:
        if self._state is not None:
            return self._state.issue_pairing_code(ttl_seconds)
        # 6-digit human-readable; collision risk acceptable for personal-use.
        code = f"{secrets.randbelow(1_000_000):06d}"
        exp = int(time.time()) + ttl_seconds
        self._pairing_codes[code] = exp
        return code, exp

    def consume_pairing_code(self, code: str) -> bool:
        if self._state is not None:
            return self._state.consume_pairing_code(code)
        self._purge()
        exp = self._pairing_codes.pop(code, None)
        return exp is not None and time.time() < exp

    def _purge(self) -> None:
        now = time.time()
        self._challenges = {c: e for c, e in self._challenges.items() if e > now}
        self._pairing_codes = {c: e for c, e in self._pairing_codes.items() if e > now}


class BootloaderHandler(BaseHTTPRequestHandler):
    """HTTP request handler implementing the v0.4 endpoint set."""

    # Override the default banner to not leak Python version.
    server_version = "RectoBootloader/0.4"
    sys_version = ""

    config: BootloaderConfig = BootloaderConfig()

    # ------------------------------------------------------------------
    # Request dispatch
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Cluster registry -- /v0.5/clusters/* .
    # Config-presence gated like every surface here: deployments that
    # leave clusters_registry unset keep all endpoints 404. That gate IS
    # the two-deployment / one-codebase split: one deployment sets it
    # (the registry writer) and configures nothing agent-facing; another
    # leaves it unset and serves the agent surfaces. Registry laws: one
    # writer (runtime consumers read the exported projection file, never
    # these endpoints); leases catch the dying that never report (reap
    # persists the orphan transitions); records hold pointers, never
    # secret values (the heartbeat token is returned exactly once at
    # register and stored only as a hash).
    # ------------------------------------------------------------------
    _clusters_lock = threading.Lock()

    def _clusters_or_404(self):
        registry = getattr(self.config, "clusters_registry", None)
        if registry is None:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown_endpoint"})
        return registry

    def _clusters_spawn_authed(self) -> bool:
        supplied = self.headers.get("X-Recto-Spawn-Token", "").strip()
        expected = getattr(self.config, "clusters_spawn_token", None) or ""
        if not supplied or not expected or not _constant_time_compare(supplied, expected):
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "spawn_token_required"})
            return False
        return True

    def _handle_clusters_list(self) -> None:
        registry = self._clusters_or_404()
        if registry is None:
            return
        if not self._clusters_spawn_authed():
            return
        with self._clusters_lock:
            clusters = registry.list_clusters()
        self._send_json(HTTPStatus.OK, {"clusters": clusters})

    def _handle_clusters_register(self, body: dict[str, Any]) -> None:
        registry = self._clusters_or_404()
        if registry is None:
            return
        if not self._clusters_spawn_authed():
            return
        try:
            with self._clusters_lock:
                rec, token = registry.register(
                    region=str(body.get("region", "")),
                    ordinal=str(body.get("ordinal", "")),
                    color=str(body.get("color", "")),
                    endpoints=body.get("endpoints") or {},
                    metadata=body.get("metadata") or {},
                    lease_ttl_seconds=body.get("lease_ttl_seconds"),
                )
        except ClusterRegistryError as e:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "cluster_registry", "detail": str(e)},
            )
            return
        payload = rec.public_view()
        payload["heartbeat_token"] = token  # returned exactly once
        self._send_json(HTTPStatus.OK, payload)

    def _handle_clusters_heartbeat(self, body: dict[str, Any]) -> None:
        registry = self._clusters_or_404()
        if registry is None:
            return
        token = self.headers.get("X-Recto-Cluster-Token", "").strip()
        try:
            with self._clusters_lock:
                rec = registry.heartbeat(
                    str(body.get("cluster_id", "")),
                    token,
                    endpoints=body.get("endpoints") or None,
                    metadata=body.get("metadata") or None,
                )
        except ClusterRegistryError as e:
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "cluster_registry", "detail": str(e)},
            )
            return
        self._send_json(HTTPStatus.OK, rec.public_view())

    def _handle_clusters_retire(self, body: dict[str, Any]) -> None:
        registry = self._clusters_or_404()
        if registry is None:
            return
        token = self.headers.get("X-Recto-Cluster-Token", "").strip()
        try:
            with self._clusters_lock:
                rec = registry.retire(
                    str(body.get("cluster_id", "")),
                    token,
                    reason=str(body.get("reason", "retired")),
                )
        except ClusterRegistryError as e:
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "cluster_registry", "detail": str(e)},
            )
            return
        self._send_json(HTTPStatus.OK, rec.public_view())

    def _handle_clusters_reap(self) -> None:
        registry = self._clusters_or_404()
        if registry is None:
            return
        if not self._clusters_spawn_authed():
            return
        with self._clusters_lock:
            newly = registry.reap()
        self._send_json(HTTPStatus.OK, {"orphaned": newly})

    def do_GET(self) -> None:
        try:
            url = urlparse(self.path)
            print(f"[bootloader] GET {url.path}{'?' + url.query if url.query else ''}", flush=True)
            if url.path == "/v0.4/registration_challenge":
                self._handle_registration_challenge(url)
            elif url.path == "/v0.4/pending":
                self._handle_pending(url)
            elif url.path == "/v0.4/manage/phones":
                self._handle_manage_phones(url)
            elif url.path == "/v0.4/health":
                self._handle_health()
            elif url.path == "/v0.4/version":
                self._handle_version()
            elif url.path.startswith("/v0.4/capability/result/"):
                request_id = url.path[len("/v0.4/capability/result/"):]
                self._handle_capability_result(request_id)
            elif url.path == "/v0.4/capability/manifest":
                self._handle_capability_manifest()
            elif url.path == "/v0.4/capability/revocations":
                self._handle_capability_revocations()
            elif url.path.startswith("/v0.4/profile/result/"):
                request_id = url.path[len("/v0.4/profile/result/"):]
                self._handle_profile_create_result(request_id)
            elif url.path.startswith("/v0.4/profile/add-device-result/"):
                request_id = url.path[
                    len("/v0.4/profile/add-device-result/"):
                ]
                self._handle_profile_add_device_result(request_id)
            elif url.path.startswith("/v0.4/profile/revoke-device-result/"):
                request_id = url.path[
                    len("/v0.4/profile/revoke-device-result/"):
                ]
                self._handle_profile_revoke_device_result(request_id)
            elif url.path == "/v0.4/connections":
                self._handle_connections_list(url)
            elif url.path == "/v0.4/connections/secret":
                self._handle_connections_secret(url)
            elif url.path == "/v0.4/user-vault":
                self._handle_user_vault_list(url)
            elif url.path == "/v0.4/user-vault/release":
                self._handle_user_vault_release(url)
            elif url.path == "/v0.5/clusters":
                self._handle_clusters_list()
            else:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown_endpoint"})
        except BootloaderError as e:
            print(f"[bootloader] BootloaderError on {url.path}: {e}", flush=True)
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "bootloader_error", "detail": str(e)})
        except Exception as e:  # noqa: BLE001
            import traceback
            print(f"[bootloader] EXCEPTION on {url.path}: {type(e).__name__}: {e}", flush=True)
            traceback.print_exc()
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "internal", "detail": type(e).__name__},
            )

    def do_POST(self) -> None:
        try:
            url = urlparse(self.path)
            body = self._read_json_body()
            print(f"[bootloader] POST {url.path}", flush=True)
            if url.path == "/v0.4/register":
                self._handle_register(body)
            elif url.path == "/v0.4/issue_session":
                self._handle_issue_session(body)
            elif url.path.startswith("/v0.4/respond/"):
                request_id = url.path[len("/v0.4/respond/"):]
                self._handle_respond(request_id, body)
            elif url.path == "/v0.4/capability/request":
                self._handle_capability_request(body)
            elif url.path == "/v0.4/capability/revoke":
                self._handle_capability_revoke(body)
            elif url.path == "/v0.4/pairing/code":
                self._handle_mint_pairing_code(body)
            elif url.path == "/v0.4/manage/push_token":
                self._handle_push_token_update(body)
            elif url.path == "/v0.4/manage/phones/revoke":
                self._handle_revoke_phone(body)
            elif url.path == "/v0.4/secrets/read":
                self._handle_secret_read(body)
            elif url.path == "/v0.4/devices/pair":
                self._handle_devices_pair(body)
            elif url.path == "/v0.4/devices/unpair":
                self._handle_devices_unpair(body)
            elif url.path == "/v0.4/profile/create":
                self._handle_profile_create(body)
            elif (
                url.path.startswith("/v0.4/profile/")
                and url.path.endswith("/add-device")
            ):
                profile_id = url.path[
                    len("/v0.4/profile/"):-len("/add-device")
                ]
                self._handle_profile_add_device(profile_id, body)
            elif (
                url.path.startswith("/v0.4/profile/")
                and url.path.endswith("/revoke-device")
            ):
                profile_id = url.path[
                    len("/v0.4/profile/"):-len("/revoke-device")
                ]
                self._handle_profile_revoke_device(profile_id, body)
            elif url.path == "/v0.4/connections":
                self._handle_connections_upsert(body)
            elif url.path == "/v0.4/connections/enable":
                self._handle_connections_enable(body)
            elif url.path == "/v0.4/connections/delete":
                self._handle_connections_delete(body)
            elif url.path == "/v0.4/user-vault/set":
                self._handle_user_vault_set(body)
            elif url.path == "/v0.4/user-vault/delete":
                self._handle_user_vault_delete(body)
            elif url.path == "/v0.5/clusters/register":
                self._handle_clusters_register(body)
            elif url.path == "/v0.5/clusters/heartbeat":
                self._handle_clusters_heartbeat(body)
            elif url.path == "/v0.5/clusters/retire":
                self._handle_clusters_retire(body)
            elif url.path == "/v0.5/clusters/reap":
                self._handle_clusters_reap()
            else:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown_endpoint"})
        except BootloaderError as e:
            print(f"[bootloader] BootloaderError on {url.path}: {e}", flush=True)
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "bootloader_error", "detail": str(e)})
        except Exception as e:  # noqa: BLE001
            import traceback
            print(f"[bootloader] EXCEPTION on {url.path}: {type(e).__name__}: {e}", flush=True)
            traceback.print_exc()
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "internal", "detail": type(e).__name__},
            )

    # ------------------------------------------------------------------
    # GET /v0.4/health
    # ------------------------------------------------------------------

    def _handle_health(self) -> None:
        cfg = self.config
        self._send_json(HTTPStatus.OK, {
            "ok": True,
            "bootloader_id": cfg.bootloader_id,
            "v0_4_protocol": PROTOCOL_VERSION,
        })

    # ------------------------------------------------------------------
    # GET /v0.4/version  -- GATE 3 prerequisite #2
    # ------------------------------------------------------------------

    def _handle_version(self) -> None:
        """What is actually running here, answerable without host access.

        WHY THIS EXISTS. Until 2026-08-18 the only way to learn which commit a
        bootloader was serving was to read the container image label from the
        Docker host -- which found, on its first use, a container that had been
        serving a PRE-GENESIS build for weeks while CI reported green. That
        check is good and it is not enough: it requires a shell on the machine,
        so no phone, no client, and no remote operator could ask.

        `recto --version` could not answer either. It read a hardcoded
        `__version__` that said 0.1.0.dev0 while pyproject said 1.0.0 -- one
        value in two places, disagreeing, for months.

        THE THREE FIELDS ARE DELIBERATELY DIFFERENT KINDS OF FACT:
          version   the PACKAGE, from installed metadata (pyproject is the only
                    declaration; this cannot drift from it)
          revision  the SOURCE COMMIT, from RECTO_BUILD_REVISION, which the
                    Dockerfile has exported into the container environment all
                    along and nothing has ever read
          created   the BUILD TIME, same source

        "unknown" is returned verbatim rather than omitted or guessed. An image
        built without the stamp genuinely does not know its commit, and saying
        so is the honest answer -- absent and stale look identical, which is
        exactly how the pre-genesis container went unnoticed.

        UNAUTHENTICATED, and that is a decision. It discloses a version, a
        commit sha of a public repository, and a build timestamp -- nothing an
        attacker cannot read from GitHub. Weighed against it: a health check
        that cannot say what it is checking is the class of instrument this
        estate spent 2026-08-17 removing.
        """
        cfg = self.config
        self._send_json(HTTPStatus.OK, {
            "version": __version__,
            "revision": os.environ.get("RECTO_BUILD_REVISION", "unknown"),
            "created": os.environ.get("RECTO_BUILD_CREATED", "unknown"),
            "bootloader_id": cfg.bootloader_id,
            "v0_4_protocol": PROTOCOL_VERSION,
        })

    # ------------------------------------------------------------------
    # GET /v0.4/registration_challenge
    # ------------------------------------------------------------------

    def _handle_registration_challenge(self, url) -> None:
        cfg = self.config
        if cfg.challenges is None:
            raise BootloaderError("challenge store not initialized")
        # Optional pairing-code gating: if `code=` query param is present,
        # the operator-issued pairing code must match.
        params = parse_qs(url.query)
        if "code" in params:
            if not cfg.challenges.consume_pairing_code(params["code"][0]):
                raise RegistrationExpiredError("pairing code expired or invalid")
        challenge, expires_at = cfg.challenges.issue_challenge()
        self._send_json(HTTPStatus.OK, {
            "challenge_b64u": challenge,
            "expires_at_unix": expires_at,
        })

    # ------------------------------------------------------------------
    # POST /v0.4/register
    # ------------------------------------------------------------------

    def _handle_register(self, body: dict[str, Any]) -> None:
        cfg = self.config
        if cfg.state is None or cfg.challenges is None:
            raise BootloaderError("server not initialized")
        proof = body.get("registration_proof") or {}
        challenge = proof.get("challenge", "")
        sig = proof.get("signature_b64u", "")
        public_key_b64u = body.get("public_key_b64u", "")
        device_label = body.get("device_label", "(unnamed)")
        # GATE 2a (2026-08-17). This read `body.get("supported_algorithms",
        # ["ed25519"])` -- an ABSENT field enrolled the phone as software-keyed,
        # and line 814 below re-defaulted an EMPTY list the same way. Two
        # independent defaults, both resolving silence to the software path, in
        # a substrate whose entire claim is a hardware-held key.
        #
        # REFUSE instead. A phone that cannot say what it signs with does not
        # enroll. This is safe to make fatal HERE and nowhere else: it binds
        # only FUTURE enrollments, so no live phone can be locked out by it --
        # see _registered_algorithm() for why the read sites only warn.
        raw_algos = body.get("supported_algorithms")
        if not isinstance(raw_algos, list) or not raw_algos:
            raise BootloaderError(
                "registration refused: supported_algorithms is absent or empty. "
                "A hardware-root system does not enroll a software key by "
                f"omission. Send one of {list(SUPPORTED_ALGORITHMS)}."
            )
        algos = tuple(str(a) for a in raw_algos)
        unknown = [a for a in algos if a not in SUPPORTED_ALGORITHMS]
        if unknown:
            raise BootloaderError(
                f"registration refused: unsupported algorithm(s) {unknown}. "
                f"This bootloader verifies {list(SUPPORTED_ALGORITHMS)}. "
                "Previously an unknown string was passed straight to "
                "verification and surfaced as an opaque signature failure."
            )
        if body.get("v0_4_protocol") != PROTOCOL_VERSION:
            raise BootloaderError(
                f"protocol version mismatch: server={PROTOCOL_VERSION}, "
                f"phone={body.get('v0_4_protocol')!r}"
            )
        if not cfg.challenges.consume_challenge(challenge):
            raise RegistrationExpiredError("registration challenge expired or invalid")
        # Pick the algorithm the phone declared. The registration body's
        # `supported_algorithms` is a list (phone enumerates what it
        # CAN sign with); for v1 we treat the first entry as the algo
        # actually used to sign the registration challenge. iOS Secure
        # Enclave phones send ["ecdsa-p256"]; Android StrongBox / software
        # fallback phones send ["ed25519"]. Both paths are supported by
        # recto.bootloader.sessions.verify_signature.
        # `algos` is now guaranteed non-empty and vocabulary-checked above,
        # so this no longer needs -- or is permitted -- a fallback.
        chosen_algo = algos[0]
        # Verify the phone's signature over the challenge using the
        # claimed public key. This proves possession of the private
        # key without disclosing it.
        ok = verify_signature(
            payload=challenge.encode("ascii"),
            signature_b64u=sig,
            public_key_b64u=public_key_b64u,
            algorithm=chosen_algo,
        )
        if not ok:
            raise BootloaderError(
                f"registration proof signature invalid (algorithm={chosen_algo!r})"
            )
        # Optional silent-push wake routing (wave C): the phone supplies
        # its APNs / FCM token at registration when it has one. Absent /
        # empty means poll-only. Platform values are validated so a
        # future platform string doesn't silently register unroutable.
        push_token = body.get("push_token") or None
        push_platform = body.get("push_platform") or None
        if push_token is not None and push_platform not in ("apns", "fcm"):
            raise BootloaderError(
                f"unknown push_platform {push_platform!r}; "
                "expected 'apns' or 'fcm'"
            )
        reg = PhoneRegistration.new(
            device_label=str(device_label),
            public_key_b64u=public_key_b64u,
            supported_algorithms=algos,
            push_token=push_token,
            push_platform=push_platform if push_token else None,
        )
        cfg.state.register_phone(reg)
        resp: dict[str, Any] = {
            "registered": True,
            "phone_id": reg.phone_id,
            # phone_ref (2026-08-13, phone_id split): the pure-reference
            # sibling of phone_id -- "pk_" + first 16 hex of
            # sha256(raw pubkey bytes). Additive; NEVER authenticates
            # anything. Re-keying registries onto it is deferred until
            # signed_poll_mode flips to "required".
            "phone_ref": _phone_ref(reg.public_key_b64u),
            "bootloader_id": cfg.bootloader_id,
            # Empty managed_secrets for now; the operator wires services
            # to specific phone_ids via service.yaml's
            # spec.secrets[].config.phone_id field (TBD once the launcher
            # side lands).
            "managed_secrets": [],
        }
        if cfg.public_urls:
            # Additive multi-URL failover field (wave C): primary first.
            # Phones persist the list; pre-wave-C phones ignore the
            # unknown key. Emitted only when the operator configured
            # public_urls, so single-host installs stay byte-identical.
            resp["bootloader_urls"] = list(cfg.public_urls)
        if cfg.bootloader_identity_inputs is not None:
            # GATE 5b phone-recomputation half (additive, same convention
            # as bootloader_urls): the derivation inputs that produced
            # bootloader_id, so the phone can RECOMPUTE the id from the
            # key set instead of trusting a name. Omitted when the id is
            # not derived -- an rb1- id always travels with its inputs.
            resp["bootloader_identity"] = cfg.bootloader_identity_inputs
        self._send_json(HTTPStatus.CREATED, resp)

    def _notify_push(self, req: PendingRequest) -> None:
        """Fire a best-effort silent wake push for a just-queued
        request. Never raises, never blocks the request path -- the
        dispatcher does the send on a daemon thread and logs failures
        (push is a delivery HINT; polling remains the fallback).
        No-op when no dispatcher is configured or the target phone has
        no registered push token."""
        cfg = self.config
        dispatcher = cfg.push_dispatcher
        if dispatcher is None or cfg.state is None:
            return
        try:
            phone = cfg.state.get_phone(req.phone_id)
            if phone is not None:
                dispatcher.notify(phone, req.request_id)
        except Exception:  # noqa: BLE001 - push must never break queueing
            logging.getLogger("recto.bootloader.push").warning(
                "push notify failed for request %s", req.request_id,
                exc_info=True,
            )

    # ------------------------------------------------------------------
    # Signed-poll gate (2026-08-13, phone_id split)
    # ------------------------------------------------------------------

    def _check_poll_signature(
        self, phone: PhoneRegistration, path: str,
    ) -> bool:
        """Verify (or advise on) the phone's poll signature for one
        possession-of-phone_id read surface.

        Returns True when the request may proceed. Returns False after
        having already sent the 401 refusal (required mode only). The
        caller pattern is ``if not self._check_poll_signature(...):
        return`` immediately after the get_phone possession lookup.

        Signing input is the ASCII string
        ``recto-poll-v1|{phone_id}|{ts}|{path}`` (ts = unix seconds as
        sent in the header; path = URL path only). Verification runs
        against the REGISTRATION's pubkey + declared algorithm via
        recto.bootloader.sessions.verify_signature -- the same trust
        anchor every approval already uses. Freshness is +/-
        POLL_SIG_FRESHNESS_SECONDS around the server clock.

        Logging discipline: verdicts and phone_id only -- NEVER the
        signature or timestamp header values.
        """
        cfg = self.config
        mode = getattr(cfg, "signed_poll_mode", "advisory") or "advisory"
        if mode == "off":
            return True
        log = logging.getLogger("recto.bootloader.signed_polls")
        sig = (self.headers.get(POLL_SIG_HEADER) or "").strip()
        ts_raw = (self.headers.get(POLL_SIG_TS_HEADER) or "").strip()

        if not sig and not ts_raw:
            if mode == "required":
                self._send_json(HTTPStatus.UNAUTHORIZED, {
                    "error": "poll_signature_required",
                    "detail": (
                        f"{path} requires a signed poll "
                        f"({POLL_SIG_HEADER} + {POLL_SIG_TS_HEADER} "
                        "headers) when signed_poll_mode=required"
                    ),
                })
                return False
            log.info(
                "poll verdict=unsigned mode=%s path=%s phone_id=%s",
                mode, path, phone.phone_id,
            )
            return True

        # A half-supplied pair (sig without ts, or ts without sig) can
        # never verify; classify it as invalid rather than unsigned so
        # the advisory log surfaces broken clients distinctly.
        verdict = "signed-invalid"
        if sig and ts_raw:
            try:
                ts = int(ts_raw)
            except ValueError:
                ts = None
            if ts is not None and abs(int(time.time()) - ts) <= POLL_SIG_FRESHNESS_SECONDS:
                payload = f"{POLL_SIG_PREFIX}|{phone.phone_id}|{ts}|{path}"
                phone_algo = _registered_algorithm(phone, phone.phone_id)
                try:
                    ok = verify_signature(
                        payload=payload.encode("ascii"),
                        signature_b64u=sig,
                        public_key_b64u=phone.public_key_b64u,
                        algorithm=phone_algo,
                    )
                except BootloaderError:
                    # Undecodable registration pubkey / unsupported algo:
                    # the signature cannot be validated, which is a
                    # verdict, not a server error.
                    ok = False
                if ok:
                    verdict = "signed-valid"

        if verdict == "signed-valid":
            log.info(
                "poll verdict=signed-valid mode=%s path=%s phone_id=%s",
                mode, path, phone.phone_id,
            )
            return True
        if mode == "required":
            self._send_json(HTTPStatus.UNAUTHORIZED, {
                "error": "poll_signature_invalid",
                "detail": (
                    "poll signature failed verification (bad signature, "
                    "stale/invalid timestamp, or wrong key)"
                ),
            })
            return False
        log.warning(
            "poll verdict=signed-invalid mode=%s path=%s phone_id=%s",
            mode, path, phone.phone_id,
        )
        return True

    # ------------------------------------------------------------------
    # POST /v0.4/manage/push_token
    # ------------------------------------------------------------------

    def _handle_push_token_update(self, body: dict[str, Any]) -> None:
        """Phone-side push-token rotation. The phone calls this whenever
        its FCM / APNs token changes (FCM rotates per Google guidance;
        APNs tokens can change after backup-restore or reinstall).

        Wire shape matches the phone app's PushTokenUpdateRequest:
        ``{phone_id, push_token, push_platform}`` ->
        ``{updated, phone_id}``. Same auth posture as the pending-fetch
        surface (possession of the registered phone_id); the token is
        wake-routing metadata, not authority -- a forged update can at
        worst misroute delivery hints, never request content.
        """
        cfg = self.config
        if cfg.state is None:
            raise BootloaderError("server not initialized")
        phone_id = body.get("phone_id", "")
        push_token = body.get("push_token") or None
        push_platform = body.get("push_platform") or None
        if not push_token or push_platform not in ("apns", "fcm"):
            raise BootloaderError(
                "push_token and push_platform ('apns' | 'fcm') are required"
            )
        phone = cfg.state.get_phone(phone_id)
        if phone is None:
            raise UnknownPhoneError(f"phone_id {phone_id!r} not registered")
        # Signed-poll gate (phone_id split): possession of the phone_id
        # string stops being the credential once required-mode flips.
        if not self._check_poll_signature(phone, "/v0.4/manage/push_token"):
            return
        from dataclasses import replace as _replace
        updated = _replace(
            phone,
            push_token=push_token,
            push_platform=push_platform,
            last_seen_unix=int(time.time()),
        )
        cfg.state.register_phone(updated)  # upsert semantics
        self._send_json(HTTPStatus.OK, {
            "updated": True,
            "phone_id": phone_id,
        })

    # ------------------------------------------------------------------
    # POST /v0.4/issue_session
    # ------------------------------------------------------------------

    def _handle_issue_session(self, body: dict[str, Any]) -> None:
        cfg = self.config
        if cfg.state is None:
            raise BootloaderError("server not initialized")
        phone_id = body.get("phone_id", "")
        token = body.get("session_token_jwt", "")
        phone = cfg.state.get_phone(phone_id)
        if phone is None:
            raise UnknownPhoneError(f"phone_id {phone_id!r} not registered")
        # Verify the JWT signature against the phone's public key, and
        # parse the claims.
        claims = verify_jwt(
            token,
            public_key_b64u=phone.public_key_b64u,
            audience=cfg.bootloader_id,
        )
        sess = Session(
            service=claims.service,
            secret=claims.secret,
            phone_id=phone_id,
            jwt=token,
            expires_at_unix=claims.exp,
            issued_at_unix=claims.iat,
            max_uses=claims.recto_max_uses,
            uses_so_far=0,
        )
        cfg.state.put_session(sess)
        self._send_json(HTTPStatus.CREATED, {
            "session_id": claims.jti,
            "expires_at_unix": claims.exp,
        })

    # ------------------------------------------------------------------
    # GET /v0.4/pending?phone_id=<id>
    # ------------------------------------------------------------------

    def _handle_pending(self, url) -> None:
        cfg = self.config
        if cfg.state is None:
            raise BootloaderError("server not initialized")
        params = parse_qs(url.query)
        phone_ids = params.get("phone_id", [])
        if not phone_ids:
            raise BootloaderError("phone_id query parameter required")
        phone_id = phone_ids[0]
        phone = cfg.state.get_phone(phone_id)
        if phone is None:
            raise UnknownPhoneError(f"phone_id {phone_id!r} not registered")
        # Signed-poll gate (phone_id split): possession of the phone_id
        # string stops being the credential once required-mode flips.
        if not self._check_poll_signature(phone, "/v0.4/pending"):
            return
        pending = cfg.state.list_pending_for_phone(phone_id)
        pending = [self._restamp_grant_window(p) for p in pending]
        self._send_json(HTTPStatus.OK, {
            "requests": [self._pending_to_wire(p) for p in pending],
        })

    def _restamp_grant_window(self, req):
        """Re-stamp a queued capability_request's grant window at
        card-open (v0.6+ queued-card flow).

        A capability request that declared ``grant_ttl_seconds`` gets
        its claims' iat/nbf/exp REBUILT — iat = nbf = now, exp = now +
        grant_ttl — the FIRST time the phone fetches the pending list.
        Card-open is the anchor: the authority window starts when the
        operator looks, not when the requesting agent queued the card
        (which can be many minutes earlier, while verifier-side
        lifetime ceilings are deliberately short).

        Stamped EXACTLY ONCE (``cap_window_stamped_at_unix`` guards):
        the phone signs the bytes it fetched, and mutating them on a
        later poll would make the returned signature verify against
        nothing. A card opened but not approved within the grant
        window yields a JWS the downstream verifier refuses as
        expired — the designed failure; the agent re-requests.

        Non-capability kinds and requests without a grant TTL pass
        through untouched.
        """
        if (
            req.kind != "capability_request"
            or req.cap_grant_ttl_seconds is None
            or req.cap_window_stamped_at_unix is not None
            or not req.cap_payload_b64
        ):
            return req
        import base64 as _base64
        import json as _json
        from dataclasses import replace as _replace

        from recto.capability.jwt import (
            _dict_to_claims as _to_claims,
            build_signing_input,
        )
        try:
            pad = "=" * (-len(req.cap_payload_b64) % 4)
            payload = _json.loads(_base64.urlsafe_b64decode(req.cap_payload_b64 + pad))
            now = int(time.time())
            payload["iat"] = now
            payload["nbf"] = now
            payload["exp"] = now + req.cap_grant_ttl_seconds
            claims = _to_claims(payload)
            digest, header_b64, payload_b64 = build_signing_input(claims)
        except Exception as exc:
            # A claims set that queued cleanly but no longer rebuilds is
            # a defect worth surfacing, not hiding behind a stale window.
            raise BootloaderError(
                f"grant-window re-stamp failed for {req.request_id}: {exc}"
            ) from exc
        payload_hash_b64u = (
            base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        )
        updated = _replace(
            req,
            cap_header_b64=header_b64,
            cap_payload_b64=payload_b64,
            payload_hash_b64u=payload_hash_b64u,
            cap_window_stamped_at_unix=now,
        )
        self.config.state.add_pending(updated)
        return updated

    # ------------------------------------------------------------------
    # GET /v0.4/manage/phones?phone_id=<self>
    # ------------------------------------------------------------------
    #
    # Returns every paired phone OTHER than the requesting phone. The
    # MAUI client renders these as the "Registered phones" pane so the
    # operator can see what other devices share the bootloader and
    # revoke any that have been lost. Single-user-operator scoping
    # today (Recto's current model: one operator, N paired devices);
    # multi-tenant scoping (per-user filter) is a future v3 concern
    # that adds a `user_id` filter clause without changing the contract.

    def _handle_manage_phones(self, url) -> None:
        cfg = self.config
        if cfg.state is None:
            raise BootloaderError("server not initialized")
        params = parse_qs(url.query)
        phone_ids = params.get("phone_id", [])
        if not phone_ids:
            raise BootloaderError("phone_id query parameter required")
        requester_phone_id = phone_ids[0]
        requester = cfg.state.get_phone(requester_phone_id)
        if requester is None:
            raise UnknownPhoneError(
                f"phone_id {requester_phone_id!r} not registered"
            )
        # Signed-poll gate (phone_id split): possession of the phone_id
        # string stops being the credential once required-mode flips.
        if not self._check_poll_signature(requester, "/v0.4/manage/phones"):
            return
        others = [
            p for p in cfg.state.list_phones()
            if p.phone_id != requester_phone_id
        ]
        self._send_json(HTTPStatus.OK, {
            "phones": [
                {
                    "phone_id": p.phone_id,
                    # Additive reference field (phone_id split); never
                    # auth. Unknown key to pre-split phone clients.
                    "phone_ref": _phone_ref(p.public_key_b64u),
                    "device_label": p.device_label,
                    "algorithm": (
                        p.supported_algorithms[0]
                        if p.supported_algorithms
                        else ""
                    ),
                    "paired_at": datetime.fromtimestamp(
                        p.registered_at_unix, tz=timezone.utc
                    ).isoformat(),
                }
                for p in others
            ],
        })

    @staticmethod
    def _pending_to_wire(p: PendingRequest) -> dict[str, Any]:
        context: dict[str, Any] = {
            "child_pid": p.child_pid,
            "child_argv0": p.child_argv0,
            "requested_at_unix": p.requested_at_unix,
            "operation_description": p.operation_description,
            "payload_hash_b64u": p.payload_hash_b64u,
        }
        # ETH-specific context fields. Emitted only when actually set so
        # non-ETH kinds keep an unchanged wire shape (kept-keys minimal,
        # easier to assert in tests). Mirrors the C# PendingRequestContext
        # additions in Recto.Shared.Protocol.V04.
        if p.kind == "eth_sign":
            context["eth_chain_id"] = p.eth_chain_id
            context["eth_message_kind"] = p.eth_message_kind
            context["eth_address"] = p.eth_address
            context["eth_derivation_path"] = p.eth_derivation_path
            if p.eth_message_text is not None:
                context["eth_message_text"] = p.eth_message_text
            if p.eth_typed_data_json is not None:
                context["eth_typed_data_json"] = p.eth_typed_data_json
            if p.eth_transaction_json is not None:
                context["eth_transaction_json"] = p.eth_transaction_json
        # BTC-specific context fields. Same pattern as ETH — emitted only
        # for `btc_sign` kind so non-BTC wire shape is unchanged.
        if p.kind == "btc_sign":
            context["btc_network"] = p.btc_network
            context["btc_message_kind"] = p.btc_message_kind
            context["btc_address"] = p.btc_address
            context["btc_derivation_path"] = p.btc_derivation_path
            if p.btc_message_text is not None:
                context["btc_message_text"] = p.btc_message_text
            if p.btc_psbt_base64 is not None:
                context["btc_psbt_base64"] = p.btc_psbt_base64
            # Wave-7 multi-coin: emit btc_coin so the phone can pick the
            # right preamble + address format. Default null at the wire
            # layer so v0.5 phones (which would silently treat absent
            # field as Bitcoin) don't break.
            if p.btc_coin is not None and p.btc_coin != "btc":
                context["btc_coin"] = p.btc_coin
        # ED25519-chain context (kind == "ed_sign", wave-8). Same
        # emit-only-when-set pattern as ETH/BTC so non-ed wire shape
        # is unchanged. Mirrors the C# `PendingRequestContext` ED
        # additions in `Recto.Shared.Protocol.V04`.
        if p.kind == "ed_sign":
            context["ed_chain"] = p.ed_chain
            context["ed_message_kind"] = p.ed_message_kind
            context["ed_address"] = p.ed_address
            context["ed_derivation_path"] = p.ed_derivation_path
            if p.ed_message_text is not None:
                context["ed_message_text"] = p.ed_message_text
            if p.ed_payload_hex is not None:
                context["ed_payload_hex"] = p.ed_payload_hex
        # TRON-specific context (kind == "tron_sign", wave-9). Same
        # emit-only-when-set pattern. Mirrors the C# `PendingRequestContext`
        # TRON additions in `Recto.Shared.Protocol.V04`.
        if p.kind == "tron_sign":
            context["tron_network"] = p.tron_network
            context["tron_message_kind"] = p.tron_message_kind
            context["tron_address"] = p.tron_address
            context["tron_derivation_path"] = p.tron_derivation_path
            if p.tron_message_text is not None:
                context["tron_message_text"] = p.tron_message_text
            if p.tron_payload_hex is not None:
                context["tron_payload_hex"] = p.tron_payload_hex
        # Capability-request context (kind == "capability_request",
        # Phase 5 Wave B). Phone signs `SHA-256(f"{cap_header_b64}.{
        # cap_payload_b64}".encode("ascii"))` with the operator's
        # secp256k1 BIP-39-derived key and returns the 64-byte raw
        # r||s on the respond endpoint. The phone-side render arm
        # (Wave B part 2) decodes cap_payload_b64 to extract the
        # CapabilityClaims and renders the structured-list approval
        # UI with foundation-count breakdown; until part 2 lands, the
        # current Home.razor falls through to the generic kind label
        # which is fine for routing-layer testing.
        if p.kind == "capability_request":
            context["cap_header_b64"] = p.cap_header_b64
            context["cap_payload_b64"] = p.cap_payload_b64
            if p.cap_agent_id is not None:
                context["cap_agent_id"] = p.cap_agent_id
        # Profile-create context (kind == "profile_create", Phase 2.0.B
        # integration). Phone-side render arm (Wave C.3 in
        # Recto.Shared/Pages/Home.razor) reads candidate_kind /
        # candidate_display_name / derivation purpose+coin_type+index +
        # theme_hint / scim_provider to render the approval card. The
        # signing input (canonical JSON of these fields plus the
        # master_pubkey_hex) lives in cap_payload_b64 so the phone can
        # re-derive the digest after injecting child_pubkey_hex at
        # signing time.
        if p.kind == "profile_create":
            context["candidate_profile_id"] = p.candidate_profile_id
            context["candidate_kind"] = p.candidate_kind
            context["candidate_display_name"] = p.candidate_display_name
            context["candidate_derivation_purpose"] = p.candidate_derivation_purpose
            context["candidate_derivation_coin_type"] = p.candidate_derivation_coin_type
            context["candidate_derivation_index"] = p.candidate_derivation_index
            if p.candidate_theme_hint is not None:
                context["candidate_theme_hint"] = p.candidate_theme_hint
            if p.candidate_scim_provider is not None:
                context["candidate_scim_provider"] = p.candidate_scim_provider
            if p.cap_payload_b64 is not None:
                context["cap_payload_b64"] = p.cap_payload_b64
            if p.cap_agent_id is not None:
                context["cap_agent_id"] = p.cap_agent_id
        # Profile-add-device context (kind == "profile_add_device",
        # Phase 2.0.C wave C.5 integration). Phone-side render arm
        # displays addev_profile_id (target profile) + addev_new_phone_id
        # (the new device being authorized) + optional friendly label.
        # Signing input (canonical JSON of profile_id + new_phone_id +
        # added_at_unix + request_id) lives in cap_payload_b64; phone
        # SHA-256s it and signs with the operator master key. No
        # phone-supplied field needs injection at respond time, unlike
        # profile_create's child_pubkey_hex flow.
        if p.kind == "profile_add_device":
            context["addev_profile_id"] = p.addev_profile_id
            context["addev_new_phone_id"] = p.addev_new_phone_id
            if p.addev_new_phone_label is not None:
                context["addev_new_phone_label"] = p.addev_new_phone_label
            if p.cap_payload_b64 is not None:
                context["cap_payload_b64"] = p.cap_payload_b64
            if p.cap_agent_id is not None:
                context["cap_agent_id"] = p.cap_agent_id
        # Profile-revoke-device context (kind == "profile_revoke_device",
        # Phase 2.0.C wave C.6 integration). Phone-side render arm
        # displays revdev_profile_id (target) + revdev_phone_id_to_revoke
        # (the device being removed) + optional revoker_label (the
        # name of the device that's signing the revocation, for the
        # operator's situational awareness). Signing input lives in
        # cap_payload_b64; phone SHA-256s it and signs with the
        # operator master key (m/44'/60'/0'/0/0). Same shape as
        # profile_add_device's wire — no phone-supplied field at
        # respond time.
        if p.kind == "profile_revoke_device":
            context["revdev_profile_id"] = p.revdev_profile_id
            context["revdev_phone_id_to_revoke"] = p.revdev_phone_id_to_revoke
            if p.revdev_revoker_label is not None:
                context["revdev_revoker_label"] = p.revdev_revoker_label
            if p.cap_payload_b64 is not None:
                context["cap_payload_b64"] = p.cap_payload_b64
            if p.cap_agent_id is not None:
                context["cap_agent_id"] = p.cap_agent_id
        # Phase 5 Wave C part 3: app_context. Generic top-level field
        # (NOT capability-specific) so every phone-rendered request
        # kind carries it. Bootloader injects from
        # BootloaderConfig.principal_apps at queue time. Emit-only-
        # when-set; nested object fields are also omit-when-null so
        # the wire shape stays compact.
        if p.app_context is not None:
            ac = p.app_context
            ac_obj: dict[str, Any] = {
                "app_id": ac.app_id,
                "app_name": ac.app_name,
                "app_description": ac.app_description,
            }
            if ac.app_url is not None:
                ac_obj["app_url"] = ac.app_url
            if ac.app_icon_url is not None:
                ac_obj["app_icon_url"] = ac.app_icon_url
            if ac.app_version is not None:
                ac_obj["app_version"] = ac.app_version
            context["app_context"] = ac_obj
        return {
            "request_id": p.request_id,
            "kind": p.kind,
            "service": p.service,
            "secret": p.secret,
            "context": context,
        }

    # ------------------------------------------------------------------
    # POST /v0.4/respond/<request_id>
    # ------------------------------------------------------------------

    def _handle_respond(self, request_id: str, body: dict[str, Any]) -> None:
        cfg = self.config
        if cfg.state is None:
            raise BootloaderError("server not initialized")
        req = cfg.state.take_pending(request_id)
        if req is None:
            raise PendingRequestNotFoundError(
                f"request_id {request_id!r} not found"
            )
        decision = body.get("decision", "")
        if decision == "denied":
            # Operator declined; surface to whoever is awaiting the
            # response. The waiting mechanism (an in-process Future or
            # similar) is the launcher's responsibility; the bootloader
            # just marks the pending as resolved-with-denial.
            reason = body.get("reason", "denied")
            self._notify_resolved(req, ok=False, signature_b64u=None,
                                  eth_signature_rsv=None,
                                  btc_signature_base64=None,
                                  reason=reason)
            # For capability_request, also stash a denied result so the
            # requesting agent's poll endpoint can return a clean
            # "denied" status with the operator's reason.
            if req.kind == "capability_request":
                self._store_capability_result(
                    req,
                    status="denied",
                    capability_jws=None,
                    reason=reason,
                )
            # For profile_create (Phase 2.0.B), same pattern — caller
            # polls /v0.4/profile/result/<request_id> and gets a clean
            # denied status without re-prompting the operator.
            elif req.kind == "profile_create":
                self._store_profile_create_result(
                    req,
                    status="denied",
                    profile_id=None,
                    reason=reason,
                )
            elif req.kind == "profile_add_device":
                self._store_profile_add_device_result(
                    req,
                    status="denied",
                    profile_id=None,
                    new_phone_id=None,
                    reason=reason,
                )
            elif req.kind == "profile_revoke_device":
                self._store_profile_revoke_device_result(
                    req,
                    status="denied",
                    profile_id=None,
                    phone_id_revoked=None,
                    reason=reason,
                )
            self._send_json(HTTPStatus.OK, {"resolved": True})
            return
        if decision != "approved":
            raise BootloaderError(f"unknown decision {decision!r}")
        sig = body.get("signature_b64u", "")
        phone = cfg.state.get_phone(req.phone_id)
        if phone is None:
            raise UnknownPhoneError(f"phone {req.phone_id!r} no longer registered")
        # Verify the phone's signature over the payload hash.
        # The phone signs the BLAKE2b-256 hash, not the raw payload,
        # so we verify against the hash bytes.
        # For kind=="eth_sign" this Ed25519 envelope still applies — it
        # proves the response came from the paired phone. The Ethereum
        # secp256k1 r||s||v signature rides alongside as an opaque
        # forwarded value (see protocol RFC §"Approval response").
        padding = "=" * (-len(req.payload_hash_b64u) % 4)
        hash_bytes = base64.urlsafe_b64decode(req.payload_hash_b64u + padding)
        # The phone's registered algorithm (ed25519 or ecdsa-p256, etc.)
        # determines the verify path. Without this, ecdsa-p256-pubkey
        # phones fail with "ed25519 public key must decode to 32 bytes;
        # got 64" because verify_signature defaults to ed25519.
        phone_algo = _registered_algorithm(phone, phone.phone_id)
        ok = verify_signature(
            payload=hash_bytes,
            signature_b64u=sig,
            public_key_b64u=phone.public_key_b64u,
            algorithm=phone_algo,
        )
        if not ok:
            self._notify_resolved(req, ok=False, signature_b64u=None,
                                  eth_signature_rsv=None,
                                  btc_signature_base64=None,
                                  reason="signature verification failed")
            raise BootloaderError("approved-response signature invalid")
        # Extract the Ethereum signature when the kind is eth_sign. Per
        # the protocol RFC the bootloader does NOT validate the secp256k1
        # signature itself — that's the consumer's responsibility (smart
        # contract on chain, off-chain verifier, capability-JWT scope
        # enforcer, etc.). We just enforce a structural shape so a
        # malformed rsv doesn't propagate downstream silently.
        eth_sig = None
        if req.kind == "eth_sign":
            eth_sig = body.get("eth_signature_rsv")
            if not isinstance(eth_sig, str) or not eth_sig:
                self._notify_resolved(req, ok=False, signature_b64u=None,
                                      eth_signature_rsv=None,
                                      btc_signature_base64=None,
                                      reason="eth_signature_rsv missing on eth_sign approval")
                raise BootloaderError(
                    "eth_sign approval missing eth_signature_rsv"
                )
            cleaned = eth_sig[2:] if eth_sig.startswith(("0x", "0X")) else eth_sig
            # personal_sign + typed_data return a 65-byte r||s||v signature
            # (130 hex chars). transaction returns the FULL signed raw-tx
            # bytes (0x02 || rlp([fields..., yParity, r, s])) which varies
            # in length depending on the access-list size and the byte
            # widths of the signed integers (typical simple ETH transfer
            # is ~108-114 bytes / ~216-228 hex chars; an EIP-1559 tx with
            # accessList entries can be much longer). For transaction we
            # accept any length above a sane minimum and let the consumer
            # (RPC node / eth_sendRawTransaction) do the heavy validation.
            kind = req.eth_message_kind or "personal_sign"
            if kind == "transaction":
                if len(cleaned) < 200:
                    self._notify_resolved(req, ok=False, signature_b64u=None,
                                          eth_signature_rsv=None,
                                          btc_signature_base64=None,
                                          reason="eth_signature_rsv too short for transaction")
                    raise BootloaderError(
                        f"eth_signature_rsv for transaction must be at least 200 hex chars (signed-tx is too short to be valid), got {len(cleaned)}"
                    )
            else:
                if len(cleaned) != 130:
                    self._notify_resolved(req, ok=False, signature_b64u=None,
                                          eth_signature_rsv=None,
                                          btc_signature_base64=None,
                                          reason="eth_signature_rsv wrong length")
                    raise BootloaderError(
                        f"eth_signature_rsv for {kind} must be 130 hex chars after optional 0x prefix, got {len(cleaned)}"
                    )
            try:
                bytes.fromhex(cleaned)
            except ValueError as exc:
                self._notify_resolved(req, ok=False, signature_b64u=None,
                                      eth_signature_rsv=None,
                                      btc_signature_base64=None,
                                      reason="eth_signature_rsv not hex")
                raise BootloaderError(
                    f"eth_signature_rsv must be hex, got {exc}"
                ) from exc
        # Same shape for btc_sign: structure-check only, opaque forward.
        # BIP-137 compact signatures are 65 raw bytes base64-encoded,
        # which is 88 chars (with padding) or 87 chars (without).
        # Some encoders strip trailing `=` padding; accept both.
        btc_sig = None
        if req.kind == "btc_sign":
            btc_sig = body.get("btc_signature_base64")
            if not isinstance(btc_sig, str) or not btc_sig:
                self._notify_resolved(req, ok=False, signature_b64u=None,
                                      eth_signature_rsv=None,
                                      btc_signature_base64=None,
                                      reason="btc_signature_base64 missing on btc_sign approval")
                raise BootloaderError(
                    "btc_sign approval missing btc_signature_base64"
                )
            try:
                decoded = base64.b64decode(btc_sig.strip(), validate=False)
            except Exception as exc:
                self._notify_resolved(req, ok=False, signature_b64u=None,
                                      eth_signature_rsv=None,
                                      btc_signature_base64=None,
                                      reason="btc_signature_base64 not base64")
                raise BootloaderError(
                    f"btc_signature_base64 must be valid base64, got {exc}"
                ) from exc
            if len(decoded) != 65:
                self._notify_resolved(req, ok=False, signature_b64u=None,
                                      eth_signature_rsv=None,
                                      btc_signature_base64=None,
                                      reason="btc_signature_base64 wrong decoded length")
                raise BootloaderError(
                    f"btc_signature_base64 must decode to 65 bytes, got {len(decoded)}"
                )
            header = decoded[0]
            if header < 27 or header > 42:
                self._notify_resolved(req, ok=False, signature_b64u=None,
                                      eth_signature_rsv=None,
                                      btc_signature_base64=None,
                                      reason="btc_signature_base64 header byte out of range")
                raise BootloaderError(
                    f"BIP-137 header byte must be in 27..42, got {header}"
                )
        # Same shape for ed_sign: structure-check only, opaque forward.
        # Raw ed25519 signatures are exactly 64 bytes (R||S). The
        # response also carries ed_pubkey_hex (32-byte ed25519 public
        # key, 64 hex chars) because XRP addresses are HASH160s and
        # can't recover their pubkey — for protocol uniformity all
        # three ed25519 chains carry the pubkey explicitly. The
        # bootloader does NOT verify the ed25519 signature itself —
        # that's the consumer's responsibility (chain RPC node /
        # off-chain attestation verifier / capability-scope enforcer).
        ed_sig: str | None = None
        ed_pub: str | None = None
        if req.kind == "ed_sign":
            ed_sig = body.get("ed_signature_base64")
            if not isinstance(ed_sig, str) or not ed_sig:
                self._notify_resolved(req, ok=False, signature_b64u=None,
                                      eth_signature_rsv=None,
                                      btc_signature_base64=None,
                                      ed_signature_base64=None,
                                      ed_pubkey_hex=None,
                                      reason="ed_signature_base64 missing on ed_sign approval")
                raise BootloaderError(
                    "ed_sign approval missing ed_signature_base64"
                )
            try:
                ed_decoded = base64.b64decode(ed_sig.strip(), validate=False)
            except Exception as exc:
                self._notify_resolved(req, ok=False, signature_b64u=None,
                                      eth_signature_rsv=None,
                                      btc_signature_base64=None,
                                      ed_signature_base64=None,
                                      ed_pubkey_hex=None,
                                      reason="ed_signature_base64 not base64")
                raise BootloaderError(
                    f"ed_signature_base64 must be valid base64, got {exc}"
                ) from exc
            if len(ed_decoded) != 64:
                self._notify_resolved(req, ok=False, signature_b64u=None,
                                      eth_signature_rsv=None,
                                      btc_signature_base64=None,
                                      ed_signature_base64=None,
                                      ed_pubkey_hex=None,
                                      reason="ed_signature_base64 wrong decoded length")
                raise BootloaderError(
                    f"ed_signature_base64 must decode to 64 bytes, got {len(ed_decoded)}"
                )
            ed_pub = body.get("ed_pubkey_hex")
            if not isinstance(ed_pub, str) or not ed_pub:
                self._notify_resolved(req, ok=False, signature_b64u=None,
                                      eth_signature_rsv=None,
                                      btc_signature_base64=None,
                                      ed_signature_base64=None,
                                      ed_pubkey_hex=None,
                                      reason="ed_pubkey_hex missing on ed_sign approval")
                raise BootloaderError(
                    "ed_sign approval missing ed_pubkey_hex"
                )
            ed_pub_clean = ed_pub.strip()
            ed_pub_clean = ed_pub_clean[2:] if ed_pub_clean.startswith(("0x", "0X")) else ed_pub_clean
            if len(ed_pub_clean) != 64:
                self._notify_resolved(req, ok=False, signature_b64u=None,
                                      eth_signature_rsv=None,
                                      btc_signature_base64=None,
                                      ed_signature_base64=None,
                                      ed_pubkey_hex=None,
                                      reason="ed_pubkey_hex wrong length")
                raise BootloaderError(
                    f"ed_pubkey_hex must be 64 hex chars (32-byte ed25519 pubkey) "
                    f"after optional 0x prefix, got {len(ed_pub_clean)}"
                )
            try:
                bytes.fromhex(ed_pub_clean)
            except ValueError as exc:
                self._notify_resolved(req, ok=False, signature_b64u=None,
                                      eth_signature_rsv=None,
                                      btc_signature_base64=None,
                                      ed_signature_base64=None,
                                      ed_pubkey_hex=None,
                                      reason="ed_pubkey_hex not hex")
                raise BootloaderError(
                    f"ed_pubkey_hex must be hex, got {exc}"
                ) from exc
            # Normalize ed_pub to the un-prefixed form for downstream
            # forwarding so consumers don't have to re-strip.
            ed_pub = ed_pub_clean
        # Same shape for tron_sign: structure-check only, opaque
        # forward. TRON message-signing produces a 65-byte r||s||v
        # secp256k1 signature exactly like Ethereum (130 hex chars
        # after optional 0x prefix). The bootloader does NOT verify
        # the secp256k1 signature itself -- consumers (chain RPC /
        # off-chain verifier / capability-scope enforcer) recover
        # the address via `recto.tron.recover_address` and compare
        # to `tron_address` from the request context.
        tron_sig: str | None = None
        if req.kind == "tron_sign":
            tron_sig = body.get("tron_signature_rsv")
            if not isinstance(tron_sig, str) or not tron_sig:
                self._notify_resolved(req, ok=False, signature_b64u=None,
                                      eth_signature_rsv=None,
                                      btc_signature_base64=None,
                                      ed_signature_base64=None,
                                      ed_pubkey_hex=None,
                                      tron_signature_rsv=None,
                                      reason="tron_signature_rsv missing on tron_sign approval")
                raise BootloaderError(
                    "tron_sign approval missing tron_signature_rsv"
                )
            cleaned = tron_sig[2:] if tron_sig.startswith(("0x", "0X")) else tron_sig
            # message_signing returns 65-byte r||s||v = 130 hex chars.
            # transaction is reserved (refused at construction time);
            # add a length floor only when TRON transaction signing
            # actually lands.
            if len(cleaned) != 130:
                self._notify_resolved(req, ok=False, signature_b64u=None,
                                      eth_signature_rsv=None,
                                      btc_signature_base64=None,
                                      ed_signature_base64=None,
                                      ed_pubkey_hex=None,
                                      tron_signature_rsv=None,
                                      reason="tron_signature_rsv wrong length")
                raise BootloaderError(
                    f"tron_signature_rsv must be 130 hex chars after optional "
                    f"0x prefix, got {len(cleaned)}"
                )
            try:
                bytes.fromhex(cleaned)
            except ValueError as exc:
                self._notify_resolved(req, ok=False, signature_b64u=None,
                                      eth_signature_rsv=None,
                                      btc_signature_base64=None,
                                      ed_signature_base64=None,
                                      ed_pubkey_hex=None,
                                      tron_signature_rsv=None,
                                      reason="tron_signature_rsv not hex")
                raise BootloaderError(
                    f"tron_signature_rsv must be hex, got {exc}"
                ) from exc
        # Capability-request approval (Phase 5 Wave B). Phone returns
        # the secp256k1 sig over SHA-256(`{cap_header_b64}.{cap_payload_b64}`)
        # via cap_signature_b64u (64 raw bytes, base64url-encoded). The
        # bootloader assembles the final 3-part JWS and stores it as a
        # CapabilityResult for the requesting agent to fetch via the
        # result endpoint. If cfg.capability_operator_pubkey is set,
        # the bootloader also verifies the JWS signature recovers to
        # the expected operator pubkey before storing — production
        # deployments MUST configure this; dev / test deployments may
        # leave it None and trust the Ed25519 paired-phone envelope
        # alone (the signature is still produced by the phone, just
        # not pubkey-verified by the bootloader).
        capability_jws: str | None = None
        if req.kind == "capability_request":
            cap_sig_b64u = body.get("cap_signature_b64u")
            if not isinstance(cap_sig_b64u, str) or not cap_sig_b64u:
                self._notify_resolved(req, ok=False, signature_b64u=None,
                                      eth_signature_rsv=None,
                                      btc_signature_base64=None,
                                      ed_signature_base64=None,
                                      ed_pubkey_hex=None,
                                      tron_signature_rsv=None,
                                      capability_jws=None,
                                      reason="cap_signature_b64u missing on capability_request approval")
                self._store_capability_result(
                    req, status="signature_error", capability_jws=None,
                    reason="cap_signature_b64u missing",
                )
                raise BootloaderError(
                    "capability_request approval missing cap_signature_b64u"
                )
            try:
                cap_pad = "=" * (-len(cap_sig_b64u) % 4)
                cap_sig_bytes = base64.urlsafe_b64decode(cap_sig_b64u + cap_pad)
            except Exception as exc:  # noqa: BLE001
                self._notify_resolved(req, ok=False, signature_b64u=None,
                                      eth_signature_rsv=None,
                                      btc_signature_base64=None,
                                      ed_signature_base64=None,
                                      ed_pubkey_hex=None,
                                      tron_signature_rsv=None,
                                      capability_jws=None,
                                      reason="cap_signature_b64u not base64url")
                self._store_capability_result(
                    req, status="signature_error", capability_jws=None,
                    reason=f"cap_signature_b64u not base64url: {exc}",
                )
                raise BootloaderError(
                    f"cap_signature_b64u must be base64url, got {exc}"
                ) from exc
            if len(cap_sig_bytes) != 64:
                self._notify_resolved(req, ok=False, signature_b64u=None,
                                      eth_signature_rsv=None,
                                      btc_signature_base64=None,
                                      ed_signature_base64=None,
                                      ed_pubkey_hex=None,
                                      tron_signature_rsv=None,
                                      capability_jws=None,
                                      reason="cap_signature_b64u wrong decoded length")
                self._store_capability_result(
                    req, status="signature_error", capability_jws=None,
                    reason=(
                        f"cap_signature_b64u must decode to 64 bytes "
                        f"(raw r||s); got {len(cap_sig_bytes)}"
                    ),
                )
                raise BootloaderError(
                    f"cap_signature_b64u must decode to 64 bytes, "
                    f"got {len(cap_sig_bytes)}"
                )
            # Assemble the final 3-part JWS. Imported lazily to keep
            # the bootloader package importable without recto.capability
            # for other endpoints.
            from recto.capability.jwt import assemble_jws as _assemble_jws
            capability_jws = _assemble_jws(
                req.cap_header_b64, req.cap_payload_b64, cap_sig_bytes,
            )
            # Verify the assembled JWS signature recovers to the operator
            # pubkey. Defense against a phone-side bug that signs the wrong
            # digest.
            #
            # THIS BLOCK USED TO READ `if cfg.capability_operator_pubkey is
            # not None:` — i.e. it SKIPPED verification entirely when no
            # operator key was configured, and returned the assembled JWS
            # anyway. Every other site that consumes this field already
            # fails closed (:1981, :2189, :2385, :4946 all refuse when it is
            # None); this one was the lone fail-open, and the default is
            # None. A bootloader that has never been told who the operator
            # is would mint on any signature it was handed.
            #
            # This is not necessarily the only verification of a minted
            # capability: a consuming service is expected to verify the JWS
            # against its own configured operator pubkey before acting on it.
            # So the check here is defence in depth rather than the sole
            # gate. It fails closed regardless, because a defence that
            # silently disables itself is not one.
            if cfg.capability_operator_pubkey is None:
                reason = (
                    "capability minting requires capability_operator_pubkey; "
                    "none is configured. Provision it (vault_root.json in the "
                    "bootloader state dir, written at spawn) and restart."
                )
                self._notify_resolved(req, ok=False, signature_b64u=None,
                                      eth_signature_rsv=None,
                                      btc_signature_base64=None,
                                      ed_signature_base64=None,
                                      ed_pubkey_hex=None,
                                      tron_signature_rsv=None,
                                      capability_jws=None,
                                      reason=reason)
                self._store_capability_result(
                    req, status="not_configured", capability_jws=None,
                    reason=reason,
                )
                raise BootloaderError(reason)

            from recto.capability.jwt import verify_jws as _verify_jws
            try:
                _verify_jws(
                    capability_jws,
                    expected_pubkey=cfg.capability_operator_pubkey,
                )
            except Exception as exc:  # noqa: BLE001
                self._notify_resolved(req, ok=False, signature_b64u=None,
                                      eth_signature_rsv=None,
                                      btc_signature_base64=None,
                                      ed_signature_base64=None,
                                      ed_pubkey_hex=None,
                                      tron_signature_rsv=None,
                                      capability_jws=None,
                                      reason=f"capability JWS verify failed: {exc}")
                self._store_capability_result(
                    req, status="signature_error", capability_jws=None,
                    reason=f"capability JWS verify failed: {exc}",
                )
                raise BootloaderError(
                    f"capability JWS signature did not verify against "
                    f"operator pubkey: {exc}"
                ) from exc
            # All structure / signature checks passed — stash the
            # assembled JWS for the agent's result-poll fetch.
            self._store_capability_result(
                req, status="approved",
                capability_jws=capability_jws, reason=None,
            )
        # Profile-create approval (Phase 2.0.B). Phone returns the
        # secp256k1 master-attestation sig over
        # SHA-256(canonical_json(candidate_fields)) via
        # cap_signature_b64u (64 raw bytes, base64url-encoded — same
        # field name and shape as capability_request's signature so
        # phone-side respond logic doesn't fork). Bootloader:
        #   1. Decodes + structurally validates the 64-byte raw r||s.
        #   2. Re-derives the digest from cap_payload_b64 (the canonical-
        #      JSON encoding stashed at queue time).
        #   3. Recovers the secp256k1 pubkey from the signature; if it
        #      matches cfg.capability_operator_pubkey, the master has
        #      attested to this candidate profile shape.
        #   4. **Persist-last (Milan commitment B)**: calls
        #      profile.manage.create_child_profile to atomic-write the
        #      new Profile row to master_identity.json.
        #   5. Stashes a ProfileCreateResult with the new profile_id
        #      for the caller's poll.
        # Order is critical: every failure path stores a non-approved
        # result with a clearly-prefixed reason so the caller can
        # distinguish "phone signed wrong" from "disk write failed"
        # (Milan commitment C — never claim success when source-of-truth
        # failed).
        if req.kind == "profile_create":
            cap_sig_b64u = body.get("cap_signature_b64u")
            if not isinstance(cap_sig_b64u, str) or not cap_sig_b64u:
                self._notify_resolved(req, ok=False, signature_b64u=None,
                                      eth_signature_rsv=None,
                                      btc_signature_base64=None,
                                      ed_signature_base64=None,
                                      ed_pubkey_hex=None,
                                      tron_signature_rsv=None,
                                      reason="cap_signature_b64u missing on profile_create approval")
                self._store_profile_create_result(
                    req, status="signature_error", profile_id=None,
                    reason="cap_signature_b64u missing",
                )
                raise BootloaderError(
                    "profile_create approval missing cap_signature_b64u"
                )
            # Decode + length check
            try:
                cap_pad = "=" * (-len(cap_sig_b64u) % 4)
                cap_sig_bytes = base64.urlsafe_b64decode(cap_sig_b64u + cap_pad)
            except Exception as exc:  # noqa: BLE001
                self._notify_resolved(req, ok=False, signature_b64u=None,
                                      eth_signature_rsv=None,
                                      btc_signature_base64=None,
                                      ed_signature_base64=None,
                                      ed_pubkey_hex=None,
                                      tron_signature_rsv=None,
                                      reason="cap_signature_b64u not base64url")
                self._store_profile_create_result(
                    req, status="signature_error", profile_id=None,
                    reason=f"cap_signature_b64u not base64url: {exc}",
                )
                raise BootloaderError(
                    f"cap_signature_b64u must be base64url, got {exc}"
                ) from exc
            if len(cap_sig_bytes) != 64:
                self._notify_resolved(req, ok=False, signature_b64u=None,
                                      eth_signature_rsv=None,
                                      btc_signature_base64=None,
                                      ed_signature_base64=None,
                                      ed_pubkey_hex=None,
                                      tron_signature_rsv=None,
                                      reason="cap_signature_b64u wrong decoded length")
                self._store_profile_create_result(
                    req, status="signature_error", profile_id=None,
                    reason=(
                        f"cap_signature_b64u must decode to 64 bytes "
                        f"(raw r||s); got {len(cap_sig_bytes)}"
                    ),
                )
                raise BootloaderError(
                    f"cap_signature_b64u must decode to 64 bytes, "
                    f"got {len(cap_sig_bytes)}"
                )
            # v2.0.C wave C.1: child_pubkey_hex on the response body
            # is REQUIRED. The phone derives this from the master
            # mnemonic at the candidate's BIP-32 path and signs over
            # the FULL canonical JSON (queue-time candidate fields +
            # this pubkey). Bootloader reconstructs the same canonical
            # JSON server-side, SHA-256s it, recovers the secp256k1
            # signature against the operator pubkey. If the phone lied
            # about the derived pubkey, the recovered pubkey won't
            # match the operator and the request fails.
            #
            # v2.0.B-shaped responses (no child_pubkey_hex) are
            # rejected with `protocol_violation` — no conditional
            # fallback. Operators upgrading bootloader without
            # upgrading phones get a clear actionable error per the
            # SPEC.md C.1 design decision.
            child_pubkey_hex_raw = body.get("child_pubkey_hex")
            if not isinstance(child_pubkey_hex_raw, str) or not child_pubkey_hex_raw:
                self._notify_resolved(req, ok=False, signature_b64u=None,
                                      eth_signature_rsv=None,
                                      btc_signature_base64=None,
                                      ed_signature_base64=None,
                                      ed_pubkey_hex=None,
                                      tron_signature_rsv=None,
                                      reason="child_pubkey_hex missing on profile_create approval (v2.0.C)")
                self._store_profile_create_result(
                    req, status="signature_error", profile_id=None,
                    reason=(
                        "protocol_violation: child_pubkey_hex required in "
                        "v2.0.C wire shape; v2.0.B clients must upgrade to "
                        "a v2.0.C-aware phone build"
                    ),
                )
                raise BootloaderError(
                    "profile_create approval missing child_pubkey_hex (v2.0.C requirement)"
                )
            # Normalize: accept 0x / 0x04 prefixed forms (operator
            # paste-shape footgun defense, same pattern as the vault-
            # bootstrap pubkey accept path), lowercase, validate
            # hex chars + length.
            child_pubkey_clean = child_pubkey_hex_raw.strip().lower()
            if child_pubkey_clean.startswith("0x"):
                child_pubkey_clean = child_pubkey_clean[2:]
            if child_pubkey_clean.startswith("04") and len(child_pubkey_clean) == 130:
                child_pubkey_clean = child_pubkey_clean[2:]
            if len(child_pubkey_clean) != 128:
                self._store_profile_create_result(
                    req, status="signature_error", profile_id=None,
                    reason=(
                        f"child_pubkey_hex must be 128 hex chars after "
                        f"optional 0x / 0x04 prefix strip; got "
                        f"{len(child_pubkey_clean)}"
                    ),
                )
                raise BootloaderError(
                    f"profile_create child_pubkey_hex wrong length: "
                    f"{len(child_pubkey_clean)}"
                )
            try:
                bytes.fromhex(child_pubkey_clean)
            except ValueError as exc:
                self._store_profile_create_result(
                    req, status="signature_error", profile_id=None,
                    reason=f"child_pubkey_hex contains non-hex chars: {exc}",
                )
                raise BootloaderError(
                    f"profile_create child_pubkey_hex non-hex: {exc}"
                ) from exc

            # Re-derive the digest the phone signed over. The signing
            # input was stashed in cap_payload_b64 at queue time; we
            # PARSE that JSON back, INJECT child_pubkey_hex (which the
            # phone added before signing), re-canonicalize with the
            # same encoder, then SHA-256 the resulting bytes to get
            # the 32-byte digest the secp256k1 signature is over.
            try:
                pad = "=" * (-len(req.cap_payload_b64) % 4)
                signing_input_bytes = base64.urlsafe_b64decode(req.cap_payload_b64 + pad)
            except Exception as exc:  # noqa: BLE001
                self._store_profile_create_result(
                    req, status="signature_error", profile_id=None,
                    reason=f"cap_payload_b64 malformed at verify time: {exc}",
                )
                raise BootloaderError(
                    f"profile_create cap_payload_b64 malformed: {exc}"
                ) from exc
            try:
                partial_fields = json.loads(signing_input_bytes.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                self._store_profile_create_result(
                    req, status="signature_error", profile_id=None,
                    reason=(
                        f"queue-time cap_payload_b64 not valid JSON at "
                        f"verify time: {exc}"
                    ),
                )
                raise BootloaderError(
                    f"profile_create cap_payload_b64 not valid JSON: {exc}"
                ) from exc
            if not isinstance(partial_fields, dict):
                self._store_profile_create_result(
                    req, status="signature_error", profile_id=None,
                    reason=(
                        f"queue-time cap_payload_b64 must be a JSON object, "
                        f"got {type(partial_fields).__name__}"
                    ),
                )
                raise BootloaderError(
                    "profile_create cap_payload_b64 not a JSON object"
                )
            # Defense: reject any queue-time payload that already
            # includes child_pubkey_hex (shouldn't happen — bootloader's
            # _handle_profile_create never stashes it). Catches a
            # malicious or buggy queue-time injection that would let an
            # attacker pre-pin the pubkey and skip the master-attestation
            # binding.
            if "child_pubkey_hex" in partial_fields:
                self._store_profile_create_result(
                    req, status="signature_error", profile_id=None,
                    reason=(
                        "queue-time cap_payload_b64 unexpectedly includes "
                        "child_pubkey_hex; expected to be absent until phone "
                        "supplies"
                    ),
                )
                raise BootloaderError(
                    "profile_create queue-time payload pre-populated child_pubkey_hex"
                )
            from recto.capability.jwt import _canonical_json as _to_canonical
            partial_fields["child_pubkey_hex"] = child_pubkey_clean
            full_signing_input_bytes = _to_canonical(partial_fields)
            digest = hashlib.sha256(full_signing_input_bytes).digest()
            # Verify the master attestation. The operator pubkey MUST
            # be configured for profile_create to be usable in
            # production — without it, anyone with a paired phone could
            # mint profiles. Dev / test deployments that leave it None
            # MUST treat the Ed25519 paired-phone envelope as the only
            # signal of authenticity (still meaningful, just not
            # operator-master-attested).
            if cfg.capability_operator_pubkey is None:
                self._store_profile_create_result(
                    req, status="signature_error", profile_id=None,
                    reason=(
                        "operator pubkey not configured; profile_create "
                        "verification requires capability_operator_pubkey "
                        "to be set via `recto vault bootstrap`"
                    ),
                )
                raise BootloaderError(
                    "profile_create requires capability_operator_pubkey "
                    "to be configured on the bootloader"
                )
            # The phone signs raw r||s (64 bytes); recto.ethereum.recover_public_key
            # expects the 65-byte r||s||v form, so we try both rec_id
            # candidates by constructing synthetic rsv signatures —
            # same pattern recto.capability.jwt.verify_jws uses for the
            # capability_request flow.
            from recto.ethereum import recover_public_key as _recover_secp256k1_pubkey
            matched = False
            recovery_error: Exception | None = None
            for rec_id in (0, 1):
                synthetic_rsv = cap_sig_bytes + bytes([27 + rec_id])
                try:
                    candidate = _recover_secp256k1_pubkey(digest, synthetic_rsv)
                    if candidate == cfg.capability_operator_pubkey:
                        matched = True
                        break
                except Exception as exc:  # noqa: BLE001
                    recovery_error = exc
                    continue
            if not matched:
                reason_detail = (
                    f": last error {recovery_error}"
                    if recovery_error is not None else ""
                )
                self._store_profile_create_result(
                    req, status="signature_error", profile_id=None,
                    reason=(
                        f"master attestation did not recover to the "
                        f"configured operator pubkey{reason_detail}"
                    ),
                )
                raise BootloaderError(
                    "profile_create master attestation did not "
                    "recover to operator pubkey"
                )
            # Milan commitment B — persist BEFORE storing the result.
            # The atomic write to master_identity.json is the source
            # of truth; if it fails, the caller's poll will see a
            # "signature_error: persist_error: <diag>" result and can
            # diagnose disk state without re-prompting the operator.
            from recto.profile.manage import (
                create_child_profile as _create_child_profile,
            )
            # Pass the bootloader's state directory through so the
            # persist lands in the same location as the rest of the
            # bootloader's persistent state (and same location the
            # POST endpoint's idempotency precheck loaded from).
            _state_dir = cfg.state.state_dir
            try:
                new_profile = _create_child_profile(
                    kind=req.candidate_kind,
                    display_name=req.candidate_display_name,
                    theme_hint=req.candidate_theme_hint,
                    scim_provider=req.candidate_scim_provider,
                    profile_index_override=req.candidate_derivation_index,
                    profile_id_override=req.candidate_profile_id,
                    derived_pubkey_hex=child_pubkey_clean,
                    state_dir=_state_dir,
                )
            except FileNotFoundError as exc:
                # Master not bootstrapped (shouldn't happen — the
                # _handle_profile_create endpoint checks this before
                # queueing — but defense-in-depth).
                self._store_profile_create_result(
                    req, status="signature_error", profile_id=None,
                    reason=(
                        f"persist_error: MasterIdentity not bootstrapped "
                        f"at persist time: {exc}"
                    ),
                )
                raise BootloaderError(
                    f"profile_create persist failed: master not bootstrapped: {exc}"
                ) from exc
            except (OSError, ValueError) as exc:
                # Filesystem error (permission denied, disk full) OR
                # validation regression (kind / display_name rejected
                # at the manage-layer despite passing endpoint
                # validation). Either way: persist failed, don't lie.
                self._store_profile_create_result(
                    req, status="signature_error", profile_id=None,
                    reason=f"persist_error: {type(exc).__name__}: {exc}",
                )
                raise BootloaderError(
                    f"profile_create persist failed: {exc}"
                ) from exc
            # Persist succeeded — stash the approved result for the
            # caller's poll. If the result-store itself fails (in-memory
            # dict insert is effectively unfailable, but defense-in-depth
            # for the case where a future durable result-store throws),
            # log + continue: the profile is on disk and recoverable
            # via `recto profile list` (Milan commitment B).
            try:
                self._store_profile_create_result(
                    req, status="approved",
                    profile_id=new_profile.profile_id, reason=None,
                )
            except Exception as exc:  # noqa: BLE001
                # Log via the bootloader's stderr convention; the
                # caller will see request_not_found and recover via
                # list. The DISK state is consistent — that's what
                # matters.
                print(
                    f"[bootloader] WARNING: profile_create persist succeeded "
                    f"(profile_id={new_profile.profile_id!r}) but result-store "
                    f"failed: {type(exc).__name__}: {exc}. Caller should "
                    f"recover via `recto profile list`.",
                    flush=True,
                )
        # ----------------------------------------------------------
        # profile_add_device branch (Phase 2.0.C wave C.5)
        # ----------------------------------------------------------
        # Sister of profile_create's branch above but simpler — no
        # phone-supplied field needs injection at respond time. The
        # full canonical-JSON signing input was stashed in
        # cap_payload_b64 at queue time; phone signs SHA-256 of those
        # exact bytes. Bootloader at respond time decodes
        # cap_payload_b64, SHA-256s, recovers the secp256k1 signature
        # against the operator master pubkey, then calls
        # profile.manage.profile_add_device to append the new phone_id
        # to the target profile's device_ids tuple.
        #
        # Milan partial-failure discipline (same as profile_create):
        #   * Idempotency-key (caller's request_id) handled at the
        #     endpoint layer's pre-flight check.
        #   * Persist BEFORE storing the result (commitment B).
        #   * Never claim success when persist failed (commitment C):
        #     all failure paths store status="signature_error" with
        #     a "persist_error: ..." reason prefix when disk-write
        #     bombed.
        if req.kind == "profile_add_device":
            cap_sig_b64u = body.get("cap_signature_b64u")
            if not isinstance(cap_sig_b64u, str) or not cap_sig_b64u:
                self._notify_resolved(req, ok=False, signature_b64u=None,
                                      eth_signature_rsv=None,
                                      btc_signature_base64=None,
                                      ed_signature_base64=None,
                                      ed_pubkey_hex=None,
                                      tron_signature_rsv=None,
                                      reason="cap_signature_b64u missing on profile_add_device approval")
                self._store_profile_add_device_result(
                    req, status="signature_error",
                    profile_id=None, new_phone_id=None,
                    reason="cap_signature_b64u missing",
                )
                raise BootloaderError(
                    "profile_add_device approval missing cap_signature_b64u"
                )
            try:
                cap_pad = "=" * (-len(cap_sig_b64u) % 4)
                cap_sig_bytes = base64.urlsafe_b64decode(cap_sig_b64u + cap_pad)
            except Exception as exc:  # noqa: BLE001
                self._notify_resolved(req, ok=False, signature_b64u=None,
                                      eth_signature_rsv=None,
                                      btc_signature_base64=None,
                                      ed_signature_base64=None,
                                      ed_pubkey_hex=None,
                                      tron_signature_rsv=None,
                                      reason="cap_signature_b64u not base64url")
                self._store_profile_add_device_result(
                    req, status="signature_error",
                    profile_id=None, new_phone_id=None,
                    reason=f"cap_signature_b64u not base64url: {exc}",
                )
                raise BootloaderError(
                    f"cap_signature_b64u must be base64url, got {exc}"
                ) from exc
            if len(cap_sig_bytes) != 64:
                self._store_profile_add_device_result(
                    req, status="signature_error",
                    profile_id=None, new_phone_id=None,
                    reason=(
                        f"cap_signature_b64u must decode to 64 bytes "
                        f"(raw r||s); got {len(cap_sig_bytes)}"
                    ),
                )
                raise BootloaderError(
                    f"cap_signature_b64u must decode to 64 bytes, "
                    f"got {len(cap_sig_bytes)}"
                )
            # Decode the queue-time canonical-JSON signing input.
            try:
                pad = "=" * (-len(req.cap_payload_b64) % 4)
                signing_input_bytes = base64.urlsafe_b64decode(
                    req.cap_payload_b64 + pad
                )
            except Exception as exc:  # noqa: BLE001
                self._store_profile_add_device_result(
                    req, status="signature_error",
                    profile_id=None, new_phone_id=None,
                    reason=f"cap_payload_b64 malformed at verify time: {exc}",
                )
                raise BootloaderError(
                    f"profile_add_device cap_payload_b64 malformed: {exc}"
                ) from exc
            digest = hashlib.sha256(signing_input_bytes).digest()
            # Master pubkey required
            if cfg.capability_operator_pubkey is None:
                self._store_profile_add_device_result(
                    req, status="signature_error",
                    profile_id=None, new_phone_id=None,
                    reason=(
                        "operator pubkey not configured; profile_add_device "
                        "verification requires capability_operator_pubkey "
                        "to be set via `recto vault bootstrap`"
                    ),
                )
                raise BootloaderError(
                    "profile_add_device requires capability_operator_pubkey "
                    "to be configured on the bootloader"
                )
            # Recover signature; try both rec_id candidates (same pattern
            # as profile_create + capability_request).
            from recto.ethereum import (
                recover_public_key as _recover_secp256k1_pubkey,
            )
            matched = False
            recovery_error: Exception | None = None
            for rec_id in (0, 1):
                synthetic_rsv = cap_sig_bytes + bytes([27 + rec_id])
                try:
                    candidate = _recover_secp256k1_pubkey(digest, synthetic_rsv)
                    if candidate == cfg.capability_operator_pubkey:
                        matched = True
                        break
                except Exception as exc:  # noqa: BLE001
                    recovery_error = exc
                    continue
            if not matched:
                reason_detail = (
                    f": last error {recovery_error}"
                    if recovery_error is not None else ""
                )
                self._store_profile_add_device_result(
                    req, status="signature_error",
                    profile_id=None, new_phone_id=None,
                    reason=(
                        f"master attestation did not recover to the "
                        f"configured operator pubkey{reason_detail}"
                    ),
                )
                raise BootloaderError(
                    "profile_add_device master attestation did not "
                    "recover to operator pubkey"
                )
            # Verified — persist via manage.py. Milan commitment B.
            from recto.profile.manage import (
                profile_add_device as _profile_add_device,
            )
            _state_dir = cfg.state.state_dir
            try:
                updated_profile = _profile_add_device(
                    profile_id=req.addev_profile_id,
                    new_phone_id=req.addev_new_phone_id,
                    state_dir=_state_dir,
                )
            except KeyError as exc:
                # Profile not found under the master (rare —
                # the endpoint pre-flight checks this — but
                # defense-in-depth).
                self._store_profile_add_device_result(
                    req, status="signature_error",
                    profile_id=None, new_phone_id=None,
                    reason=(
                        f"persist_error: profile_id not found at "
                        f"persist time: {exc}"
                    ),
                )
                raise BootloaderError(
                    f"profile_add_device persist failed: profile not found: {exc}"
                ) from exc
            except FileNotFoundError as exc:
                self._store_profile_add_device_result(
                    req, status="signature_error",
                    profile_id=None, new_phone_id=None,
                    reason=(
                        f"persist_error: MasterIdentity not bootstrapped "
                        f"at persist time: {exc}"
                    ),
                )
                raise BootloaderError(
                    f"profile_add_device persist failed: master not bootstrapped: {exc}"
                ) from exc
            except (OSError, ValueError) as exc:
                # ValueError: revoked-profile guard, malformed inputs
                # OSError: disk full / permission denied at write
                self._store_profile_add_device_result(
                    req, status="signature_error",
                    profile_id=None, new_phone_id=None,
                    reason=f"persist_error: {type(exc).__name__}: {exc}",
                )
                raise BootloaderError(
                    f"profile_add_device persist failed: {exc}"
                ) from exc
            # Persist succeeded — stash the approved result for the
            # caller's poll. Same defense-in-depth as profile_create.
            try:
                self._store_profile_add_device_result(
                    req, status="approved",
                    profile_id=updated_profile.profile_id,
                    new_phone_id=req.addev_new_phone_id, reason=None,
                )
            except Exception as exc:  # noqa: BLE001
                print(
                    f"[bootloader] WARNING: profile_add_device persist succeeded "
                    f"(profile_id={updated_profile.profile_id!r}, "
                    f"new_phone_id={req.addev_new_phone_id!r}) but result-store "
                    f"failed: {type(exc).__name__}: {exc}. Caller should "
                    f"recover via `recto profile show <profile_id>`.",
                    flush=True,
                )
        # ----------------------------------------------------------
        # profile_revoke_device branch (Phase 2.0.C wave C.6)
        # ----------------------------------------------------------
        # Sister of profile_add_device's branch but calls
        # profile_revoke_device on the manage.py side instead of
        # profile_add_device. Same Milan partial-failure discipline:
        # verify signature first, persist via manage.py, store result
        # only after persist succeeds.
        #
        # At v1 this branch handles K=1 master-only signing (the
        # operator master phone signs the canonical-JSON binding with
        # its BIP-39-derived secp256k1 key, bootloader recovers
        # against vault_root.json's operator pubkey). K>=2 quorum
        # aggregation is rejected at the endpoint pre-flight with
        # quorum_not_yet_implemented before any queue happens, so by
        # the time we get here only K=1 requests exist.
        if req.kind == "profile_revoke_device":
            cap_sig_b64u = body.get("cap_signature_b64u")
            if not isinstance(cap_sig_b64u, str) or not cap_sig_b64u:
                self._notify_resolved(req, ok=False, signature_b64u=None,
                                      eth_signature_rsv=None,
                                      btc_signature_base64=None,
                                      ed_signature_base64=None,
                                      ed_pubkey_hex=None,
                                      tron_signature_rsv=None,
                                      reason="cap_signature_b64u missing on profile_revoke_device approval")
                self._store_profile_revoke_device_result(
                    req, status="signature_error",
                    profile_id=None, phone_id_revoked=None,
                    reason="cap_signature_b64u missing",
                )
                raise BootloaderError(
                    "profile_revoke_device approval missing cap_signature_b64u"
                )
            try:
                cap_pad = "=" * (-len(cap_sig_b64u) % 4)
                cap_sig_bytes = base64.urlsafe_b64decode(cap_sig_b64u + cap_pad)
            except Exception as exc:  # noqa: BLE001
                self._notify_resolved(req, ok=False, signature_b64u=None,
                                      eth_signature_rsv=None,
                                      btc_signature_base64=None,
                                      ed_signature_base64=None,
                                      ed_pubkey_hex=None,
                                      tron_signature_rsv=None,
                                      reason="cap_signature_b64u not base64url")
                self._store_profile_revoke_device_result(
                    req, status="signature_error",
                    profile_id=None, phone_id_revoked=None,
                    reason=f"cap_signature_b64u not base64url: {exc}",
                )
                raise BootloaderError(
                    f"cap_signature_b64u must be base64url, got {exc}"
                ) from exc
            if len(cap_sig_bytes) != 64:
                self._store_profile_revoke_device_result(
                    req, status="signature_error",
                    profile_id=None, phone_id_revoked=None,
                    reason=(
                        f"cap_signature_b64u must decode to 64 bytes "
                        f"(raw r||s); got {len(cap_sig_bytes)}"
                    ),
                )
                raise BootloaderError(
                    f"cap_signature_b64u must decode to 64 bytes, "
                    f"got {len(cap_sig_bytes)}"
                )
            # Decode the queue-time canonical-JSON signing input.
            try:
                pad = "=" * (-len(req.cap_payload_b64) % 4)
                signing_input_bytes = base64.urlsafe_b64decode(
                    req.cap_payload_b64 + pad
                )
            except Exception as exc:  # noqa: BLE001
                self._store_profile_revoke_device_result(
                    req, status="signature_error",
                    profile_id=None, phone_id_revoked=None,
                    reason=f"cap_payload_b64 malformed at verify time: {exc}",
                )
                raise BootloaderError(
                    f"profile_revoke_device cap_payload_b64 malformed: {exc}"
                ) from exc
            digest = hashlib.sha256(signing_input_bytes).digest()
            if cfg.capability_operator_pubkey is None:
                self._store_profile_revoke_device_result(
                    req, status="signature_error",
                    profile_id=None, phone_id_revoked=None,
                    reason=(
                        "operator pubkey not configured; "
                        "profile_revoke_device verification requires "
                        "capability_operator_pubkey to be set via "
                        "`recto vault bootstrap`"
                    ),
                )
                raise BootloaderError(
                    "profile_revoke_device requires capability_operator_pubkey "
                    "to be configured on the bootloader"
                )
            from recto.ethereum import (
                recover_public_key as _recover_secp256k1_pubkey,
            )
            matched = False
            recovery_error: Exception | None = None
            for rec_id in (0, 1):
                synthetic_rsv = cap_sig_bytes + bytes([27 + rec_id])
                try:
                    candidate = _recover_secp256k1_pubkey(digest, synthetic_rsv)
                    if candidate == cfg.capability_operator_pubkey:
                        matched = True
                        break
                except Exception as exc:  # noqa: BLE001
                    recovery_error = exc
                    continue
            if not matched:
                reason_detail = (
                    f": last error {recovery_error}"
                    if recovery_error is not None else ""
                )
                self._store_profile_revoke_device_result(
                    req, status="signature_error",
                    profile_id=None, phone_id_revoked=None,
                    reason=(
                        f"master attestation did not recover to the "
                        f"configured operator pubkey{reason_detail}"
                    ),
                )
                raise BootloaderError(
                    "profile_revoke_device master attestation did not "
                    "recover to operator pubkey"
                )
            # Verified — persist via manage.py. Milan commitment B.
            from recto.profile.manage import (
                profile_revoke_device as _profile_revoke_device,
            )
            _state_dir = cfg.state.state_dir
            try:
                updated_profile = _profile_revoke_device(
                    profile_id=req.revdev_profile_id,
                    phone_id_to_revoke=req.revdev_phone_id_to_revoke,
                    state_dir=_state_dir,
                )
            except KeyError as exc:
                self._store_profile_revoke_device_result(
                    req, status="signature_error",
                    profile_id=None, phone_id_revoked=None,
                    reason=(
                        f"persist_error: profile_id not found at "
                        f"persist time: {exc}"
                    ),
                )
                raise BootloaderError(
                    f"profile_revoke_device persist failed: profile not found: {exc}"
                ) from exc
            except FileNotFoundError as exc:
                self._store_profile_revoke_device_result(
                    req, status="signature_error",
                    profile_id=None, phone_id_revoked=None,
                    reason=(
                        f"persist_error: MasterIdentity not bootstrapped "
                        f"at persist time: {exc}"
                    ),
                )
                raise BootloaderError(
                    f"profile_revoke_device persist failed: master not bootstrapped: {exc}"
                ) from exc
            except (OSError, ValueError) as exc:
                # ValueError: revoked-profile guard OR last-device
                # guard fired at storage layer (the endpoint pre-flight
                # should have caught both, but defense-in-depth).
                # OSError: filesystem error at persist time.
                self._store_profile_revoke_device_result(
                    req, status="signature_error",
                    profile_id=None, phone_id_revoked=None,
                    reason=f"persist_error: {type(exc).__name__}: {exc}",
                )
                raise BootloaderError(
                    f"profile_revoke_device persist failed: {exc}"
                ) from exc
            # Persist succeeded. Note: the idempotent "not a member"
            # path doesn't reach here — the endpoint pre-flight
            # short-circuits with already_not_member 200 before
            # queueing. If a respond-time race somehow gets us here
            # AND the phone wasn't actually in device_ids, the
            # manage.py primitive returns the unchanged profile and
            # we still mark approved (the desired end-state — phone
            # not in device_ids — IS achieved).
            try:
                self._store_profile_revoke_device_result(
                    req, status="approved",
                    profile_id=updated_profile.profile_id,
                    phone_id_revoked=req.revdev_phone_id_to_revoke,
                    reason=None,
                )
            except Exception as exc:  # noqa: BLE001
                print(
                    f"[bootloader] WARNING: profile_revoke_device persist succeeded "
                    f"(profile_id={updated_profile.profile_id!r}, "
                    f"phone_id_revoked={req.revdev_phone_id_to_revoke!r}) but "
                    f"result-store failed: {type(exc).__name__}: {exc}. Caller "
                    f"should recover via `recto profile show <profile_id>`.",
                    flush=True,
                )
        self._notify_resolved(req, ok=True, signature_b64u=sig,
                              eth_signature_rsv=eth_sig,
                              btc_signature_base64=btc_sig,
                              ed_signature_base64=ed_sig,
                              ed_pubkey_hex=ed_pub,
                              tron_signature_rsv=tron_sig,
                              capability_jws=capability_jws, reason=None)
        self._send_json(HTTPStatus.OK, {"resolved": True})

    def _notify_resolved(
        self,
        req: PendingRequest,
        *,
        ok: bool,
        signature_b64u: str | None,
        reason: str | None,
        eth_signature_rsv: str | None = None,
        btc_signature_base64: str | None = None,
        ed_signature_base64: str | None = None,
        ed_pubkey_hex: str | None = None,
        tron_signature_rsv: str | None = None,
        capability_jws: str | None = None,
    ) -> None:
        """Surface a request resolution to the waiting launcher.

        Production wires this through an in-process map of
        request_id -> threading.Event / Future. For v0.4.0 this is
        intentionally a no-op stub -- the integration hook lives on
        the BootloaderConfig and tests inject their own callable.

        ``eth_signature_rsv`` is populated only when ``req.kind ==
        "eth_sign"`` and the operator approved; ``btc_signature_base64``
        only when ``req.kind == "btc_sign"`` and approved;
        ``ed_signature_base64`` + ``ed_pubkey_hex`` only when ``req.kind
        == "ed_sign"`` and approved; ``tron_signature_rsv`` only when
        ``req.kind == "tron_sign"`` and approved; ``capability_jws``
        only when ``req.kind == "capability_request"`` and approved
        (carries the assembled 3-part JWS the requesting agent will
        fetch from the result endpoint). The launcher forwards all of
        these to the consumer (smart contract / off-chain verifier /
        wallet performing on-chain verification / capability-scope
        enforcer) without further validation. ``signature_b64u`` is
        the Ed25519 paired-phone identity proof and is populated for
        every approval regardless of kind.
        """
        notify_fn = getattr(self.config, "notify_resolved_fn", None)
        if notify_fn is not None:
            # Be tolerant of older notify_fn signatures that don't
            # accept the new kwargs. Try the full signature first;
            # if the callable doesn't accept capability_jws, retry
            # without it; if it doesn't accept tron_*, retry without
            # those; etc., all the way down to the v0.4.0 base 4-arg
            # shape.
            try:
                notify_fn(
                    req=req,
                    ok=ok,
                    signature_b64u=signature_b64u,
                    eth_signature_rsv=eth_signature_rsv,
                    btc_signature_base64=btc_signature_base64,
                    ed_signature_base64=ed_signature_base64,
                    ed_pubkey_hex=ed_pubkey_hex,
                    tron_signature_rsv=tron_signature_rsv,
                    capability_jws=capability_jws,
                    reason=reason,
                )
                return
            except TypeError:
                pass
            try:
                notify_fn(
                    req=req,
                    ok=ok,
                    signature_b64u=signature_b64u,
                    eth_signature_rsv=eth_signature_rsv,
                    btc_signature_base64=btc_signature_base64,
                    ed_signature_base64=ed_signature_base64,
                    ed_pubkey_hex=ed_pubkey_hex,
                    tron_signature_rsv=tron_signature_rsv,
                    reason=reason,
                )
                return
            except TypeError:
                pass
            try:
                notify_fn(
                    req=req,
                    ok=ok,
                    signature_b64u=signature_b64u,
                    eth_signature_rsv=eth_signature_rsv,
                    btc_signature_base64=btc_signature_base64,
                    ed_signature_base64=ed_signature_base64,
                    ed_pubkey_hex=ed_pubkey_hex,
                    reason=reason,
                )
                return
            except TypeError:
                pass
            try:
                notify_fn(
                    req=req,
                    ok=ok,
                    signature_b64u=signature_b64u,
                    eth_signature_rsv=eth_signature_rsv,
                    btc_signature_base64=btc_signature_base64,
                    reason=reason,
                )
                return
            except TypeError:
                pass
            try:
                notify_fn(
                    req=req,
                    ok=ok,
                    signature_b64u=signature_b64u,
                    eth_signature_rsv=eth_signature_rsv,
                    reason=reason,
                )
                return
            except TypeError:
                pass
            notify_fn(req=req, ok=ok, signature_b64u=signature_b64u,
                      reason=reason)

    # ------------------------------------------------------------------
    # POST /v0.4/capability/request  (Phase 5 Wave B)
    # ------------------------------------------------------------------

    def _handle_capability_request(self, body: dict[str, Any]) -> None:
        """Queue a capability request for operator approval.

        External agents (downstream consumer chatbots, automation
        runners, etc.) call this endpoint when they need a capability
        JWT to act on the operator's behalf. The bootloader:

        1. Authenticates the agent via X-Recto-Agent-Id +
           X-Recto-Agent-Token headers (matched against
           cfg.capability_agent_tokens).
        2. Validates the proposed CapabilityClaims (shape + future exp
           + non-empty groups/allow_actions).
        3. Canonical-JSON-encodes the claims into JWS header_b64 +
           payload_b64 segments via build_signing_input.
        4. Constructs a PendingRequest via
           PendingRequest.new_capability_request and queues it on the
           operator's phone.
        5. Returns request_id + result_url so the agent can poll for
           the assembled JWS once the operator approves.
        """
        cfg = self.config
        if cfg.state is None:
            raise BootloaderError("server not initialized")
        if not cfg.capability_agent_tokens:
            # Endpoint is disabled when no tokens are configured.
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown_endpoint"})
            return
        # Auth headers
        agent_id = self.headers.get("X-Recto-Agent-Id", "").strip()
        agent_token = self.headers.get("X-Recto-Agent-Token", "").strip()
        if not agent_id or not agent_token:
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "agent_auth_required",
                 "detail": "X-Recto-Agent-Id and X-Recto-Agent-Token headers required"},
            )
            return
        expected = cfg.capability_agent_tokens.get(agent_id)
        if expected is None or not _constant_time_compare(expected, agent_token):
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "agent_auth_failed"},
            )
            return
        # Body shape
        phone_id = body.get("phone_id", "")
        if not phone_id or not isinstance(phone_id, str):
            raise BootloaderError("phone_id required in capability_request body")
        if cfg.state.get_phone(phone_id) is None:
            raise UnknownPhoneError(f"phone_id {phone_id!r} not registered")
        claims_raw = body.get("claims")
        if not isinstance(claims_raw, dict):
            raise BootloaderError(
                "claims required in capability_request body (CapabilityClaims as JSON object)"
            )
        operation_description = body.get(
            "operation_description",
            f"capability_request from {agent_id}",
        )
        if not isinstance(operation_description, str):
            raise BootloaderError("operation_description must be a string")
        # Optional override for the request TTL (capped to a sane
        # ceiling so a buggy agent can't park requests on the queue
        # forever).
        ttl_seconds = body.get("ttl_seconds", 3600)
        if not isinstance(ttl_seconds, int) or ttl_seconds < 60 or ttl_seconds > 86400:
            raise BootloaderError(
                "ttl_seconds must be an integer in [60, 86400] (1 minute - 24 hours)"
            )
        # Optional grant-window TTL (v0.6+ queued-card flow). Distinct
        # from ttl_seconds: that bounds how long the CARD waits on the
        # queue; this bounds how long the signed AUTHORITY lives. When
        # set, the claims' iat/nbf/exp are REBUILT at card-open (the
        # first phone fetch of the pending list — see _handle_pending)
        # so a short authority window and a long queue wait can coexist.
        grant_ttl_seconds = body.get("grant_ttl_seconds")
        if grant_ttl_seconds is not None and (
            not isinstance(grant_ttl_seconds, int)
            or grant_ttl_seconds < 30
            or grant_ttl_seconds > 900
        ):
            raise BootloaderError(
                "grant_ttl_seconds must be an integer in [30, 900] when provided"
            )
        # Convert dict -> typed CapabilityClaims to drive validation
        # through the same code path verifiers use. Lazy-imported to
        # keep the bootloader package free of recto.capability when
        # this endpoint is disabled.
        from recto.capability.jwt import (
            _dict_to_claims as _to_claims,
            build_signing_input,
        )
        try:
            claims = _to_claims(claims_raw)
        except (ValueError, KeyError) as exc:
            raise BootloaderError(
                f"claims failed CapabilityClaims validation: {exc}"
            ) from exc
        # Requestable-action policy: evaluated BEFORE carding, so a
        # request outside the agent's declared surface is refused here
        # and never spends the operator's attention. Deny-by-default
        # for agents that carry a policy; agents without one pass
        # through unchanged (approval remains their gate). The refusal
        # names the disallowed actions and the allowed set — a refusal
        # that names what is missing beats a silent drop.
        requestable = cfg.capability_agent_requestable.get(agent_id)
        if requestable is not None:
            if claims.cap.groups:
                manifest = cfg.capability_manifest
                if manifest is None:
                    # Cannot expand groups without a manifest: fail
                    # CLOSED. Letting group-carried actions through
                    # unexpanded would make "add a group" the bypass
                    # for a policy stated in actions.
                    self._send_json(
                        HTTPStatus.FORBIDDEN,
                        {"error": "action_policy_unevaluable",
                         "detail": ("agent carries a requestable-action policy "
                                    "but no action manifest is loaded to expand "
                                    "the claims' groups; refusing rather than "
                                    "passing unexpanded scope")},
                    )
                    return
                from recto.capability.manifest import resolve_actions
                try:
                    effective = resolve_actions(claims.cap, manifest)
                except ValueError as exc:
                    raise BootloaderError(
                        f"claims failed action resolution against the "
                        f"manifest: {exc}"
                    ) from exc
            else:
                effective = set(claims.cap.allow_actions) - set(
                    claims.cap.deny_actions
                )
            disallowed = sorted(effective - set(requestable))
            if disallowed:
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {"error": "action_not_requestable",
                     "agent_id": agent_id,
                     "disallowed_actions": disallowed,
                     "requestable_actions": sorted(requestable)},
                )
                return
        # Build the JWS signing input via the same canonical-JSON
        # encoder verifiers use — guarantees the cap_*_b64 fields the
        # phone signs over are byte-identical to what verify_jws
        # consumes downstream.
        digest, header_b64, payload_b64 = build_signing_input(claims)
        # The Ed25519 paired-phone envelope rides on payload_hash_b64u,
        # which we set to base64url(SHA-256(signing_input)) — same
        # digest the secp256k1 cap-signature is over, so the operator's
        # consent on the envelope binds 1:1 to the JWS they sign.
        payload_hash_b64u = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        try:
            req = PendingRequest.new_capability_request(
                service=body.get("service", "recto"),
                secret=body.get("secret", "capability"),
                phone_id=phone_id,
                operation_description=operation_description,
                payload_hash_b64u=payload_hash_b64u,
                child_pid=0,
                child_argv0="(external-agent)",
                cap_header_b64=header_b64,
                cap_payload_b64=payload_b64,
                cap_agent_id=agent_id,
                ttl_seconds=ttl_seconds,
                grant_ttl_seconds=grant_ttl_seconds,
            )
        except ValueError as exc:
            raise BootloaderError(
                f"capability_request construction failed: {exc}"
            ) from exc
        # Phase 5 Wave C part 3: inject app_context. Look up by
        # cap_agent_id first (capability_request flow); fall back to
        # service name if no agent registration but a service one
        # exists. None when no registration matches -- phone renders
        # "Unknown app" warning banner.
        app_ctx = (
            cfg.principal_apps.get(agent_id)
            or cfg.principal_apps.get(req.service)
        )
        if app_ctx is not None:
            from dataclasses import replace as _replace
            req = _replace(req, app_context=app_ctx)
        cfg.state.add_pending(req)
        self._notify_push(req)
        self._send_json(HTTPStatus.CREATED, {
            "request_id": req.request_id,
            "expires_at_unix": req.expires_at_unix,
            "result_url": f"/v0.4/capability/result/{req.request_id}",
        })

    # ------------------------------------------------------------------
    # POST /v0.4/devices/pair  (Phase H end-user device pairing relay,
    # 2026-05-19)
    # ------------------------------------------------------------------

    def _handle_devices_pair(self, body: dict[str, Any]) -> None:
        """Relay an end-user device-pairing request to a consumer.

        Phase H end-user pairing surface. The bootloader is a THIN RELAY
        between the user's Recto Phone app and the consumer's
        ``/api/v1/devices/pairing/complete`` endpoint:

          1. User opens the Recto Phone app, chooses "Pair a new
             service", enters the consumer's URL + the 8-char pairing
             code displayed on the consumer's web UI.
          2. Phone enclave signs a JWS with the user's secp256k1 master
             key. JWS payload has ``cap.allow_actions = ["devices:pair"]``
             and ``cap.scope.pairing_code = "<typed code>"`` so the
             signature commits to that exact pairing code.
          3. Phone POSTs ``/v0.4/devices/pair`` to this bootloader with
             ``{consumer_base_url, pairing_code, user_pubkey_hex,
             user_jws}`` — no auth on the incoming request (the JWS IS
             the user-side auth).
          4. Bootloader looks up the consumer's webhook token in
             ``cfg.devices_pair_consumer_webhook_tokens`` (operator
             registered the (URL, token) pair at deploy time).
          5. Bootloader POSTs to ``{consumer_base_url}/api/v1/devices/pairing/complete``
             with ``X-Openclaw-Token: <looked-up token>`` and body
             ``{code: pairing_code, masterPubkeyHex: user_pubkey_hex,
             capabilityJws: user_jws}``.
          6. Bootloader returns the consumer's response (status + body)
             verbatim to the phone.

        **Trust model:** the X-Openclaw-Token gate on the consumer's
        side proves "the request came through THIS authorized
        bootloader." The user's JWS self-attestation (verified at the
        consumer's side via the caller-supplied pubkey) proves "the
        phone signing this attestation holds the master pubkey it
        claims." Together they form the trust chain that lets an
        end-user safely bind their phone to their consumer account
        without the operator's bootloader being able to silently
        substitute its own pubkey.

        **Auth on the incoming request:** none. The phone's identity
        is established by the JWS the phone forwarded; the bootloader
        doesn't authenticate the caller because the JWS IS the
        authentication primitive (and the consumer verifies it).
        Rate-limiting and abuse defense are out of scope at v0; future
        iteration may add per-phone-id or per-IP rate limits if the
        endpoint surface starts getting probed.

        **Endpoint disabled** when
        ``cfg.devices_pair_consumer_webhook_tokens`` is empty — returns
        404 ``unknown_endpoint``. Bootloaders that don't broker
        end-user device pairing for any consumer have zero attack
        surface on this path.

        Body:
          ``consumer_base_url``: full URL of the target consumer
            (e.g. ``"https://consumer.example.com"``). MUST match a
            key in ``cfg.devices_pair_consumer_webhook_tokens``.
          ``pairing_code``: 8-char code the user typed (consumer
            generated it via ``POST /api/v1/devices/pairing/start``).
          ``user_pubkey_hex``: 128-hex secp256k1 master pubkey
            (X||Y, no 0x04 prefix). The signature on ``user_jws``
            must recover to this value.
          ``user_jws``: full 3-part JWS string the phone enclave
            signed.

        Response: ``{status: int, body: <consumer's JSON>}`` —
        relays the consumer's HTTP status + body verbatim so the
        caller can surface specific error reasons
        (``pubkey_already_bound``, ``user_already_paired``,
        ``capability_invalid``, etc.) without the bootloader
        re-interpreting them.
        """
        cfg = self.config
        if not cfg.devices_pair_consumer_webhook_tokens:
            # No consumers registered → endpoint is disabled.
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown_endpoint"})
            return

        # Body shape validation
        consumer_base_url = body.get("consumer_base_url")
        pairing_code = body.get("pairing_code")
        user_pubkey_hex = body.get("user_pubkey_hex")
        user_jws = body.get("user_jws")

        if not isinstance(consumer_base_url, str) or not consumer_base_url.strip():
            raise BootloaderError("consumer_base_url is required")
        if not isinstance(pairing_code, str) or not pairing_code.strip():
            raise BootloaderError("pairing_code is required")
        if not isinstance(user_pubkey_hex, str) or not user_pubkey_hex.strip():
            raise BootloaderError("user_pubkey_hex is required")
        if not isinstance(user_jws, str) or not user_jws.strip():
            raise BootloaderError("user_jws is required")

        # Strip trailing slash for canonical-lookup parity (operator
        # may have registered the URL with or without trailing slash).
        normalized_url = consumer_base_url.rstrip("/")
        webhook_token = cfg.devices_pair_consumer_webhook_tokens.get(normalized_url)
        if webhook_token is None:
            # Also try the variant with trailing slash, since some
            # operator-paste workflows leave it in. Idiosyncratic
            # forgiveness rather than reject-and-retry friction.
            webhook_token = cfg.devices_pair_consumer_webhook_tokens.get(
                normalized_url + "/"
            )
        if webhook_token is None:
            print(
                f"[bootloader] devices/pair: unknown consumer_base_url={consumer_base_url!r}",
                flush=True,
            )
            self._send_json(
                HTTPStatus.NOT_FOUND,
                {
                    "error": "unknown_consumer",
                    "detail": "consumer_base_url not registered with this bootloader",
                },
            )
            return

        # Build the forward payload. Field names mirror the consumer's
        # CompletePairingRequest schema (CamelCase JSON property names);
        # the consumer's binder is case-insensitive on most stacks but
        # we match the canonical shape so other consumers replicating
        # the schema get clean field-binding.
        #
        # relay_url override (commitment #17, three-zone architecture):
        # when the consumer manifest declares a relay_url, the outbound
        # request targets that hostname instead of the phone-supplied
        # base_url.  This lets the phone know the .com URL while the
        # bootloader relays through the .ai agent-zone hostname.
        relay_base = cfg.devices_pair_consumer_relay_urls.get(normalized_url)
        if relay_base is None:
            relay_base = normalized_url
        forward_url = relay_base + "/api/v1/devices/pairing/complete"
        forward_body_bytes = json.dumps({
            "code": pairing_code,
            "masterPubkeyHex": user_pubkey_hex,
            "capabilityJws": user_jws,
        }).encode("utf-8")

        request = urllib.request.Request(
            forward_url,
            data=forward_body_bytes,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-Openclaw-Token": webhook_token,
                "User-Agent": "recto-bootloader/v0.4 devices-pair-relay",
            },
        )

        timeout = cfg.devices_pair_consumer_timeout_seconds
        consumer_status: int
        consumer_body: Any
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                consumer_status = response.status
                raw = response.read()
                try:
                    consumer_body = json.loads(raw) if raw else None
                except json.JSONDecodeError:
                    # Consumer returned non-JSON — pass back as a string
                    # in the relayed response so the phone can surface
                    # SOMETHING actionable instead of swallowing the body.
                    consumer_body = {"raw": raw.decode("utf-8", errors="replace")}
        except urllib.error.HTTPError as e:
            # Consumer returned a non-2xx with a body — we want to relay
            # the consumer's diagnostic to the caller verbatim so the
            # phone can show "pubkey_already_bound" / "capability_invalid"
            # etc. rather than a generic "bootloader 502".
            consumer_status = e.code
            try:
                raw = e.read()
                print(
                    f"[bootloader] devices/pair: HTTPError {e.code} from "
                    f"{forward_url}, headers={dict(e.headers)}, "
                    f"body={raw[:500] if raw else b'(empty)'}",
                    flush=True,
                )
                consumer_body = json.loads(raw) if raw else None
            except (json.JSONDecodeError, Exception):
                consumer_body = {"raw": str(e)}
        except urllib.error.URLError as e:
            # Network-level failure (DNS, connection refused, TLS, etc.)
            # — the consumer's endpoint didn't respond at all. 502 maps
            # this cleanly: "got nothing useful from the upstream."
            print(
                f"[bootloader] devices/pair: URLError forwarding to {forward_url}: {e}",
                flush=True,
            )
            self._send_json(
                HTTPStatus.BAD_GATEWAY,
                {
                    "error": "consumer_unreachable",
                    "detail": f"could not reach {forward_url}: {e.reason}",
                },
            )
            return
        except Exception as e:  # noqa: BLE001
            print(
                f"[bootloader] devices/pair: unexpected error forwarding to "
                f"{forward_url}: {type(e).__name__}: {e}",
                flush=True,
            )
            self._send_json(
                HTTPStatus.BAD_GATEWAY,
                {
                    "error": "consumer_forwarding_failed",
                    "detail": f"{type(e).__name__}: {e}",
                },
            )
            return

        print(
            f"[bootloader] devices/pair: relayed to {forward_url} "
            f"(status={consumer_status})",
            flush=True,
        )

        # Relay status + body. Use the same HTTPStatus mapping as the
        # consumer so callers can switch on the status verbatim.
        try:
            relayed_status = HTTPStatus(consumer_status)
        except ValueError:
            # Consumer returned a status outside HTTPStatus's known
            # range (rare; some custom proxies emit 9xx). Pass through
            # as a raw int — _send_json handles that.
            relayed_status = consumer_status  # type: ignore[assignment]

        self._send_json(relayed_status, {
            "consumer_status": consumer_status,
            "consumer_body": consumer_body,
        })

    # ------------------------------------------------------------------
    # POST /v0.4/devices/unpair  (Phase H end-user device unpairing relay,
    # 2026-06-21)
    # ------------------------------------------------------------------

    def _handle_devices_unpair(self, body: dict[str, Any]) -> None:
        """Relay an end-user device-UNPAIR request to a consumer.

        The cryptographic teardown sibling of ``_handle_devices_pair``.
        Recto Phone's per-service unpair (Build 6) removes the binding
        from the phone's local Connected Services registry; this relay
        is what tears the binding down on the CONSUMER side too, so a
        later re-pair isn't blocked by the consumer's one-pubkey-one-user
        constraint (downstream commitment #11). Without it, granular
        unpair is local-only and the operator has to NULL the consumer's
        bound-pubkey column out of band.

        Flow (mirrors devices/pair minus the pairing code):

          1. User taps "Unpair this service" on a real (non-demo)
             Connected Service in the Recto Phone app.
          2. Phone enclave signs a JWS with the user's secp256k1 master
             key. JWS payload has ``cap.allow_actions =
             ["devices:pairing_revoke"]`` and ``cap.scope.user_id =
             "<consumer account being unpaired>"``.
          3. Phone POSTs ``/v0.4/devices/unpair`` to this bootloader with
             ``{consumer_base_url, user_pubkey_hex, user_jws}`` — no
             pairing code (the binding is identified by the pubkey, not a
             fresh code), no auth on the incoming request (the JWS IS the
             user-side auth).
          4. Bootloader looks up the consumer's webhook token in
             ``cfg.devices_pair_consumer_webhook_tokens`` — the SAME
             registry pair uses; a consumer that brokers pairing brokers
             unpairing.
          5. Bootloader POSTs to ``{consumer_base_url}/api/v1/devices/pairing/revoke``
             with ``X-Openclaw-Token: <looked-up token>`` and body
             ``{masterPubkeyHex: user_pubkey_hex, capabilityJws:
             user_jws}``.
          6. Consumer recovers the JWS signature against the master
             pubkey currently bound on the user row (self-attested, the
             same model devices/pair uses), confirms it matches, NULLs
             the binding + records an audit row, and returns its
             response, which the bootloader relays verbatim.

        **Self-attested, authority-removing.** The JWS proves the phone
        holds the master key that was bound at pair time; the consumer's
        X-Openclaw-Token gate proves the request came through THIS
        authorized bootloader. The action only REMOVES authority (tears
        down a binding), so its blast radius is strictly smaller than
        the devices:pair it reverses — Tier 0 in the manifest.

        **Endpoint disabled** when
        ``cfg.devices_pair_consumer_webhook_tokens`` is empty — returns
        404 ``unknown_endpoint``, same zero-attack-surface posture as
        devices/pair.

        Body:
          ``consumer_base_url``: full URL of the target consumer. MUST
            match a key in ``cfg.devices_pair_consumer_webhook_tokens``.
          ``user_pubkey_hex``: 128-hex secp256k1 master pubkey (X||Y, no
            0x04 prefix). The signature on ``user_jws`` must recover to
            this value (consumer-side check).
          ``user_jws``: full 3-part JWS string the phone enclave signed.

        Response: ``{consumer_status: int, consumer_body: <consumer's
        JSON>}`` — relays the consumer's HTTP status + body verbatim so
        the phone can surface specific reasons (``not_paired``,
        ``capability_invalid``, ``pubkey_mismatch``, etc.) without the
        bootloader re-interpreting them. The phone removes its local
        Connected Service entry only on a success status.
        """
        cfg = self.config
        if not cfg.devices_pair_consumer_webhook_tokens:
            # No consumers registered → endpoint is disabled.
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown_endpoint"})
            return

        # Body shape validation (no pairing_code — unpair identifies the
        # binding by the bound pubkey, not a fresh code).
        consumer_base_url = body.get("consumer_base_url")
        user_pubkey_hex = body.get("user_pubkey_hex")
        user_jws = body.get("user_jws")

        if not isinstance(consumer_base_url, str) or not consumer_base_url.strip():
            raise BootloaderError("consumer_base_url is required")
        if not isinstance(user_pubkey_hex, str) or not user_pubkey_hex.strip():
            raise BootloaderError("user_pubkey_hex is required")
        if not isinstance(user_jws, str) or not user_jws.strip():
            raise BootloaderError("user_jws is required")

        # Canonical-lookup parity with the trailing-slash forgiveness
        # devices/pair uses (operator may register URL with or without).
        normalized_url = consumer_base_url.rstrip("/")
        webhook_token = cfg.devices_pair_consumer_webhook_tokens.get(normalized_url)
        if webhook_token is None:
            webhook_token = cfg.devices_pair_consumer_webhook_tokens.get(
                normalized_url + "/"
            )
        if webhook_token is None:
            print(
                f"[bootloader] devices/unpair: unknown consumer_base_url={consumer_base_url!r}",
                flush=True,
            )
            self._send_json(
                HTTPStatus.NOT_FOUND,
                {
                    "error": "unknown_consumer",
                    "detail": "consumer_base_url not registered with this bootloader",
                },
            )
            return

        # relay_url override (commitment #17 three-zone architecture):
        # same .com-known / .ai-relayed split devices/pair uses.
        relay_base = cfg.devices_pair_consumer_relay_urls.get(normalized_url)
        if relay_base is None:
            relay_base = normalized_url
        forward_url = relay_base + "/api/v1/devices/pairing/revoke"
        forward_body_bytes = json.dumps({
            "masterPubkeyHex": user_pubkey_hex,
            "capabilityJws": user_jws,
        }).encode("utf-8")

        request = urllib.request.Request(
            forward_url,
            data=forward_body_bytes,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-Openclaw-Token": webhook_token,
                "User-Agent": "recto-bootloader/v0.4 devices-unpair-relay",
            },
        )

        timeout = cfg.devices_pair_consumer_timeout_seconds
        consumer_status: int
        consumer_body: Any
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                consumer_status = response.status
                raw = response.read()
                try:
                    consumer_body = json.loads(raw) if raw else None
                except json.JSONDecodeError:
                    consumer_body = {"raw": raw.decode("utf-8", errors="replace")}
        except urllib.error.HTTPError as e:
            # Relay the consumer's diagnostic verbatim (not_paired /
            # capability_invalid / pubkey_mismatch / etc.).
            consumer_status = e.code
            try:
                raw = e.read()
                print(
                    f"[bootloader] devices/unpair: HTTPError {e.code} from "
                    f"{forward_url}, headers={dict(e.headers)}, "
                    f"body={raw[:500] if raw else b'(empty)'}",
                    flush=True,
                )
                consumer_body = json.loads(raw) if raw else None
            except (json.JSONDecodeError, Exception):
                consumer_body = {"raw": str(e)}
        except urllib.error.URLError as e:
            print(
                f"[bootloader] devices/unpair: URLError forwarding to {forward_url}: {e}",
                flush=True,
            )
            self._send_json(
                HTTPStatus.BAD_GATEWAY,
                {
                    "error": "consumer_unreachable",
                    "detail": f"could not reach {forward_url}: {e.reason}",
                },
            )
            return
        except Exception as e:  # noqa: BLE001
            print(
                f"[bootloader] devices/unpair: unexpected error forwarding to "
                f"{forward_url}: {type(e).__name__}: {e}",
                flush=True,
            )
            self._send_json(
                HTTPStatus.BAD_GATEWAY,
                {
                    "error": "consumer_forwarding_failed",
                    "detail": f"{type(e).__name__}: {e}",
                },
            )
            return

        print(
            f"[bootloader] devices/unpair: relayed to {forward_url} "
            f"(status={consumer_status})",
            flush=True,
        )

        try:
            relayed_status = HTTPStatus(consumer_status)
        except ValueError:
            relayed_status = consumer_status  # type: ignore[assignment]

        self._send_json(relayed_status, {
            "consumer_status": consumer_status,
            "consumer_body": consumer_body,
        })

    # ------------------------------------------------------------------
    # POST /v0.4/profile/create  (Phase 2.0.B multi-profile integration)
    # ------------------------------------------------------------------

    def _handle_profile_create(self, body: dict[str, Any]) -> None:
        """Queue a profile-create request for operator approval.

        Phase 2.0.B integration. Multi-profile-identity callers (CLI's
        ``recto profile create``, SCIM provisioning glue, future
        automation) submit a candidate profile shape; bootloader queues
        the request on the operator's phone; phone displays an approval
        card with the proposed kind / display_name / derivation path;
        on approval, phone signs a master-attestation over the
        canonical-JSON encoding of the candidate fields; bootloader
        verifies the attestation against the operator pubkey loaded
        via vault_root.json, atomic-writes the new Profile row to
        master_identity.json, and stashes a ProfileCreateResult for
        the caller to poll.

        Partial-failure design (banked from Milan Jovanović's "use
        case is a unit of intent, not a unit of atomicity"):

          * **A — caller-authored idempotency key.** ``candidate_profile_id``
            is generated by the caller (CLI / SCIM / etc.) at submit
            time and used as the canonical key throughout the flow:
            queue lookup, persist-store check, result-store key. A
            retry with the same key is safe. If the candidate_profile_id
            already corresponds to a persisted Profile (caller restarted
            mid-poll, network glitched, etc.), the bootloader returns
            HTTP 200 with status="already_exists" + the existing
            profile_id WITHOUT re-prompting the operator. The phone
            never sees a duplicate approval card for the same key.

          * **B — persist last; in-memory result is derived.** The
            atomic write to master_identity.json is the source of
            truth. The ProfileCreateResult store is a derived projection;
            if it fails or expires before caller polls, the caller can
            recover via ``recto profile list`` filtered by candidate
            id. Step ordering in _handle_respond's profile_create
            branch: (1) verify attestation, (2) atomic persist, (3)
            store result — never reversed.

          * **C — never claim success when persist failed.** If the
            atomic write throws (filesystem error, permission denied,
            disk full), the bootloader stores ``signature_error``
            status with reason ``"persist_error: <diagnostic>"`` so the
            caller knows recovery requires fixing the host's disk state
            (NOT re-prompting the phone). The reason-prefix lets
            callers distinguish without forking the status enum.

        Auth: ``X-Recto-Agent-Id`` + ``X-Recto-Agent-Token`` headers,
        same posture as ``/v0.4/capability/request``. Endpoint is
        disabled (404) when ``cfg.capability_agent_tokens`` is empty.

        Body shape:
            {
                "phone_id": "<paired-phone-id>",
                "candidate_profile_id": "<caller-authored UUID4>",
                "kind": "personal:child|work|school|contractor|custom:...",
                "display_name": "Personal (pseudonym)",
                "theme_hint": <optional str>,
                "scim_provider": <optional str>,
                "ttl_seconds": <optional int, default 600, range 60..86400>,
                "operation_description": <optional str>
            }

        Response (201, new request queued):
            {
                "request_id": "<uuid>",
                "candidate_profile_id": "<echo from body>",
                "expires_at_unix": <int>,
                "result_url": "/v0.4/profile/result/<request_id>"
            }

        Response (200, idempotent hit on existing profile):
            {
                "status": "already_exists",
                "profile_id": "<existing>",
                "candidate_profile_id": "<echo from body>",
                "reason": "candidate_profile_id was already used; profile exists"
            }
        """
        cfg = self.config
        if cfg.state is None:
            raise BootloaderError("server not initialized")
        if not cfg.capability_agent_tokens:
            # Same posture as capability_request: agent-token gate is the
            # endpoint's existence trigger. No tokens configured -> no
            # surface area.
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown_endpoint"})
            return
        # Auth headers
        agent_id = self.headers.get("X-Recto-Agent-Id", "").strip()
        agent_token = self.headers.get("X-Recto-Agent-Token", "").strip()
        if not agent_id or not agent_token:
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "agent_auth_required",
                 "detail": "X-Recto-Agent-Id and X-Recto-Agent-Token headers required"},
            )
            return
        expected = cfg.capability_agent_tokens.get(agent_id)
        if expected is None or not _constant_time_compare(expected, agent_token):
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "agent_auth_failed"},
            )
            return
        # Body shape — strict, with clear field-level errors so a buggy
        # caller can diagnose without a debugger.
        phone_id = body.get("phone_id", "")
        if not phone_id or not isinstance(phone_id, str):
            raise BootloaderError("phone_id required in profile_create body")
        if cfg.state.get_phone(phone_id) is None:
            raise UnknownPhoneError(f"phone_id {phone_id!r} not registered")
        candidate_profile_id = body.get("candidate_profile_id", "")
        if not candidate_profile_id or not isinstance(candidate_profile_id, str):
            raise BootloaderError(
                "candidate_profile_id required in profile_create body "
                "(caller-authored UUID4 — see partial-failure docstring "
                "for the idempotency-key contract)"
            )
        kind = body.get("kind", "")
        if not kind or not isinstance(kind, str):
            raise BootloaderError("kind required in profile_create body")
        display_name = body.get("display_name", "")
        if not display_name or not isinstance(display_name, str) or not display_name.strip():
            raise BootloaderError(
                "display_name required (non-empty after strip) in profile_create body"
            )
        theme_hint = body.get("theme_hint")
        if theme_hint is not None and not isinstance(theme_hint, str):
            raise BootloaderError("theme_hint must be a string or null")
        scim_provider = body.get("scim_provider")
        if scim_provider is not None and not isinstance(scim_provider, str):
            raise BootloaderError("scim_provider must be a string or null")
        ttl_seconds = body.get("ttl_seconds", 600)
        if not isinstance(ttl_seconds, int) or ttl_seconds < 60 or ttl_seconds > 86400:
            raise BootloaderError(
                "ttl_seconds must be an integer in [60, 86400] (1 minute - 24 hours)"
            )
        operation_description = body.get(
            "operation_description",
            f"profile_create from {agent_id}: {kind} / {display_name}",
        )
        if not isinstance(operation_description, str):
            raise BootloaderError("operation_description must be a string")

        # Milan commitment A — idempotency-key precheck. If this
        # candidate_profile_id has already been used, return the
        # existing profile rather than re-prompting the operator. The
        # CALLER is responsible for generating unique UUIDs per intent;
        # collision detection here defends against retry-replay only,
        # not against malicious or buggy callers reusing keys for
        # different intents.
        from recto.profile.manage import (
            get_profile_by_id as _get_profile_by_id,
            _resolve_coin_type,
            _next_profile_index,
            PROFILE_BIP32_PURPOSE as _PROFILE_BIP32_PURPOSE,
        )
        from recto.profile.store import load_master_identity as _load_mi
        # The bootloader's StateStore knows the operator's chosen
        # state directory (RECTO_BOOTLOADER_STATE_DIR env var or
        # platform default). MasterIdentity lives in the SAME
        # directory so the whole bootloader's persistent state is
        # co-located — pass state.state_dir through every profile
        # call so test fixtures + multi-instance hosts work
        # correctly.
        _state_dir = cfg.state.state_dir
        existing = _get_profile_by_id(candidate_profile_id, state_dir=_state_dir)
        if existing is not None:
            self._send_json(HTTPStatus.OK, {
                "status": "already_exists",
                "profile_id": existing.profile_id,
                "candidate_profile_id": candidate_profile_id,
                "reason": "candidate_profile_id was already used; profile exists",
            })
            return

        # Resolve the BIP-32 derivation slot at queue time so the
        # operator's phone approval card shows the FINAL derivation
        # path (not a placeholder that might shift if a concurrent
        # create steals the index). The profile manage layer's
        # _next_profile_index is stable as long as no other create
        # is in-flight; the bootloader's single-threaded handler model
        # serializes profile_create POSTs naturally.
        mi = _load_mi(state_dir=_state_dir)
        if mi is None:
            raise BootloaderError(
                "MasterIdentity not bootstrapped; "
                "run `recto vault bootstrap` first"
            )
        try:
            coin_type = _resolve_coin_type(kind)
        except ValueError as exc:
            raise BootloaderError(f"invalid kind: {exc}") from exc
        derivation_index = _next_profile_index(mi, coin_type)

        # Build the canonical-JSON signing input over the candidate
        # fields. Same canonical encoder verifiers use elsewhere —
        # guarantees byte-identical input on the phone's signing side
        # and the bootloader's verify side. The phone signs
        # SHA-256(canonical_json) per the Phase 2.0.B SPEC; the
        # signing input is what the bootloader stashes in
        # cap_payload_b64 so the phone can re-derive the digest after
        # approving on screen.
        from recto.capability.jwt import _canonical_json as _to_canonical
        candidate_fields = {
            "candidate_profile_id": candidate_profile_id,
            "kind": kind,
            "display_name": display_name.strip(),
            "derivation_purpose": _PROFILE_BIP32_PURPOSE,
            "derivation_coin_type": coin_type,
            "derivation_index": derivation_index,
            "theme_hint": theme_hint,
            "scim_provider": scim_provider,
            "master_pubkey_hex": mi.master_pubkey_hex,
        }
        signing_input_bytes = _to_canonical(candidate_fields)
        digest = hashlib.sha256(signing_input_bytes).digest()
        payload_hash_b64u = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        # Stash the canonical encoding as cap_payload_b64 so _handle_respond's
        # profile_create branch can re-derive the digest for verification
        # without re-loading the master identity (which may have changed
        # by the time the operator approves on the phone).
        cap_payload_b64 = base64.urlsafe_b64encode(signing_input_bytes).rstrip(b"=").decode("ascii")

        try:
            req = PendingRequest.new_profile_create(
                service=body.get("service", "recto"),
                secret=body.get("secret", "profile"),
                phone_id=phone_id,
                operation_description=operation_description,
                payload_hash_b64u=payload_hash_b64u,
                child_pid=0,
                child_argv0="(external-agent)",
                candidate_profile_id=candidate_profile_id,
                candidate_kind=kind,
                candidate_display_name=display_name.strip(),
                candidate_derivation_purpose=_PROFILE_BIP32_PURPOSE,
                candidate_derivation_coin_type=coin_type,
                candidate_derivation_index=derivation_index,
                candidate_theme_hint=theme_hint,
                candidate_scim_provider=scim_provider,
                ttl_seconds=ttl_seconds,
            )
        except ValueError as exc:
            raise BootloaderError(
                f"profile_create construction failed: {exc}"
            ) from exc
        # Stash the canonical-encoded payload + agent id alongside the
        # candidate fields so _handle_respond can re-verify. cap_payload_b64
        # holds the signing input; cap_agent_id pins ownership so only the
        # submitting agent can fetch the result.
        from dataclasses import replace as _replace
        req = _replace(
            req,
            cap_payload_b64=cap_payload_b64,
            cap_agent_id=agent_id,
        )
        # AppContext injection — phone shows the requesting app's
        # branding at the top of the approval card.
        app_ctx = (
            cfg.principal_apps.get(agent_id)
            or cfg.principal_apps.get(req.service)
        )
        if app_ctx is not None:
            req = _replace(req, app_context=app_ctx)
        cfg.state.add_pending(req)
        self._notify_push(req)
        self._send_json(HTTPStatus.CREATED, {
            "request_id": req.request_id,
            "candidate_profile_id": candidate_profile_id,
            "expires_at_unix": req.expires_at_unix,
            "result_url": f"/v0.4/profile/result/{req.request_id}",
        })

    # ------------------------------------------------------------------
    # POST /v0.4/profile/<profile_id>/add-device  (Phase 2.0.C wave C.5)
    # ------------------------------------------------------------------

    def _handle_profile_add_device(
        self, profile_id: str, body: dict[str, Any]
    ) -> None:
        """Queue a profile_add_device request for operator approval.

        Phase 2.0.C wave C.5 integration. Multi-device-per-profile
        callers (CLI's ``recto profile add-device``, SCIM
        provisioning, future automation) submit a target profile_id +
        the phone_id of an already-registered new device; bootloader
        queues the request on the operator's master phone; phone
        displays an approval card with target + new-device info; on
        approval, phone signs a master-attestation over the canonical
        -JSON encoding of (profile_id + new_phone_id + added_at_unix
        + request_id); bootloader verifies the attestation against
        the operator pubkey loaded via vault_root.json, atomic-writes
        the appended phone_id to master_identity.json, and stashes a
        ProfileAddDeviceResult for the caller to poll.

        Partial-failure design (same shape as profile_create):

          * **A — caller-authored idempotency key.** ``candidate_request_id``
            is generated by the caller at submit time and used as
            the canonical key. A retry with the same key returns the
            existing PendingRequest or result without re-prompting.

          * **B — persist last; in-memory result is derived.** The
            atomic write to master_identity.json is the source of
            truth. The ProfileAddDeviceResult store is a derived
            projection.

          * **C — never claim success when persist failed.** If the
            atomic write throws, the bootloader stores
            ``signature_error`` with reason ``"persist_error: ..."``
            so the caller knows recovery requires fixing the host's
            disk state.

        Auth: ``X-Recto-Agent-Id`` + ``X-Recto-Agent-Token`` headers.
        Endpoint is disabled (404) when ``cfg.capability_agent_tokens``
        is empty.

        Pre-flight checks:
          - profile_id (URL path) must exist under the bootstrapped master
          - target profile must NOT be revoked
          - new_phone_id (body) must be a registered phone_id
          - new_phone_id must NOT already be in profile's device_ids
            (returns 200 "already_member" idempotent hit without
            queueing)

        Body shape:
            {
                "master_phone_id": "<paired-phone-id of master>",
                "new_phone_id": "<paired-phone-id of new device>",
                "new_phone_label": <optional str>,
                "candidate_request_id": <optional str>,
                "ttl_seconds": <optional int, default 600, range 60..86400>,
                "operation_description": <optional str>
            }

        Response (201, new request queued):
            {
                "request_id": "<uuid>",
                "profile_id": "<echo from URL>",
                "new_phone_id": "<echo from body>",
                "expires_at_unix": <int>,
                "result_url": "/v0.4/profile/add-device-result/<request_id>"
            }

        Response (200, idempotent hit on already-member):
            {
                "status": "already_member",
                "profile_id": "<echo from URL>",
                "new_phone_id": "<echo from body>",
                "reason": "new_phone_id is already in the profile's device_ids tuple"
            }
        """
        cfg = self.config
        if cfg.state is None:
            raise BootloaderError("server not initialized")
        if not cfg.capability_agent_tokens:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown_endpoint"})
            return
        # Auth
        agent_id = self.headers.get("X-Recto-Agent-Id", "").strip()
        agent_token = self.headers.get("X-Recto-Agent-Token", "").strip()
        if not agent_id or not agent_token:
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "agent_auth_required",
                 "detail": "X-Recto-Agent-Id and X-Recto-Agent-Token headers required"},
            )
            return
        expected = cfg.capability_agent_tokens.get(agent_id)
        if expected is None or not _constant_time_compare(expected, agent_token):
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "agent_auth_failed"},
            )
            return
        # Body shape validation
        if not profile_id or not isinstance(profile_id, str):
            raise BootloaderError("profile_id required in URL path")
        master_phone_id = body.get("master_phone_id", "")
        if not master_phone_id or not isinstance(master_phone_id, str):
            raise BootloaderError(
                "master_phone_id required in profile_add_device body "
                "(phone_id of the master's paired device that will sign "
                "the attestation)"
            )
        if cfg.state.get_phone(master_phone_id) is None:
            raise UnknownPhoneError(
                f"master_phone_id {master_phone_id!r} not registered"
            )
        new_phone_id = body.get("new_phone_id", "")
        if not new_phone_id or not isinstance(new_phone_id, str):
            raise BootloaderError(
                "new_phone_id required in profile_add_device body"
            )
        if cfg.state.get_phone(new_phone_id) is None:
            raise UnknownPhoneError(
                f"new_phone_id {new_phone_id!r} not registered; "
                f"new device must complete the v0.4 pair flow before "
                f"being added to a profile"
            )
        if new_phone_id == master_phone_id:
            raise BootloaderError(
                "new_phone_id must be different from master_phone_id"
            )
        new_phone_label = body.get("new_phone_label")
        if new_phone_label is not None and not isinstance(new_phone_label, str):
            raise BootloaderError("new_phone_label must be a string or null")
        ttl_seconds = body.get("ttl_seconds", 600)
        if not isinstance(ttl_seconds, int) or ttl_seconds < 60 or ttl_seconds > 86400:
            raise BootloaderError(
                "ttl_seconds must be an integer in [60, 86400]"
            )
        operation_description = body.get(
            "operation_description",
            f"profile_add_device from {agent_id}: append {new_phone_id} to {profile_id}",
        )
        if not isinstance(operation_description, str):
            raise BootloaderError("operation_description must be a string")

        # Pre-flight: profile must exist + not be revoked + new_phone_id
        # must not already be a member. The respond branch will re-check
        # these defensively but catching here saves a phone prompt for
        # bad requests.
        from recto.profile.manage import (
            get_profile_by_id as _get_profile_by_id,
        )
        from recto.profile.store import load_master_identity as _load_mi
        _state_dir = cfg.state.state_dir
        mi = _load_mi(state_dir=_state_dir)
        if mi is None:
            raise BootloaderError(
                "MasterIdentity not bootstrapped; "
                "run `recto vault bootstrap` first"
            )
        target = _get_profile_by_id(profile_id, state_dir=_state_dir)
        if target is None:
            raise BootloaderError(
                f"profile_id {profile_id!r} not found under master "
                f"{mi.master_pubkey_hex[:16]}..."
            )
        if target.revoked:
            raise BootloaderError(
                f"profile_id {profile_id!r} is revoked; cannot add devices"
            )
        # Idempotent hit: new_phone_id already in device_ids → return
        # already_member without queueing.
        if new_phone_id in target.device_ids:
            self._send_json(HTTPStatus.OK, {
                "status": "already_member",
                "profile_id": profile_id,
                "new_phone_id": new_phone_id,
                "reason": (
                    "new_phone_id is already in the profile's "
                    "device_ids tuple"
                ),
            })
            return

        # Build the canonical-JSON signing input. The request_id is
        # part of the binding so that re-running with the same intent
        # produces a fresh attestation (defends against replay across
        # two simultaneous identical requests).
        from recto.capability.jwt import _canonical_json as _to_canonical
        added_at_unix = int(time.time())
        request_id = str(uuid.uuid4())
        signing_fields = {
            "action": "profile_add_device",
            "profile_id": profile_id,
            "new_phone_id": new_phone_id,
            "added_at_unix": added_at_unix,
            "request_id": request_id,
            "master_pubkey_hex": mi.master_pubkey_hex,
        }
        signing_input_bytes = _to_canonical(signing_fields)
        digest = hashlib.sha256(signing_input_bytes).digest()
        payload_hash_b64u = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        cap_payload_b64 = base64.urlsafe_b64encode(signing_input_bytes).rstrip(b"=").decode("ascii")

        try:
            req = PendingRequest.new_profile_add_device(
                service=body.get("service", "recto"),
                secret=body.get("secret", "profile"),
                phone_id=master_phone_id,
                operation_description=operation_description,
                payload_hash_b64u=payload_hash_b64u,
                child_pid=0,
                child_argv0="(external-agent)",
                addev_profile_id=profile_id,
                addev_new_phone_id=new_phone_id,
                addev_new_phone_label=new_phone_label,
                ttl_seconds=ttl_seconds,
            )
        except ValueError as exc:
            raise BootloaderError(
                f"profile_add_device construction failed: {exc}"
            ) from exc
        # Override request_id so it matches the one embedded in the
        # signing input (so signature verification at respond time
        # has access to the actual request_id used).
        from dataclasses import replace as _replace
        req = _replace(
            req,
            request_id=request_id,
            cap_payload_b64=cap_payload_b64,
            cap_agent_id=agent_id,
        )
        # AppContext injection
        app_ctx = (
            cfg.principal_apps.get(agent_id)
            or cfg.principal_apps.get(req.service)
        )
        if app_ctx is not None:
            req = _replace(req, app_context=app_ctx)
        cfg.state.add_pending(req)
        self._notify_push(req)
        self._send_json(HTTPStatus.CREATED, {
            "request_id": req.request_id,
            "profile_id": profile_id,
            "new_phone_id": new_phone_id,
            "expires_at_unix": req.expires_at_unix,
            "result_url": f"/v0.4/profile/add-device-result/{req.request_id}",
        })

    # ------------------------------------------------------------------
    # POST /v0.4/profile/<profile_id>/revoke-device  (Phase 2.0.C wave C.6)
    # ------------------------------------------------------------------

    def _handle_profile_revoke_device(
        self, profile_id: str, body: dict[str, Any]
    ) -> None:
        """Queue a profile_revoke_device request for operator approval.

        Phase 2.0.C wave C.6 integration. Multi-device-per-profile
        revocation flow. The master phone signs an attestation over
        the canonical-JSON binding (profile_id + phone_id_to_revoke +
        revoked_at_unix + request_id), bootloader verifies + calls
        profile.manage.profile_revoke_device.

        At v1 only K=1 master-only signing is wired (the endpoint
        rejects K>=2 with quorum_not_yet_implemented). K-of-N
        aggregation across non-master devices is banked for v1.1.

        Pre-flight checks (save the operator a phone prompt on bad
        requests):
          - profile_id exists under bootstrapped master
          - profile is NOT revoked
          - profile.revoke_quorum_k == 1 (K>=2 rejected with
            quorum_not_yet_implemented)
          - phone_id_to_revoke is registered with the bootloader
          - master_phone_id (the signer) is registered
          - phone_id_to_revoke IS in profile.device_ids (else returns
            200 already_not_member idempotent without queueing)
          - removing phone_id_to_revoke would NOT empty device_ids
            (last-device guard surfaced as 400 here rather than
            triggering the storage-primitive ValueError at respond
            time)

        Auth: ``X-Recto-Agent-Id`` + ``X-Recto-Agent-Token`` headers.

        Body shape:
            {
                "master_phone_id": "<paired-phone-id of master>",
                "phone_id_to_revoke": "<paired-phone-id to remove>",
                "revoker_label": <optional str>,
                "ttl_seconds": <optional int, default 600, range 60..86400>,
                "operation_description": <optional str>
            }

        Response (201, queued):
            {
                "request_id": "<uuid>",
                "profile_id": "<echo>",
                "phone_id_to_revoke": "<echo>",
                "expires_at_unix": <int>,
                "result_url": "/v0.4/profile/revoke-device-result/<request_id>"
            }

        Response (200, idempotent hit on already_not_member):
            {
                "status": "already_not_member",
                "profile_id": "<echo>",
                "phone_id_to_revoke": "<echo>",
                "reason": "phone_id_to_revoke is not in profile.device_ids"
            }
        """
        cfg = self.config
        if cfg.state is None:
            raise BootloaderError("server not initialized")
        if not cfg.capability_agent_tokens:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown_endpoint"})
            return
        agent_id = self.headers.get("X-Recto-Agent-Id", "").strip()
        agent_token = self.headers.get("X-Recto-Agent-Token", "").strip()
        if not agent_id or not agent_token:
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "agent_auth_required",
                 "detail": "X-Recto-Agent-Id and X-Recto-Agent-Token headers required"},
            )
            return
        expected = cfg.capability_agent_tokens.get(agent_id)
        if expected is None or not _constant_time_compare(expected, agent_token):
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "agent_auth_failed"},
            )
            return
        if not profile_id or not isinstance(profile_id, str):
            raise BootloaderError("profile_id required in URL path")
        master_phone_id = body.get("master_phone_id", "")
        if not master_phone_id or not isinstance(master_phone_id, str):
            raise BootloaderError(
                "master_phone_id required in profile_revoke_device body"
            )
        if cfg.state.get_phone(master_phone_id) is None:
            raise UnknownPhoneError(
                f"master_phone_id {master_phone_id!r} not registered"
            )
        phone_id_to_revoke = body.get("phone_id_to_revoke", "")
        if not phone_id_to_revoke or not isinstance(phone_id_to_revoke, str):
            raise BootloaderError(
                "phone_id_to_revoke required in profile_revoke_device body"
            )
        revoker_label = body.get("revoker_label")
        if revoker_label is not None and not isinstance(revoker_label, str):
            raise BootloaderError("revoker_label must be a string or null")
        ttl_seconds = body.get("ttl_seconds", 600)
        if not isinstance(ttl_seconds, int) or ttl_seconds < 60 or ttl_seconds > 86400:
            raise BootloaderError(
                "ttl_seconds must be an integer in [60, 86400]"
            )
        operation_description = body.get(
            "operation_description",
            f"profile_revoke_device from {agent_id}: remove {phone_id_to_revoke} from {profile_id}",
        )
        if not isinstance(operation_description, str):
            raise BootloaderError("operation_description must be a string")

        from recto.profile.manage import (
            get_profile_by_id as _get_profile_by_id,
        )
        from recto.profile.store import load_master_identity as _load_mi
        _state_dir = cfg.state.state_dir
        mi = _load_mi(state_dir=_state_dir)
        if mi is None:
            raise BootloaderError(
                "MasterIdentity not bootstrapped; "
                "run `recto vault bootstrap` first"
            )
        target = _get_profile_by_id(profile_id, state_dir=_state_dir)
        if target is None:
            raise BootloaderError(
                f"profile_id {profile_id!r} not found under master "
                f"{mi.master_pubkey_hex[:16]}..."
            )
        if target.revoked:
            raise BootloaderError(
                f"profile_id {profile_id!r} is revoked; cannot mutate "
                f"device_ids on a revoked profile"
            )
        # K-of-N quorum at v1: only K=1 is wired end-to-end. Reject
        # K>=2 with a clear error rather than silently queueing a
        # request that the respond branch wouldn't know how to
        # aggregate.
        #
        # THE AGGREGATION PRIMITIVE NOW EXISTS: `recto.quorum.verify_quorum`
        # (2026-08-19), built plane-agnostic precisely so this path and the
        # genesis member set share ONE definition of "k distinct signatures"
        # instead of growing two that drift. It counts MEMBERS satisfied,
        # never signatures accepted.
        #
        # WHAT ACTUALLY REMAINS, and it is NOT what the message below used to
        # claim. The old text said this was blocked on "the schema bump that
        # adds secp256k1 pubkeys to non-master phone registrations" -- that
        # blocker is GONE and probably has been for a while: `public_key_b64u`
        # is a required field on every `PhoneRegistration`, master or not,
        # and this very endpoint already resolves one (`revoker.public_key_b64u`).
        # A reader would have concluded the work was waiting on a schema
        # change that had already landed.
        #
        # The real remainder is a STATE MACHINE, not a verifier: K>=2 means
        # N approvals accumulating against ONE PendingRequest across time and
        # devices, which needs partial-signature persistence, per-signer
        # replay protection, and an expiry rule for a half-collected quorum.
        # `verify_quorum` is the last step of that flow, not the flow.
        if target.revoke_quorum_k != 1:
            self._send_json(HTTPStatus.BAD_REQUEST, {
                "error": "quorum_not_yet_implemented",
                "profile_id": profile_id,
                "revoke_quorum_k": target.revoke_quorum_k,
                "detail": (
                    f"profile_id {profile_id!r} requires "
                    f"{target.revoke_quorum_k}-of-N signatures to "
                    f"revoke a device. The signature-aggregation "
                    f"primitive exists (recto.quorum.verify_quorum); "
                    f"what remains is collecting N approvals against a "
                    f"single pending request over time -- partial-"
                    f"signature persistence, per-signer replay "
                    f"protection, and an expiry rule for a half-"
                    f"collected quorum. At v1 only profiles with K=1 "
                    f"can be revoked from."
                ),
            })
            return
        # phone_id_to_revoke must be a registered phone (defense:
        # revoking a never-registered phone_id would be a bug
        # upstream).
        if cfg.state.get_phone(phone_id_to_revoke) is None:
            raise UnknownPhoneError(
                f"phone_id_to_revoke {phone_id_to_revoke!r} not registered"
            )
        # Idempotent already_not_member: phone isn't in device_ids at
        # all → return 200 without queueing. Sister of add-device's
        # already_member pattern.
        if phone_id_to_revoke not in target.device_ids:
            self._send_json(HTTPStatus.OK, {
                "status": "already_not_member",
                "profile_id": profile_id,
                "phone_id_to_revoke": phone_id_to_revoke,
                "reason": (
                    "phone_id_to_revoke is not in the profile's "
                    "device_ids tuple"
                ),
            })
            return
        # Last-device guard: surfacing here saves the operator a phone
        # prompt. Storage-primitive enforces too (defense-in-depth).
        if len(target.device_ids) == 1:
            self._send_json(HTTPStatus.BAD_REQUEST, {
                "error": "last_device_guard",
                "profile_id": profile_id,
                "phone_id_to_revoke": phone_id_to_revoke,
                "detail": (
                    f"cannot revoke the only device on profile "
                    f"{profile_id!r}; would make the profile "
                    f"unreachable. Add a replacement device via "
                    f"profile_add_device first."
                ),
            })
            return

        # Build canonical-JSON signing input.
        from recto.capability.jwt import _canonical_json as _to_canonical
        revoked_at_unix = int(time.time())
        request_id = str(uuid.uuid4())
        signing_fields = {
            "action": "profile_revoke_device",
            "profile_id": profile_id,
            "phone_id_to_revoke": phone_id_to_revoke,
            "revoked_at_unix": revoked_at_unix,
            "request_id": request_id,
            "master_pubkey_hex": mi.master_pubkey_hex,
        }
        signing_input_bytes = _to_canonical(signing_fields)
        digest = hashlib.sha256(signing_input_bytes).digest()
        payload_hash_b64u = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        cap_payload_b64 = base64.urlsafe_b64encode(signing_input_bytes).rstrip(b"=").decode("ascii")

        try:
            req = PendingRequest.new_profile_revoke_device(
                service=body.get("service", "recto"),
                secret=body.get("secret", "profile"),
                phone_id=master_phone_id,
                operation_description=operation_description,
                payload_hash_b64u=payload_hash_b64u,
                child_pid=0,
                child_argv0="(external-agent)",
                revdev_profile_id=profile_id,
                revdev_phone_id_to_revoke=phone_id_to_revoke,
                revdev_revoker_label=revoker_label,
                ttl_seconds=ttl_seconds,
            )
        except ValueError as exc:
            raise BootloaderError(
                f"profile_revoke_device construction failed: {exc}"
            ) from exc
        from dataclasses import replace as _replace
        req = _replace(
            req,
            request_id=request_id,
            cap_payload_b64=cap_payload_b64,
            cap_agent_id=agent_id,
        )
        app_ctx = (
            cfg.principal_apps.get(agent_id)
            or cfg.principal_apps.get(req.service)
        )
        if app_ctx is not None:
            req = _replace(req, app_context=app_ctx)
        cfg.state.add_pending(req)
        self._notify_push(req)
        self._send_json(HTTPStatus.CREATED, {
            "request_id": req.request_id,
            "profile_id": profile_id,
            "phone_id_to_revoke": phone_id_to_revoke,
            "expires_at_unix": req.expires_at_unix,
            "result_url": f"/v0.4/profile/revoke-device-result/{req.request_id}",
        })

    # ------------------------------------------------------------------
    # POST /v0.4/pairing/code  (operator-trusted fresh-code mint)
    # ------------------------------------------------------------------

    def _handle_mint_pairing_code(self, body: dict[str, Any]) -> None:
        """Mint a fresh pairing code without restarting the bootloader.

        Operator-trusted agents (downstream consumer chatbots,
        automation runners, the launcher itself when running
        supervised) call this endpoint to obtain a fresh 6-digit
        pairing code on demand. Removes the friction of bouncing the
        bootloader to issue a new code when the existing code's TTL
        has elapsed -- a real pain point during multi-phone bring-ups
        where the foreground bootloader's startup-printed code times
        out before all phones have completed pairing.

        Auth: same agent-token posture as
        ``/v0.4/capability/request`` -- operator-trusted agents only
        via ``X-Recto-Agent-Id`` + ``X-Recto-Agent-Token``. Endpoint
        is disabled (404) when no agent tokens are configured,
        matching the rest of the agent-trusted surface (an operator
        who hasn't issued any agent tokens has no need for fresh-
        code minting via HTTP -- the launcher's stdout-printed
        startup code is sufficient).

        Body (optional): ``{"ttl_seconds": int}``
          - default: 300 (5 minutes)
          - min: 60 (1 minute)
          - max: 3600 (1 hour) -- ceiling so a buggy/malicious
            caller can't park codes on the bootloader's in-memory
            store indefinitely.

        Response (200):
          ``{"code": "NNNNNN", "expires_at_unix": int, "ttl_seconds": int}``

        The minted code is consumable via
        ``GET /v0.4/registration_challenge?code=...`` on the very
        next pairing flow (no restart needed).
        """
        cfg = self.config
        if cfg.challenges is None:
            raise BootloaderError("challenge store not initialized")
        if not cfg.capability_agent_tokens:
            # Endpoint is disabled when no tokens are configured.
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown_endpoint"})
            return
        # Auth headers (mirror capability_request shape exactly so
        # operator-side conventions stay consistent across the
        # agent-trusted surface).
        agent_id = self.headers.get("X-Recto-Agent-Id", "").strip()
        agent_token = self.headers.get("X-Recto-Agent-Token", "").strip()
        if not agent_id or not agent_token:
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "agent_auth_required",
                 "detail": "X-Recto-Agent-Id and X-Recto-Agent-Token headers required"},
            )
            return
        expected = cfg.capability_agent_tokens.get(agent_id)
        if expected is None or not _constant_time_compare(expected, agent_token):
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "agent_auth_failed"},
            )
            return
        # Body shape: optional ttl_seconds with bounds enforcement
        ttl_seconds = body.get("ttl_seconds", 300)
        if not isinstance(ttl_seconds, int) or ttl_seconds < 60 or ttl_seconds > 3600:
            raise BootloaderError(
                "ttl_seconds must be an integer in [60, 3600] (1 minute - 1 hour)"
            )
        # Mint via the in-process ChallengeStore primitive
        code, exp = cfg.challenges.issue_pairing_code(ttl_seconds=ttl_seconds)
        # Operator-friendly stdout for the foreground-bootloader case
        # (matches the existing startup-print convention).
        print(f"[bootloader] minted pairing code via /v0.4/pairing/code "
              f"(agent={agent_id}, expires_at_unix={exp})", flush=True)
        self._send_json(HTTPStatus.OK, {
            "code": code,
            "expires_at_unix": exp,
            "ttl_seconds": ttl_seconds,
        })

    # ------------------------------------------------------------------
    # POST /v0.4/manage/phones/revoke
    # ------------------------------------------------------------------

    def _handle_revoke_phone(self, body: dict[str, Any]) -> None:
        """Revoke a paired phone (self-revoke OR sibling-revoke).

        Single endpoint handles both flows:
          - self-revoke: revoker_phone_id == target_phone_id (the
            phone is retiring itself; "Unpair" button on the phone UI).
          - sibling-revoke: revoker_phone_id != target_phone_id (phone A
            removes phone B; "Revoke" button on the registered-phones
            list when the target is a sibling). Trust model: any genuine
            paired phone has implicit authority over its siblings (the
            "phones-as-master-quorum" model banked in CLAUDE.md). Phase 5
            v3 multi-device-per-user architecture will tighten this with
            capability-JWT-gating; for v1 the signed-challenge from a
            registered phone IS the authority.

        Auth: signed-challenge from the source phone, NOT capability-
        agent-token (this endpoint's caller is a paired phone, not an
        external agent). Mirrors the registration flow's challenge-
        signature shape:

          1. Caller fetches a fresh challenge via the existing
             ``GET /v0.4/registration_challenge`` endpoint.
          2. Caller signs the ASCII bytes of
             ``f"{challenge_b64u}:{target_phone_id}"`` with its enclave
             key. The colon-binding prevents replay -- a captured
             signature for one target can't be reused against a different
             target because the payload bytes differ.
          3. Caller POSTs to this endpoint with the body shape below.
          4. Bootloader verifies the signature against the revoker's
             registered pubkey, consumes the challenge (single-use),
             and removes the target via StateStore.revoke_phone (which
             cascades to sessions + pending in one transaction).

        Body:
          ``{"revoker_phone_id": str,
             "target_phone_id": str,
             "challenge_b64u": str,
             "signature_b64u": str}``

        Response (200):
          ``{"revoked": true,
             "revoked_phone_id": str,
             "was_self_revoke": bool,
             "remaining_phones_count": int}``

        Error responses:
          - 400 (BootloaderError): missing/malformed body fields,
            expired challenge, unknown algorithm
          - 400 (UnknownPhoneError): unknown revoker_phone_id or
            target_phone_id
          - 401 (BootloaderError): signature verification failed

        v1 deferred to v2:
          - capability-JWT-gated sibling-revoke (Phase 5 v3 multi-
            device-per-user architecture). Today any genuine paired
            phone can revoke any sibling; v2 ties revocation authority
            to a capability JWT signed by the operator's BIP-39 key
            so an attacker who compromises ONE phone can't necessarily
            revoke OTHER phones.
          - Quorum-protect-master rule: if revoking a phone would drop
            the master-tier quorum below the operator-configured
            threshold (default 1, recommended 2), require additional
            confirmation. Today we trust the caller to know what
            they're doing.
        """
        cfg = self.config
        if cfg.state is None or cfg.challenges is None:
            raise BootloaderError("server not initialized")
        revoker_phone_id = body.get("revoker_phone_id", "")
        target_phone_id = body.get("target_phone_id", "")
        challenge = body.get("challenge_b64u", "")
        sig = body.get("signature_b64u", "")
        for name, val in [
            ("revoker_phone_id", revoker_phone_id),
            ("target_phone_id", target_phone_id),
            ("challenge_b64u", challenge),
            ("signature_b64u", sig),
        ]:
            if not isinstance(val, str) or not val:
                raise BootloaderError(f"{name} required (non-empty string)")
        revoker = cfg.state.get_phone(revoker_phone_id)
        if revoker is None:
            raise UnknownPhoneError(
                f"revoker phone_id {revoker_phone_id!r} not registered"
            )
        target = cfg.state.get_phone(target_phone_id)
        if target is None:
            raise UnknownPhoneError(
                f"target phone_id {target_phone_id!r} not registered"
            )
        # Consume challenge (single-use; same surface the registration
        # flow uses, just consumed by a different POST handler).
        if not cfg.challenges.consume_challenge(challenge):
            raise RegistrationExpiredError(
                "challenge expired or invalid (fetch a fresh one via "
                "GET /v0.4/registration_challenge)"
            )
        # Verify the revoker's signature over the colon-bound payload.
        # The colon binding is what prevents replay -- a sig captured
        # for one target can't be reused against a different target.
        # Algorithm comes from the revoker's registered supported_algorithms
        # (first entry, matching the registration flow convention).
        chosen_algo = _registered_algorithm(revoker, revoker.phone_id)
        payload = f"{challenge}:{target_phone_id}".encode("ascii")
        ok = verify_signature(
            payload=payload,
            signature_b64u=sig,
            public_key_b64u=revoker.public_key_b64u,
            algorithm=chosen_algo,
        )
        if not ok:
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "revoke_signature_invalid",
                 "detail": (
                     f"signature did not verify against revoker's "
                     f"pubkey (algorithm={chosen_algo!r}). The phone "
                     "must sign the ASCII bytes of "
                     "f'{challenge_b64u}:{target_phone_id}'."
                 )},
            )
            return
        was_self_revoke = (revoker_phone_id == target_phone_id)
        removed = cfg.state.revoke_phone(target_phone_id)
        # Should always be True since we verified target exists above,
        # but be defensive: a concurrent revoke from another caller
        # could race us between the get_phone check and this delete.
        if not removed:
            raise UnknownPhoneError(
                f"target phone_id {target_phone_id!r} no longer registered "
                "(concurrent revoke from another caller?)"
            )
        remaining = len(cfg.state.list_phones())
        print(
            f"[bootloader] phone revoked: target={target_phone_id} "
            f"by revoker={revoker_phone_id} "
            f"(self={was_self_revoke}, remaining={remaining})",
            flush=True,
        )
        self._send_json(HTTPStatus.OK, {
            "revoked": True,
            "revoked_phone_id": target_phone_id,
            "was_self_revoke": was_self_revoke,
            "remaining_phones_count": remaining,
        })

    # ------------------------------------------------------------------
    # GET /v0.4/capability/result/<request_id>  (Phase 5 Wave B)
    # ------------------------------------------------------------------

    def _handle_capability_result(self, request_id: str) -> None:
        """Poll for a resolved capability_request result.

        Three response states:
        - 200 + status="approved" + capability_jws=<3-part JWS> when the
          operator approved and the bootloader assembled the JWS. Single
          fetch only — the result is removed from the store on read.
        - 200 + status="denied" + reason=<operator's reason> when the
          operator declined.
        - 200 + status="signature_error" + reason when the bootloader
          rejected a malformed signature from the phone (rare).
        - 200 + status="pending" when the request is still on the
          queue waiting for operator action.
        - 404 when the request_id has expired (TTL elapsed) or never
          existed. Agent should treat as "request lost" and re-submit.

        Auth via the same X-Recto-Agent-Id + X-Recto-Agent-Token
        headers used by /capability/request — only the agent that
        created the request can fetch its result, AND the result is
        scoped to that agent (cap_agent_id pinned at request time).
        """
        cfg = self.config
        if cfg.state is None:
            raise BootloaderError("server not initialized")
        if not cfg.capability_agent_tokens:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown_endpoint"})
            return
        agent_id = self.headers.get("X-Recto-Agent-Id", "").strip()
        agent_token = self.headers.get("X-Recto-Agent-Token", "").strip()
        if not agent_id or not agent_token:
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "agent_auth_required"},
            )
            return
        expected = cfg.capability_agent_tokens.get(agent_id)
        if expected is None or not _constant_time_compare(expected, agent_token):
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "agent_auth_failed"},
            )
            return
        # Check the resolved-results store first; if nothing's there,
        # check the pending queue (still waiting). 404 if neither.
        result = cfg.state.get_capability_result(request_id)
        if result is None:
            # Could still be pending. We don't expose the pending list
            # by id here — just check existence in the queue. (The
            # pending dict is private to StateStore; we use the public
            # take_pending None-test pattern by glancing at a peek
            # method... actually the easiest correct thing is to ask
            # the store directly via _pending dict access.)
            # Cleaner: the StateStore has list_pending_for_phone but
            # not get_pending_by_id; we can sweep the phone's queue
            # for the id. Acceptable cost — the queue is small.
            # As a simpler inline impl:
            still_pending = False
            for _phone_id_unused in (
                phone.phone_id for phone in cfg.state.list_phones()
            ):
                for p in cfg.state.list_pending_for_phone(_phone_id_unused):
                    if p.request_id == request_id:
                        # Validate ownership before disclosing pending
                        # state — only the agent that submitted the
                        # request can poll for it.
                        if p.cap_agent_id != agent_id:
                            self._send_json(
                                HTTPStatus.NOT_FOUND,
                                {"error": "request_not_found"},
                            )
                            return
                        still_pending = True
                        break
                if still_pending:
                    break
            if still_pending:
                self._send_json(HTTPStatus.OK, {"status": "pending"})
                return
            self._send_json(HTTPStatus.NOT_FOUND,
                            {"error": "request_not_found"})
            return
        # Result found — enforce agent ownership before disclosing.
        if result.agent_id != agent_id:
            self._send_json(HTTPStatus.NOT_FOUND,
                            {"error": "request_not_found"})
            return
        # Single-use semantics: take the result so subsequent fetches
        # return 404. Agent is responsible for caching the JWT
        # locally if it needs to re-use it.
        cfg.state.take_capability_result(request_id)
        out: dict[str, Any] = {"status": result.status}
        if result.capability_jws is not None:
            out["capability_jws"] = result.capability_jws
        if result.reason is not None:
            out["reason"] = result.reason
        self._send_json(HTTPStatus.OK, out)

    def _store_capability_result(
        self,
        req: PendingRequest,
        *,
        status: str,
        capability_jws: str | None,
        reason: str | None,
    ) -> None:
        """Stash a CapabilityResult for the requesting agent's later
        poll. Called from _handle_respond after the bootloader has
        decided whether to approve, deny, or signature-error.
        """
        cfg = self.config
        if cfg.state is None:
            return
        now = int(time.time())
        ttl = max(60, int(cfg.capability_result_ttl_seconds))
        result = CapabilityResult(
            request_id=req.request_id,
            status=status,
            capability_jws=capability_jws,
            reason=reason,
            agent_id=req.cap_agent_id,
            resolved_at_unix=now,
            expires_at_unix=now + ttl,
        )
        cfg.state.put_capability_result(result)

    # ------------------------------------------------------------------
    # GET /v0.4/profile/result/<request_id>  (Phase 2.0.B)
    # ------------------------------------------------------------------

    def _handle_profile_create_result(self, request_id: str) -> None:
        """Poll for a resolved profile_create result.

        Sister of ``_handle_capability_result`` for the multi-profile
        identity flow. Single-use fetch (the result is removed from
        the store on read); cap_agent_id ownership pin (only the agent
        that submitted the request can fetch its result).

        Response states:
          - 200 + status="approved" + profile_id=<new uuid>:
              operator approved; new profile is persisted in
              master_identity.json.
          - 200 + status="denied" + reason=<operator's note>:
              operator declined at the phone.
          - 200 + status="signature_error" + reason=<diagnostic>:
              phone returned an attestation that didn't verify against
              the operator pubkey. If reason starts with "persist_error:",
              the attestation verified but the disk write failed
              (recovery = fix the disk state, retry with same key).
          - 200 + status="pending": waiting for operator action.
          - 404: request_id expired (TTL elapsed) or never existed;
              caller should treat as "request lost" and re-submit
              (with the SAME candidate_profile_id — retry is safe
              per the idempotency-key contract).

        Auth: ``X-Recto-Agent-Id`` + ``X-Recto-Agent-Token`` headers,
        matched against ``cap_agent_id`` on the pending/result entry.
        Endpoint is disabled (404) when no agent tokens are configured.
        """
        cfg = self.config
        if cfg.state is None:
            raise BootloaderError("server not initialized")
        if not cfg.capability_agent_tokens:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown_endpoint"})
            return
        agent_id = self.headers.get("X-Recto-Agent-Id", "").strip()
        agent_token = self.headers.get("X-Recto-Agent-Token", "").strip()
        if not agent_id or not agent_token:
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "agent_auth_required"},
            )
            return
        expected = cfg.capability_agent_tokens.get(agent_id)
        if expected is None or not _constant_time_compare(expected, agent_token):
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "agent_auth_failed"},
            )
            return
        # Check the resolved-results store first; if not present, check
        # the pending queue for a still-in-flight request matching the
        # id.
        result = cfg.state.get_profile_create_result(request_id)
        if result is None:
            still_pending = False
            for _phone_id_unused in (
                phone.phone_id for phone in cfg.state.list_phones()
            ):
                for p in cfg.state.list_pending_for_phone(_phone_id_unused):
                    if p.request_id == request_id:
                        # Ownership check — only the submitting agent
                        # can poll for the result.
                        if p.cap_agent_id != agent_id:
                            self._send_json(
                                HTTPStatus.NOT_FOUND,
                                {"error": "request_not_found"},
                            )
                            return
                        still_pending = True
                        break
                if still_pending:
                    break
            if still_pending:
                self._send_json(HTTPStatus.OK, {"status": "pending"})
                return
            self._send_json(HTTPStatus.NOT_FOUND,
                            {"error": "request_not_found"})
            return
        # Result found — single-use semantics: take the result so
        # subsequent fetches return 404. Caller is responsible for
        # caching the profile_id locally if it needs to re-use it.
        # Note: the profile itself is persisted in master_identity.json
        # and remains discoverable via `recto profile list` even after
        # this result is consumed (Milan commitment B — persist is the
        # source of truth; result-store is a convenience projection).
        cfg.state.take_profile_create_result(request_id)
        out: dict[str, Any] = {"status": result.status}
        if result.profile_id is not None:
            out["profile_id"] = result.profile_id
        if result.reason is not None:
            out["reason"] = result.reason
        self._send_json(HTTPStatus.OK, out)

    # ------------------------------------------------------------------
    # GET /v0.4/profile/add-device-result/<request_id>  (Phase 2.0.C wave C.5)
    # ------------------------------------------------------------------

    def _handle_profile_add_device_result(self, request_id: str) -> None:
        """Poll for a resolved profile_add_device result.

        Sister of ``_handle_profile_create_result`` for the device-set
        mutation flow. Single-use fetch (the result is removed from
        the store on read); cap_agent_id ownership pin (only the agent
        that submitted the request can fetch its result).

        Response states:
          - 200 + status="approved" + profile_id + new_phone_id:
              operator approved; new phone_id is now in the profile's
              device_ids tuple.
          - 200 + status="already_member" + profile_id + new_phone_id:
              idempotent hit at endpoint pre-flight; no phone prompt
              occurred.
          - 200 + status="denied" + reason: operator declined.
          - 200 + status="signature_error" + reason: phone returned an
              attestation that didn't verify, OR disk write failed
              (reason prefix "persist_error:" for the latter).
          - 200 + status="pending": waiting for operator action.
          - 404: request_id expired or never existed.

        Auth: ``X-Recto-Agent-Id`` + ``X-Recto-Agent-Token`` headers.
        """
        cfg = self.config
        if cfg.state is None:
            raise BootloaderError("server not initialized")
        if not cfg.capability_agent_tokens:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown_endpoint"})
            return
        agent_id = self.headers.get("X-Recto-Agent-Id", "").strip()
        agent_token = self.headers.get("X-Recto-Agent-Token", "").strip()
        if not agent_id or not agent_token:
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "agent_auth_required"},
            )
            return
        expected = cfg.capability_agent_tokens.get(agent_id)
        if expected is None or not _constant_time_compare(expected, agent_token):
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "agent_auth_failed"},
            )
            return
        result = cfg.state.get_profile_add_device_result(request_id)
        if result is None:
            still_pending = False
            for _phone_id_unused in (
                phone.phone_id for phone in cfg.state.list_phones()
            ):
                for p in cfg.state.list_pending_for_phone(_phone_id_unused):
                    if p.request_id == request_id:
                        if p.cap_agent_id != agent_id:
                            self._send_json(
                                HTTPStatus.NOT_FOUND,
                                {"error": "request_not_found"},
                            )
                            return
                        still_pending = True
                        break
                if still_pending:
                    break
            if still_pending:
                self._send_json(HTTPStatus.OK, {"status": "pending"})
                return
            self._send_json(HTTPStatus.NOT_FOUND,
                            {"error": "request_not_found"})
            return
        cfg.state.take_profile_add_device_result(request_id)
        out: dict[str, Any] = {"status": result.status}
        if result.profile_id is not None:
            out["profile_id"] = result.profile_id
        if result.new_phone_id is not None:
            out["new_phone_id"] = result.new_phone_id
        if result.reason is not None:
            out["reason"] = result.reason
        self._send_json(HTTPStatus.OK, out)

    # ------------------------------------------------------------------
    # GET /v0.4/profile/revoke-device-result/<request_id>  (Phase 2.0.C wave C.6)
    # ------------------------------------------------------------------

    def _handle_profile_revoke_device_result(self, request_id: str) -> None:
        """Poll for a resolved profile_revoke_device result.

        Sister of ``_handle_profile_add_device_result``. Single-use
        fetch; cap_agent_id ownership pin (only the agent that
        submitted the request can fetch its result).

        Response states:
          - 200 + status="approved" + profile_id + phone_id_revoked
          - 200 + status="already_not_member" + profile_id + phone_id_revoked
          - 200 + status="denied" + reason
          - 200 + status="signature_error" + reason
          - 200 + status="pending"
          - 404: request_id expired or never existed.

        Auth: ``X-Recto-Agent-Id`` + ``X-Recto-Agent-Token``.
        """
        cfg = self.config
        if cfg.state is None:
            raise BootloaderError("server not initialized")
        if not cfg.capability_agent_tokens:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown_endpoint"})
            return
        agent_id = self.headers.get("X-Recto-Agent-Id", "").strip()
        agent_token = self.headers.get("X-Recto-Agent-Token", "").strip()
        if not agent_id or not agent_token:
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "agent_auth_required"},
            )
            return
        expected = cfg.capability_agent_tokens.get(agent_id)
        if expected is None or not _constant_time_compare(expected, agent_token):
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "agent_auth_failed"},
            )
            return
        result = cfg.state.get_profile_revoke_device_result(request_id)
        if result is None:
            still_pending = False
            for _phone_id_unused in (
                phone.phone_id for phone in cfg.state.list_phones()
            ):
                for p in cfg.state.list_pending_for_phone(_phone_id_unused):
                    if p.request_id == request_id:
                        if p.cap_agent_id != agent_id:
                            self._send_json(
                                HTTPStatus.NOT_FOUND,
                                {"error": "request_not_found"},
                            )
                            return
                        still_pending = True
                        break
                if still_pending:
                    break
            if still_pending:
                self._send_json(HTTPStatus.OK, {"status": "pending"})
                return
            self._send_json(HTTPStatus.NOT_FOUND,
                            {"error": "request_not_found"})
            return
        cfg.state.take_profile_revoke_device_result(request_id)
        out: dict[str, Any] = {"status": result.status}
        if result.profile_id is not None:
            out["profile_id"] = result.profile_id
        if result.phone_id_revoked is not None:
            out["phone_id_revoked"] = result.phone_id_revoked
        if result.reason is not None:
            out["reason"] = result.reason
        self._send_json(HTTPStatus.OK, out)

    def _store_profile_create_result(
        self,
        req: PendingRequest,
        *,
        status: str,
        profile_id: str | None,
        reason: str | None,
    ) -> None:
        """Stash a ProfileCreateResult for the submitting agent's later
        poll. Called from _handle_respond's profile_create branch after
        the bootloader has decided approve / deny / signature_error.

        Milan commitment B: this is the DERIVED projection of the
        persistent state in master_identity.json. The on-disk Profile
        is the source of truth; this result is a poll-convenience
        layer that survives only until expires_at_unix.
        """
        cfg = self.config
        if cfg.state is None:
            return
        now = int(time.time())
        ttl = max(60, int(cfg.capability_result_ttl_seconds))
        result = ProfileCreateResult(
            request_id=req.request_id,
            status=status,
            profile_id=profile_id,
            reason=reason,
            resolved_at_unix=now,
            expires_at_unix=now + ttl,
        )
        cfg.state.put_profile_create_result(result)

    def _store_profile_add_device_result(
        self,
        req: PendingRequest,
        *,
        status: str,
        profile_id: str | None,
        new_phone_id: str | None,
        reason: str | None,
    ) -> None:
        """Stash a ProfileAddDeviceResult for the submitting agent's
        later poll. Called from _handle_respond's profile_add_device
        branch after the bootloader has decided approve / deny /
        signature_error.

        Milan commitment B: this is the DERIVED projection of the
        persistent device_ids tuple state in master_identity.json.
        The on-disk Profile is the source of truth; this result is a
        poll-convenience layer that survives only until expires_at_unix.
        """
        from recto.bootloader.state import ProfileAddDeviceResult
        cfg = self.config
        if cfg.state is None:
            return
        now = int(time.time())
        ttl = max(60, int(cfg.capability_result_ttl_seconds))
        result = ProfileAddDeviceResult(
            request_id=req.request_id,
            status=status,
            profile_id=profile_id,
            new_phone_id=new_phone_id,
            reason=reason,
            resolved_at_unix=now,
            expires_at_unix=now + ttl,
        )
        cfg.state.put_profile_add_device_result(result)

    def _store_profile_revoke_device_result(
        self,
        req: PendingRequest,
        *,
        status: str,
        profile_id: str | None,
        phone_id_revoked: str | None,
        reason: str | None,
    ) -> None:
        """Stash a ProfileRevokeDeviceResult for the submitting agent's
        later poll. Called from _handle_respond's profile_revoke_device
        branch after the bootloader has decided approve / deny /
        signature_error.

        Milan commitment B: the on-disk Profile (with the phone removed
        from device_ids) is the source of truth; this result is a
        poll-convenience layer that survives only until expires_at_unix.
        """
        from recto.bootloader.state import ProfileRevokeDeviceResult
        cfg = self.config
        if cfg.state is None:
            return
        now = int(time.time())
        ttl = max(60, int(cfg.capability_result_ttl_seconds))
        result = ProfileRevokeDeviceResult(
            request_id=req.request_id,
            status=status,
            profile_id=profile_id,
            phone_id_revoked=phone_id_revoked,
            reason=reason,
            resolved_at_unix=now,
            expires_at_unix=now + ttl,
        )
        cfg.state.put_profile_revoke_device_result(result)

    # ------------------------------------------------------------------
    # POST /v0.4/capability/revoke  (Phase 5 Wave C part 2)
    # ------------------------------------------------------------------

    def _handle_capability_revoke(self, body: dict[str, Any]) -> None:
        """Add a JWT jti to the persistent revocation list.

        Auth: pre-shared operator token via the
        ``X-Recto-Operator-Token`` header. v1 deliberately uses a
        shared secret rather than capability-JWT gating because
        revocation needs to work for the chicken-and-egg case of
        "revoke a compromised JWT" -- gating revocation behind
        another JWT would create a cycle. Future iteration may layer
        a tier-3 ``capability:revoke-other`` check ON TOP of the
        operator-token check (revocation requires BOTH), but v1
        keeps it simple.

        Endpoint disabled (returns 404) when
        ``cfg.capability_operator_token`` is None / empty.

        Body shape: ``{jti, original_exp_unix, reason?}``.
          - ``jti``: the JWT identifier to revoke (required, must
            be a non-empty string).
          - ``original_exp_unix``: the original JWT's exp claim
            (required; used for auto-pruning the revocation entry
            once the JWT would have expired anyway).
          - ``reason``: optional operator-supplied audit note.

        Idempotent: revoking an already-revoked jti is a no-op
        (returns 200 with a flag indicating the entry was already
        present). Same idempotence as the StateStore.add_revocation
        method.
        """
        cfg = self.config
        if cfg.state is None:
            raise BootloaderError("server not initialized")
        if not cfg.capability_operator_token:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown_endpoint"})
            return
        operator_token = self.headers.get("X-Recto-Operator-Token", "").strip()
        if not operator_token:
            self._send_json(HTTPStatus.UNAUTHORIZED, {
                "error": "operator_token_required",
                "detail": "X-Recto-Operator-Token header required",
            })
            return
        if not _constant_time_compare(operator_token, cfg.capability_operator_token):
            self._send_json(HTTPStatus.UNAUTHORIZED, {
                "error": "operator_token_invalid",
            })
            return
        jti = body.get("jti", "")
        if not jti or not isinstance(jti, str):
            raise BootloaderError("jti (non-empty string) required in body")
        original_exp_unix = body.get("original_exp_unix")
        if not isinstance(original_exp_unix, int):
            raise BootloaderError(
                "original_exp_unix (integer unix timestamp) required in body"
            )
        reason = body.get("reason")
        if reason is not None and not isinstance(reason, str):
            raise BootloaderError("reason must be a string when present")
        # Construct the entry. revoked_at_unix = now.
        already_revoked = cfg.state.is_revoked(jti)
        entry = RevocationEntry(
            jti=jti,
            revoked_at_unix=int(time.time()),
            original_exp_unix=original_exp_unix,
            reason=reason,
        )
        cfg.state.add_revocation(entry)
        self._send_json(HTTPStatus.OK, {
            "revoked": True,
            "jti": jti,
            "already_revoked": already_revoked,
        })

    # ------------------------------------------------------------------
    # GET /v0.4/capability/revocations  (Phase 5 Wave C part 2)
    # ------------------------------------------------------------------

    def _handle_capability_revocations(self) -> None:
        """Serve the current revocation list as canonical JSON.

        Public endpoint -- the revocation list itself isn't sensitive
        (knowing a jti is revoked doesn't grant any capability), and
        the whole point is for verifiers (consumer-side servers,
        other Recto instances, future external services) to fetch
        on a short cadence and cache locally.

        ETag is the SHA-256 of the canonical-JSON wire shape so
        verifiers can do If-None-Match revalidation cheaply.
        Cache-Control: public, max-age=30 -- balances revoke-to-
        honor latency against fetch volume. Verifiers SHOULD treat
        the revocation list as eventually-consistent: a revocation
        committed now propagates to verifiers within ~30s + the
        verifier's own poll cadence.

        Endpoint is always available (no opt-out via empty list) --
        even an empty revocation list is meaningful information for
        verifiers (it says "no JWTs are currently revoked"). The
        404 disabled-by-empty pattern only applies to write-side
        endpoints.
        """
        cfg = self.config
        if cfg.state is None:
            self._send_json(HTTPStatus.SERVICE_UNAVAILABLE, {
                "error": "state_not_configured",
            })
            return
        entries = cfg.state.list_revocations()
        wire_entries = [
            {
                "jti": e.jti,
                "revoked_at_unix": e.revoked_at_unix,
                "original_exp_unix": e.original_exp_unix,
                "reason": e.reason,
            }
            for e in entries
        ]
        body = {"revocations": wire_entries}
        payload = json.dumps(body, sort_keys=True).encode("utf-8")
        # ETag: SHA-256 of the canonical bytes. Stable + short.
        import hashlib as _hashlib
        etag_hash = _hashlib.sha256(payload).hexdigest()[:32]
        etag = f'"{etag_hash}"'
        if_none_match = self.headers.get("If-None-Match", "").strip()
        if if_none_match == etag:
            self.send_response(HTTPStatus.NOT_MODIFIED)
            self.send_header("ETag", etag)
            self.send_header("Cache-Control", "public, max-age=30")
            self.end_headers()
            return
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("ETag", etag)
        self.send_header("Cache-Control", "public, max-age=30")
        self.end_headers()
        self.wfile.write(payload)

    # ------------------------------------------------------------------
    # GET /v0.4/capability/manifest  (Phase 5 Wave C part 1)
    # ------------------------------------------------------------------

    def _handle_capability_manifest(self) -> None:
        """Serve the canonical capability action manifest.

        Public endpoint -- manifests are public-by-design (they
        describe what actions exist + their foundation counts; they
        DON'T describe who has access to which actions, which is the
        capability JWT's job). Verifiers fetch this once + cache via
        standard HTTP cache semantics; agents that need to compute a
        capability's foundation-count breakdown server-side fetch
        too.

        Returns 404 when no manifest is configured (deployments that
        don't broker capability auth leave it unset).

        ETag is the manifest's `version` string so verifiers can
        revalidate via If-None-Match without re-downloading.
        """
        cfg = self.config
        if cfg.capability_manifest is None:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "no_manifest_configured"})
            return
        manifest = cfg.capability_manifest
        # Build the JSON wire shape (mirror of recto/capability/manifest_v1.json
        # structure). Lazy-import to avoid a hard dep on recto.capability
        # at module load time.
        from recto.capability.types import ActionManifest as _ActionManifestT
        if not isinstance(manifest, _ActionManifestT):
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR,
                            {"error": "manifest_misconfigured"})
            return
        etag = f'"{manifest.version}"'
        if_none_match = self.headers.get("If-None-Match", "").strip()
        if if_none_match == etag:
            self.send_response(HTTPStatus.NOT_MODIFIED)
            self.send_header("ETag", etag)
            self.send_header("Cache-Control", "public, max-age=300")
            self.end_headers()
            return
        body: dict[str, Any] = {
            "version": manifest.version,
            "actions": {
                key: {"count": defn.count, "description": defn.description}
                for key, defn in manifest.actions.items()
            },
            "groups": {
                key: {"actions": list(defn.actions)}
                for key, defn in manifest.groups.items()
            },
        }
        payload = json.dumps(body, sort_keys=True).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("ETag", etag)
        self.send_header("Cache-Control", "public, max-age=300")
        self.end_headers()
        self.wfile.write(payload)

    # ------------------------------------------------------------------
    # POST /v0.4/secrets/read  (Phase 5 Wave C part 1)
    # ------------------------------------------------------------------

    def _handle_secret_read(self, body: dict[str, Any]) -> None:
        """Read a vault secret using a capability JWT for authorization.

        Body shape: ``{capability_jws, service, secret_name}``. The
        bootloader:

        1. Verifies the JWS against ``cfg.capability_operator_pubkey``
           (returns 401 on signature failure / expired exp / wrong aud).
        2. Checks ``jti`` against ``cfg.capability_revocation_jtis``
           (returns 401 if revoked).
        3. Loads the manifest from ``cfg.capability_manifest`` and
           evaluates ``secret:read`` against the JWT's scope (returns
           403 if the action isn't permitted).
        4. Checks ``clause.scope.services`` -- if non-empty, the
           requested ``service`` must appear in the list (returns
           403 otherwise).
        5. Looks up ``(service, secret_name)`` in
           ``cfg.capability_vault_secrets`` (returns 404 if not
           present).
        6. Returns ``200 + {value}``.

        Endpoint is disabled (returns 404) when
        ``cfg.capability_vault_secrets`` is empty.
        """
        cfg = self.config
        if not cfg.capability_vault_secrets:
            self._send_json(HTTPStatus.NOT_FOUND,
                            {"error": "unknown_endpoint"})
            return
        if cfg.capability_operator_pubkey is None:
            self._send_json(HTTPStatus.SERVICE_UNAVAILABLE,
                            {"error": "operator_pubkey_not_configured",
                             "detail": "Server-side capability_operator_pubkey "
                                       "is required for /v0.4/secrets/read."})
            return
        if cfg.capability_manifest is None:
            self._send_json(HTTPStatus.SERVICE_UNAVAILABLE,
                            {"error": "manifest_not_configured",
                             "detail": "Server-side capability_manifest is "
                                       "required for /v0.4/secrets/read."})
            return

        jws = body.get("capability_jws", "")
        service = body.get("service", "")
        secret_name = body.get("secret_name", "")
        if not jws or not isinstance(jws, str):
            raise BootloaderError(
                "capability_jws (string) required in body"
            )
        if not service or not isinstance(service, str):
            raise BootloaderError("service (string) required in body")
        if not secret_name or not isinstance(secret_name, str):
            raise BootloaderError("secret_name (string) required in body")

        # 1. Verify the JWS signature + standard time bounds.
        from recto.capability.jwt import verify_jws as _verify_jws
        try:
            claims = _verify_jws(jws, expected_pubkey=cfg.capability_operator_pubkey)
        except ValueError as exc:
            self._send_json(HTTPStatus.UNAUTHORIZED, {
                "error": "capability_jws_invalid",
                "detail": str(exc),
            })
            return

        # 2. Revocation check. Wave C part 2 moved the source-of-truth
        # from the in-memory cfg.capability_revocation_jtis set to the
        # StateStore's persistent revocation list (revocations.json
        # under the state dir). Auto-purges expired entries on every
        # call so revocations don't accumulate past their original JWT
        # exp.
        if cfg.state is not None and cfg.state.is_revoked(claims.jti):
            self._send_json(HTTPStatus.UNAUTHORIZED, {
                "error": "capability_revoked",
                "jti": claims.jti,
            })
            return

        # 3. Scope check: secret:read action permitted.
        from recto.capability.manifest import evaluate_scope as _evaluate_scope
        if not _evaluate_scope("secret:read", claims.cap, cfg.capability_manifest):
            self._send_json(HTTPStatus.FORBIDDEN, {
                "error": "scope_denied",
                "detail": "capability does not include 'secret:read' action",
                "jti": claims.jti,
            })
            return

        # 4. Per-service scope narrowing. When clause.scope.services is
        # non-empty, the requested service must be in the list.
        if claims.cap.scope.services and service not in claims.cap.scope.services:
            self._send_json(HTTPStatus.FORBIDDEN, {
                "error": "scope_service_denied",
                "detail": (
                    f"capability scope.services {claims.cap.scope.services!r} "
                    f"does not include requested service {service!r}"
                ),
                "jti": claims.jti,
            })
            return

        # 5. Look up the secret.
        value = cfg.capability_vault_secrets.get((service, secret_name))
        if value is None:
            self._send_json(HTTPStatus.NOT_FOUND, {
                "error": "secret_not_found",
                "service": service,
                "secret_name": secret_name,
            })
            return

        # 6. Return value. Cache-Control no-store -- callers MUST NOT
        # cache secret values; the capability JWT's lifetime is the
        # only bound on usage.
        out: dict[str, Any] = {
            "value": value,
            "service": service,
            "secret_name": secret_name,
            "jti": claims.jti,
        }
        payload = json.dumps(out, sort_keys=True).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    # ------------------------------------------------------------------
    # Recto Connections Substrate (2026-06-13)
    #
    # Generic, consumer-agnostic vault-backed connection (API key)
    # management. The consuming app (any application installed alongside
    # Recto) depends on recto-core and reaches the vault through these HTTP
    # endpoints because the secret VALUE lives in a dpapi-machine blob
    # that a Linux Docker container cannot decrypt directly (the blob is
    # Windows-machine-bound). Metadata (display name, category, has_secret
    # flag, enabled, config, health_url) lives secret-free in a sidecar
    # JSON; the secret value is ONLY ever returned by the agent-gated,
    # service-scoped /secret read path with Cache-Control: no-store.
    #
    # Auth tiers:
    #   - READS  (list metadata, fetch secret value): agent-token-gated
    #     AND service-scoped via connections_agent_services. A consumer
    #     reads only its own service's connections (Hard Rule #9 least
    #     authority -- one consumer can't read another consumer's keys).
    #   - WRITES (upsert/rotate/enable/delete): operator-token-gated via
    #     capability_operator_token (v1; sister of /capability/revoke's
    #     chicken-and-egg gate). v2 layers a phone connections:set
    #     capability JWS on top.
    # ------------------------------------------------------------------

    def _connections_agent_service(self) -> str | None:
        """Authenticate an agent-token READ; return the SERVICE the agent
        may access, or None after sending the failure response.

        Gate order mirrors every other agent-gated endpoint:
        connections-disabled -> 404, missing headers -> 401, bad token ->
        401, agent-not-mapped -> 403.
        """
        cfg = self.config
        if not cfg.connections_path:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown_endpoint"})
            return None
        agent_id = self.headers.get("X-Recto-Agent-Id", "").strip()
        agent_token = self.headers.get("X-Recto-Agent-Token", "").strip()
        if not agent_id or not agent_token:
            self._send_json(HTTPStatus.UNAUTHORIZED, {
                "error": "agent_auth_required",
                "detail": "X-Recto-Agent-Id and X-Recto-Agent-Token headers required",
            })
            return None
        expected = cfg.capability_agent_tokens.get(agent_id)
        if expected is None or not _constant_time_compare(expected, agent_token):
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "agent_auth_invalid"})
            return None
        service = cfg.connections_agent_services.get(agent_id)
        if not service:
            self._send_json(HTTPStatus.FORBIDDEN, {
                "error": "agent_not_mapped",
                "detail": f"agent '{agent_id}' is not mapped to a connections service",
            })
            return None
        return service

    def _connections_key_allowed(self, service: str, key: str) -> bool:
        """Gate a secret VALUE read against the calling agent's key
        allowlist. Returns True when the read may proceed.

        Runs in one of two modes (config.connections_key_acl_enforce):
          - AUDIT (default): logs every would-be denial at WARNING and
            returns True. Used to discover the live key set before the
            gate can safely bite -- see the config docstring.
          - ENFORCE: sends 403 key_not_allowed and returns False.

        Default-deny: an agent absent from connections_agent_keys matches
        no pattern, so in ENFORCE mode it reads nothing. The caller has
        already authenticated the agent and resolved its service, so the
        agent_id header is trusted here.
        """
        cfg = self.config
        agent_id = self.headers.get("X-Recto-Agent-Id", "").strip()
        patterns = cfg.connections_agent_keys.get(agent_id) or []
        logger = logging.getLogger("recto.bootloader.connections")
        for pattern in patterns:
            if _connection_key_matches(pattern, key):
                # GATE 0b (2026-08-17). This line did not exist, and its
                # absence was structural rather than cosmetic: an ADMITTED
                # read produced NO EVIDENCE AT ALL, while an unadmitted one
                # produced the WARNING below. So the audit trail could show
                # what was MISSING from an allowlist and never what was
                # UNUSED in one — and an allowlist that cannot show its own
                # dead entries CAN ONLY EVER GROW. That is fatal to
                # least-privilege, whose entire job is removal.
                #
                # It also made the rollout unverifiable: the plan was "add
                # the measured key set, observe one window, then enforce" —
                # but the moment a key is added its reads go SILENT, so the
                # window reports nothing whether the set was right or wrong,
                # and the only feedback left is breakage in production.
                #
                # INFO, not DEBUG: this has to survive a default logging
                # configuration or it is not evidence.
                logger.info(
                    "connections key ACL: agent %r read secret %r in service %r "
                    "(admitted by pattern %r)",
                    agent_id, key, service, pattern,
                )
                return True
        if not cfg.connections_key_acl_enforce:
            logger.warning(
                "connections key ACL (AUDIT, not enforcing): agent %r read "
                "secret %r in service %r, which no allowlist pattern admits "
                "(patterns=%r). Add it to connections_agent_keys before "
                "enabling connections_key_acl_enforce.",
                agent_id, key, service, patterns,
            )
            return True
        logger.warning(
            "connections key ACL DENIED: agent %r may not read secret %r in "
            "service %r (patterns=%r).",
            agent_id, key, service, patterns,
        )
        self._send_json(HTTPStatus.FORBIDDEN, {
            "error": "key_not_allowed",
            "detail": (
                f"agent '{agent_id}' is not allowlisted to read key '{key}'"
            ),
        })
        return False

    def _connections_operator_ok(self) -> bool:
        """Gate an operator WRITE on the pre-shared operator token. Sends
        the response + returns False on failure; returns True when OK.

        Disabled (404) when connections_path OR capability_operator_token
        is unset -- an operator who hasn't wired a write token manages
        connections directly on the Windows host instead.
        """
        cfg = self.config
        if not cfg.connections_path:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown_endpoint"})
            return False
        if not cfg.capability_operator_token:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown_endpoint"})
            return False
        token = self.headers.get("X-Recto-Operator-Token", "").strip()
        if not token:
            self._send_json(HTTPStatus.UNAUTHORIZED, {
                "error": "operator_token_required",
                "detail": "X-Recto-Operator-Token header required",
            })
            return False
        if not _constant_time_compare(token, cfg.capability_operator_token):
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "operator_token_invalid"})
            return False
        return True

    def _handle_connections_list(self, url: Any) -> None:
        """GET /v0.4/connections -- secret-free metadata for the calling
        agent's service. The runtime discovery path: a consumer lists
        which connections it has + whether each carries a secret, without
        ever fetching the value.
        """
        service = self._connections_agent_service()
        if service is None:
            return
        from pathlib import Path as _Path
        from recto.connections.manage import list_connections
        rows = list_connections(_Path(self.config.connections_path), service=service)
        self._send_json(HTTPStatus.OK, {
            "service": service,
            "connections": [m.to_dict() for m in rows],
        })

    def _handle_connections_secret(self, url: Any) -> None:
        """GET /v0.4/connections/secret?key=<key> -- the secret VALUE for
        the calling agent's service + key. The runtime read path consumers
        call at call-time so a rotation takes effect with no redeploy.
        Cache-Control: no-store (callers MUST NOT cache; re-read per call).

        An UNREGISTERED key is 404 (2026-08-13). Before this, any key --
        including against an empty store -- returned 200 with value:null,
        so a consumer could not distinguish "registered, value unset
        (rotation in flight)" from "this key does not exist here": a vault
        read that lies. `required: False` at the vault fetch guards
        ABSENCE OF A VALUE, not nonsense; existence is the metadata
        store's question and is asked there. Registered-but-unset keeps
        the honest 200 has_value:false.
        """
        service = self._connections_agent_service()
        if service is None:
            return
        from urllib.parse import parse_qs
        raw_key = (parse_qs(url.query).get("key", [""])[0]).strip()
        if not raw_key:
            raise BootloaderError("key query parameter required")
        from recto.connections.manage import get_connection_secret
        from recto.connections.types import normalize_connection_key
        secret_kwargs: dict[str, Any] = {}
        if self.config.connections_secret_source_factory is not None:
            secret_kwargs["secret_source_factory"] = (
                self.config.connections_secret_source_factory
            )
        try:
            # Normalize so the echoed key is canonical (matches list output)
            # AND so a bad key shape surfaces as a clean 400 rather than a
            # vault lookup miss.
            key = normalize_connection_key(raw_key)
        except ValueError as exc:
            raise BootloaderError(str(exc)) from exc
        # Per-key allowlist (2026-07-28). Checked AFTER normalization so a
        # pattern can't be dodged by casing/whitespace, and BEFORE the
        # vault touch so a denied key is never decrypted at all.
        if not self._connections_key_allowed(service, key):
            return
        # Existence gate (2026-08-13): a key with no metadata row in this
        # service's namespace is 404, never 200+null. Consulting metadata
        # for EXISTENCE does not re-cache the VALUE -- the value read
        # below still hits the vault live, so rotation semantics are
        # untouched. An empty/missing sidecar therefore 404s every key,
        # which is the loud failure VAULT #11 was missing.
        from recto.connections.manage import get_connection_meta
        from pathlib import Path as _Path
        if get_connection_meta(
            _Path(self.config.connections_path), service, key
        ) is None:
            self._send_json(HTTPStatus.NOT_FOUND, {
                "error": "unknown_connection",
                "detail": (
                    f"no connection '{key}' registered for service "
                    f"'{service}'"
                ),
            })
            return
        try:
            value = get_connection_secret(service, key, **secret_kwargs)
        except ValueError as exc:
            raise BootloaderError(str(exc)) from exc
        self._send_json(HTTPStatus.OK, {
            "service": service,
            "key": key,
            "has_value": value is not None,
            "value": value,
        })

    def _handle_connections_upsert(self, body: dict[str, Any]) -> None:
        """POST /v0.4/connections -- operator upsert/rotate. Body carries
        the full connection; a non-empty `secret` writes/rotates the vault
        value. The operator token is the root, so the body's `service` may
        target any service. Returns the secret-free metadata.
        """
        if not self._connections_operator_ok():
            return
        service = (body.get("service") or "").strip()
        key = (body.get("key") or "").strip()
        if not service or not key:
            raise BootloaderError("service and key are required")
        config = body.get("config")
        if config is not None and not isinstance(config, dict):
            raise BootloaderError("config must be an object when present")
        from pathlib import Path as _Path
        from recto.connections.manage import set_connection
        secret_kwargs: dict[str, Any] = {}
        if self.config.connections_secret_source_factory is not None:
            secret_kwargs["secret_source_factory"] = (
                self.config.connections_secret_source_factory
            )
        try:
            meta = set_connection(
                _Path(self.config.connections_path),
                service=service,
                key=key,
                display_name=body.get("display_name"),
                category=body.get("category"),
                secret=body.get("secret"),
                config=config,
                enabled=body.get("enabled"),
                health_url=body.get("health_url"),
                **secret_kwargs,
            )
        except ValueError as exc:
            raise BootloaderError(str(exc)) from exc
        self._send_json(HTTPStatus.OK, {"connection": meta.to_dict()})

    def _handle_connections_enable(self, body: dict[str, Any]) -> None:
        """POST /v0.4/connections/enable -- operator toggle a connection
        in/out of the active fan-out. Body {service, key, enabled}.
        """
        if not self._connections_operator_ok():
            return
        service = (body.get("service") or "").strip()
        key = (body.get("key") or "").strip()
        enabled = body.get("enabled")
        if not service or not key or not isinstance(enabled, bool):
            raise BootloaderError("service, key, and boolean enabled are required")
        from pathlib import Path as _Path
        from recto.connections.manage import set_enabled
        try:
            meta = set_enabled(_Path(self.config.connections_path), service, key, enabled)
        except ValueError as exc:
            raise BootloaderError(str(exc)) from exc
        self._send_json(HTTPStatus.OK, {"connection": meta.to_dict()})

    def _handle_connections_delete(self, body: dict[str, Any]) -> None:
        """POST /v0.4/connections/delete -- operator delete (drops the
        metadata row AND the vault secret value). Body {service, key}.
        """
        if not self._connections_operator_ok():
            return
        service = (body.get("service") or "").strip()
        key = (body.get("key") or "").strip()
        if not service or not key:
            raise BootloaderError("service and key are required")
        from pathlib import Path as _Path
        from recto.connections.manage import delete_connection
        secret_kwargs: dict[str, Any] = {}
        if self.config.connections_secret_source_factory is not None:
            secret_kwargs["secret_source_factory"] = (
                self.config.connections_secret_source_factory
            )
        try:
            removed = delete_connection(
                _Path(self.config.connections_path),
                service=service,
                key=key,
                **secret_kwargs,
            )
        except ValueError as exc:
            raise BootloaderError(str(exc)) from exc
        self._send_json(HTTPStatus.OK, {
            "deleted": removed is not None,
            "connection": removed.to_dict() if removed else None,
        })

    # ------------------------------------------------------------------
    # /v0.4/user-vault/* -- Recto User Vault Substrate (2026-07-25)
    #
    # Per-USER secret storage ("bring your own key") -- the user-tier
    # sister of the connections substrate above. Same storage split
    # (secret-free metadata sidecar + secret backend for values), same
    # injectable secret-source seam, but a different auth posture:
    #
    #   ALL FOUR verbs (set / list / release / delete) are agent-token-
    #   gated AND platform-scoped via user_vault_agent_platforms, and
    #   every operation is further scoped by the X-Recto-User-Id claim
    #   the calling platform supplies. There is no operator tier here:
    #   user-vault writes are the platform acting for its OWN user at
    #   runtime (the user pasted a key into the platform's UI), so the
    #   platform's agent token is the trust anchor and the user-id
    #   claim bounds each request to one user's namespace. One platform
    #   can never touch another platform's users (agent map), and a
    #   request can never span users (single claimed id per call).
    #
    # Release-on-approval seam (Hard Rule #9): the release response
    # carries a `status` field -- "released" | "unset" today. The
    # phone-vault backend later adds "pending" / "denied" WITHOUT a
    # contract change; consumers must treat any non-"released" status
    # as value-absent and tolerate latency + denial.
    # ------------------------------------------------------------------

    def _user_vault_agent_platform(self) -> str | None:
        """Authenticate the agent token; return the PLATFORM the agent
        may operate on, or None after sending the failure response.

        Gate order mirrors _connections_agent_service: substrate
        disabled -> 404, missing headers -> 401, bad token -> 401,
        agent-not-mapped -> 403.
        """
        cfg = self.config
        if not cfg.user_vault_path:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown_endpoint"})
            return None
        agent_id = self.headers.get("X-Recto-Agent-Id", "").strip()
        agent_token = self.headers.get("X-Recto-Agent-Token", "").strip()
        if not agent_id or not agent_token:
            self._send_json(HTTPStatus.UNAUTHORIZED, {
                "error": "agent_auth_required",
                "detail": "X-Recto-Agent-Id and X-Recto-Agent-Token headers required",
            })
            return None
        expected = cfg.capability_agent_tokens.get(agent_id)
        if expected is None or not _constant_time_compare(expected, agent_token):
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "agent_auth_invalid"})
            return None
        platform = cfg.user_vault_agent_platforms.get(agent_id)
        if not platform:
            self._send_json(HTTPStatus.FORBIDDEN, {
                "error": "agent_not_mapped",
                "detail": f"agent '{agent_id}' is not mapped to a user-vault platform",
            })
            return None
        return platform

    def _user_vault_user_id(self) -> str | None:
        """Read + validate the X-Recto-User-Id scoping claim. Returns the
        normalized (lowercase GUID) user id, or None after sending the
        failure response. The header travels on every user-vault call --
        a claim the AUTHENTICATED platform supplies, scoping the request
        to exactly one user's namespace."""
        raw = self.headers.get("X-Recto-User-Id", "").strip()
        if not raw:
            self._send_json(HTTPStatus.BAD_REQUEST, {
                "error": "user_id_required",
                "detail": "X-Recto-User-Id header required",
            })
            return None
        from recto.user_vault.types import normalize_user_id
        try:
            return normalize_user_id(raw)
        except ValueError:
            self._send_json(HTTPStatus.BAD_REQUEST, {
                "error": "user_id_invalid",
                "detail": "X-Recto-User-Id must be a GUID",
            })
            return None

    def _user_vault_secret_kwargs(self) -> dict[str, Any]:
        if self.config.user_vault_secret_source_factory is not None:
            return {
                "secret_source_factory": (
                    self.config.user_vault_secret_source_factory
                )
            }
        return {}

    def _handle_user_vault_list(self, url: Any) -> None:
        """GET /v0.4/user-vault -- secret-free metadata for the claimed
        user within the calling platform. NEVER values; `has_secret` is
        the only signal a value exists."""
        platform = self._user_vault_agent_platform()
        if platform is None:
            return
        user_id = self._user_vault_user_id()
        if user_id is None:
            return
        from pathlib import Path as _Path
        from recto.user_vault.manage import list_user_entries
        rows = list_user_entries(
            _Path(self.config.user_vault_path), platform, user_id
        )
        self._send_json(HTTPStatus.OK, {
            "platform": platform,
            "user_id": user_id,
            "entries": [m.to_dict() for m in rows],
        })

    def _handle_user_vault_release(self, url: Any) -> None:
        """GET /v0.4/user-vault/release?key=<key> -- the secret VALUE for
        the claimed user's entry, released to the platform's own call
        path at call time (rotation takes effect with no redeploy).
        Cache-Control: no-store (callers MUST NOT cache; re-read per call).

        Response contract (pre-cut for phone release-on-approval):
        status "released" carries the value; "unset" carries null; the
        future phone-vault backend adds "pending"/"denied" with null.
        """
        platform = self._user_vault_agent_platform()
        if platform is None:
            return
        user_id = self._user_vault_user_id()
        if user_id is None:
            return
        from urllib.parse import parse_qs
        raw_key = (parse_qs(url.query).get("key", [""])[0]).strip()
        if not raw_key:
            raise BootloaderError("key query parameter required")
        from recto.user_vault.manage import release_user_secret
        from recto.user_vault.types import normalize_user_vault_key
        try:
            key = normalize_user_vault_key(raw_key)
            value = release_user_secret(
                platform, user_id, key, **self._user_vault_secret_kwargs()
            )
        except ValueError as exc:
            raise BootloaderError(str(exc)) from exc
        self._send_json(HTTPStatus.OK, {
            "platform": platform,
            "user_id": user_id,
            "key": key,
            "status": "released" if value is not None else "unset",
            "has_value": value is not None,
            "value": value,
        })

    def _handle_user_vault_set(self, body: dict[str, Any]) -> None:
        """POST /v0.4/user-vault/set -- create/rotate the claimed user's
        entry. Body {key, display_name?, category?, secret?}. A non-empty
        `secret` writes/rotates the value; None/empty updates metadata
        only, preserving the value. Returns the secret-free metadata."""
        platform = self._user_vault_agent_platform()
        if platform is None:
            return
        user_id = self._user_vault_user_id()
        if user_id is None:
            return
        key = (body.get("key") or "").strip()
        if not key:
            raise BootloaderError("key is required")
        secret = body.get("secret")
        if secret is not None and not isinstance(secret, str):
            raise BootloaderError("secret must be a string when present")
        from pathlib import Path as _Path
        from recto.user_vault.manage import set_user_entry
        try:
            meta = set_user_entry(
                _Path(self.config.user_vault_path),
                platform=platform,
                user_id=user_id,
                key=key,
                display_name=body.get("display_name"),
                category=body.get("category"),
                secret=secret,
                **self._user_vault_secret_kwargs(),
            )
        except ValueError as exc:
            raise BootloaderError(str(exc)) from exc
        self._send_json(HTTPStatus.OK, {"entry": meta.to_dict()})

    def _handle_user_vault_delete(self, body: dict[str, Any]) -> None:
        """POST /v0.4/user-vault/delete -- remove the claimed user's
        entry (metadata AND value). Idempotent. Body {key}."""
        platform = self._user_vault_agent_platform()
        if platform is None:
            return
        user_id = self._user_vault_user_id()
        if user_id is None:
            return
        key = (body.get("key") or "").strip()
        if not key:
            raise BootloaderError("key is required")
        from pathlib import Path as _Path
        from recto.user_vault.manage import delete_user_entry
        try:
            removed = delete_user_entry(
                _Path(self.config.user_vault_path),
                platform=platform,
                user_id=user_id,
                key=key,
                **self._user_vault_secret_kwargs(),
            )
        except ValueError as exc:
            raise BootloaderError(str(exc)) from exc
        self._send_json(HTTPStatus.OK, {
            "deleted": removed is not None,
            "entry": removed.to_dict() if removed else None,
        })

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _read_json_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise BootloaderError(f"invalid JSON body: {exc}") from exc
        if not isinstance(data, dict):
            raise BootloaderError("body must be a JSON object")
        return data

    def _send_json(self, status: HTTPStatus, body: dict[str, Any]) -> None:
        payload = json.dumps(body, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: Any) -> None:
        # Override default stderr logging to use Recto's logging
        # convention. The bootloader runs as a service; default
        # http.server logging would flood AppStdout.
        # For v0.4.0 we silently drop access logs; v0.4.1+ adds a
        # configurable access log path.
        return


def create_server(
    *,
    bind_host: str,
    bind_port: int,
    state: StateStoreBase,
    bootloader_id: str | None = None,
    challenges: ChallengeStore | None = None,
    notify_resolved_fn: Any = None,
    ssl_context: Any = None,
    capability_agent_tokens: dict[str, str] | None = None,
    capability_agent_requestable: dict[str, list[str]] | None = None,
    capability_operator_pubkey: bytes | None = None,
    capability_result_ttl_seconds: int = 600,
    capability_manifest: object | None = None,
    capability_manifest_path: str | None = None,
    capability_vault_secrets: dict[tuple[str, str], str] | None = None,
    capability_revocation_jtis: set[str] | None = None,
    capability_operator_token: str | None = None,
    principal_apps: dict[str, AppContext] | None = None,
    devices_pair_consumer_webhook_tokens: dict[str, str] | None = None,
    devices_pair_consumer_relay_urls: dict[str, str] | None = None,
    devices_pair_consumer_timeout_seconds: float = 15.0,
    connections_path: str | None = None,
    connections_agent_services: dict[str, str] | None = None,
    connections_agent_keys: dict[str, list[str]] | None = None,
    # MUST stay in lockstep with BootloaderConfig.connections_key_acl_enforce.
    # These are two statements of one value: create_server unconditionally
    # assigns this onto the config below, so the dataclass default never
    # applies and a disagreement here silently wins. Flipping only the
    # dataclass on 2026-08-09 left the enforcing default INERT until this
    # line was found -- the same duplicated-value defect the tree has now
    # been bitten by three times in one day.
    connections_key_acl_enforce: bool = True,
    connections_secret_source_factory: Any = None,
    user_vault_path: str | None = None,
    user_vault_agent_platforms: dict[str, str] | None = None,
    user_vault_secret_source_factory: Any = None,
    push_dispatcher: Any = None,
    public_urls: tuple[str, ...] | list[str] | None = None,
    clusters_registry_path: str | None = None,
    clusters_projection_path: str | None = None,
    clusters_spawn_token: str | None = None,
    clusters_lease_ttl_seconds: int = 180,
    signed_poll_mode: str = "advisory",
) -> ThreadingHTTPServer:
    """Construct (but do not start) a bootloader HTTPServer.

    Caller is responsible for `server.serve_forever()` and shutdown.
    The handler class is mutated with the runtime config; if you need
    multiple bootloaders in the same process (rare), copy
    BootloaderHandler and pass that copy to a fresh ThreadingHTTPServer.

    `ssl_context` is an `ssl.SSLContext` already loaded with the cert
    chain. None means HTTP (NOT recommended; useful only for tests).

    `capability_agent_tokens` is a map of agent_id -> bearer token
    that gates the Phase 5 Wave B `/v0.4/capability/request` and
    `/v0.4/capability/result/<id>` endpoints. When None or empty,
    those endpoints return 404 — bootloaders that don't issue
    capabilities to external agents leave it unset.

    `capability_agent_requestable` is an optional per-agent policy on
    what may be ASKED: agent_id -> list of requestable action keys.
    An agent with an entry is deny-by-default — a capability request
    whose resolved action set strays outside the list is refused 403
    before it is ever queued (no card reaches the operator). Agents
    without an entry are unrestricted at this layer. Requires
    `capability_manifest` to be loaded if policed agents send
    group-bearing claims (groups are refused unexpanded, fail-closed).

    `capability_operator_pubkey` is the operator's expected secp256k1
    pubkey (uncompressed 64-byte X || Y, no 0x04 prefix). When set,
    the bootloader cross-checks every approved capability JWS by
    recovering the signature and confirming it matches this key
    before storing the assembled JWS for agent fetch. Production
    deployments MUST set this; dev / test deployments may leave it
    None and rely on the Ed25519 paired-phone envelope alone.

    `capability_result_ttl_seconds` is how long resolved capability
    results sit in the bootloader's in-memory store waiting for the
    agent to fetch them. Default 600s (10 min); raise for bursty
    fan-outs that may delay polling.

    `capability_manifest` is a pre-loaded
    ``recto.capability.types.ActionManifest`` instance the bootloader
    will serve at ``GET /v0.4/capability/manifest`` and use for
    scope-evaluation in ``POST /v0.4/secrets/read``. Mutually
    exclusive with `capability_manifest_path`; if both are passed,
    `capability_manifest` wins.

    `capability_manifest_path` is a path to a manifest JSON file that
    `create_server` loads at startup via
    ``recto.capability.manifest.load_manifest``. Convenience for
    deployments that ship a manifest file rather than constructing
    the dataclass programmatically.

    `capability_vault_secrets` is a pre-populated map of
    ``(service, secret_name) -> value`` exposing secrets via the
    capability-gated ``POST /v0.4/secrets/read`` endpoint. Empty /
    None means the endpoint returns 404 -- bootloaders that don't
    expose vault secrets via HTTP have zero attack surface. v1
    keeps the secret-resolution chain in the launcher's existing
    flow; v2 will wire the bootloader directly to
    ``recto.secrets.SecretSource`` implementations.

    `capability_revocation_jtis` (test-convenience kwarg) is the
    set of revoked JWT jti values the bootloader will pre-seed into
    the StateStore at startup. Wave C part 2 moved the source-of-
    truth from an in-memory set to the StateStore's persistent
    revocation list (revocations.json); this kwarg now seeds the
    StateStore with synthetic RevocationEntry rows so tests that
    pre-populate revocations don't have to write JSON files
    themselves. Production deployments add revocations via
    `POST /v0.4/capability/revoke` instead, which survives
    bootloader restart.

    `capability_operator_token` is the pre-shared bearer token the
    `POST /v0.4/capability/revoke` endpoint requires (operators
    pass it via `X-Recto-Operator-Token` header). When None /
    empty, the revoke endpoint returns 404 -- bootloaders that
    don't expose revocation via HTTP can run revocation entirely
    operator-side via direct StateStore writes (or via Wave D's
    phone-mediated flow when that ships).

    `principal_apps` (Wave C part 3) is the operator-administered
    registry of `AppContext` entries keyed by principal-id. The
    bootloader injects the matching AppContext into every
    PendingRequest at queue time so the phone can show the app's
    icon + name + description at the top of the approval card. Look-
    up order: cap_agent_id (capability_request) -> service-name
    (other phone-rendered kinds). None / empty disables app-context
    injection entirely; PendingRequests carry app_context=None and
    the phone shows an "Unknown app" warning banner.
    """
    server = ThreadingHTTPServer((bind_host, bind_port), BootloaderHandler)
    if ssl_context is not None:
        server.socket = ssl_context.wrap_socket(server.socket, server_side=True)
    BootloaderHandler.config = BootloaderConfig()
    BootloaderHandler.config.bootloader_id = (
        bootloader_id if bootloader_id is not None else str(uuid.uuid4())
    )
    BootloaderHandler.config.state = state
    BootloaderHandler.config.challenges = (
        challenges if challenges is not None else ChallengeStore(state=state)
    )
    if notify_resolved_fn is not None:
        BootloaderHandler.config.notify_resolved_fn = notify_resolved_fn  # type: ignore[attr-defined]
    BootloaderHandler.config.capability_agent_tokens = (
        dict(capability_agent_tokens) if capability_agent_tokens else {}
    )
    BootloaderHandler.config.capability_agent_requestable = (
        {k: list(v) for k, v in capability_agent_requestable.items()}
        if capability_agent_requestable
        else {}
    )
    # GATE 5a -- OPERATOR IMMUTABILITY: DISAGREEMENT IS FATAL (2026-08-18).
    #
    # THIS BLOCK USED TO SAY: "Explicit kwarg still wins -- backward compat for
    # deployments that pass the pubkey directly." The persisted value was a
    # FALLBACK. That precedence is exactly backwards for a trust root.
    #
    # THE TAKEOVER IT ALLOWED, and it needed no stolen device:
    # `capability_operator_pubkey` is constructor config, re-read on EVERY
    # start. A launcher passing a different key silently replaced the operator
    # -- no signature, no chain entry, no trace, no restart barrier. WHOEVER
    # CONTROLLED THE DEPLOY CONTROLLED THE OPERATOR. The sealed vault_root.json
    # sat right there and was consulted only when nothing else was offered.
    #
    # "Backward compat for deployments that pass the pubkey directly" is the
    # reason the old comment gave. It is A CONVENIENCE THAT OUTLIVED ITS
    # PURPOSE, and that is the whole class: an exception granted for a real
    # reason, never given an expiry, still standing long after the reason
    # died. Nothing failed, so nothing surfaced it.
    #
    # THE RULE (brief S OPERATOR IMMUTABILITY, operator 2026-08-17):
    # "On disagreement between config and sealed state the bootloader REFUSES
    #  TO START. Disagreement is fatal, never an update."
    #
    # Four cases; only the last changes behaviour:
    #   sealed, no kwarg      -> sealed wins          (unchanged)
    #   no sealed, kwarg      -> kwarg, LOUD WARNING  (first boot, pre-seal)
    #   sealed + kwarg AGREE  -> fine                 (unchanged)
    #   sealed + kwarg DIFFER -> REFUSE TO START      <-- the takeover path
    #
    # Membership changes ride a signature from the current set, chained to
    # genesis. That is the ONLY mutation path. Not a kwarg. Not a restart.
    _sealed_operator_pubkey = state.get_operator_pubkey()
    if capability_operator_pubkey is None:
        capability_operator_pubkey = _sealed_operator_pubkey
    elif _sealed_operator_pubkey is None:
        # Legitimate first boot: the vault has not been bootstrapped yet.
        # Permitted, but never quietly -- an unsealed trust root is a window,
        # and a window nobody is told about stays open.
        logging.getLogger("recto.bootloader.operator").warning(
            "operator pubkey supplied by CONFIG with NO SEALED VALUE in the "
            "state dir. This is only correct on a bootloader that has never "
            "been bootstrapped. Run `recto vault bootstrap <hex>` to seal it; "
            "until then the trust root can be replaced by anyone who can "
            "change how this process is launched."
        )
    elif _sealed_operator_pubkey != capability_operator_pubkey:
        raise BootloaderError(
            "REFUSING TO START: the operator pubkey in config disagrees with "
            "the value sealed in this bootloader's vault_root.json. "
            f"sealed={_sealed_operator_pubkey.hex()[:16]}... "
            f"config={capability_operator_pubkey.hex()[:16]}... "
            "The sealed value is the trust root and config cannot replace it. "
            "Changing the operator is not a restart -- it is an act signed by "
            "the current set and chained to genesis. If the sealed value is "
            "genuinely wrong, that is a vault operation performed deliberately "
            "with the machine key, never a launcher argument."
        )
    BootloaderHandler.config.capability_operator_pubkey = capability_operator_pubkey
    BootloaderHandler.config.capability_result_ttl_seconds = capability_result_ttl_seconds

    # GATE 5b -- FLIP. THE DERIVED ID IS NOW THE IDENTITY. (2026-08-19)
    #
    # `bootloader_id` IS THE JWT AUDIENCE (`verify_jwt(..., audience=...)`).
    # Until now it was handed in by config, or failing that A FRESH RANDOM UUID
    # PER PROCESS -- so an unconfigured bootloader silently invalidated every
    # token it had ever issued on each restart. Neither form was derived from
    # anything, which made the id A NAME THE PHONE WAS TOLD rather than a claim
    # the phone could check. A look-alike deployment at any hostname could
    # assert any id and be believed.
    #
    # DERIVED, THE ID BECOMES EVIDENCE: recomputed from the operator key set,
    # so a mismatch is ARITHMETIC rather than the operator noticing a hostname
    # looks off. (This is also why the hostname question dissolved -- the app
    # carries no compiled-in host at all; the right target was never "which
    # name" but that the phone should not trust a name.)
    #
    # === CONFIG IS NOT CONSULTED WHEN SEALED, AND THAT IS STRONGER THAN
    # === REFUSING TO START.
    #
    # GATE 5a refuses when config and the sealed operator pubkey DISAGREE,
    # because there both values were candidates for the same slot and picking
    # either would have left a launcher able to probe. **Here there is only ONE
    # candidate.** The id is a function of the sealed key; a config
    # `bootloader_id` is not a competing value, it is a value with nowhere to
    # go. Ignoring it is not a fail-open -- it makes the setting INERT, which
    # is a stronger property than refusing on disagreement.
    #
    # It is also what lets this ship WITHOUT a coordinated compose change:
    # a deployment may still set RECTO_BOOTLOADER_ID to whatever it always
    # set, and that value simply stops mattering. **A disagreeing config is
    # reported at
    # WARNING, because it means something in the estate believes a false thing
    # about this bootloader's identity** -- inert is not the same as harmless.
    #
    # UNSEALED IS UNCHANGED: no sealed pubkey -> config, else random UUID.
    # GATE 5a already owns the alarm for an unsealed trust root; this block
    # does not raise a second one for the same fact.
    _configured_id = BootloaderHandler.config.bootloader_id
    _id_log = logging.getLogger("recto.bootloader.identity")
    try:
        _phone_count = len(state.list_phones())
    except Exception:
        _phone_count = -1
    # Reset the snapshot FIRST: config is a class attribute, so without this
    # an unsealed create_server in the same process would inherit the inputs
    # of a previously created sealed one -- an id-less server describing a
    # dead id.
    BootloaderHandler.config.bootloader_identity_inputs = None
    # GATE 5b, the SET half: sealed genesis members of the
    # identity kinds join the derivation, so enrolling the recovery phone
    # CHANGES the id -- the "new bootloader" is born by arithmetic when the
    # set changes, not by anyone renaming anything. Today, with only the
    # passphrase sealed (a quorum member, not identity), the contribution is
    # empty and the id is unchanged -- deliberate: no identity churn before
    # the enrolment ceremony.
    try:
        _members_full = state.list_genesis_members_full()
    except Exception:
        _members_full = {}
    _identity_member_pubkeys, _excluded_kinds = collect_identity_member_pubkeys(
        _members_full
    )
    if _excluded_kinds:
        _id_log.info(
            "GATE 5b: sealed member kind(s) NOT part of the identity "
            "derivation (quorum-only, by the IDENTITY_MEMBER_KINDS "
            "allowlist): %s",
            ", ".join(_excluded_kinds),
        )
    try:
        _derived_id = derive_bootloader_id(
            capability_operator_pubkey, _identity_member_pubkeys
        )
    except ValueError:
        _id_log.info(
            "GATE 5b: bootloader_id=%r NOT DERIVED -- no sealed operator "
            "pubkey (see GATE 5a). registered_phones=%d",
            _configured_id, _phone_count,
        )
    else:
        BootloaderHandler.config.bootloader_id = _derived_id
        # The inputs that produced the id, snapshotted with it -- emitted to
        # phones at registration so the id is a recomputable claim.
        def _ident_b64u(b: bytes) -> str:
            return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")
        BootloaderHandler.config.bootloader_identity_inputs = {
            "derivation": BOOTLOADER_ID_DERIVATION_V1,
            "operator_pubkey_b64u": _ident_b64u(capability_operator_pubkey),
            "member_pubkeys_b64u": [
                _ident_b64u(k) for k in _identity_member_pubkeys
            ],
        }
        if _configured_id and _configured_id != _derived_id:
            _id_log.warning(
                "GATE 5b: config supplied bootloader_id=%r, which is NOT this "
                "bootloader's identity and has been IGNORED. The identity is "
                "DERIVED from the sealed operator key set: %r. Anything still "
                "using the configured name believes something false about this "
                "bootloader. Tokens minted for the old audience will no longer "
                "verify -- affected registered phones: %d (they must re-pair).",
                _configured_id, _derived_id, _phone_count,
            )
        else:
            _id_log.info(
                "GATE 5b: bootloader_id=%r DERIVED from operator=%s. "
                "registered_phones=%d",
                _derived_id,
                capability_operator_pubkey.hex()[:16] + "...",
                _phone_count,
            )
    # WHY registered_phones IS REPORTED BUT NOT CONSUMED BY THE DERIVATION: an
    # id computed over "every phone registered right now" would rotate -- and
    # invalidate every outstanding JWT -- on EVERY enrolment. The genesis set
    # must be FIXED AT GENESIS and sealed, never recomputed from live
    # registrations. Today the derivation takes the operator key alone; the
    # count is logged because it is exactly the number of devices a flip costs.

    # Manifest: in-memory wins over path; if both unset, leave None
    # (manifest endpoint returns 404 + secret-read endpoint returns
    # 503 when called).
    if capability_manifest is not None:
        BootloaderHandler.config.capability_manifest = capability_manifest
    elif capability_manifest_path is not None:
        from recto.capability.manifest import load_manifest as _load_manifest
        BootloaderHandler.config.capability_manifest = _load_manifest(capability_manifest_path)
    else:
        BootloaderHandler.config.capability_manifest = None

    BootloaderHandler.config.capability_vault_secrets = (
        dict(capability_vault_secrets) if capability_vault_secrets else {}
    )
    # Wave C part 2: capability_revocation_jtis is now a TEST-CONVENIENCE
    # SEED rather than the source-of-truth. When provided, populate the
    # StateStore's persistent revocation list with synthetic
    # RevocationEntry rows so tests that pre-stage revocations don't
    # have to write JSON files themselves. Production paths use
    # POST /v0.4/capability/revoke which goes through the same
    # StateStore.add_revocation method and survives bootloader restart.
    BootloaderHandler.config.capability_revocation_jtis = (
        set(capability_revocation_jtis) if capability_revocation_jtis else set()
    )
    if capability_revocation_jtis:
        # Seed with a generous original_exp_unix (now + 1 year) so the
        # synthetic test entries don't auto-prune mid-test. Real entries
        # carry the actual JWT exp.
        seed_exp = int(time.time()) + 365 * 86400
        seed_now = int(time.time())
        for jti in capability_revocation_jtis:
            state.add_revocation(RevocationEntry(
                jti=jti,
                revoked_at_unix=seed_now,
                original_exp_unix=seed_exp,
                reason="test-convenience seed via create_server",
            ))
    BootloaderHandler.config.capability_operator_token = capability_operator_token
    BootloaderHandler.config.principal_apps = (
        dict(principal_apps) if principal_apps else {}
    )
    # Phase H end-user device pairing relay (2026-05-19). Empty dict
    # leaves the new /v0.4/devices/pair endpoint disabled (returns 404).
    BootloaderHandler.config.devices_pair_consumer_webhook_tokens = (
        dict(devices_pair_consumer_webhook_tokens)
        if devices_pair_consumer_webhook_tokens
        else {}
    )
    BootloaderHandler.config.devices_pair_consumer_relay_urls = (
        dict(devices_pair_consumer_relay_urls)
        if devices_pair_consumer_relay_urls
        else {}
    )
    BootloaderHandler.config.devices_pair_consumer_timeout_seconds = (
        devices_pair_consumer_timeout_seconds
    )
    # Recto Connections Substrate (2026-06-13). Empty/None connections_path
    # leaves all /v0.4/connections/* endpoints disabled (404). The agent->
    # service read map and the operator write token (capability_operator_token,
    # already wired above) together gate the read/write split.
    BootloaderHandler.config.connections_path = connections_path
    BootloaderHandler.config.connections_agent_services = (
        dict(connections_agent_services) if connections_agent_services else {}
    )
    BootloaderHandler.config.connections_agent_keys = (
        {k: list(v) for k, v in connections_agent_keys.items()}
        if connections_agent_keys
        else {}
    )
    BootloaderHandler.config.connections_key_acl_enforce = bool(
        connections_key_acl_enforce
    )
    BootloaderHandler.config.connections_secret_source_factory = (
        connections_secret_source_factory
    )
    # Cluster registry. None registry path leaves every
    # /v0.5/clusters/* endpoint disabled (404) -- the agent-facing
    # deployment never sets it; the registry-writer deployment sets it
    # (plus the write token) and configures nothing agent-facing.
    if clusters_registry_path:
        BootloaderHandler.config.clusters_registry = ClusterRegistry(
            clusters_registry_path,
            projection_path=clusters_projection_path,
            default_lease_ttl_seconds=clusters_lease_ttl_seconds,
        )
    else:
        BootloaderHandler.config.clusters_registry = None
    BootloaderHandler.config.clusters_spawn_token = clusters_spawn_token
    # Startup posture for the per-key ACL, logged once so a deployment's
    # actual stance is visible in the boot log rather than inferred from
    # config. FOUR shapes worth naming: audit-only (gate present, not
    # biting), enforcing-with-EMPTY-allowlist (nothing is readable at all),
    # enforcing-with-wildcard (a named agent opted out), and the quiet good
    # case (enforcing, populated, no wildcards) which says nothing.
    if connections_path:
        _acl_log = logging.getLogger("recto.bootloader.connections")
        _wildcarded = sorted(
            agent_id
            for agent_id, patterns in
            BootloaderHandler.config.connections_agent_keys.items()
            if any((p or "").strip() == "*" for p in patterns)
        )
        if not BootloaderHandler.config.connections_key_acl_enforce:
            _acl_log.warning(
                "connections per-key ACL is in AUDIT mode: secret reads "
                "outside an agent's allowlist are LOGGED BUT ALLOWED. Set "
                "connections_key_acl_enforce=True once the logs show the "
                "live key set."
            )
        elif not BootloaderHandler.config.connections_agent_keys:
            # The fresh-install shape, and the whole reason the enforcing
            # default is safe to ship: default-deny plus an empty allowlist
            # means EVERY secret read is refused. That is correct, and on its
            # own it is indistinguishable from a broken bootloader -- so it
            # says its own name at startup rather than being diagnosed later
            # from a pile of 403s.
            _acl_log.warning(
                "connections per-key ACL is ENFORCING and connections_agent_keys "
                "is EMPTY: every secret read will be refused with 403 "
                "key_not_allowed. This is fail-closed, not a fault. Populate "
                "connections_agent_keys, or set connections_key_acl_enforce=False "
                "to run AUDIT mode and discover the live key set from the logs."
            )
        elif _wildcarded:
            _acl_log.warning(
                "connections per-key ACL is enforcing, but these agents "
                "carry the '*' allow-all escape hatch and can read every "
                "secret in their service: %s",
                ", ".join(_wildcarded),
            )
    # Recto User Vault Substrate (2026-07-25). Empty/None user_vault_path
    # leaves all /v0.4/user-vault/* endpoints disabled (404). All four
    # verbs are agent-gated + platform-scoped via the agent->platform map,
    # then user-scoped by the per-request X-Recto-User-Id claim.
    BootloaderHandler.config.user_vault_path = user_vault_path
    BootloaderHandler.config.user_vault_agent_platforms = (
        dict(user_vault_agent_platforms) if user_vault_agent_platforms else {}
    )
    BootloaderHandler.config.user_vault_secret_source_factory = (
        user_vault_secret_source_factory
    )
    # Silent-push wake dispatcher (wave C). None = poll-only. Build via
    # recto.bootloader.push.PushDispatcher([ApnsPushSender(...),
    # FcmPushSender(...)]); provider credentials (APNs .p8 key, FCM
    # service-account JSON) resolve through a SecretSource, never
    # inline config.
    BootloaderHandler.config.push_dispatcher = push_dispatcher
    # Multi-URL failover list emitted at registration (primary first).
    # Empty/None keeps the registration response byte-identical to v1.
    BootloaderHandler.config.public_urls = (
        tuple(public_urls) if public_urls else ()
    )
    # Signed-poll enforcement mode (2026-08-13, phone_id split).
    # Validated here so a typo'd config fails at startup, loudly, not
    # at first poll: an enforcement mode that silently falls back to a
    # default is a boundary nobody chose.
    if signed_poll_mode not in SIGNED_POLL_MODES:
        raise ValueError(
            f"signed_poll_mode must be one of {SIGNED_POLL_MODES}; "
            f"got {signed_poll_mode!r}"
        )
    BootloaderHandler.config.signed_poll_mode = signed_poll_mode
    _poll_log = logging.getLogger("recto.bootloader.signed_polls")
    if signed_poll_mode == "advisory":
        _poll_log.info(
            "signed_poll_mode=advisory: possession-of-phone_id reads are "
            "ALLOWED and each poll's verdict (signed-valid / "
            "signed-invalid / unsigned) is logged. Flip to 'required' "
            "once the evidence window shows every live phone signing."
        )
    elif signed_poll_mode == "off":
        _poll_log.info(
            "signed_poll_mode=off: poll signatures are not processed."
        )
    return server
