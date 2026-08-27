"""
Capability-JWT type definitions — Phase 5 Wave A foundation.

Dataclass scaffolds for the JWT claim shape and the capability action
manifest. JWT mint / verify functions land in a follow-on commit; this
file establishes the data contract that mint / verify / phone-side UI
all share.

Design reference: project-memory section "Phase 5 capability-JWT schema
design (drafted 2026-05-05)".

Hard rules in play:
  - #9: phone enclave is generic capability provider; agents inherit
    from humans. Capabilities NEVER bypass operator-issued scope.
  - Constant string keys, NOT enums (operator's call 2026-05-05):
    action and group identifiers are unique strings registered in the
    manifest. New actions register without touching code; no enum
    drift between Recto / consumer-side / phone-side.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Capability claim shape (the JWT payload)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CapabilityScope:
    """Resource-bounding for a capability. Narrows the tier defaults.

    `env` / `services` / `repos` are allow-lists; empty list means "no
    restriction at this dimension" (rare — most capabilities scope all
    three).

    `create_for_owner` (added 2026-05-17) is the canonical scope-extension
    field for the `agents:create` action class. Per the consumer's
    architectural commitment #9 (every agent-creation is capability-
    bounded), the operator pins the owner Guid that the new agent's
    `OwnerUserId` resolves to at phone-tap time. Optional + frozen at
    None when unset; the verifier-side reads this back via raw JWS-
    payload re-parse to extract the canonical owner.

    `chat_room_id` (added 2026-05-17 evening Phase F) is the canonical
    scope-extension field for the `chat:post_reply` action class. Binds
    the JWS to a specific ChatRoom Guid — without the binding, an agent
    could redirect an approved reply to a different room than the operator
    approved. The consumer's agent-reply verifier reads this
    back via raw JWS-payload re-parse (same pattern as create_for_owner)
    and rejects any room-target mismatch with a structured 403.

    `target_user_id` (added 2026-05-19 Phase F follow-on / first smoke
    of `chat:promote_user_to_tier_1`) is the canonical scope-extension
    field for the `chat:promote_user_to_tier_*` + `chat:demote_to_tier_0`
    action family. Binds the JWS to a SPECIFIC user being promoted (or
    demoted) — without the binding, a compromised agent could redirect
    an approved promotion JWS to promote a different user than the
    operator approved. The consumer's tier-promotion
    verifier reads this back via raw JWS-payload re-parse (same pattern
    as `chat_room_id` and `create_for_owner`) and rejects any
    user-target mismatch with a structured 403.

    `pairing_code` (added 2026-05-19 night Phase H phone-side smoke /
    first end-user "Pair a service" round-trip) is the canonical scope-
    extension field for the `devices:pair` action. Binds the JWS to a
    SPECIFIC 8-char pairing code the user typed in the phone's "Pair a
    service" surface — without the binding, a leaked JWS could be
    replayed against a different pairing code than the operator
    approved. The consumer's pairing-completion verifier
    reads this back via raw JWS-payload re-parse (same pattern as
    `target_user_id` / `chat_room_id` / `create_for_owner`) and rejects
    any code-target mismatch with a structured 403. Distinct from the
    other `cap:*` scope fields in that it carries a SHORT human-typed
    code rather than a Guid — both Recto Phone's payload assembly +
    the consumer's verifier treat it as an opaque case-preserving string;
    the consumer mints + validates the code's alphabet on its own side.

    Per the per-action canonical scope-extension pattern banked
    2026-05-18: each `chat:*` action declares its own canonical scope
    field naming the entity the action bounds to —
    `chat:post_reply → chat_room_id`,
    `chat:promote_user_to_tier_1 → target_user_id`,
    reserved future `chat:promote_user_to_tier_2 → target_user_id`,
    `chat:demote_to_tier_0 → target_user_id`,
    `chat:cite_message → target_message_id + chat_room_id pair`.
    Phase H extension: `devices:pair → pairing_code`.

    Future scope extensions follow the same pattern: add a new
    `str | None = None` field here, parse it in `_dict_to_claims`,
    let `_claims_to_dict` recursively strip None values so unset
    fields don't appear in the JSON (preserves byte-parity with
    existing pinned-fixture tests).
    """

    env: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    repos: list[str] = field(default_factory=list)
    create_for_owner: str | None = None
    chat_room_id: str | None = None
    target_user_id: str | None = None
    pairing_code: str | None = None

    # `payload_sha256` (added 2026-08-25) is the canonical scope-extension
    # field for push/task-approval action classes: the SHA-256 hex
    # fingerprint of the EXACT execution payload the operator approved.
    # Binds the JWS to one specific pending change — without it, an
    # approval names only a repo, and a repo-wide grant could be replayed
    # onto a different change than the operator saw on the card. The
    # consumer-side executor recomputes the fingerprint from its own
    # record at run time and refuses on mismatch (same read-back pattern
    # as create_for_owner / chat_room_id). Optional + None-omitted like
    # every scope extension.
    payload_sha256: str | None = None


@dataclass(frozen=True)
class CapabilityLimits:
    """Rate-limit constraints. Verifier enforces these per-capability.

    Keys are constant-string action / metric identifiers (matching the
    manifest's action keys). Values are integer limits over the named
    window. Missing keys mean "no limit on that metric".
    """

    per_hour: dict[str, int] = field(default_factory=dict)
    per_day: dict[str, int] = field(default_factory=dict)
    per_session: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class CapabilityClause:
    """The `cap` claim in a capability JWT.

    Hybrid scope expression (Option C, locked 2026-05-05):
      - `tier` provides default behavior
      - `groups` is the list of group identifiers (manifest-resolved
        to action sets)
      - `scope` narrows the tier defaults to specific env / services
        / repos
      - `allow_actions` adds beyond tier defaults (raw action keys)
      - `deny_actions` subtracts narrower than tier defaults
      - `limits` carries rate-limit constraints
      - `registry_version` pins which manifest version this capability
        was issued against
    """

    tier: int
    registry_version: str
    groups: list[str] = field(default_factory=list)
    scope: CapabilityScope = field(default_factory=CapabilityScope)
    allow_actions: list[str] = field(default_factory=list)
    deny_actions: list[str] = field(default_factory=list)
    limits: CapabilityLimits = field(default_factory=CapabilityLimits)


@dataclass(frozen=True)
class CapabilityClaims:
    """Full JWT payload. Standard claims (RFC 7519) + custom Recto claims.

    Standard:
      - iss: who minted this capability (always 'phone:erik:enclave'
        in v1)
      - sub: who this capability is issued TO (e.g.
        'agent:darwin@staging')
      - aud: which consumers should accept this (list)
      - iat / nbf / exp: standard time bounds
      - jti: unique JWT ID for revocation lookup

    Custom:
      - cap: the actual capability scope (CapabilityClause)
      - purpose: human-readable description for audit
      - parent_cap: jti of the parent capability if this is a
        delegated child (None for top-level operator-issued caps)
      - max_uses: single-use vs reusable (None = reusable)
      - parent_profile: v2.0 forward-compat slot. When present, the
        JWS is signed by the named child profile's BIP-32-derived
        key (NOT the master root key directly). Verifier extension
        (v2.0+) validates that the named profile is non-revoked
        under the master that owns the claim's ``iss`` field; the
        signature must recover to the profile's derived pubkey, not
        the master pubkey. Absent at v1.x — single-identity-mode
        claims recover to the master pubkey directly (backward-
        compat per Hard Rule #1). Reserved here so v1.x consumers
        can write conditional code paths (e.g. "if claims.parent_profile
        is None, run the v1.x verifier; else fail-loud until the
        v2.0 verifier extension is wired in"). See
        ``recto/profile/types.py``'s
        ``CAPABILITY_CLAIM_FIELD_PARENT_PROFILE`` constant for the
        canonical field-name reservation.
    """

    iss: str
    sub: str
    aud: list[str]
    iat: int
    nbf: int
    exp: int
    jti: str
    cap: CapabilityClause
    purpose: str
    parent_cap: str | None = None
    max_uses: int | None = None
    parent_profile: str | None = None


# ---------------------------------------------------------------------------
# Capability action manifest (the registry that lives in the vault)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ActionDefinition:
    """A single action in the registry.

    `count` is the foundation-weight for this action — used by the phone
    UI to render the trust-transfer breakdown at approval time. At v1
    the count is informational-only; runtime-enforced budget-spending
    is a v2 follow-on (consumer-side backlog tracks the deferred
    design).
    """

    count: int
    description: str


@dataclass(frozen=True)
class GroupDefinition:
    """A named collection of action keys.

    Group weight = sum of member action counts (computed by the manifest
    at lookup time, NOT stored — single source of truth is the action
    counts).
    """

    actions: list[str]


@dataclass(frozen=True)
class ActionManifest:
    """Versioned registry of all known actions and groups.

    Stored in Recto's vault under `recto:meta:capability_action_manifest`.
    Distributed to verifiers via a HTTP-cached fetch keyed by manifest
    version. JWTs reference the manifest version they were issued
    against (`CapabilityClause.registry_version`); verifiers fetch that
    version's manifest at validation time.

    New actions / groups are added by bumping the version and re-
    publishing. Capabilities issued under old versions stay valid until
    their `exp`; new capabilities are issued against the current
    manifest. The manifest itself is a vault entry, so updating it
    requires a `manifest:add-action` capability (count: 5, moderate).
    """

    version: str
    actions: dict[str, ActionDefinition]
    groups: dict[str, GroupDefinition]

    def group_weight(self, group_key: str) -> int:
        """Sum of counts for all actions in the named group.

        Raises KeyError if the group or any member action is unknown to
        this manifest version.
        """
        group = self.groups[group_key]
        return sum(self.actions[action_key].count for action_key in group.actions)

    def capability_weight(self, clause: CapabilityClause) -> int:
        """Total foundation-weight of a CapabilityClause.

        Sum of group weights for every group named in `clause.groups`,
        plus counts for any raw `allow_actions` (which are not in any
        group). `deny_actions` does NOT subtract weight — denials are a
        scope-narrowing mechanism, not a weight-reducing one.

        Used by the phone UI at approval time to show the running total
        with the tier ceiling reference (e.g. "Tier 1 — total weight:
        18 / 30").
        """
        group_total = sum(self.group_weight(g) for g in clause.groups)
        action_total = sum(self.actions[a].count for a in clause.allow_actions)
        return group_total + action_total


# ---------------------------------------------------------------------------
# Tier ceilings (v1 starter calibration — operator can adjust over time)
# ---------------------------------------------------------------------------

# Used by the phone UI to render "weight X / Y" running totals at approval
# time. Not enforced cryptographically in v1 — the operator confirms by
# eyeballing whether the total fits the chosen tier. Hard enforcement is a
# v2 follow-on if the runtime-enforced budget feature lands.

TIER_WEIGHT_CEILINGS: dict[int, int] = {
    0: 5,    # Always autonomous, both staging and prod
    1: 30,   # Autonomous staging; human-confirm to prod
    2: 100,  # Explicit pre-authorization per capability
    # Tier 3: > 100, always fresh operator approval, no caching
}
