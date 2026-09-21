"""
Multi-profile identity — v2.0 wire-protocol type contracts.

Dataclass scaffolds for the Profile, MasterIdentity, and
ProfileDerivationPath shapes that v2.0 will ship as a runtime layer
on top of v1.x's single-identity model. JWT-claim extension (the
`parent_profile` field on CapabilityClaims), CLI subcommands, phone-
side profile picker, and federation handshake all happen in v2.0;
this file establishes the data contract that mint / verify / phone-
side UI all share.

Design reference: ARCHITECTURE.md section "Multi-profile identity:
personal-as-master-key hierarchy (DESIGN BANKED)" (2026-05-15 entry).

Hard rules in play:
  - #1: backward compatibility — v2.0 ships as additive expansions
    to v1.x types; nothing in this file changes a v1.x wire shape.
  - #9 (plural-profiles corollary): every profile derives from one
    operator's master enclave key. Profiles are extensions of
    personal identity, not independent enclaves. The master is the
    unconditional root of trust; profiles inherit from it.
  - Constant string keys, NOT enums for ProfileKind values: same
    rationale as capability action keys — new profile types register
    via manifest / config without enum drift across Recto + consumers
    + phone-side.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Profile kind (constant string keys, not enums — see module docstring)
# ---------------------------------------------------------------------------

# Canonical profile-kind identifiers. Operators can extend via custom strings
# (e.g. "personal:throwaway", "work:contractor", "school:graduate") — the
# core set below is what v2.0 ships with native UI / SCIM / federation
# support for.

PROFILE_KIND_PERSONAL_MASTER = "personal:master"
"""The master profile — root of the hierarchy. Exactly ONE per master
enclave key. Cannot be deleted while child profiles exist. Holds the
catastrophic-tier authority (operator-key:rotate, profile:rotate_master,
etc.). Direct phone-tap confirmation for every capability the master
itself signs; child-profile capabilities are signed by the master's key
via BIP-32 derivation but rendered on the phone under the child profile's
display name + theme."""

PROFILE_KIND_PERSONAL_CHILD = "personal:child"
"""A second personal-tier profile under the same master. Use cases:
public-persona vs private-identity, on-chain pseudonymity, throwaway
profiles for accounts the operator wants to keep isolated from their
canonical identity. Same trust posture as master; inherits the master's
phone-enclave as root of trust."""

PROFILE_KIND_WORK = "work"
"""An employer-bound profile. Provisioned via SCIM or manual import
from Azure AD / Okta / Google Workspace. Capability scope is subject
to employer-imposed deny-actions (the employer's SCIM admin can lock
out operator-side action sets that conflict with corporate policy).
On employment termination, the SCIM provider revokes the profile —
keys derived under it become unusable for new capability mints, but
the operator's master is unaffected."""

PROFILE_KIND_SCHOOL = "school"
"""An educational-institution-bound profile. Provisioned via the
school's SSO or manual federation handshake. Same SCIM-style scope
restrictions as work profiles. On graduation or transfer, the school
revokes; master unaffected. Adolescents whose master is not yet
established (no enclave-paired phone of their own) can have a
school-only profile bound to a parent's master — covered by the
'managed-master' v2.1 follow-on."""

PROFILE_KIND_CONTRACTOR = "contractor"
"""Same shape as work, but project-bound rather than employer-bound.
Multiple contractor profiles can coexist (one per client engagement).
Operator is the SCIM admin (no external provider), so the deny-action
set is operator-authored. Useful for billing audit trails and per-
engagement capability isolation."""

CANONICAL_PROFILE_KINDS: tuple[str, ...] = (
    PROFILE_KIND_PERSONAL_MASTER,
    PROFILE_KIND_PERSONAL_CHILD,
    PROFILE_KIND_WORK,
    PROFILE_KIND_SCHOOL,
    PROFILE_KIND_CONTRACTOR,
)
"""Profile kinds that v2.0 ships with native UI + SCIM + federation
support for. Operators MAY use custom kind strings (the type system
doesn't enforce this set) but lose the canonical-shape conveniences."""


# ---------------------------------------------------------------------------
# ProfileDerivationPath — how a child profile's key tree is rooted in the master
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProfileDerivationPath:
    """BIP-32 derivation path from the master enclave key to a profile.

    Same primitive Recto already uses for per-chain wallet derivation
    (each cryptocurrency family lives at m/44'/<coin>'/0'/0/N). v2.0
    reuses the BIP-32 hardened-key derivation primitive to fan out
    PROFILES under the master enclave key, with a coin-type slot
    reserved for "Recto profile" (purpose: 'rectoP', custom coin-type
    index TBD at v2.0 ship — banked as a reservation in the v2.0
    spec).

    Path shape: m/<purpose>'/<profile_coin_type>'/<profile_index>'/0/0

    Each profile gets ONE BIP-32 subtree. Within that subtree, per-
    chain wallet derivation continues at the existing per-chain
    paths (m/44'/60'/0'/0/N for ETH, m/84'/0'/0'/0/N for BTC, etc.),
    rooted at the profile's master-derived key rather than at the
    operator's master directly.

    Net effect: same set of cryptographic primitives, same audit
    trail, ONE key tree per profile — and the operator can prove
    ownership across all profiles by demonstrating control of the
    master enclave key.
    """

    purpose: int
    """BIP-32 purpose field. Reserved 'rectoP' for v2.0 (exact integer
    pinned at v2.0 ship; 0x5265_6374 or 'rect' interpreted as ASCII
    integer is the leading candidate, hardened)."""

    profile_coin_type: int
    """Coin-type-slot equivalent for the profile dimension. Operator-
    extensible; v2.0 reserves indices 0-99 for canonical kinds in the
    order they appear in CANONICAL_PROFILE_KINDS."""

    profile_index: int
    """Per-master index within a coin-type. Personal-master is always
    index 0; the operator may have multiple personal-child profiles
    indexed 1, 2, 3, ..."""

    def as_bip32_string(self) -> str:
        """Standard BIP-32 path notation (purpose'/coin_type'/index'/0/0)."""
        return (
            f"m/{self.purpose}'/"
            f"{self.profile_coin_type}'/"
            f"{self.profile_index}'/0/0"
        )


# ---------------------------------------------------------------------------
# Profile dataclass — the in-memory representation of a profile
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Profile:
    """A single profile under one master enclave key.

    The master profile is itself a Profile row with kind =
    PROFILE_KIND_PERSONAL_MASTER and parent_profile_id = None.
    All other profiles MUST have parent_profile_id set to the master's
    profile_id (v2.0 disallows non-master parents; v2.1+ may relax for
    nested delegation, e.g. a work profile that itself delegates to a
    project-bounded sub-profile, but bank that as a follow-on).
    """

    profile_id: str
    """Stable opaque identifier. Operator-authored or auto-generated
    UUID4 at profile-create time. Used in capability JWS sub: and aud:
    fields, in vault entry naming, in operator-facing UI."""

    kind: str
    """One of the constants above (or a custom operator-defined string).
    Drives phone-side rendering, SCIM provider selection, default
    deny-action sets."""

    display_name: str
    """Human-readable label shown on the phone approval card.
    e.g. 'Personal', 'Work — Acme Corp', 'Pseudonym 1'. Operator-
    chosen at create time; mutable via profile-edit (capability-
    gated)."""

    derivation: ProfileDerivationPath
    """BIP-32 path from master enclave key. The profile_id ↔ derivation
    binding is canonicalized at profile-create time and immutable
    thereafter (rotation rotates the master, not individual profile
    derivations)."""

    parent_profile_id: str | None = None
    """The master's profile_id for non-master profiles; None for the
    master. v2.0 enforces 'all non-master profiles have the master as
    parent'; v2.1+ may relax for nested delegation."""

    theme_hint: str | None = None
    """Optional UI theme identifier rendered on the phone's profile-
    picker + approval cards. Helps operators visually distinguish
    work vs personal vs school at approval time. v2.0 ships with a
    canonical set (work=blue, school=green, personal-master=neutral,
    personal-child=operator-chosen, contractor=amber); operators can
    override with custom theme strings."""

    scim_provider: str | None = None
    """For work / school / contractor profiles managed via SCIM, the
    provider URL or identifier (e.g. 'azure-ad:tenant-id',
    'okta:org-slug', 'workspace:domain.com'). Master + personal-child
    profiles always have scim_provider=None — they're operator-
    controlled, not externally provisioned."""

    deny_actions_inherited: tuple[str, ...] = field(default_factory=tuple)
    """Action keys that this profile CANNOT use under any circumstances.
    For work / school profiles, populated by the SCIM provider's
    policy push (e.g. an employer might deny 'treasury:transfer' on
    all work profiles regardless of capability scope). For personal
    profiles, defaults empty (operator has full latitude). These are
    structural overrides — capability scope is bounded by them at
    verify time, not by what the operator wishes."""

    created_at_unix: int = 0
    """Profile creation timestamp. Authored by the master at create-
    time (signed in the profile_create PendingRequest), tamper-evident."""

    revoked: bool = False
    """Set true when the profile is revoked. Capability JWSes with
    parent_profile pointing at a revoked profile fail verification.
    Master profile cannot be revoked while child profiles exist (must
    revoke children first OR rotate master, which is the
    operator-key:rotate action and re-keys the whole tree)."""

    derived_pubkey_hex: str | None = None
    """128-hex secp256k1 pubkey (X||Y, no 0x04 prefix) derived from
    the master enclave's BIP-39 mnemonic at this profile's
    `derivation` path. Populated by the phone at profile_create
    approval time and verified bootloader-side via the master's
    secp256k1 attestation over the canonical-JSON binding (kind,
    display_name, derivation, pubkey).

    Nullable for backward compat with v2.0.B-era Profile rows that
    were persisted before this field existed. v2.0.C-and-later
    creates MUST populate it; v2.0.B rows can be opt-in backfilled
    later via a future `recto profile derive-pubkey <profile_id>`
    admin command (out of Phase 2.0.C scope).

    Phase 2.0.C wave 2's `parent_profile` capability JWS verifier
    extension looks up this field on the named profile to recover
    JWS signatures against the child key (not the master root).
    Profiles with `derived_pubkey_hex=None` cannot serve as
    `parent_profile` claim targets — the verifier rejects with a
    clear "profile lacks derived pubkey; run backfill" message."""

    device_ids: tuple[str, ...] = field(default_factory=tuple)
    """phone_id values of paired devices authorized to act on this
    profile's behalf (sign capability_requests, approve add-device
    /revoke-device operations, etc.). The same phone_id can appear
    on multiple profiles — typically the operator's primary phone is
    on the master + every personal-child profile, while a work
    profile's device set might include only the work phone.

    Empty tuple for v2.0.B-era Profile rows that were persisted
    before this field existed (Phase 2.0.C wave C.5 schema bump).
    Reader tolerates the absence and defaults to empty. v2.0.C-and-
    later profile_create operations auto-populate this tuple with
    the approving phone's phone_id at creation time (the phone that
    approves the master attestation becomes the new profile's first
    device). Subsequent additions go via the profile_add_device
    PendingRequest flow (Phase 2.0.C wave C.5); revocations via
    profile_revoke_device (Phase 2.0.C wave C.6).

    Phase 2.0.C wave C.5's `profile_add_device` verifier appends to
    this tuple after the master OR an already-paired device on the
    profile signs the canonical-JSON binding (profile_id +
    new_device_phone_id + new_device_pubkey + added_at_unix).
    Idempotent: re-adding an existing phone_id is a no-op (returns
    `already_exists` rather than re-prompting the phone). Privilege
    graph integrity: a phone CANNOT add itself to a profile it isn't
    already on — the signing authority comes from a phone ALREADY
    in `device_ids`, not from the candidate device."""

    revoke_quorum_k: int = 1
    """How many signatures from devices in `device_ids` are required
    to authorize a `profile_revoke_device` operation against this
    profile. Default `1` means any single paired device (including
    the master) can sign alone to revoke another device. Higher
    values introduce a K-of-N multi-signature quorum: K distinct
    devices in `device_ids` must each sign the same canonical-JSON
    revoke binding before the bootloader persists the removal.

    Phase 2.0.C wave C.6 schema bump. At v1 (this wave) only K=1 is
    fully wired end-to-end via the bootloader; values >=2 are
    PERSISTED CORRECTLY but the signature-aggregation state machine
    (multi-PendingRequest collection + partial-signature stash +
    persist-when-K-collected) is banked for v1.1. The field exists
    at v1 so a future K-of-N rollout doesn't need a schema migration
    — operators can create profiles with `revoke_quorum_k=2` today,
    and the bootloader-side respond branch will reject the second
    revoke attempt as `quorum_not_yet_implemented` with a clear
    error rather than silently persisting.

    Validation: must be >= 1 (set at create time + immutable
    afterward; rotation of the quorum requires a separate
    `rotate_quorum` action that doesn't exist yet — deferred). At
    create time the manage.py layer also enforces `revoke_quorum_k
    <= len(device_ids)` when device_ids is non-empty (you can't
    require 3 signatures from a profile with 2 devices). Empty
    device_ids skip the upper-bound check because profile_add_device
    will populate device_ids before any revoke can fire.

    Omitted from on-disk JSON when equal to the default (1) so
    v2.0.B / v2.0.C-pre-C.6-era Profile rows round-trip byte-
    identical. Reader tolerates absence and defaults to 1."""


# ---------------------------------------------------------------------------
# MasterIdentity — the canonical representation of "an operator's master"
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MasterIdentity:
    """Top-level descriptor for an operator's master enclave + profiles.

    The MasterIdentity is the canonical 'who is this person' record.
    The phone enclave holds the BIP-39 mnemonic; every profile under
    the master derives from that one seed via the BIP-32 paths above.

    In v2.0's vault, the MasterIdentity is stored as a JSON blob under
    a vault entry keyed by master enclave pubkey fingerprint. Profile
    rows are stored as a list under the master, NOT as standalone vault
    entries — this keeps 'list my profiles' a single vault read AND
    enforces the 'all profiles trace back to one master' invariant at
    the storage layer.
    """

    master_pubkey_hex: str
    """secp256k1 master enclave pubkey, 128 hex chars (64 raw bytes
    uncompressed X || Y). The fingerprint (first 8 chars + '...' +
    last 8 chars) is the operator-facing short identifier."""

    master_profile_id: str
    """The profile_id of this master's PROFILE_KIND_PERSONAL_MASTER
    profile. Convenience field — equals
    [p for p in profiles if p.kind == PERSONAL_MASTER][0].profile_id."""

    profiles: tuple[Profile, ...] = field(default_factory=tuple)
    """All profiles under this master, including the master itself.
    Immutable snapshot; mutations go via the v2.0 ProfileStore (which
    produces a new MasterIdentity instance). Empty tuple is invalid —
    a MasterIdentity always contains at least the master profile."""

    label: str | None = None
    """Optional operator-facing label for the master itself, e.g.
    'Erik (primary)'. Defaults to the master profile's display_name
    if None."""


# ---------------------------------------------------------------------------
# Wire-protocol slot reservations (banked for v2.0 — not active in v1.x)
# ---------------------------------------------------------------------------

# These constants are reserved here so v1.x consumers can write
# conditional code paths that activate when the runtime lands. v2.0 will
# add these to the canonical wire shapes in recto.bootloader.state +
# recto.capability.types + the action manifest.

PENDING_REQUEST_KIND_PROFILE_CREATE = "profile_create"
"""PendingRequest.kind for 'mint a new profile under my master'.
v2.0 wire shape: includes parent_profile_pubkey (the master's pubkey),
proposed profile shape (kind, display_name, derivation), and the
operator's phone-side approval gates a one-shot child-profile mint."""

PENDING_REQUEST_KIND_PROFILE_ADD_DEVICE = "profile_add_device"
"""PendingRequest.kind for 'pair another device to
this profile'. Same wire shape as the existing pair flow, scoped to a
specific profile. v2.0 supports per-profile device sets — the master
can have N devices, each child profile can have a subset (e.g. only
operator's personal phone holds the master key; the work-profile
device set includes the operator's work phone but not the master)."""

PENDING_REQUEST_KIND_PROFILE_REVOKE_DEVICE = "profile_revoke_device"
"""PendingRequest.kind for 'revoke a paired device from this profile'.
Signed by the master OR any other still-paired device on the profile
(N-of-M revoke quorum is operator-configurable at profile-create
time)."""

CAPABILITY_ACTION_PROFILE_CREATE = "profile:create"
"""Action key for the profile_create capability. Operator phone-tap
approves the master signing a new profile derivation. Reserved at
weight 20 (significant — creates a new identity under the master)."""

CAPABILITY_ACTION_PROFILE_ADD_DEVICE = "profile:add_device"
"""Action key for adding a device to a profile. Reserved at weight
10 (moderate — expands the trust set)."""

CAPABILITY_ACTION_PROFILE_REVOKE_DEVICE = "profile:revoke_device"
"""Action key for revoking a device from a profile. Reserved at weight
15 (between create and rotate — revocation has security implications
but doesn't mint new authority)."""

CAPABILITY_ACTION_PROFILE_ROTATE_MASTER = "profile:rotate_master"
"""Action key for the catastrophic-tier master rotation. Re-derives
EVERY profile under the master from a new mnemonic; the old keys are
retired. Reserved at weight 500 (catastrophic — same tier as
operator-key:rotate, which it's essentially aliased to in the v2.0
implementation)."""

CAPABILITY_CLAIM_FIELD_PARENT_PROFILE = "parent_profile"
"""Optional field on CapabilityClaims (v2.0 extension). When present,
the JWS recovers to the named profile's derived key (NOT the master's
root key). Verifier validates that the named profile is non-revoked
under the master that owns the claim's `iss` field. Absent for v1.x
single-identity-mode claims (backward-compat)."""
