using System.Collections.Generic;

namespace Recto.Shared.Profile;

// ---------------------------------------------------------------------------
// Multi-profile identity — v2.0 wire-protocol type contracts (C# mirror).
// ---------------------------------------------------------------------------
//
// Mirror of recto.profile.types in Python. Same field names (snake_case
// preserved on the wire via canonical JSON), same shape, same semantics.
// Cross-language signature verification of the v2.0 parent_profile claim
// chain depends on byte-identical canonical JSON output, which depends on
// these records emitting the same field set with the same names and the
// same omit-when-default rules as Python's dataclasses.
//
// Status: v1.x ships the type contracts only. The runtime (BIP-32
// master-to-profile derivation, the profile_create / profile_add_device /
// profile_revoke_device PendingRequest handlers, the capability-JWS
// parent_profile extension, the SCIM provisioning surface, the phone-side
// profile picker) ships in v2.0. Consumers can reference these types today
// to write v2.0-aware code paths.
//
// Design reference: ARCHITECTURE.md "Multi-profile identity:
// personal-as-master-key hierarchy (DESIGN BANKED)" (2026-05-15 entry)
// and recto/profile/SPEC.md.
//
// Hard rules in play:
//   - #1: backward compatibility — v2.0 ships as additive expansions to
//     v1.x types; nothing here changes a v1.x wire shape.
//   - #9 (plural-profiles corollary): every profile derives from one
//     operator's master enclave key. Profiles are extensions of personal
//     identity, not independent enclaves.

/// <summary>
/// Canonical profile-kind identifiers. Operators MAY use custom kind
/// strings (the type system doesn't enforce this set), but lose the
/// canonical-shape conveniences (native UI, SCIM auto-detect, federation
/// handshake defaults).
/// </summary>
public static class ProfileKinds
{
    /// <summary>The master profile — root of the hierarchy. Exactly ONE
    /// per master enclave key.</summary>
    public const string PersonalMaster = "personal:master";

    /// <summary>A second personal-tier profile under the same master.
    /// Same trust posture as master; inherits the master's phone-enclave
    /// as root of trust.</summary>
    public const string PersonalChild = "personal:child";

    /// <summary>An employer-bound profile. Provisioned via SCIM or
    /// manual import from Azure AD / Okta / Google Workspace.</summary>
    public const string Work = "work";

    /// <summary>An educational-institution-bound profile. Provisioned
    /// via the school's SSO or manual federation handshake.</summary>
    public const string School = "school";

    /// <summary>A project-bounded profile. Operator-authored deny-action
    /// set (no external SCIM provider).</summary>
    public const string Contractor = "contractor";

    /// <summary>Profile kinds that v2.0 ships with native UI + SCIM +
    /// federation support for.</summary>
    public static readonly IReadOnlyList<string> Canonical = new[]
    {
        PersonalMaster, PersonalChild, Work, School, Contractor,
    };
}

/// <summary>
/// BIP-32 derivation path from the master enclave key to a profile.
/// <para>
/// Same primitive Recto already uses for per-chain wallet derivation
/// (each cryptocurrency family lives at m/44'/&lt;coin&gt;'/0'/0/N). v2.0
/// reuses the BIP-32 hardened-key derivation primitive to fan out
/// PROFILES under the master enclave key.
/// </para>
/// <para>
/// Path shape: m/&lt;purpose&gt;'/&lt;profile_coin_type&gt;'/&lt;profile_index&gt;'/0/0
/// </para>
/// </summary>
public sealed record ProfileDerivationPath(
    long Purpose,
    long ProfileCoinType,
    long ProfileIndex)
{
    /// <summary>Standard BIP-32 path notation.</summary>
    public string AsBip32String() =>
        $"m/{Purpose}'/{ProfileCoinType}'/{ProfileIndex}'/0/0";
}

/// <summary>
/// A single profile under one master enclave key.
/// <para>
/// The master profile is itself a <see cref="Profile"/> row with kind =
/// <see cref="ProfileKinds.PersonalMaster"/> and
/// <see cref="ParentProfileId"/> = null. All other profiles MUST have
/// <see cref="ParentProfileId"/> set to the master's <see cref="ProfileId"/>
/// (v2.0 disallows non-master parents; v2.1+ may relax for nested
/// delegation).
/// </para>
/// </summary>
public sealed record Profile(
    string ProfileId,
    string Kind,
    string DisplayName,
    ProfileDerivationPath Derivation,
    string? ParentProfileId = null,
    string? ThemeHint = null,
    string? ScimProvider = null,
    IReadOnlyList<string>? DenyActionsInherited = null,
    long CreatedAtUnix = 0,
    bool Revoked = false)
{
    public IReadOnlyList<string> EffectiveDenyActions =>
        DenyActionsInherited ?? System.Array.Empty<string>();
}

/// <summary>
/// Top-level descriptor for an operator's master enclave + profiles.
/// <para>
/// The MasterIdentity is the canonical 'who is this person' record. The
/// phone enclave holds the BIP-39 mnemonic; every profile under the master
/// derives from that one seed via the BIP-32 paths in
/// <see cref="ProfileDerivationPath"/>.
/// </para>
/// </summary>
public sealed record MasterIdentity(
    string MasterPubkeyHex,
    string MasterProfileId,
    IReadOnlyList<Profile> Profiles,
    string? Label = null);

/// <summary>
/// Wire-protocol slot reservations for v2.0 (banked here as constants so
/// v1.x consumers can write conditional code paths that activate when the
/// runtime lands).
/// </summary>
public static class ProfileWireProtocol
{
    /// <summary>PendingRequest.kind for 'mint a new profile under my
    /// master'.</summary>
    public const string PendingRequestKindProfileCreate = "profile_create";

    /// <summary>PendingRequest.kind for 'pair another device (phone or
    /// yubikey) to this profile'.</summary>
    public const string PendingRequestKindProfileAddDevice = "profile_add_device";

    /// <summary>PendingRequest.kind for 'revoke a paired device from
    /// this profile'.</summary>
    public const string PendingRequestKindProfileRevokeDevice = "profile_revoke_device";

    /// <summary>Action key for the profile_create capability (count: 20
    /// — significant, creates a new identity under the master).</summary>
    public const string CapabilityActionProfileCreate = "profile:create";

    /// <summary>Action key for adding a device to a profile (count: 10
    /// — moderate, expands the trust set).</summary>
    public const string CapabilityActionProfileAddDevice = "profile:add_device";

    /// <summary>Action key for revoking a device from a profile
    /// (count: 15 — between create and rotate).</summary>
    public const string CapabilityActionProfileRevokeDevice = "profile:revoke_device";

    /// <summary>Action key for catastrophic-tier master rotation (count:
    /// 500 — re-derives every profile under the master).</summary>
    public const string CapabilityActionProfileRotateMaster = "profile:rotate_master";

    /// <summary>Optional field name on CapabilityClaims for the v2.0
    /// extension. When present in the JSON wire form, the JWS recovers
    /// to the named profile's derived key (NOT the master's root key).
    /// Absent for v1.x single-identity-mode claims (backward-compat).
    /// </summary>
    public const string CapabilityClaimFieldParentProfile = "parent_profile";
}
