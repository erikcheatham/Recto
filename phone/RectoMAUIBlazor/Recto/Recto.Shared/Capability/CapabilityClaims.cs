using System.Collections.Generic;

namespace Recto.Shared.Capability;

// ---------------------------------------------------------------------------
// Capability claim shape (the JWT payload)
// ---------------------------------------------------------------------------
//
// Mirror of recto.capability.types in Python. Same field names (snake_case
// preserved on the wire via canonical JSON), same shape, same semantics.
// Cross-language signature verification depends on byte-identical canonical
// JSON output, which depends on these records emitting the same field set
// with the same names and the same omit-when-default rules as Python's
// dataclasses.
//
// Hard rules in play:
//   - #9: phone enclave is generic capability provider; agents inherit
//     from humans. Capabilities NEVER bypass operator-issued scope.
//   - Constant string keys, NOT enums (operator's call 2026-05-05):
//     action and group identifiers are unique strings registered in the
//     manifest. New actions register without touching code.

/// <summary>
/// Resource-bounding for a capability. Narrows the tier defaults.
/// <para>
/// <c>Env</c> / <c>Services</c> / <c>Repos</c> are allow-lists; an empty
/// list means "no restriction at this dimension" (rare &mdash; most
/// capabilities scope all three).
/// </para>
/// </summary>
public sealed record CapabilityScope(
    IReadOnlyList<string> Env,
    IReadOnlyList<string> Services,
    IReadOnlyList<string> Repos)
{
    public static CapabilityScope Empty { get; } = new(
        Env: System.Array.Empty<string>(),
        Services: System.Array.Empty<string>(),
        Repos: System.Array.Empty<string>());
}

/// <summary>
/// Rate-limit constraints. The verifier enforces these per-capability.
/// <para>
/// Keys are constant-string action / metric identifiers (matching the
/// manifest's action keys). Values are integer limits over the named
/// window. Missing keys mean "no limit on that metric".
/// </para>
/// </summary>
public sealed record CapabilityLimits(
    IReadOnlyDictionary<string, long> PerHour,
    IReadOnlyDictionary<string, long> PerDay,
    IReadOnlyDictionary<string, long> PerSession)
{
    public static CapabilityLimits Empty { get; } = new(
        PerHour: new Dictionary<string, long>(),
        PerDay: new Dictionary<string, long>(),
        PerSession: new Dictionary<string, long>());
}

/// <summary>
/// The <c>cap</c> claim in a capability JWT.
/// <para>
/// Hybrid scope expression (Option C, locked 2026-05-05):
/// <list type="bullet">
/// <item><c>Tier</c> provides default behavior</item>
/// <item><c>Groups</c> is the list of group identifiers (manifest-resolved
/// to action sets)</item>
/// <item><c>Scope</c> narrows the tier defaults to specific env / services / repos</item>
/// <item><c>AllowActions</c> adds beyond tier defaults (raw action keys)</item>
/// <item><c>DenyActions</c> subtracts narrower than tier defaults</item>
/// <item><c>Limits</c> carries rate-limit constraints</item>
/// <item><c>RegistryVersion</c> pins which manifest version this capability was issued against</item>
/// </list>
/// </para>
/// </summary>
public sealed record CapabilityClause(
    int Tier,
    string RegistryVersion,
    IReadOnlyList<string> Groups,
    CapabilityScope Scope,
    IReadOnlyList<string> AllowActions,
    IReadOnlyList<string> DenyActions,
    CapabilityLimits Limits)
{
    /// <summary>
    /// Convenience constructor with sensible defaults for the optional
    /// fields. Mirrors Python's <c>CapabilityClause(tier=, registry_version=,
    /// groups=[...])</c> shorthand.
    /// </summary>
    public static CapabilityClause Create(
        int tier,
        string registryVersion,
        IReadOnlyList<string>? groups = null,
        CapabilityScope? scope = null,
        IReadOnlyList<string>? allowActions = null,
        IReadOnlyList<string>? denyActions = null,
        CapabilityLimits? limits = null)
    {
        return new CapabilityClause(
            Tier: tier,
            RegistryVersion: registryVersion,
            Groups: groups ?? System.Array.Empty<string>(),
            Scope: scope ?? CapabilityScope.Empty,
            AllowActions: allowActions ?? System.Array.Empty<string>(),
            DenyActions: denyActions ?? System.Array.Empty<string>(),
            Limits: limits ?? CapabilityLimits.Empty);
    }
}

/// <summary>
/// Full JWT payload. Standard claims (RFC 7519) + custom Recto claims.
/// <para>
/// Standard:
/// <list type="bullet">
/// <item><c>Iss</c>: who minted this capability (always
/// <c>phone:&lt;operator&gt;:enclave</c> in v1)</item>
/// <item><c>Sub</c>: who this capability is issued TO
/// (e.g. <c>agent:darwin@staging</c>)</item>
/// <item><c>Aud</c>: which consumers should accept this</item>
/// <item><c>Iat / Nbf / Exp</c>: standard time bounds (Unix seconds)</item>
/// <item><c>Jti</c>: unique JWT ID for revocation lookup</item>
/// </list>
/// </para>
/// <para>
/// Custom:
/// <list type="bullet">
/// <item><c>Cap</c>: the actual capability scope</item>
/// <item><c>Purpose</c>: human-readable description for audit</item>
/// <item><c>ParentCap</c>: jti of the parent capability if this is a
/// delegated child (<c>null</c> for top-level operator-issued caps)</item>
/// <item><c>MaxUses</c>: single-use vs reusable (<c>null</c> = reusable)</item>
/// <item><c>ParentProfile</c>: v2.0 forward-compat slot for the
/// multi-profile identity layer. When present, the JWS is signed by
/// the named child profile's BIP-32-derived key (NOT the master root
/// key directly). The v2.0 verifier extension will validate that the
/// named profile is non-revoked under the master that owns the claim's
/// <c>Iss</c> field, and that the signature recovers to the profile's
/// derived pubkey rather than the master pubkey. Absent at v1.x —
/// single-identity-mode claims recover to the master pubkey directly,
/// backward-compatible per Hard Rule #1. Reserved here so v1.x
/// consumers can write conditional code paths against v2.0 ahead of
/// the runtime landing. Mirrors Python
/// <c>recto/capability/types.py::CapabilityClaims.parent_profile</c>
/// and the field-name reservation in
/// <c>recto/profile/types.py::CAPABILITY_CLAIM_FIELD_PARENT_PROFILE</c>.</item>
/// </list>
/// </para>
/// </summary>
public sealed record CapabilityClaims(
    string Iss,
    string Sub,
    IReadOnlyList<string> Aud,
    long Iat,
    long Nbf,
    long Exp,
    string Jti,
    CapabilityClause Cap,
    string Purpose,
    string? ParentCap = null,
    long? MaxUses = null,
    string? ParentProfile = null);
