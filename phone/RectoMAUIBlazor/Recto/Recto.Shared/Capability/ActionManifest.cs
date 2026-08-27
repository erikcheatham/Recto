using System.Collections.Generic;

namespace Recto.Shared.Capability;

// ---------------------------------------------------------------------------
// Capability action manifest (the registry that lives in the vault)
// ---------------------------------------------------------------------------
//
// Mirror of the dataclasses in recto.capability.types (action / group /
// manifest types) plus the TIER_WEIGHT_CEILINGS constant. Evaluation
// helpers (load / resolve / evaluate / breakdown) live in
// ActionManifestLoader.cs to keep the data shape and the verb surface
// in separate files &mdash; easier to grep, easier to test.

/// <summary>
/// A single action in the registry.
/// <para>
/// <c>Count</c> is the foundation-weight for this action &mdash; used by
/// the phone UI to render the trust-transfer breakdown at approval time.
/// At v1 the count is informational-only; runtime-enforced budget-spending
/// is a v2 follow-on (consumer-side backlog tracks the deferred design).
/// </para>
/// </summary>
public sealed record ActionDefinition(int Count, string Description);

/// <summary>
/// A named collection of action keys.
/// <para>
/// Group weight = sum of member action counts (computed by the manifest
/// at lookup time, NOT stored &mdash; single source of truth is the action
/// counts).
/// </para>
/// </summary>
public sealed record GroupDefinition(IReadOnlyList<string> Actions);

/// <summary>
/// Versioned registry of all known actions and groups.
/// <para>
/// Stored in Recto's vault under
/// <c>recto:meta:capability_action_manifest</c>. Distributed to verifiers
/// via an HTTP-cached fetch keyed by manifest version. JWTs reference the
/// manifest version they were issued against
/// (<see cref="CapabilityClause.RegistryVersion"/>); verifiers fetch that
/// version's manifest at validation time.
/// </para>
/// <para>
/// New actions / groups are added by bumping the version and re-publishing.
/// Capabilities issued under old versions stay valid until their
/// <see cref="CapabilityClaims.Exp"/>; new capabilities are issued against
/// the current manifest. The manifest itself is a vault entry, so updating
/// it requires a <c>manifest:add-action</c> capability (count: 5,
/// moderate).
/// </para>
/// </summary>
public sealed record ActionManifest(
    string Version,
    IReadOnlyDictionary<string, ActionDefinition> Actions,
    IReadOnlyDictionary<string, GroupDefinition> Groups)
{
    /// <summary>
    /// Sum of counts for all actions in the named group. Throws
    /// <see cref="System.Collections.Generic.KeyNotFoundException"/> if
    /// the group or any member action is unknown to this manifest version.
    /// </summary>
    public long GroupWeight(string groupKey)
    {
        var group = Groups[groupKey];
        long total = 0;
        foreach (var actionKey in group.Actions)
        {
            total += Actions[actionKey].Count;
        }
        return total;
    }

    /// <summary>
    /// Total foundation-weight of a <see cref="CapabilityClause"/>.
    /// <para>
    /// Sum of group weights for every group named in
    /// <see cref="CapabilityClause.Groups"/>, plus counts for any raw
    /// <see cref="CapabilityClause.AllowActions"/> (which are not in any
    /// group). <see cref="CapabilityClause.DenyActions"/> does NOT
    /// subtract weight &mdash; denials are a scope-narrowing mechanism,
    /// not a weight-reducing one.
    /// </para>
    /// <para>
    /// Used by the phone UI at approval time to show the running total
    /// with the tier ceiling reference (e.g. "Tier 1 &mdash; total weight:
    /// 18 / 30").
    /// </para>
    /// </summary>
    public long CapabilityWeight(CapabilityClause clause)
    {
        long total = 0;
        foreach (var groupKey in clause.Groups)
        {
            total += GroupWeight(groupKey);
        }
        foreach (var actionKey in clause.AllowActions)
        {
            total += Actions[actionKey].Count;
        }
        return total;
    }
}

/// <summary>
/// Tier ceilings (v1 starter calibration &mdash; operator can adjust over time).
/// <para>
/// Used by the phone UI to render "weight X / Y" running totals at approval
/// time. Not enforced cryptographically in v1 &mdash; the operator confirms by
/// eyeballing whether the total fits the chosen tier. Hard enforcement is
/// a v2 follow-on if the runtime-enforced budget feature lands.
/// </para>
/// <list type="bullet">
/// <item>Tier 0: weight &le; 5 &mdash; always autonomous, both staging and prod</item>
/// <item>Tier 1: weight &le; 30 &mdash; autonomous staging; human-confirm to prod</item>
/// <item>Tier 2: weight &le; 100 &mdash; explicit pre-authorization per capability</item>
/// <item>Tier 3: weight &gt; 100 &mdash; always fresh operator approval, no caching</item>
/// </list>
/// </summary>
public static class TierWeightCeilings
{
    public const long Tier0 = 5;
    public const long Tier1 = 30;
    public const long Tier2 = 100;

    /// <summary>
    /// Lookup table mirroring Python's <c>TIER_WEIGHT_CEILINGS</c> dict
    /// for callers that want a numeric ceiling for a given tier number.
    /// Returns <c>null</c> for Tier 3 (no upper bound &mdash; always
    /// fresh approval).
    /// </summary>
    public static long? ForTier(int tier) => tier switch
    {
        0 => Tier0,
        1 => Tier1,
        2 => Tier2,
        _ => null,
    };
}

/// <summary>
/// Capability weight breakdown shape &mdash; the structured data the phone
/// UI renders at approval time. Mirrors the Python
/// <c>clause_weight_breakdown</c> return shape.
/// </summary>
public sealed record CapabilityWeightBreakdown(
    int Tier,
    long? TierCeiling,
    long Total,
    IReadOnlyList<GroupWeightSummary> Groups,
    IReadOnlyList<ActionWeightSummary> ExtraActions,
    IReadOnlyList<string> DeniedActions);

/// <summary>
/// One row in <see cref="CapabilityWeightBreakdown.Groups"/> &mdash; a single
/// group's contribution to the total weight, plus its constituent actions
/// for the operator-visible tree view.
/// </summary>
public sealed record GroupWeightSummary(
    string Key,
    long Weight,
    IReadOnlyList<ActionWeightSummary> Actions);

/// <summary>
/// One row in either <see cref="GroupWeightSummary.Actions"/> or
/// <see cref="CapabilityWeightBreakdown.ExtraActions"/> &mdash; a single
/// action's contribution to the total weight.
/// </summary>
public sealed record ActionWeightSummary(string Key, long Count);
