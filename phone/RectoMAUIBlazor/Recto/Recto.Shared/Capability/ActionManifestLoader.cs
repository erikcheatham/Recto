using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace Recto.Shared.Capability;

/// <summary>
/// Load, scope-resolution, and weight-breakdown helpers for the
/// capability action manifest. Mirrors recto.capability.manifest in
/// Python &mdash; same validation rules, same fail-closed semantics, same
/// breakdown shape.
/// <para>
/// Manifest distribution / vault-storage / version-fetching is a Wave C
/// concern; this class operates on already-loaded manifest data.
/// </para>
/// </summary>
public static class ActionManifestLoader
{
    /// <summary>
    /// Load a capability action manifest from a JSON file on disk.
    /// <para>
    /// Validates the shape &mdash; every action key referenced in any group
    /// MUST exist in the actions table. Throws <see cref="InvalidDataException"/>
    /// on shape errors with a descriptive message naming the offending key.
    /// </para>
    /// </summary>
    public static ActionManifest Load(string path)
    {
        var json = File.ReadAllText(path);
        return LoadFromJson(json);
    }

    /// <summary>
    /// Parse a JSON string into an <see cref="ActionManifest"/>. Same
    /// validation as <see cref="Load"/> &mdash; useful when the manifest
    /// comes from a vault fetch rather than disk.
    /// </summary>
    public static ActionManifest LoadFromJson(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        // Version
        if (!root.TryGetProperty("version", out var versionElem)
            || versionElem.ValueKind != JsonValueKind.String
            || string.IsNullOrEmpty(versionElem.GetString()))
        {
            throw new InvalidDataException(
                "Manifest missing or invalid 'version' field");
        }
        var version = versionElem.GetString()!;

        // Actions
        if (!root.TryGetProperty("actions", out var actionsElem)
            || actionsElem.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException(
                "Manifest 'actions' must be an object");
        }

        var actions = new Dictionary<string, ActionDefinition>(StringComparer.Ordinal);
        foreach (var prop in actionsElem.EnumerateObject())
        {
            var key = prop.Name;
            if (prop.Value.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidDataException(
                    $"Action '{key}' definition must be an object");
            }
            if (!prop.Value.TryGetProperty("count", out var countElem)
                || countElem.ValueKind != JsonValueKind.Number
                || !countElem.TryGetInt32(out var count)
                || count < 0)
            {
                throw new InvalidDataException(
                    $"Action '{key}' must have a non-negative integer 'count'");
            }
            string description = "";
            if (prop.Value.TryGetProperty("description", out var descElem))
            {
                if (descElem.ValueKind != JsonValueKind.String)
                {
                    throw new InvalidDataException(
                        $"Action '{key}' 'description' must be a string");
                }
                description = descElem.GetString() ?? "";
            }
            actions[key] = new ActionDefinition(count, description);
        }

        // Groups
        if (!root.TryGetProperty("groups", out var groupsElem)
            || groupsElem.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException(
                "Manifest 'groups' must be an object");
        }

        var groups = new Dictionary<string, GroupDefinition>(StringComparer.Ordinal);
        foreach (var prop in groupsElem.EnumerateObject())
        {
            var key = prop.Name;
            if (prop.Value.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidDataException(
                    $"Group '{key}' definition must be an object");
            }
            if (!prop.Value.TryGetProperty("actions", out var memberElem)
                || memberElem.ValueKind != JsonValueKind.Array)
            {
                throw new InvalidDataException(
                    $"Group '{key}' 'actions' must be a list");
            }
            var members = new List<string>();
            foreach (var item in memberElem.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.String)
                {
                    throw new InvalidDataException(
                        $"Group '{key}' member must be a string");
                }
                var actionKey = item.GetString()!;
                if (!actions.ContainsKey(actionKey))
                {
                    throw new InvalidDataException(
                        $"Group '{key}' references unknown action '{actionKey}'");
                }
                members.Add(actionKey);
            }
            groups[key] = new GroupDefinition(members);
        }

        return new ActionManifest(version, actions, groups);
    }

    /// <summary>
    /// Expand a <see cref="CapabilityClause"/>'s groups + allow_actions
    /// into the full effective action set, with deny_actions subtracted.
    /// <para>
    /// Returns a set of action keys the capability authorizes. Used by
    /// verifiers to check whether a specific requested action is permitted.
    /// </para>
    /// <para>
    /// Throws <see cref="InvalidOperationException"/> if the clause
    /// references unknown groups or actions in this manifest version
    /// (caller should fail closed and refuse the capability rather than
    /// continue with partial scope).
    /// </para>
    /// </summary>
    public static HashSet<string> ResolveActions(
        CapabilityClause clause,
        ActionManifest manifest)
    {
        if (clause.RegistryVersion != manifest.Version)
        {
            throw new InvalidOperationException(
                $"Clause registry_version '{clause.RegistryVersion}' does not "
                + $"match manifest version '{manifest.Version}'");
        }

        var permitted = new HashSet<string>(StringComparer.Ordinal);

        foreach (var groupKey in clause.Groups)
        {
            if (!manifest.Groups.TryGetValue(groupKey, out var group))
            {
                throw new InvalidOperationException(
                    $"Clause references unknown group '{groupKey}' in "
                    + $"manifest version '{manifest.Version}'");
            }
            foreach (var actionKey in group.Actions)
            {
                permitted.Add(actionKey);
            }
        }

        foreach (var actionKey in clause.AllowActions)
        {
            if (!manifest.Actions.ContainsKey(actionKey))
            {
                throw new InvalidOperationException(
                    $"Clause allow_actions references unknown action "
                    + $"'{actionKey}' in manifest version '{manifest.Version}'");
            }
            permitted.Add(actionKey);
        }

        foreach (var actionKey in clause.DenyActions)
        {
            permitted.Remove(actionKey);
        }

        return permitted;
    }

    /// <summary>
    /// Check whether a requested action is permitted by a
    /// <see cref="CapabilityClause"/>.
    /// <para>
    /// Convenience wrapper around <see cref="ResolveActions"/> for the
    /// common single-action check at verification time. Returns true if
    /// the action is in the resolved permitted set, false otherwise.
    /// </para>
    /// <para>
    /// <b>Fail-closed:</b> if the clause references an unknown group or
    /// an unknown manifest version, this returns false (does not throw).
    /// Mirrors Python's <c>evaluate_scope</c>.
    /// </para>
    /// <para>
    /// Note: this checks only action-set membership. Verifier callers
    /// must additionally check signature validity, jti revocation, rate
    /// limits, and environment / service / repo scope &mdash; those are
    /// caller-side / application-specific concerns.
    /// </para>
    /// </summary>
    public static bool EvaluateScope(
        string requestedAction,
        CapabilityClause clause,
        ActionManifest manifest)
    {
        try
        {
            var permitted = ResolveActions(clause, manifest);
            return permitted.Contains(requestedAction);
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }

    /// <summary>
    /// Compute the foundation-count breakdown for a
    /// <see cref="CapabilityClause"/> &mdash; the structured data the phone
    /// UI renders at approval time so the operator sees the trust-transfer
    /// quantitatively.
    /// <para>
    /// Mirrors Python's <c>clause_weight_breakdown</c>. Unknown groups and
    /// unknown allow_actions are silently skipped (NOT raised) &mdash; the
    /// breakdown is informational, and a clause that wouldn't pass scope
    /// resolution should still render a meaningful "what would you have
    /// approved" view rather than blowing up the UI.
    /// </para>
    /// <para>
    /// At v1 this output is informational-only. v2 adds runtime
    /// budget-spending where the total becomes a spend ceiling enforced by
    /// every verifier.
    /// </para>
    /// </summary>
    public static CapabilityWeightBreakdown ClauseWeightBreakdown(
        CapabilityClause clause,
        ActionManifest manifest)
    {
        var groupSummaries = new List<GroupWeightSummary>();
        var extraSummaries = new List<ActionWeightSummary>();
        long total = 0;

        foreach (var groupKey in clause.Groups)
        {
            if (!manifest.Groups.TryGetValue(groupKey, out var group))
            {
                continue;
            }
            var actions = new List<ActionWeightSummary>();
            long groupWeight = 0;
            foreach (var actionKey in group.Actions)
            {
                if (!manifest.Actions.TryGetValue(actionKey, out var def))
                {
                    continue;
                }
                actions.Add(new ActionWeightSummary(actionKey, def.Count));
                groupWeight += def.Count;
            }
            groupSummaries.Add(new GroupWeightSummary(groupKey, groupWeight, actions));
            total += groupWeight;
        }

        foreach (var actionKey in clause.AllowActions)
        {
            if (!manifest.Actions.TryGetValue(actionKey, out var def))
            {
                continue;
            }
            extraSummaries.Add(new ActionWeightSummary(actionKey, def.Count));
            total += def.Count;
        }

        return new CapabilityWeightBreakdown(
            Tier: clause.Tier,
            TierCeiling: TierWeightCeilings.ForTier(clause.Tier),
            Total: total,
            Groups: groupSummaries,
            ExtraActions: extraSummaries,
            DeniedActions: new List<string>(clause.DenyActions));
    }
}
