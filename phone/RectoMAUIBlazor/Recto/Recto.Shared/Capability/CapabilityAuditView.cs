using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace Recto.Shared.Capability;

/// <summary>
/// AUDIT DETAILS v2 (2026-08-13) &mdash; the capability_request card's
/// view-model, computed entirely from the decoded
/// <see cref="CapabilityClaims"/> (i.e. from the exact
/// <c>cap_payload_b64</c> bytes the phone signs).
/// <para>
/// LAW (sign-what-you-see): the card renders claims ONLY from the
/// payload bytes it signs. Transport facts (cap_agent_id, AppContext)
/// are NOT fields here &mdash; the render arm shows them in a visually
/// separate section marked unsigned. A contradiction inside the signed
/// payload (a UUID in the purpose text that matches nothing in the
/// structured claims) produces a <see cref="Warnings"/> entry the
/// render arm must show with styling that cannot be suppressed.
/// </para>
/// <para>
/// Lives in Recto.Shared/Capability (not as a page-private record) so
/// the per-field unit tests + the cross-check red-build reach it
/// without a Blazor render harness; Home.razor consumes it thin.
/// </para>
/// </summary>
public sealed record CapabilityAuditView(
    // 1 — subject split: stop rendering Sub as one opaque string.
    string RawSub,
    string ActingAgent,
    string? OnBehalfOfUser,
    // 2 — actions: full allow list + counts. The render label is
    // "Allowed actions" — NEVER "Allow extra" (that name leaked the
    // internal groups-vs-extra split onto a trust surface).
    IReadOnlyList<string> AllowedActions,
    IReadOnlyList<string> DeniedActions,
    IReadOnlyList<string> Groups,
    int AllowedCount,
    int DeniedCount,
    int GroupCount,
    // 3 — scope
    IReadOnlyList<string> ScopeServices,
    IReadOnlyList<string> ScopeRepos,
    IReadOnlyList<string> ScopeEnv,
    // 4 — tier (kept from v1)
    int Tier,
    long? TierCeiling,
    // 5 — validity: iat -> exp as "requested Xs ago · Ys left" so
    // transit consumption is visible (a card that arrives with 20s of
    // its 60s budget already spent SAYS so).
    long Iat,
    long Exp,
    string RequestedAgo,
    string TimeLeft,
    string ExpiresLocal,
    // 6 — pre-approval tense: this is what the operator's approval
    // will MAKE true, not a fact that already holds.
    string WillIssueAs,
    // 7 — request id
    string Jti,
    bool SingleUse,
    // 8 — registry pin
    string RegistryVersion,
    // 9 — cross-check verdicts (empty = consistent)
    IReadOnlyList<string> Warnings,
    // headline
    string PurposeShort,
    string PurposeFull)
{
    private const int PurposeMax = 240;

    private static readonly Regex UuidRegex = new(
        "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        RegexOptions.Compiled);

    public static CapabilityAuditView From(CapabilityClaims claims)
        => From(claims, DateTimeOffset.UtcNow);

    /// <summary>
    /// <paramref name="now"/> is injectable so validity strings and
    /// the freshness math are deterministic under test.
    /// </summary>
    public static CapabilityAuditView From(CapabilityClaims claims, DateTimeOffset now)
    {
        var (agent, user) = ParseSub(claims.Sub);
        long? ceiling = TierWeightCeilings.ForTier(claims.Cap.Tier);

        var nowUnix = now.ToUnixTimeSeconds();
        var agoSeconds = Math.Max(0, nowUnix - claims.Iat);
        var leftSeconds = claims.Exp - nowUnix;
        var requestedAgo = FormatSpan(agoSeconds) + " ago";
        var timeLeft = leftSeconds <= 0 ? "expired" : FormatSpan(leftSeconds) + " left";
        var expiresLocal = DateTimeOffset.FromUnixTimeSeconds(claims.Exp)
            .ToLocalTime().ToString("yyyy-MM-dd HH:mm");

        var purposeShort = claims.Purpose.Length > PurposeMax
            ? claims.Purpose.Substring(0, PurposeMax) + "..."
            : claims.Purpose;

        return new CapabilityAuditView(
            RawSub: claims.Sub,
            ActingAgent: agent,
            OnBehalfOfUser: user,
            AllowedActions: claims.Cap.AllowActions,
            DeniedActions: claims.Cap.DenyActions,
            Groups: claims.Cap.Groups,
            AllowedCount: claims.Cap.AllowActions.Count,
            DeniedCount: claims.Cap.DenyActions.Count,
            GroupCount: claims.Cap.Groups.Count,
            ScopeServices: claims.Cap.Scope.Services,
            ScopeRepos: claims.Cap.Scope.Repos,
            ScopeEnv: claims.Cap.Scope.Env,
            Tier: claims.Cap.Tier,
            TierCeiling: ceiling,
            Iat: claims.Iat,
            Exp: claims.Exp,
            RequestedAgo: requestedAgo,
            TimeLeft: timeLeft,
            ExpiresLocal: expiresLocal,
            WillIssueAs: claims.Iss,
            Jti: claims.Jti,
            SingleUse: claims.MaxUses == 1,
            RegistryVersion: claims.Cap.RegistryVersion,
            Warnings: CrossCheck(claims, agent),
            PurposeShort: purposeShort,
            PurposeFull: claims.Purpose);
    }

    /// <summary>
    /// Splits the canonical <c>agent:&lt;id&gt;@user:&lt;id&gt;</c>
    /// subject into its acting-agent and on-behalf-of-user halves.
    /// Subjects without the <c>@user:</c> marker (v1 single-part
    /// subjects like <c>agent:darwin@staging</c>, where the @ is part
    /// of the agent's own name) come back as (sub, null) &mdash; the
    /// split only fires on the explicit marker, never on a bare @.
    /// </summary>
    public static (string Agent, string? User) ParseSub(string sub)
    {
        const string marker = "@user:";
        var idx = sub.IndexOf(marker, StringComparison.Ordinal);
        if (idx < 0)
        {
            return (sub, null);
        }
        var agent = sub.Substring(0, idx);
        var user = sub.Substring(idx + marker.Length);
        if (agent.Length == 0 || user.Length == 0)
        {
            return (sub, null);
        }
        return (agent, "user:" + user);
    }

    /// <summary>All UUID-shaped tokens in <paramref name="text"/>.</summary>
    public static IReadOnlyList<string> ExtractUuids(string text)
        => UuidRegex.Matches(text).Select(m => m.Value).ToList();

    /// <summary>
    /// The purpose-vs-claims consistency check (field 9). Every UUID
    /// the free-text purpose names must appear somewhere in the
    /// STRUCTURED claims (sub foremost; also jti, iss, aud, scope
    /// lists, parent_cap / parent_profile). A UUID that appears only
    /// in the prose is exactly how a misleading purpose smuggles a
    /// different principal past the operator's eye &mdash; the
    /// 2026-08-13 live incident is the fixture. Each mismatch yields
    /// one warning naming BOTH values.
    /// </summary>
    public static IReadOnlyList<string> CrossCheck(CapabilityClaims claims, string actingAgent)
    {
        var purposeUuids = ExtractUuids(claims.Purpose);
        if (purposeUuids.Count == 0)
        {
            return Array.Empty<string>();
        }

        var structuredText = string.Join("\n",
            new[]
            {
                claims.Sub, claims.Jti, claims.Iss,
                claims.ParentCap ?? string.Empty,
                claims.ParentProfile ?? string.Empty,
            }
            .Concat(claims.Aud)
            .Concat(claims.Cap.Scope.Services)
            .Concat(claims.Cap.Scope.Repos)
            .Concat(claims.Cap.Scope.Env)
            .Concat(claims.Cap.Groups)
            .Concat(claims.Cap.AllowActions)
            .Concat(claims.Cap.DenyActions));
        var claimUuids = new HashSet<string>(
            ExtractUuids(structuredText), StringComparer.OrdinalIgnoreCase);

        var warnings = new List<string>();
        foreach (var uuid in purposeUuids.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!claimUuids.Contains(uuid))
            {
                warnings.Add(
                    $"Purpose text names {uuid}, but no signed claim carries it — " +
                    $"the signed subject is {actingAgent}. Verify before approving.");
            }
        }
        return warnings;
    }

    /// <summary>Compact humane span: 42s · 3m 10s · 2h 5m · 3d 4h.</summary>
    public static string FormatSpan(long totalSeconds)
    {
        if (totalSeconds < 60)
        {
            return $"{totalSeconds}s";
        }
        if (totalSeconds < 3600)
        {
            return $"{totalSeconds / 60}m {totalSeconds % 60}s";
        }
        if (totalSeconds < 86400)
        {
            return $"{totalSeconds / 3600}h {(totalSeconds % 3600) / 60}m";
        }
        return $"{totalSeconds / 86400}d {(totalSeconds % 86400) / 3600}h";
    }
}
