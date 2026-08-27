using System;
using System.Collections.Generic;
using System.Linq;
using Recto.Shared.Capability;
using Xunit;

namespace Recto.Shared.Tests.Capability;

/// <summary>
/// AUDIT DETAILS v2 (2026-08-13) &mdash; per-field tests for the
/// capability card's view-model plus the purpose-vs-claims cross-check
/// RED-BUILD. The view-model is computed from
/// <see cref="CapabilityClaims"/> only (the decoded signed payload
/// bytes), which is what makes it testable here without a Blazor
/// render harness &mdash; and what enforces the sign-what-you-see law
/// by construction: transport facts are not even reachable from this
/// type.
/// </summary>
public class CapabilityAuditViewTests
{
    private static readonly DateTimeOffset Now =
        DateTimeOffset.FromUnixTimeSeconds(1_715_000_020);

    private static CapabilityClaims MakeClaims(
        string sub = "agent:6f9619ff-8b86-d011-b42d-00c04fc964ff@user:1b671a64-40d5-491e-99b0-da01ff1f3341",
        string purpose = "Deploy the staging web tier",
        long iat = 1_715_000_000,
        long exp = 1_715_000_060,
        long? maxUses = 1,
        IReadOnlyList<string>? allow = null,
        IReadOnlyList<string>? deny = null,
        IReadOnlyList<string>? groups = null)
    {
        return new CapabilityClaims(
            Iss: "phone:operator:enclave",
            Sub: sub,
            Aud: new[] { "consumer-app", "recto:vault" },
            Iat: iat,
            Nbf: iat,
            Exp: exp,
            Jti: "cap_2026-08-13_audit-test",
            Cap: new CapabilityClause(
                Tier: 1,
                RegistryVersion: "2026-05-05",
                Groups: groups ?? new[] { "darwin:doc-edits", "darwin:staging-deploys" },
                Scope: new CapabilityScope(
                    Env: new[] { "staging" },
                    Services: new[] { "web" },
                    Repos: new[] { "recto" }),
                AllowActions: allow ?? new[] { "deploy:staging" },
                DenyActions: deny ?? new[] { "deploy:production" },
                Limits: CapabilityLimits.Empty),
            Purpose: purpose,
            MaxUses: maxUses);
    }

    // -----------------------------------------------------------------
    // 1 — subject split
    // -----------------------------------------------------------------

    [Fact]
    public void Sub_SplitsIntoActingAgentAndOnBehalfOfUser()
    {
        var view = CapabilityAuditView.From(MakeClaims(), Now);
        Assert.Equal("agent:6f9619ff-8b86-d011-b42d-00c04fc964ff", view.ActingAgent);
        Assert.Equal("user:1b671a64-40d5-491e-99b0-da01ff1f3341", view.OnBehalfOfUser);
        Assert.Equal(
            "agent:6f9619ff-8b86-d011-b42d-00c04fc964ff@user:1b671a64-40d5-491e-99b0-da01ff1f3341",
            view.RawSub);
    }

    [Fact]
    public void Sub_WithoutUserMarker_StaysWholeAndUserIsNull()
    {
        // The v1 fixture subject: the @ is part of the agent's own
        // name; only the explicit "@user:" marker splits.
        var view = CapabilityAuditView.From(
            MakeClaims(sub: "agent:darwin@staging"), Now);
        Assert.Equal("agent:darwin@staging", view.ActingAgent);
        Assert.Null(view.OnBehalfOfUser);
    }

    // -----------------------------------------------------------------
    // 2 — actions: full allow list + counts
    // -----------------------------------------------------------------

    [Fact]
    public void Actions_CarryFullListsAndCounts()
    {
        var view = CapabilityAuditView.From(MakeClaims(), Now);
        Assert.Equal(new[] { "deploy:staging" }, view.AllowedActions);
        Assert.Equal(new[] { "deploy:production" }, view.DeniedActions);
        Assert.Equal(1, view.AllowedCount);
        Assert.Equal(1, view.DeniedCount);
        Assert.Equal(2, view.GroupCount);
    }

    // -----------------------------------------------------------------
    // 3 — scope
    // -----------------------------------------------------------------

    [Fact]
    public void Scope_ExposesServicesReposEnv()
    {
        var view = CapabilityAuditView.From(MakeClaims(), Now);
        Assert.Equal(new[] { "web" }, view.ScopeServices);
        Assert.Equal(new[] { "recto" }, view.ScopeRepos);
        Assert.Equal(new[] { "staging" }, view.ScopeEnv);
    }

    // -----------------------------------------------------------------
    // 4 — tier / ceiling (kept from v1)
    // -----------------------------------------------------------------

    [Fact]
    public void Tier_AndCeilingSurvive()
    {
        var view = CapabilityAuditView.From(MakeClaims(), Now);
        Assert.Equal(1, view.Tier);
        Assert.Equal(TierWeightCeilings.ForTier(1), view.TierCeiling);
    }

    // -----------------------------------------------------------------
    // 5 — validity: transit consumption becomes visible
    // -----------------------------------------------------------------

    [Fact]
    public void Validity_ShowsRequestedAgoAndTimeLeft()
    {
        // iat 20s before Now, exp 40s after: today's live card —
        // arrived with 20s of its 60s budget already spent, and the
        // card SAYS so.
        var view = CapabilityAuditView.From(MakeClaims(), Now);
        Assert.Equal("20s ago", view.RequestedAgo);
        Assert.Equal("40s left", view.TimeLeft);
    }

    [Fact]
    public void Validity_ExpiredRendersExpired()
    {
        var view = CapabilityAuditView.From(
            MakeClaims(iat: 1_714_999_000, exp: 1_714_999_060), Now);
        Assert.Equal("expired", view.TimeLeft);
    }

    // -----------------------------------------------------------------
    // 6 — pre-approval tense
    // -----------------------------------------------------------------

    [Fact]
    public void Issuer_RendersAsWillIssueAs()
    {
        var view = CapabilityAuditView.From(MakeClaims(), Now);
        Assert.Equal("phone:operator:enclave", view.WillIssueAs);
    }

    // -----------------------------------------------------------------
    // 7 — request id, single-use label
    // -----------------------------------------------------------------

    [Fact]
    public void Jti_LabeledSingleUseWhenMaxUsesIsOne()
    {
        var view = CapabilityAuditView.From(MakeClaims(maxUses: 1), Now);
        Assert.Equal("cap_2026-08-13_audit-test", view.Jti);
        Assert.True(view.SingleUse);

        var reusable = CapabilityAuditView.From(MakeClaims(maxUses: null), Now);
        Assert.False(reusable.SingleUse);
    }

    // -----------------------------------------------------------------
    // 8 — registry pin
    // -----------------------------------------------------------------

    [Fact]
    public void RegistryVersion_Surfaces()
    {
        var view = CapabilityAuditView.From(MakeClaims(), Now);
        Assert.Equal("2026-05-05", view.RegistryVersion);
    }

    // -----------------------------------------------------------------
    // 9 — cross-check RED-BUILD (the 2026-08-13 live incident fixture)
    // -----------------------------------------------------------------

    [Fact]
    public void CrossCheck_PurposeNamingForeignAgentUuid_MustWarn()
    {
        // RED-BUILD: a payload whose purpose names agent 00000000-…
        // while sub names another id MUST render the warning. If this
        // test goes green with an empty Warnings list, the audit card
        // is once again willing to let prose contradict the signed
        // claims silently.
        var claims = MakeClaims(
            purpose: "Approve access for agent 00000000-0000-0000-0000-000000000000 to staging");
        var view = CapabilityAuditView.From(claims, Now);

        var warning = Assert.Single(view.Warnings);
        // The warning names BOTH values: the prose UUID and the signed
        // subject's agent id.
        Assert.Contains("00000000-0000-0000-0000-000000000000", warning);
        Assert.Contains("agent:6f9619ff-8b86-d011-b42d-00c04fc964ff", warning);
    }

    [Fact]
    public void CrossCheck_PurposeUuidMatchingSub_NoWarning()
    {
        var claims = MakeClaims(
            purpose: "Agent 6f9619ff-8b86-d011-b42d-00c04fc964ff deploys the staging web tier");
        var view = CapabilityAuditView.From(claims, Now);
        Assert.Empty(view.Warnings);
    }

    [Fact]
    public void CrossCheck_PurposeUuidMatchingSub_IsCaseInsensitive()
    {
        var claims = MakeClaims(
            purpose: "Agent 6F9619FF-8B86-D011-B42D-00C04FC964FF deploys the staging web tier");
        var view = CapabilityAuditView.From(claims, Now);
        Assert.Empty(view.Warnings);
    }

    [Fact]
    public void CrossCheck_NoUuidsInPurpose_NoWarning()
    {
        var view = CapabilityAuditView.From(MakeClaims(), Now);
        Assert.Empty(view.Warnings);
    }

    [Fact]
    public void CrossCheck_TwoForeignUuids_TwoWarnings()
    {
        var claims = MakeClaims(
            purpose: "For 00000000-0000-0000-0000-000000000000 and "
                     + "11111111-1111-1111-1111-111111111111");
        var view = CapabilityAuditView.From(claims, Now);
        Assert.Equal(2, view.Warnings.Count);
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    [Theory]
    [InlineData(42, "42s")]
    [InlineData(190, "3m 10s")]
    [InlineData(7500, "2h 5m")]
    [InlineData(273600, "3d 4h")]
    public void FormatSpan_Shapes(long seconds, string expected)
    {
        Assert.Equal(expected, CapabilityAuditView.FormatSpan(seconds));
    }

    [Fact]
    public void ExtractUuids_FindsAllShapes()
    {
        var found = CapabilityAuditView.ExtractUuids(
            "a 6f9619ff-8b86-d011-b42d-00c04fc964ff b "
            + "1B671A64-40D5-491E-99B0-DA01FF1F3341 c not-a-uuid");
        Assert.Equal(2, found.Count);
    }
}
