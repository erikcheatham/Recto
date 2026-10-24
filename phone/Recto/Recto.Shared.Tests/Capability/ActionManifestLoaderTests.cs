using System;
using System.IO;
using Recto.Shared.Capability;
using Xunit;

namespace Recto.Shared.Tests.Capability;

/// <summary>
/// Pins the C# action-manifest loader and scope-evaluation helpers against
/// the same canonical claims and counts the Python tests pin in
/// <c>tests/test_capability.py</c>. The test fixture
/// <c>Capability/Fixtures/manifest_v1.json</c> is a copy of
/// <c>recto/capability/manifest_v1.json</c> &mdash; if either drifts the
/// other must update in lockstep.
/// </summary>
public class ActionManifestLoaderTests
{
    private static string FixturePath => Path.Combine(
        AppContext.BaseDirectory, "Capability", "Fixtures", "manifest_v1.json");

    private static ActionManifest LoadTemplate() =>
        ActionManifestLoader.Load(FixturePath);

    // -----------------------------------------------------------------
    // Manifest loading + canonical content pins
    // -----------------------------------------------------------------

    [Fact]
    public void TemplateManifest_LoadsAndCarriesCanonicalVersion()
    {
        var m = LoadTemplate();
        Assert.Equal("2026-05-05", m.Version);
        Assert.Contains("doc:edit", m.Actions.Keys);
        Assert.Contains("darwin:doc-edits", m.Groups.Keys);
    }

    [Fact]
    public void TemplateManifest_DocEditCountIsOne()
    {
        var m = LoadTemplate();
        Assert.Equal(1, m.Actions["doc:edit"].Count);
    }

    [Fact]
    public void TemplateManifest_SecretRotateCountIsFifty()
    {
        var m = LoadTemplate();
        Assert.Equal(50, m.Actions["secret:rotate"].Count);
    }

    [Fact]
    public void TemplateManifest_DarwinDocEditsGroupWeightsToThree()
    {
        // doc:edit (1) + doc:rename (1) + claude-md:update (1) = 3
        var m = LoadTemplate();
        Assert.Equal(3, m.GroupWeight("darwin:doc-edits"));
    }

    [Fact]
    public void TemplateManifest_DarwinStarterCapabilityTotalsEighteen()
    {
        // Pinned regression: doc-edits (3) + staging-deploys (5+1+2 = 8) +
        // secret-reads (5) + public-comms (2) = 18, well within Tier 1 (30).
        var m = LoadTemplate();
        long total = m.GroupWeight("darwin:doc-edits")
                   + m.GroupWeight("darwin:staging-deploys")
                   + m.GroupWeight("darwin:secret-reads")
                   + m.GroupWeight("darwin:public-comms");
        Assert.Equal(18L, total);
        Assert.True(total <= TierWeightCeilings.Tier1);
    }

    [Fact]
    public void TemplateManifest_CatastrophicGroupExceedsTier2Ceiling()
    {
        // capability:revoke-other (100) + treasury:transfer (200) +
        // operator-key:rotate (500) = 800, past Tier 2's ceiling of 100.
        var m = LoadTemplate();
        var weight = m.GroupWeight("operator:catastrophic");
        Assert.True(weight > TierWeightCeilings.Tier2,
            $"catastrophic weight {weight} should exceed Tier2 ceiling {TierWeightCeilings.Tier2}");
    }

    [Fact]
    public void Load_RejectsMissingVersion()
    {
        const string json = "{ \"actions\": {}, \"groups\": {} }";
        var ex = Assert.Throws<InvalidDataException>(
            () => ActionManifestLoader.LoadFromJson(json));
        Assert.Contains("version", ex.Message);
    }

    [Fact]
    public void Load_RejectsNegativeCount()
    {
        const string json = """
            {
              "version": "test",
              "actions": { "bad:action": { "count": -1, "description": "no" } },
              "groups": {}
            }
            """;
        var ex = Assert.Throws<InvalidDataException>(
            () => ActionManifestLoader.LoadFromJson(json));
        Assert.Contains("non-negative", ex.Message);
    }

    [Fact]
    public void Load_RejectsUnknownActionInGroup()
    {
        const string json = """
            {
              "version": "test",
              "actions": { "a:1": { "count": 1, "description": "" } },
              "groups": { "g1": { "actions": ["a:1", "missing:action"] } }
            }
            """;
        var ex = Assert.Throws<InvalidDataException>(
            () => ActionManifestLoader.LoadFromJson(json));
        Assert.Contains("unknown action", ex.Message);
    }

    [Fact]
    public void Load_RejectsNonIntegerCount()
    {
        const string json = """
            {
              "version": "test",
              "actions": { "a:1": { "count": "five", "description": "" } },
              "groups": {}
            }
            """;
        var ex = Assert.Throws<InvalidDataException>(
            () => ActionManifestLoader.LoadFromJson(json));
        Assert.Contains("non-negative", ex.Message);
    }

    // -----------------------------------------------------------------
    // Scope resolution
    // -----------------------------------------------------------------

    [Fact]
    public void ResolveActions_ExpandsGroups()
    {
        var m = LoadTemplate();
        var clause = CapabilityClause.Create(
            tier: 1,
            registryVersion: "2026-05-05",
            groups: new[] { "darwin:doc-edits" });
        var permitted = ActionManifestLoader.ResolveActions(clause, m);
        Assert.Contains("doc:edit", permitted);
        Assert.Contains("doc:rename", permitted);
        Assert.Contains("claude-md:update", permitted);
        Assert.DoesNotContain("deploy:staging", permitted);
    }

    [Fact]
    public void ResolveActions_CombinesGroups()
    {
        var m = LoadTemplate();
        var clause = CapabilityClause.Create(
            tier: 1,
            registryVersion: "2026-05-05",
            groups: new[] { "darwin:doc-edits", "darwin:staging-deploys" });
        var permitted = ActionManifestLoader.ResolveActions(clause, m);
        Assert.Contains("doc:edit", permitted);
        Assert.Contains("deploy:staging", permitted);
        Assert.Contains("smoke-test", permitted);
    }

    [Fact]
    public void ResolveActions_SubtractsDeny()
    {
        var m = LoadTemplate();
        var clause = CapabilityClause.Create(
            tier: 1,
            registryVersion: "2026-05-05",
            groups: new[] { "darwin:doc-edits" },
            denyActions: new[] { "doc:rename" });
        var permitted = ActionManifestLoader.ResolveActions(clause, m);
        Assert.Contains("doc:edit", permitted);
        Assert.DoesNotContain("doc:rename", permitted);
        Assert.Contains("claude-md:update", permitted);
    }

    [Fact]
    public void ResolveActions_AddsAllow()
    {
        var m = LoadTemplate();
        var clause = CapabilityClause.Create(
            tier: 1,
            registryVersion: "2026-05-05",
            groups: new[] { "darwin:doc-edits" },
            allowActions: new[] { "secret:read" });
        var permitted = ActionManifestLoader.ResolveActions(clause, m);
        Assert.Contains("secret:read", permitted);
        Assert.Contains("doc:edit", permitted);
    }

    [Fact]
    public void ResolveActions_ThrowsOnVersionMismatch()
    {
        var m = LoadTemplate();
        var clause = CapabilityClause.Create(
            tier: 1, registryVersion: "OLD-VERSION");
        var ex = Assert.Throws<InvalidOperationException>(
            () => ActionManifestLoader.ResolveActions(clause, m));
        Assert.Contains("registry_version", ex.Message);
    }

    [Fact]
    public void ResolveActions_ThrowsOnUnknownGroup()
    {
        var m = LoadTemplate();
        var clause = CapabilityClause.Create(
            tier: 1,
            registryVersion: "2026-05-05",
            groups: new[] { "unknown:group" });
        var ex = Assert.Throws<InvalidOperationException>(
            () => ActionManifestLoader.ResolveActions(clause, m));
        Assert.Contains("unknown group", ex.Message);
    }

    [Fact]
    public void EvaluateScope_PermitsAuthorizedAction()
    {
        var m = LoadTemplate();
        var clause = CapabilityClause.Create(
            tier: 1,
            registryVersion: "2026-05-05",
            groups: new[] { "darwin:staging-deploys" });
        Assert.True(ActionManifestLoader.EvaluateScope("deploy:staging", clause, m));
        Assert.True(ActionManifestLoader.EvaluateScope("smoke-test", clause, m));
    }

    [Fact]
    public void EvaluateScope_DeniesUnauthorizedAction()
    {
        var m = LoadTemplate();
        var clause = CapabilityClause.Create(
            tier: 1,
            registryVersion: "2026-05-05",
            groups: new[] { "darwin:doc-edits" });
        Assert.False(ActionManifestLoader.EvaluateScope("deploy:prod", clause, m));
        Assert.False(ActionManifestLoader.EvaluateScope("secret:rotate", clause, m));
    }

    [Fact]
    public void EvaluateScope_FailsClosedOnUnknownGroup()
    {
        var m = LoadTemplate();
        var clause = CapabilityClause.Create(
            tier: 1,
            registryVersion: "2026-05-05",
            groups: new[] { "unknown:group" });
        Assert.False(ActionManifestLoader.EvaluateScope("anything", clause, m));
    }

    [Fact]
    public void EvaluateScope_FailsClosedOnVersionMismatch()
    {
        var m = LoadTemplate();
        var clause = CapabilityClause.Create(
            tier: 1,
            registryVersion: "OLD-VERSION",
            groups: new[] { "darwin:doc-edits" });
        Assert.False(ActionManifestLoader.EvaluateScope("doc:edit", clause, m));
    }

    // -----------------------------------------------------------------
    // Weight breakdown — phone-side approval UI shape
    // -----------------------------------------------------------------

    [Fact]
    public void WeightBreakdown_BasicShape()
    {
        var m = LoadTemplate();
        var clause = CapabilityClause.Create(
            tier: 1,
            registryVersion: "2026-05-05",
            groups: new[] { "darwin:doc-edits" });
        var b = ActionManifestLoader.ClauseWeightBreakdown(clause, m);
        Assert.Equal(1, b.Tier);
        Assert.Equal(TierWeightCeilings.Tier1, b.TierCeiling);
        Assert.Equal(3L, b.Total);
        Assert.Single(b.Groups);
        Assert.Equal(3L, b.Groups[0].Weight);
        Assert.Equal("darwin:doc-edits", b.Groups[0].Key);
    }

    [Fact]
    public void WeightBreakdown_ExtraActions()
    {
        var m = LoadTemplate();
        var clause = CapabilityClause.Create(
            tier: 1,
            registryVersion: "2026-05-05",
            groups: new[] { "darwin:doc-edits" },
            allowActions: new[] { "secret:read" });
        var b = ActionManifestLoader.ClauseWeightBreakdown(clause, m);
        // doc-edits group (3) + secret:read action (5) = 8
        Assert.Equal(8L, b.Total);
        Assert.Single(b.ExtraActions);
        Assert.Equal("secret:read", b.ExtraActions[0].Key);
        Assert.Equal(5L, b.ExtraActions[0].Count);
    }

    [Fact]
    public void WeightBreakdown_FullDarwinStarterTotalsEighteen()
    {
        // Pinned regression mirroring the Python full-Darwin-starter test.
        var m = LoadTemplate();
        var clause = CapabilityClause.Create(
            tier: 1,
            registryVersion: "2026-05-05",
            groups: new[]
            {
                "darwin:doc-edits",
                "darwin:staging-deploys",
                "darwin:secret-reads",
                "darwin:public-comms",
            });
        var b = ActionManifestLoader.ClauseWeightBreakdown(clause, m);
        Assert.Equal(18L, b.Total);
        Assert.Equal(1, b.Tier);
        Assert.Equal(TierWeightCeilings.Tier1, b.TierCeiling);
    }

    [Fact]
    public void WeightBreakdown_DeniedActionsListed()
    {
        var m = LoadTemplate();
        var clause = CapabilityClause.Create(
            tier: 1,
            registryVersion: "2026-05-05",
            groups: new[] { "darwin:doc-edits" },
            denyActions: new[] { "secret:rotate" });
        var b = ActionManifestLoader.ClauseWeightBreakdown(clause, m);
        Assert.Equal(new[] { "secret:rotate" }, b.DeniedActions);
    }
}
