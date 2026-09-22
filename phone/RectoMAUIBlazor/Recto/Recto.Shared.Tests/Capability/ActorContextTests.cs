using System.Text.Json;
using Recto.Shared.Capability;
using Recto.Shared.Protocol.V04;
using Xunit;

namespace Recto.Shared.Tests.Capability;

/// <summary>
/// The actor on a capability card (2026-09-22). Two halves: the wire
/// shape pinned against <c>recto/bootloader/server.py::_pending_to_wire</c>
/// (<c>context.actor_context</c>, snake_case, icon omitted when null), and
/// the one rule that lets an unsigned name and face sit beside a signed
/// subject — <see cref="ActorContextCheck"/>: equal ids or a warning,
/// never a silent pick. Sister of <c>AppContextProtocolTests</c>.
/// </summary>
public class ActorContextTests
{
    [Fact]
    public void ActorContext_DeserializesFromPythonWireShape()
    {
        const string json = """
            {"request_id":"r","kind":"capability_request","service":"s","secret":"c",
             "context":{"child_pid":0,"child_argv0":"(external-agent)","requested_at_unix":1,"operation_description":"test",
                        "cap_agent_id":"myservice-bot",
                        "app_context":{"app_id":"myservice","app_name":"MyService","app_description":""},
                        "actor_context":{"actor_id":"agent:11111111-2222-4333-8444-555555555555",
                                         "actor_name":"Fenwick",
                                         "actor_icon_url":"https://example.com/agents/fenwick.png"}}}
            """;
        var req = JsonSerializer.Deserialize<PendingRequest>(json)!;
        var actor = req.Context.ActorContext;
        Assert.NotNull(actor);
        Assert.Equal("agent:11111111-2222-4333-8444-555555555555", actor!.ActorId);
        Assert.Equal("Fenwick", actor.ActorName);
        Assert.Equal("https://example.com/agents/fenwick.png", actor.ActorIconUrl);
        Assert.Equal("myservice", req.Context.AppContext!.AppId);
    }

    [Fact]
    public void ActorContext_AbsentOnTheWire_IsNull_AndIconIsOptional()
    {
        const string without = """{"request_id":"r","kind":"capability_request","service":"s","secret":"c","context":{"child_pid":0,"child_argv0":"x","requested_at_unix":1,"operation_description":"test"}}""";
        Assert.Null(JsonSerializer.Deserialize<PendingRequest>(without)!.Context.ActorContext);

        const string noIcon = """{"request_id":"r","kind":"capability_request","service":"s","secret":"c","context":{"child_pid":0,"child_argv0":"x","requested_at_unix":1,"operation_description":"test","actor_context":{"actor_id":"agent:a","actor_name":"A"}}}""";
        var actor = JsonSerializer.Deserialize<PendingRequest>(noIcon)!.Context.ActorContext!;
        Assert.Equal("agent:a", actor.ActorId);
        Assert.Null(actor.ActorIconUrl);
    }

    [Fact]
    public void ActorContext_SerializesSnakeCase()
    {
        var json = JsonSerializer.Serialize(new ActorContext("agent:a", "A", "https://e/x.png"));
        Assert.Contains("\"actor_id\":\"agent:a\"", json);
        Assert.Contains("\"actor_name\":\"A\"", json);
        Assert.Contains("\"actor_icon_url\":\"https://e/x.png\"", json);
    }

    // ── the rule ─────────────────────────────────────────────────────

    private const string SignedAgent = "agent:11111111-2222-4333-8444-555555555555";

    [Fact]
    public void NoActor_ShowsNothing_AndWarnsNothing()
    {
        var v = ActorContextCheck.Of(SignedAgent, null);
        Assert.False(v.Show);
        Assert.Null(v.Warning);
    }

    [Fact]
    public void EqualIds_ShowTheNameAndTheFace()
    {
        var v = ActorContextCheck.Of(SignedAgent, new ActorContext(SignedAgent, " Fenwick ", "https://example.com/f.png"));
        Assert.True(v.Show);
        Assert.Equal("Fenwick", v.Name);
        Assert.Equal("https://example.com/f.png", v.IconUrl);
        Assert.Null(v.Warning);
    }

    [Fact]
    public void ADifferentId_IsAWarning_AndNothingIsShown()
    {
        var v = ActorContextCheck.Of(SignedAgent, new ActorContext("agent:someone-else", "Fenwick", "https://example.com/f.png"));
        Assert.False(v.Show);
        Assert.Null(v.Name);
        Assert.Null(v.IconUrl);
        Assert.NotNull(v.Warning);
        Assert.Contains("agent:someone-else", v.Warning);
        Assert.Contains(SignedAgent, v.Warning);
    }

    [Fact]
    public void TheComparisonIsExact_CaseAndWhitespaceCount()
    {
        Assert.False(ActorContextCheck.Of(SignedAgent, new ActorContext(SignedAgent.ToUpperInvariant(), "F")).Show);
        Assert.False(ActorContextCheck.Of(SignedAgent, new ActorContext(SignedAgent + " ", "F")).Show);
    }

    [Fact]
    public void ANonHttpIcon_IsDropped_TheNameStillShows()
    {
        var v = ActorContextCheck.Of(SignedAgent, new ActorContext(SignedAgent, "Fenwick", "javascript:alert(1)"));
        Assert.True(v.Show);
        Assert.Equal("Fenwick", v.Name);
        Assert.Null(v.IconUrl);
    }

    [Fact]
    public void AnEmptyNameOrId_IsAWarning()
    {
        Assert.NotNull(ActorContextCheck.Of(SignedAgent, new ActorContext(SignedAgent, "  ")).Warning);
        Assert.NotNull(ActorContextCheck.Of(SignedAgent, new ActorContext("", "Fenwick")).Warning);
    }
}
