using System.Text.Json;
using Recto.Shared.Protocol.V04;
using Xunit;
// Disambiguation alias: the implicit System namespace contains
// System.AppContext (a runtime introspection class), and our
// Recto.Shared.Protocol.V04 contains AppContext (the operator-
// administered identity of a requesting app). Without this alias
// the compiler hits CS0104 "ambiguous reference between
// Recto.Shared.Protocol.V04.AppContext and System.AppContext"
// every time the test file uses the bare name. The alias binds
// AppContext to OUR record for the duration of the file; the
// rest of the codebase resolves the bare name through its own
// namespace (PendingRequestContext.cs lives in
// Recto.Shared.Protocol.V04 itself so it sees its own AppContext
// first; Home.razor accesses AppContext as a property name, not
// a type reference, so no collision either).
using AppContext = Recto.Shared.Protocol.V04.AppContext;

namespace Recto.Shared.Tests.Capability;

/// <summary>
/// Pins the C# wire shape for Phase 5 Wave C part 3's AppContext
/// against the Python emit shape in
/// <c>recto/bootloader/server.py::_pending_to_wire</c>. Any drift
/// between the snake_case JsonPropertyName values here and the
/// Python-side dict keys would silently leave the C# AppContext
/// fields null on every wire deserialize, defeating the point of
/// the abstraction (operator sees "Unknown app" warning banner
/// instead of the registered identity).
///
/// <para>
/// Sister to <c>CapabilityRequestProtocolTests</c> which pins the
/// capability_request envelope; this suite covers the AppContext
/// nested object that rides on every phone-rendered request kind.
/// </para>
/// </summary>
public class AppContextProtocolTests
{
    // -----------------------------------------------------------------
    // AppContext: snake_case JsonPropertyName + round-trip
    // -----------------------------------------------------------------

    [Fact]
    public void AppContext_SerializesAllFieldsAsSnakeCase()
    {
        var ac = new AppContext(
            AppId: "myservice",
            AppName: "MyService",
            AppDescription: "Media review platform",
            AppUrl: "https://example.com",
            AppIconUrl: "https://example.com/icon.png",
            AppVersion: "1.4.2");

        var json = JsonSerializer.Serialize(ac);

        Assert.Contains("\"app_id\":\"myservice\"", json);
        Assert.Contains("\"app_name\":\"MyService\"", json);
        Assert.Contains("\"app_description\":\"Media review platform\"", json);
        Assert.Contains("\"app_url\":\"https://example.com\"", json);
        Assert.Contains("\"app_icon_url\":\"https://example.com/icon.png\"", json);
        Assert.Contains("\"app_version\":\"1.4.2\"", json);
    }

    [Fact]
    public void AppContext_DeserializesFromPythonWireShape()
    {
        // Mirror of the wire shape Python's _pending_to_wire emits
        // for context.app_context. Pinning the literal so any
        // JsonPropertyName drift surfaces here before downstream
        // deserialize silently leaves fields null.
        const string pythonWire = """
        {
          "app_id": "myservice",
          "app_name": "MyService",
          "app_description": "Media review platform",
          "app_url": "https://example.com",
          "app_icon_url": "https://example.com/icon.png",
          "app_version": "1.4.2"
        }
        """;

        var ac = JsonSerializer.Deserialize<AppContext>(pythonWire);

        Assert.NotNull(ac);
        Assert.Equal("myservice", ac!.AppId);
        Assert.Equal("MyService", ac.AppName);
        Assert.Equal("Media review platform", ac.AppDescription);
        Assert.Equal("https://example.com", ac.AppUrl);
        Assert.Equal("https://example.com/icon.png", ac.AppIconUrl);
        Assert.Equal("1.4.2", ac.AppVersion);
    }

    [Fact]
    public void AppContext_OptionalFieldsDefaultsAreCorrect()
    {
        // Python side emits app_url / app_icon_url / app_version
        // only when the registered AppContext populated them. The
        // C# record's optional-field defaults must match what
        // System.Text.Json produces when keys are absent.
        const string minimalWire = """
        {"app_id":"x","app_name":"X"}
        """;
        var ac = JsonSerializer.Deserialize<AppContext>(minimalWire);
        Assert.NotNull(ac);
        Assert.Equal("x", ac!.AppId);
        Assert.Equal("X", ac.AppName);
        Assert.Equal("", ac.AppDescription);  // record default
        Assert.Null(ac.AppUrl);
        Assert.Null(ac.AppIconUrl);
        Assert.Null(ac.AppVersion);
    }

    [Fact]
    public void AppContext_RoundTripPreservesOptionalNulls()
    {
        var original = new AppContext(AppId: "x", AppName: "X");
        var json = JsonSerializer.Serialize(original);
        var roundTripped = JsonSerializer.Deserialize<AppContext>(json);
        Assert.Equal(original, roundTripped);
    }

    // -----------------------------------------------------------------
    // PendingRequestContext.AppContext nullable round-trip
    // -----------------------------------------------------------------

    [Fact]
    public void PendingRequestContext_AppContextOmittedWhenNull()
    {
        // PendingRequestContext with AppContext=null should round-trip
        // through JSON without losing the rest of the context.
        var ctx = new PendingRequestContext(
            ChildPid: 1,
            ChildArgv0: "x",
            RequestedAtUnix: 1715000000L,
            OperationDescription: "test",
            PayloadHashB64u: "aA",
            AppContext: null);
        var json = JsonSerializer.Serialize(ctx);
        var roundTripped = JsonSerializer.Deserialize<PendingRequestContext>(json);
        Assert.NotNull(roundTripped);
        Assert.Null(roundTripped!.AppContext);
        Assert.Equal("test", roundTripped.OperationDescription);
    }

    [Fact]
    public void PendingRequestContext_DeserializesWithAppContextNested()
    {
        // The Python wire shape: app_context is a nested object under
        // context. Deserializing should populate AppContext.
        const string wire = """
        {
          "child_pid": 0,
          "child_argv0": "(external-agent)",
          "requested_at_unix": 1715000000,
          "operation_description": "test",
          "payload_hash_b64u": "aA",
          "cap_header_b64": "h",
          "cap_payload_b64": "p",
          "cap_agent_id": "darwin",
          "app_context": {
            "app_id": "myservice",
            "app_name": "MyService",
            "app_description": "Media review platform"
          }
        }
        """;
        var ctx = JsonSerializer.Deserialize<PendingRequestContext>(wire);
        Assert.NotNull(ctx);
        Assert.NotNull(ctx!.AppContext);
        Assert.Equal("myservice", ctx.AppContext!.AppId);
        Assert.Equal("MyService", ctx.AppContext.AppName);
        Assert.Equal("Media review platform", ctx.AppContext.AppDescription);
        // capability fields still preserved
        Assert.Equal("darwin", ctx.CapAgentId);
    }
}
