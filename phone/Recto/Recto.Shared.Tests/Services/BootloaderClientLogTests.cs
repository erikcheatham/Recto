using System.Net;
using System.Text;
using Microsoft.Extensions.Logging;
using Recto.Shared.Protocol.V04;
using Recto.Shared.Services;
using Xunit;

namespace Recto.Shared.Tests.Services;

/// <summary>
/// THE LOG NAMES A ROUTE, NEVER A URL OR A BODY (2026-10-27, an outside review; hard rule 2). Every call the
/// client makes carries canary values - in its query, its path, its body and the server's answer - and every
/// outcome is driven: success, refusals with and without a code, error bodies that are not JSON or not an
/// object, malformed JSON, a network failure whose message quotes the url, an unexpected exception, a timeout
/// and a cancellation. No canary may reach a rendered log line, a structured log value or a logged exception,
/// at any level.
/// </summary>
public class BootloaderClientLogTests
{
    private const string Host = "canary-host-5521.example";
    private const string Url = "https://" + Host + "/base";
    private const string PairingCode = "CANARY-PAIRING-314159";
    private const string Nonce = "CANARY-NONCE-b64u";
    private const string PhoneId = "CANARY-PHONE-ID";
    private const string RequestId = "CANARY-REQUEST-ID";
    private const string Totp = "CANARY-TOTP-731904";
    private const string SessionJwt = "CANARY.SESSION.JWT";
    private const string Signature = "CANARY-SIGNATURE";
    private const string WebAuthn = "CANARY-WEBAUTHN";
    private const string PushToken = "CANARY-PUSH-TOKEN";
    private const string Jws = "CANARY.USER.JWS";
    private const string VaultMeta = "CANARY-VAULT-PURPOSE";
    private const string ServerSecret = "CANARY-SERVER-ECHO";

    private static readonly string[] Canaries =
    [
        Host, PairingCode, Nonce, PhoneId, RequestId, Totp, SessionJwt, Signature, WebAuthn, PushToken, Jws,
        VaultMeta, ServerSecret,
    ];

    /// <summary>Every call on the client, by name, with the route its log lines must name.</summary>
    private static readonly Dictionary<string, (string Route, Func<BootloaderClient, CancellationToken, Task> Call)> Calls = new()
    {
        ["registration_challenge"] = ("/v0.4/registration_challenge",
            (c, ct) => c.GetRegistrationChallengeAsync(Url, PairingCode, ct)),
        ["register"] = ("/v0.4/register",
            (c, ct) => c.RegisterAsync(Url, new RegistrationRequest(
                PhoneId, "label", Signature, new[] { V04Protocol.AlgorithmEcdsaP256 }, V04Protocol.Version,
                new RegistrationProof(Nonce, Signature), PushToken: PushToken, PushPlatform: PushPlatform.Fcm,
                PollPublicKeyB64u: Signature, PollKeyDelegationB64u: Signature), ct)),
        ["attest"] = ("/v0.4/attest", (c, ct) => c.AttestAsync(Url, Nonce, ct)),
        ["pending"] = ("/v0.4/pending", (c, ct) => c.GetPendingAsync(Url, PhoneId, ct)),
        ["respond approved"] = ("/v0.4/respond/{id}",
            (c, ct) => c.RespondAsync(Url, RequestId, new RespondRequest(
                PhoneId, RespondDecision.Approved, SignatureB64u: Signature, TotpCode: Totp, SessionJwt: SessionJwt,
                WebAuthnClientDataB64u: WebAuthn, WebAuthnAuthenticatorDataB64u: WebAuthn,
                CapSignatureB64u: Signature), ct)),
        ["respond denied"] = ("/v0.4/respond/{id}",
            (c, ct) => c.RespondAsync(Url, RequestId, new RespondRequest(
                PhoneId, RespondDecision.Denied, Reason: VaultMeta), ct)),
        ["manage phones"] = ("/v0.4/manage/phones", (c, ct) => c.ListRegisteredPhonesAsync(Url, PhoneId, ct)),
        ["revoke challenge"] = ("/v0.4/registration_challenge", (c, ct) => c.GetRevokeChallengeAsync(Url, PhoneId, ct)),
        ["revoke"] = ("/v0.4/manage/phones/revoke",
            (c, ct) => c.RevokePhoneAsync(Url, new RevokeRequest(PhoneId, PhoneId, Nonce, Signature), ct)),
        ["push token"] = ("/v0.4/manage/push_token",
            (c, ct) => c.UpdatePushTokenAsync(Url, new PushTokenUpdateRequest(PhoneId, PushToken, PushPlatform.Fcm), ct)),
        ["devices pair"] = ("/v0.4/devices/pair",
            (c, ct) => c.PairDeviceAsync(Url, new DevicesPairRequest(
                Url, new DevicesPairRecord(Signature, PhoneId, Signature, PairingCode, 1), Jws), ct)),
        ["devices unpair"] = ("/v0.4/devices/unpair",
            (c, ct) => c.UnpairDeviceAsync(Url, new DevicesUnpairRequest(Url, Signature, Jws), ct)),
        ["user-vault grant"] = ("/v0.4/user-vault/grant",
            (c, ct) => c.PostUserVaultGrantAsync(Url, VaultRecord(), ct)),
        ["user-vault revoke"] = ("/v0.4/user-vault/revoke",
            (c, ct) => c.PostUserVaultRevokeAsync(Url, VaultRecord(), ct)),
        ["user-vault revoke-key"] = ("/v0.4/user-vault/revoke-key",
            (c, ct) => c.PostUserVaultRevokeKeyAsync(Url, VaultRecord(), ct)),
        ["user-vault grants"] = ("/v0.4/user-vault/grants",
            (c, ct) => c.ListUserVaultGrantsAsync(Url, new UserVaultGrantsListRequest(VaultFields(), Signature), ct)),
        ["user-vault deny"] = ("/v0.4/user-vault/grant-request/deny",
            (c, ct) => c.DenyUserVaultGrantRequestAsync(Url, PhoneId, RequestId, ct)),
    };

    /// <summary>Every outcome the transport can meet. Each answers with the server's echo of the canaries where a
    /// body is possible, or throws an exception whose message quotes the request's url.</summary>
    private static readonly Dictionary<string, Func<HttpRequestMessage, HttpResponseMessage>> Outcomes = new()
    {
        ["success"] = _ => Answer(HttpStatusCode.OK, "{\"accepted\":true,\"detail\":\"" + ServerSecret + "\"}"),
        ["refused with a code"] = _ => Answer(HttpStatusCode.BadRequest,
            "{\"error\":\"bootloader_error\",\"detail\":\"expired " + ServerSecret + " " + PairingCode + "\"}"),
        ["refused with a sentence"] = _ => Answer(HttpStatusCode.NotFound,
            "{\"error\":\"no such code " + PairingCode + " for " + ServerSecret + "\"}"),
        ["server error, not JSON"] = _ => Answer(HttpStatusCode.InternalServerError,
            "<html>" + ServerSecret + " " + Totp + "</html>"),
        ["server error, a JSON array"] = _ => Answer(HttpStatusCode.InternalServerError, "[\"" + ServerSecret + "\"]"),
        ["server error, empty"] = _ => Answer(HttpStatusCode.BadGateway, ""),
        ["slot occupied"] = _ => Answer(HttpStatusCode.Conflict,
            "{\"error\":\"slot_occupied\",\"occupant\":\"" + ServerSecret + "\"}"),
        ["malformed JSON"] = _ => Answer(HttpStatusCode.OK, "{\"accepted\": " + ServerSecret),
        ["network failure"] = request => throw new HttpRequestException(HttpRequestError.ConnectionError,
            "refused " + request.RequestUri!.AbsoluteUri, new IOException(ServerSecret + " " + request.RequestUri)),
        ["unexpected exception"] = request => throw new InvalidOperationException(
            "broke on " + request.RequestUri!.AbsoluteUri + " " + ServerSecret),
        ["timeout"] = request => throw new TaskCanceledException("timed out " + request.RequestUri!.AbsoluteUri),
        ["cancellation"] = request => throw new OperationCanceledException("cancelled " + request.RequestUri!.AbsoluteUri),
    };

    public static IEnumerable<object[]> EveryCallAndOutcome()
        => from call in Calls.Keys from outcome in Outcomes.Keys select new object[] { call, outcome };

    [Theory]
    [MemberData(nameof(EveryCallAndOutcome))]
    public async Task No_canary_reaches_the_log(string call, string outcome)
    {
        var log = new CapturingLogger();
        var handler = new Handler(Outcomes[outcome]);
        var client = new BootloaderClient(new HttpClient(handler), log);
        using var cts = new CancellationTokenSource();
        if (outcome == "cancellation") cts.Cancel();

        await Calls[call].Call(client, cts.Token);

        if (outcome != "cancellation") Assert.Single(handler.Urls);   // the call met the transport, not a validation
        foreach (var entry in log.Entries)
        {
            foreach (var canary in Canaries)
            {
                Assert.DoesNotContain(canary, entry.Everything, StringComparison.OrdinalIgnoreCase);
            }
        }
    }

    [Theory]
    [MemberData(nameof(EveryCall))]
    public async Task A_refusal_names_the_route_its_status_and_its_code(string call)
    {
        var log = new CapturingLogger();
        var client = new BootloaderClient(new HttpClient(new Handler(Outcomes["refused with a code"])), log);

        await Calls[call].Call(client, CancellationToken.None);

        var warning = Assert.Single(log.Entries, e => e.Level == LogLevel.Warning);
        Assert.Equal($"Bootloader {Method(call)} {Calls[call].Route} returned 400 bootloader_error", warning.Message);
        Assert.DoesNotContain(log.Entries, e => e.Everything.Contains("(unlisted)", StringComparison.Ordinal));
    }

    public static IEnumerable<object[]> EveryCall() => Calls.Keys.Select(k => new object[] { k });

    [Fact]
    public async Task A_body_is_logged_by_its_route_and_size_only()
    {
        var log = new CapturingLogger();
        var handler = new Handler(Outcomes["success"]);
        var client = new BootloaderClient(new HttpClient(handler), log);

        await Calls["respond approved"].Call(client, CancellationToken.None);

        var info = Assert.Single(log.Entries, e => e.Level == LogLevel.Information);
        Assert.Matches(@"^Bootloader POST /v0\.4/respond/\{id\} request, \d+ bytes$", info.Message);
        Assert.Contains(Totp, Assert.Single(handler.Bodies));
    }

    [Fact]
    public async Task A_refusal_without_a_code_shaped_error_names_no_code()
    {
        var log = new CapturingLogger();
        var client = new BootloaderClient(new HttpClient(new Handler(Outcomes["refused with a sentence"])), log);

        await Calls["registration_challenge"].Call(client, CancellationToken.None);

        var warning = Assert.Single(log.Entries, e => e.Level == LogLevel.Warning);
        Assert.Equal("Bootloader GET /v0.4/registration_challenge returned 404 (no error code)", warning.Message);
    }

    [Fact]
    public async Task A_network_failure_logs_its_kind_and_never_the_exception()
    {
        var log = new CapturingLogger();
        var client = new BootloaderClient(new HttpClient(new Handler(Outcomes["network failure"])), log);

        await Calls["attest"].Call(client, CancellationToken.None);

        var warning = Assert.Single(log.Entries, e => e.Level == LogLevel.Warning);
        Assert.Equal("Bootloader GET /v0.4/attest network error HttpRequestException (ConnectionError)", warning.Message);
        Assert.Null(warning.Exception);
    }

    [Fact]
    public async Task An_unexpected_exception_logs_its_kind_at_error_and_never_the_exception()
    {
        var log = new CapturingLogger();
        var client = new BootloaderClient(new HttpClient(new Handler(Outcomes["unexpected exception"])), log);

        await Calls["pending"].Call(client, CancellationToken.None);

        var error = Assert.Single(log.Entries, e => e.Level == LogLevel.Error);
        Assert.Equal("Bootloader GET /v0.4/pending unexpected error InvalidOperationException", error.Message);
        Assert.Null(error.Exception);
    }

    [Fact]
    public async Task A_route_off_the_list_logs_as_unlisted()
    {
        var log = new CapturingLogger();
        var client = new BootloaderClient(new HttpClient(new Handler(Outcomes["refused with a code"])), log);

        await client.PostUserVaultGrantAsync(Url + "/v0.4/odd/" + PairingCode + "?code=" + PairingCode,
            VaultRecord(), CancellationToken.None);

        var warning = Assert.Single(log.Entries, e => e.Level == LogLevel.Warning);
        Assert.Contains("/v0.4/(unlisted)", warning.Message);
        Assert.DoesNotContain(PairingCode, warning.Everything);
    }

    // --- helpers ---

    private static string Method(string call) => call switch
    {
        "registration_challenge" or "attest" or "pending" or "manage phones" or "revoke challenge" => "GET",
        _ => "POST",
    };

    private static Dictionary<string, object?> VaultFields() => new()
    {
        ["purpose"] = VaultMeta,
        ["agent_name"] = VaultMeta,
        ["phone_id"] = PhoneId,
        ["grant_id"] = RequestId,
    };

    private static UserVaultSignedRecord VaultRecord() => new(VaultFields(), Signature);

    private static HttpResponseMessage Answer(HttpStatusCode status, string body) =>
        new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private sealed class Handler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public List<string> Urls { get; } = new();
        public List<string> Bodies { get; } = new();

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Urls.Add(request.RequestUri!.AbsoluteUri);
            Bodies.Add(request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(ct));
            return respond(request);
        }
    }

    private sealed record Entry(LogLevel Level, string Message, Exception? Exception, string Values)
    {
        /// <summary>The rendered line, every structured value a provider would see, and any exception in full.</summary>
        public string Everything => Message + "\n" + Values + "\n" + Exception;
    }

    private sealed class CapturingLogger : ILogger<BootloaderClient>
    {
        public List<Entry> Entries { get; } = new();
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            var values = state is IEnumerable<KeyValuePair<string, object?>> pairs
                ? string.Join("\n", pairs.Select(p => $"{p.Key}={p.Value}"))
                : state?.ToString() ?? string.Empty;
            lock (Entries) Entries.Add(new Entry(logLevel, formatter(state, exception), exception, values));
        }
    }
}
