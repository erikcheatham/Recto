using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Recto.Shared.Protocol.V04;
using Recto.Shared.Services;
using Xunit;

namespace Recto.Shared.Tests;

public class BootloaderClientTests
{
    [Fact]
    public async Task GetRegistrationChallenge_BuildsCanonicalUrl()
    {
        var handler = new RecordingHandler(_ => Json(HttpStatusCode.OK,
            "{\"challenge_b64u\":\"abc\",\"expires_at_unix\":12345,\"bootloader_id\":\"b\",\"supported_algorithms\":[\"ed25519\"]}"));
        var sut = MakeClient(handler);

        var result = await sut.GetRegistrationChallengeAsync(
            "http://127.0.0.1:8443", "314159", CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Get, handler.Requests[0].Method);
        Assert.Equal("http://127.0.0.1:8443/v0.4/registration_challenge?code=314159",
                     handler.Requests[0].RequestUri!.ToString());
    }

    [Fact]
    public async Task GetRegistrationChallenge_TrimsTrailingSlashOnBootloaderUrl()
    {
        var handler = new RecordingHandler(_ => Json(HttpStatusCode.OK,
            "{\"challenge_b64u\":\"abc\",\"expires_at_unix\":12345,\"bootloader_id\":\"b\",\"supported_algorithms\":[\"ed25519\"]}"));
        var sut = MakeClient(handler);

        await sut.GetRegistrationChallengeAsync(
            "http://127.0.0.1:8443/", "abc", CancellationToken.None);

        Assert.DoesNotContain("//v0.4", handler.Requests[0].RequestUri!.ToString());
    }

    [Fact]
    public async Task GetRegistrationChallenge_UrlEncodesPairingCode()
    {
        var handler = new RecordingHandler(_ => Json(HttpStatusCode.OK,
            "{\"challenge_b64u\":\"abc\",\"expires_at_unix\":12345,\"bootloader_id\":\"b\",\"supported_algorithms\":[\"ed25519\"]}"));
        var sut = MakeClient(handler);

        await sut.GetRegistrationChallengeAsync(
            "http://h", "code with spaces", CancellationToken.None);

        // Use AbsoluteUri (preserves percent-encoding) rather than
        // ToString() which can decode %20 back to literal space under
        // Uri's IRI-parsing canonical-form rules. The on-wire form
        // (what the bootloader sees) is the AbsoluteUri shape; that's
        // what the test should assert against.
        Assert.Contains("code%20with%20spaces", handler.Requests[0].RequestUri!.AbsoluteUri);
    }

    [Theory]
    [InlineData("", "code")]
    [InlineData("  ", "code")]
    [InlineData("http://h", "")]
    [InlineData("http://h", "  ")]
    public async Task GetRegistrationChallenge_RejectsBlankInputs(string url, string code)
    {
        var sut = MakeClient(new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)));

        var result = await sut.GetRegistrationChallengeAsync(url, code, CancellationToken.None);

        Assert.True(result.IsFailure);
    }

    [Fact]
    public async Task RegisterAsync_PostsJsonBodyToCanonicalEndpoint()
    {
        var handler = new RecordingHandler(_ => Json(HttpStatusCode.OK,
            "{\"phone_id\":\"p\",\"bootloader_id\":\"b\",\"paired_at\":\"2026-04-26T00:00:00Z\",\"managed_secrets\":[]}"));
        var sut = MakeClient(handler);
        var req = SampleRegistrationRequest();

        var result = await sut.RegisterAsync("http://127.0.0.1:8443", req, CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal(HttpMethod.Post, handler.Requests[0].Method);
        Assert.Equal("http://127.0.0.1:8443/v0.4/register",
                     handler.Requests[0].RequestUri!.ToString());
        Assert.Equal("application/json",
                     handler.Requests[0].Content!.Headers.ContentType!.MediaType);
    }

    [Fact]
    public async Task RegisterAsync_BodyHasNonZeroContentLengthAndExpectedFields()
    {
        // Pins the JsonContent.Create vs StringContent fix from round 2.
        // If Content-Length comes back 0, the MAUI HttpClient pipeline swallowed
        // the body and the bootloader will see "{}".
        string? capturedBody = null;
        var handler = new RecordingHandler(req =>
        {
            if (req.Content is not null)
            {
                capturedBody = req.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            }
            return Json(HttpStatusCode.OK,
                "{\"phone_id\":\"p\",\"bootloader_id\":\"b\",\"paired_at\":\"2026-04-26T00:00:00Z\",\"managed_secrets\":[]}");
        });
        var sut = MakeClient(handler);
        var req = SampleRegistrationRequest();

        await sut.RegisterAsync("http://h", req, CancellationToken.None);

        Assert.False(string.IsNullOrEmpty(capturedBody));
        Assert.Contains("\"phone_id\"", capturedBody);
        Assert.Contains("\"public_key_b64u\"", capturedBody);
        Assert.Contains("\"supported_algorithms\"", capturedBody);
        Assert.Contains("\"registration_proof\"", capturedBody);
    }

    [Fact]
    public async Task GetPendingAsync_BuildsUrlWithPhoneIdQuery()
    {
        var handler = new RecordingHandler(_ => Json(HttpStatusCode.OK, "{\"requests\":[]}"));
        var sut = MakeClient(handler);

        await sut.GetPendingAsync("http://h", "phone-id-1", CancellationToken.None);

        Assert.Contains("phone_id=phone-id-1", handler.Requests[0].RequestUri!.ToString());
        Assert.Contains("/v0.4/pending", handler.Requests[0].RequestUri!.ToString());
    }

    [Fact]
    public async Task RespondAsync_PutsRequestIdInPath()
    {
        var handler = new RecordingHandler(_ => Json(HttpStatusCode.OK,
            "{\"accepted\":true,\"detail\":\"ok\"}"));
        var sut = MakeClient(handler);
        var req = new RespondRequest("phone-id-1", "approved", "sig", null, null, null);

        await sut.RespondAsync("http://h", "request-7", req, CancellationToken.None);

        Assert.Contains("/v0.4/respond/request-7", handler.Requests[0].RequestUri!.ToString());
    }

    [Fact]
    public async Task ListRegisteredPhones_BuildsCanonicalUrl()
    {
        var handler = new RecordingHandler(_ => Json(HttpStatusCode.OK, "{\"phones\":[]}"));
        var sut = MakeClient(handler);

        await sut.ListRegisteredPhonesAsync("http://h", "phone-id-1", CancellationToken.None);

        Assert.Contains("/v0.4/manage/phones", handler.Requests[0].RequestUri!.ToString());
        Assert.Contains("phone_id=phone-id-1", handler.Requests[0].RequestUri!.ToString());
    }

    [Fact]
    public async Task NonSuccessStatusReturnsFailureNotException()
    {
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.NotFound)
        {
            Content = new StringContent("{\"error\":\"not found\"}", Encoding.UTF8, "application/json"),
        });
        var sut = MakeClient(handler);

        var result = await sut.GetRegistrationChallengeAsync("http://h", "code", CancellationToken.None);

        Assert.True(result.IsFailure);
    }

    [Fact]
    public async Task NetworkExceptionReturnsFailureNotException()
    {
        var handler = new RecordingHandler(_ => throw new HttpRequestException("connection refused"));
        var sut = MakeClient(handler);

        var result = await sut.GetRegistrationChallengeAsync("http://h", "code", CancellationToken.None);

        Assert.True(result.IsFailure);
    }

    [Fact]
    public async Task CancelledTokenReturnsFailureNotException()
    {
        var handler = new RecordingHandler(_ => throw new OperationCanceledException());
        var sut = MakeClient(handler);
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var result = await sut.GetRegistrationChallengeAsync("http://h", "code", cts.Token);

        Assert.True(result.IsFailure);
    }

    // --- helpers ---

    private static BootloaderClient MakeClient(RecordingHandler handler)
    {
        var http = new HttpClient(handler);
        return new BootloaderClient(http, NullLogger<BootloaderClient>.Instance);
    }

    private static RegistrationRequest SampleRegistrationRequest() => new(
        PhoneId: "phone-id-1",
        DeviceLabel: "Recto / Test",
        PublicKeyB64u: "pk-bytes-base64url",
        SupportedAlgorithms: new[] { V04Protocol.AlgorithmEd25519 },
        V04Protocol: V04Protocol.Version,
        RegistrationProof: new RegistrationProof("challenge-bytes", "signature-bytes"));

    private static HttpResponseMessage Json(HttpStatusCode status, string body) =>
        new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private sealed class RecordingHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _respond;
        public List<HttpRequestMessage> Requests { get; } = new();

        public RecordingHandler(Func<HttpRequestMessage, HttpResponseMessage> respond)
        {
            _respond = respond;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request);
            return Task.FromResult(_respond(request));
        }
    }
}
