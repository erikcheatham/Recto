using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Recto.Shared.Common;
using Recto.Shared.Models;
using Recto.Shared.Protocol.V04;
using Recto.Shared.Services;
using Xunit;

namespace Recto.Shared.Tests.Services;

/// <summary>
/// THE POLL KEY (hard rule 14.2, ruling A, 2026-09-21) -- the phone half.
/// <para>
/// THE DEFECT this closes: <see cref="PollSigning"/> shipped in 1.1.0 with a
/// payload test and NO caller, so every read the phone made was bare and the
/// bootloader's evidence window could only ever read <c>unsigned</c>. These
/// tests prove the headers are ATTACHED, at the three read surfaces and at no
/// other, and that the delegation the identity key signs is byte-identical to
/// what the server reconstructs.
/// </para>
/// </summary>
public class PollKeyReadSigningTests
{
    private const string PhoneId = "pk_0123456789abcdef";

    // ------------------------------------------------------------------
    // 1. the client attaches the headers on every read surface
    // ------------------------------------------------------------------

    [Fact]
    public async Task GetPending_CarriesThePollSignatureHeaders()
    {
        var (sut, handler, signer) = Make(Json("{\"requests\":[]}"));

        await sut.GetPendingAsync("http://h", PhoneId, CancellationToken.None);

        var req = Assert.Single(handler.Requests);
        AssertSigned(req, "sig-for-/v0.4/pending");
        Assert.Equal(new[] { (PhoneId, "/v0.4/pending") }, signer.Calls);
    }

    [Fact]
    public async Task ListRegisteredPhones_CarriesThePollSignatureHeaders()
    {
        var (sut, handler, signer) = Make(Json("{\"phones\":[]}"));

        await sut.ListRegisteredPhonesAsync("http://h", PhoneId, CancellationToken.None);

        AssertSigned(Assert.Single(handler.Requests), "sig-for-/v0.4/manage/phones");
        Assert.Equal(new[] { (PhoneId, "/v0.4/manage/phones") }, signer.Calls);
    }

    [Fact]
    public async Task UpdatePushToken_CarriesThePollSignatureHeaders()
    {
        var (sut, handler, signer) = Make(Json("{\"updated\":true,\"phone_id\":\"" + PhoneId + "\"}"));

        await sut.UpdatePushTokenAsync("http://h",
            new PushTokenUpdateRequest(PhoneId, "tok", "fcm"), CancellationToken.None);

        AssertSigned(Assert.Single(handler.Requests), "sig-for-/v0.4/manage/push_token");
        Assert.Equal(new[] { (PhoneId, "/v0.4/manage/push_token") }, signer.Calls);
    }

    [Fact]
    public async Task ThePathSignedIsTheUrlPathOnly_NeverTheQuery()
    {
        // The server reconstructs recto-poll-v1|{id}|{ts}|{path} with path =
        // URL path only. A client that signed "?phone_id=..." into the path
        // would verify on nothing.
        var (sut, _, signer) = Make(Json("{\"requests\":[]}"));
        await sut.GetPendingAsync("http://h/", PhoneId, CancellationToken.None);
        Assert.DoesNotContain("?", signer.Calls[0].Path);
        Assert.DoesNotContain("http", signer.Calls[0].Path);
    }

    // ------------------------------------------------------------------
    // 2. and on no other surface
    // ------------------------------------------------------------------

    [Fact]
    public async Task Register_IsNotSignedByThePollKey()
    {
        // Registration proves the IDENTITY key over the challenge; the poll
        // key does not exist yet from the bootloader's point of view.
        var (sut, handler, signer) = Make(Json(
            "{\"registered\":true,\"phone_id\":\"" + PhoneId + "\",\"bootloader_id\":\"b\",\"managed_secrets\":[]}"));

        await sut.RegisterAsync("http://h", new RegistrationRequest(
            PhoneId, "label", "ipub", new[] { V04Protocol.AlgorithmEcdsaP256 }, V04Protocol.Version,
            new RegistrationProof("c", "s")), CancellationToken.None);

        Assert.Empty(signer.Calls);
        Assert.False(Assert.Single(handler.Requests).Headers.Contains(PollSigning.SignatureHeader));
    }

    [Fact]
    public async Task Respond_IsNotSignedByThePollKey()
    {
        // An approval carries its own identity-key signature in the body. The
        // poll key must never appear on it -- it is a device key.
        var (sut, handler, signer) = Make(Json("{\"accepted\":true,\"detail\":\"ok\"}"));

        await sut.RespondAsync("http://h", "r1",
            new RespondRequest(PhoneId, "approved", "sig", null, null, null), CancellationToken.None);

        Assert.Empty(signer.Calls);
        Assert.False(Assert.Single(handler.Requests).Headers.Contains(PollSigning.SignatureHeader));
    }

    // ------------------------------------------------------------------
    // 3. no signer, or no poll key = bare, as before
    // ------------------------------------------------------------------

    [Fact]
    public async Task WithoutASigner_ReadsGoBare()
    {
        var handler = new RecordingHandler(_ => Json("{\"requests\":[]}"));
        var sut = new BootloaderClient(new HttpClient(handler), NullLogger<BootloaderClient>.Instance);

        await sut.GetPendingAsync("http://h", PhoneId, CancellationToken.None);

        Assert.False(handler.Requests[0].Headers.Contains(PollSigning.SignatureHeader));
    }

    [Fact]
    public async Task WhenTheSignerReturnsNull_ReadsGoBare()
    {
        var (sut, handler, _) = Make(Json("{\"requests\":[]}"), new NullSigner());

        await sut.GetPendingAsync("http://h", PhoneId, CancellationToken.None);

        Assert.False(handler.Requests[0].Headers.Contains(PollSigning.SignatureHeader));
    }

    [Fact]
    public async Task PollKeyReadSigner_IsSilentWhenThePairingRecordedNoPollKey()
    {
        var enclave = new CountingEnclave();
        var signer = new PollKeyReadSigner(enclave, new FixedPairing(PollPublicKeyB64u: null));

        var headers = await signer.SignReadAsync(PhoneId, "/v0.4/pending", CancellationToken.None);

        Assert.Null(headers);
        Assert.Equal(0, enclave.SignCalls);
    }

    [Fact]
    public async Task PollKeyReadSigner_SignsWithThePollAlias_WhenThePairingRecordedOne()
    {
        var enclave = new CountingEnclave();
        var signer = new PollKeyReadSigner(enclave, new FixedPairing(PollPublicKeyB64u: "ppub"));

        var headers = await signer.SignReadAsync(PhoneId, "/v0.4/pending", CancellationToken.None);

        Assert.NotNull(headers);
        Assert.Equal(1, enclave.SignCalls);
        Assert.Equal(PollSigning.PollKeyAlias, enclave.LastAlias);
        Assert.StartsWith($"{PollSigning.Prefix}|{PhoneId}|", Encoding.ASCII.GetString(enclave.LastMessage!));
        Assert.EndsWith("|/v0.4/pending", Encoding.ASCII.GetString(enclave.LastMessage!));
    }

    // ------------------------------------------------------------------
    // 4. the delegation bytes match the server
    // ------------------------------------------------------------------

    [Fact]
    public void DelegationPayload_MatchesTheServerReconstruction()
    {
        // server: f"recto-poll-key-v1|{public_key_b64u}|{poll_public_key_b64u}".encode("ascii")
        var bytes = PollSigning.BuildDelegationPayload("IDENT_b64u", "POLL_b64u");
        Assert.Equal("recto-poll-key-v1|IDENT_b64u|POLL_b64u", Encoding.ASCII.GetString(bytes));
        Assert.Equal("recto-poll-key-v1", PollSigning.DelegationPrefix);
    }

    [Fact]
    public void PollKeyAlias_IsNotTheIdentityAlias()
    {
        // Home.razor's identity alias is "recto.phone.identity"; a shared alias
        // would let GenerateDeviceKeyAsync overwrite the identity key.
        Assert.NotEqual("recto.phone.identity", PollSigning.PollKeyAlias);
    }

    // --- helpers ---

    private static void AssertSigned(HttpRequestMessage req, string expectedSig)
    {
        Assert.True(req.Headers.TryGetValues(PollSigning.SignatureHeader, out var sig));
        Assert.Equal(expectedSig, Assert.Single(sig!));
        Assert.True(req.Headers.TryGetValues(PollSigning.TimestampHeader, out var ts));
        Assert.Equal("1755000000", Assert.Single(ts!));
    }

    private static (BootloaderClient Sut, RecordingHandler Handler, FakeSigner Signer) Make(
        HttpResponseMessage response, IReadSigner? signerOverride = null)
    {
        var handler = new RecordingHandler(_ => response);
        var signer = new FakeSigner();
        var sut = new BootloaderClient(new HttpClient(handler), NullLogger<BootloaderClient>.Instance,
            signerOverride ?? signer);
        return (sut, handler, signer);
    }

    private static HttpResponseMessage Json(string body) =>
        new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private sealed class FakeSigner : IReadSigner
    {
        public List<(string PhoneId, string Path)> Calls { get; } = new();
        public Task<PollSignatureHeaders?> SignReadAsync(string phoneId, string path, CancellationToken ct)
        {
            Calls.Add((phoneId, path));
            return Task.FromResult<PollSignatureHeaders?>(new PollSignatureHeaders($"sig-for-{path}", 1755000000));
        }
    }

    private sealed class NullSigner : IReadSigner
    {
        public Task<PollSignatureHeaders?> SignReadAsync(string phoneId, string path, CancellationToken ct)
            => Task.FromResult<PollSignatureHeaders?>(null);
    }

    private sealed class FixedPairing : IPairingStateService
    {
        private readonly PairingState _state;
        public FixedPairing(string? PollPublicKeyB64u)
            => _state = new PairingState(PhoneId, "b", "http://h", Array.Empty<ManagedSecretRef>(),
                DateTimeOffset.UnixEpoch, PollPublicKeyB64u: PollPublicKeyB64u);
        public Task<Result<PairingState?>> GetCurrentAsync(CancellationToken ct)
            => Task.FromResult(Result.Success<PairingState?>(_state));
        public Task<Result> SaveAsync(PairingState state, CancellationToken ct) => Task.FromResult(Result.Success());
        public Task<Result> ClearAsync(CancellationToken ct) => Task.FromResult(Result.Success());
        public Task<Result<string>> GetOrCreatePhoneIdAsync(CancellationToken ct) => Task.FromResult(Result.Success(PhoneId));
    }

    private sealed class CountingEnclave : IEnclaveKeyService
    {
        public int SignCalls;
        public string? LastAlias;
        public byte[]? LastMessage;
        public string Algorithm => V04Protocol.AlgorithmEcdsaP256;
        public Task<Result<EnclavePublicKey>> GenerateAsync(string keyAlias, CancellationToken ct) => throw new NotSupportedException();
        public Task<Result<bool>> KeyExistsAsync(string keyAlias, CancellationToken ct) => Task.FromResult(Result.Success(true));
        public Task<Result<EnclavePublicKey>> GetPublicKeyAsync(string keyAlias, CancellationToken ct) => throw new NotSupportedException();
        public Task<Result<byte[]>> SignAsync(string keyAlias, byte[] message, CancellationToken ct)
        {
            SignCalls++; LastAlias = keyAlias; LastMessage = message;
            return Task.FromResult(Result.Success(new byte[64]));
        }
        public Task<Result> DeleteAsync(string keyAlias, CancellationToken ct) => Task.FromResult(Result.Success());
    }

    private sealed class RecordingHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _respond;
        public List<HttpRequestMessage> Requests { get; } = new();
        public RecordingHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) => _respond = respond;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Requests.Add(request);
            return Task.FromResult(_respond(request));
        }
    }
}
