using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Recto.Shared.Common;
using Recto.Shared.Models;
using Recto.Shared.Protocol.V04;
using Recto.Shared.Services;
using Xunit;

namespace Recto.Shared.Tests.Services;

/// <summary>
/// THE PUSH TOKEN, KEPT CURRENT. A paired phone fetches its platform token on
/// every launch and resume and sends it to <c>POST /v0.4/manage/push_token</c>
/// only when it differs from the last one this phone sent to that bootloader.
/// The last-sent record is a hash; the token itself is never stored.
/// </summary>
public class PushTokenSyncTests
{
    private const string PhoneId = "0e21fbd1-43e0-4734-a845-d2863c0d2a0e";
    private const string Url = "https://bootloader.example";
    private const string TokenA = "fcm-token-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private const string TokenB = "fcm-token-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    // Every sync and fetch below is awaited under this bound, so a fetch that
    // loses its own bound, or a sync gate that is never released, fails the
    // test that met it instead of hanging the run.
    private static readonly TimeSpan TestBound = TimeSpan.FromSeconds(5);

    // ------------------------------------------------------------------
    // the re-send decision
    // ------------------------------------------------------------------

    [Fact]
    public async Task TheFirstTokenAPairedPhoneSees_IsSent()
    {
        var h = new Harness(TokenA);

        var outcome = await h.SyncAsync(Paired("rb1-one"), Url, CancellationToken.None);

        Assert.Equal(PushTokenSyncOutcome.Sent, outcome);
        var sent = Assert.Single(h.Http.Bodies);
        Assert.Equal("https://bootloader.example/v0.4/manage/push_token", Assert.Single(h.Http.Urls));
        using var doc = JsonDocument.Parse(sent);
        Assert.Equal(PhoneId, doc.RootElement.GetProperty("phone_id").GetString());
        Assert.Equal(TokenA, doc.RootElement.GetProperty("push_token").GetString());
        Assert.Equal(PushPlatform.Fcm, doc.RootElement.GetProperty("push_platform").GetString());
    }

    [Fact]
    public async Task AnUnchangedToken_IsNotSentAgain()
    {
        var h = new Harness(TokenA);

        await h.SyncAsync(Paired("rb1-one"), Url, CancellationToken.None);
        var second = await h.SyncAsync(Paired("rb1-one"), Url, CancellationToken.None);

        Assert.Equal(PushTokenSyncOutcome.Unchanged, second);
        Assert.Single(h.Http.Bodies);
    }

    [Fact]
    public async Task AChangedToken_IsSent()
    {
        var h = new Harness(TokenA);

        await h.SyncAsync(Paired("rb1-one"), Url, CancellationToken.None);
        h.Tokens.Token = TokenB;
        var second = await h.SyncAsync(Paired("rb1-one"), Url, CancellationToken.None);

        Assert.Equal(PushTokenSyncOutcome.Sent, second);
        Assert.Equal(2, h.Http.Bodies.Count);
        Assert.Contains(TokenB, h.Http.Bodies[1]);
    }

    [Fact]
    public async Task ThePlatformIsPartOfWhatWasSent()
    {
        var h = new Harness(TokenA);

        await h.SyncAsync(Paired("rb1-one"), Url, CancellationToken.None);
        h.Tokens.Platform = PushPlatform.Apns;
        var second = await h.SyncAsync(Paired("rb1-one"), Url, CancellationToken.None);

        Assert.Equal(PushTokenSyncOutcome.Sent, second);
    }

    [Fact]
    public async Task AnotherBootloader_GetsTheTokenEvenWhenItIsUnchanged()
    {
        var h = new Harness(TokenA);

        await h.SyncAsync(Paired("rb1-one"), Url, CancellationToken.None);
        var other = await h.SyncAsync(Paired("rb1-two"), Url, CancellationToken.None);

        Assert.Equal(PushTokenSyncOutcome.Sent, other);
        Assert.Equal(2, h.Http.Bodies.Count);
    }

    [Fact]
    public async Task WithoutAPairedBootloader_NothingIsFetchedOrSent()
    {
        var h = new Harness(TokenA);

        var outcome = await h.SyncAsync(null, Url, CancellationToken.None);

        Assert.Equal(PushTokenSyncOutcome.NotPaired, outcome);
        Assert.Empty(h.Http.Bodies);
        Assert.Equal(0, h.Tokens.Calls);
    }

    [Fact]
    public async Task ADemoPairing_IsNeverSent()
    {
        var h = new Harness(TokenA);
        var demo = Paired("demo-bootloader") with { BootloaderUrl = "demo://bootloader" };

        var outcome = await h.SyncAsync(demo, "demo://bootloader", CancellationToken.None);

        Assert.Equal(PushTokenSyncOutcome.NotPaired, outcome);
        Assert.Empty(h.Http.Bodies);
    }

    [Fact]
    public async Task NoTokenOnThisPlatform_SendsNothing()
    {
        var h = new Harness(token: null);

        var outcome = await h.SyncAsync(Paired("rb1-one"), Url, CancellationToken.None);

        Assert.Equal(PushTokenSyncOutcome.NoToken, outcome);
        Assert.Empty(h.Http.Bodies);
    }

    [Fact]
    public async Task TheLaunchPath_NeverUsesThePromptingFetch()
    {
        var h = new Harness(TokenA);

        await h.SyncAsync(Paired("rb1-one"), Url, CancellationToken.None);

        Assert.Equal(0, h.Tokens.PromptingCalls);
        Assert.Equal(1, h.Tokens.QuietCalls);
    }

    [Fact]
    public async Task AFailedSend_IsNotRecorded_SoTheNextLaunchTriesAgain()
    {
        var h = new Harness(TokenA);
        h.Http.Status = HttpStatusCode.InternalServerError;

        var first = await h.SyncAsync(Paired("rb1-one"), Url, CancellationToken.None);
        h.Http.Status = HttpStatusCode.OK;
        var second = await h.SyncAsync(Paired("rb1-one"), Url, CancellationToken.None);

        Assert.Equal(PushTokenSyncOutcome.SendFailed, first);
        Assert.Equal(PushTokenSyncOutcome.Sent, second);
    }

    [Fact]
    public async Task AReplyThatDidNotUpdate_IsNotRecorded()
    {
        var h = new Harness(TokenA);
        h.Http.Reply = "{\"updated\":false,\"phone_id\":\"" + PhoneId + "\"}";

        var outcome = await h.SyncAsync(Paired("rb1-one"), Url, CancellationToken.None);

        Assert.Equal(PushTokenSyncOutcome.SendFailed, outcome);
        Assert.Empty(h.Store.Values);
    }

    [Fact]
    public async Task OverlappingSyncs_SendTheTokenOnce()
    {
        var h = new Harness(TokenA);
        h.Http.Delay = TimeSpan.FromMilliseconds(100);

        var outcomes = await Task.WhenAll(
            h.SyncAsync(Paired("rb1-one"), Url, CancellationToken.None),
            h.SyncAsync(Paired("rb1-one"), Url, CancellationToken.None),
            h.SyncAsync(Paired("rb1-one"), Url, CancellationToken.None));

        Assert.Single(h.Http.Bodies);
        Assert.Single(outcomes, o => o == PushTokenSyncOutcome.Sent);
    }

    // ------------------------------------------------------------------
    // what the store holds
    // ------------------------------------------------------------------

    [Fact]
    public async Task TheStore_NeverHoldsTheRawToken()
    {
        var h = new Harness(TokenA);

        await h.SyncAsync(Paired("rb1-one"), Url, CancellationToken.None);
        h.Tokens.Token = TokenB;
        await h.SyncAsync(Paired("rb1-one"), Url, CancellationToken.None);
        await h.RecordRegistrationAsync(Paired("rb1-two"), new PushToken(TokenA, PushPlatform.Fcm), CancellationToken.None);

        Assert.NotEmpty(h.Store.Writes);
        foreach (var (key, value) in h.Store.Writes)
        {
            Assert.DoesNotContain(TokenA, key);
            Assert.DoesNotContain(TokenB, key);
            Assert.DoesNotContain(TokenA, value ?? string.Empty);
            Assert.DoesNotContain(TokenB, value ?? string.Empty);
        }
    }

    [Fact]
    public void TheTokenHash_IsNotTheToken_AndNamesThePlatform()
    {
        var fcm = PushTokenSync.TokenHash(new PushToken(TokenA, PushPlatform.Fcm));
        var apns = PushTokenSync.TokenHash(new PushToken(TokenA, PushPlatform.Apns));

        Assert.DoesNotContain(TokenA, fcm);
        Assert.NotEqual(fcm, apns);
        Assert.Equal(64, fcm.Length);
    }

    // ------------------------------------------------------------------
    // pairing carries the token; the store follows it
    // ------------------------------------------------------------------

    [Fact]
    public async Task APairingThatCarriedTheToken_IsNotFollowedByASecondSend()
    {
        var h = new Harness(TokenA);

        await h.RecordRegistrationAsync(Paired("rb1-one"), new PushToken(TokenA, PushPlatform.Fcm), CancellationToken.None);
        var outcome = await h.SyncAsync(Paired("rb1-one"), Url, CancellationToken.None);

        Assert.Equal(PushTokenSyncOutcome.Unchanged, outcome);
        Assert.Empty(h.Http.Bodies);
    }

    [Fact]
    public async Task APairingWithoutAToken_ForgetsTheOlderRecord_SoTheNextSyncSends()
    {
        var h = new Harness(TokenA);
        await h.SyncAsync(Paired("rb1-one"), Url, CancellationToken.None);

        await h.RecordRegistrationAsync(Paired("rb1-one"), token: null, CancellationToken.None);
        var outcome = await h.SyncAsync(Paired("rb1-one"), Url, CancellationToken.None);

        Assert.Equal(PushTokenSyncOutcome.Sent, outcome);
        Assert.Equal(2, h.Http.Bodies.Count);
    }

    // ------------------------------------------------------------------
    // the bounded fetch
    // ------------------------------------------------------------------

    [Fact]
    public async Task ATokenSourceThatNeverAnswers_TimesOutQuietly()
    {
        var never = new TaskCompletionSource<Result<PushToken?>>();
        var clock = Stopwatch.StartNew();

        var result = await PushTokenSync.FetchBoundedAsync(
            _ => never.Task, TimeSpan.FromMilliseconds(100), CancellationToken.None).WaitAsync(TestBound);

        Assert.True(result.IsFailure);
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task ATokenSourceThatThrows_FailsQuietly()
    {
        var result = await PushTokenSync.FetchBoundedAsync(
            _ => throw new InvalidOperationException("no push service"), TimeSpan.FromSeconds(1), CancellationToken.None)
            .WaitAsync(TestBound);

        Assert.True(result.IsFailure);
    }

    [Fact]
    public async Task TheBoundedFetch_HandsTheSourceACancellationThatFires()
    {
        CancellationToken seen = default;
        var result = await PushTokenSync.FetchBoundedAsync(
            async ct => { seen = ct; await Task.Delay(Timeout.Infinite, ct); return Result.Success<PushToken?>(null); },
            TimeSpan.FromMilliseconds(100), CancellationToken.None).WaitAsync(TestBound);

        Assert.True(result.IsFailure);
        Assert.True(seen.IsCancellationRequested);
    }

    [Fact]
    public async Task ASyncWhoseFetchNeverAnswers_SendsNothing_AndReturns()
    {
        var h = new Harness(TokenA, fetchTimeout: TimeSpan.FromMilliseconds(100));
        h.Tokens.Never = true;

        var outcome = await h.SyncAsync(Paired("rb1-one"), Url, CancellationToken.None);

        Assert.Equal(PushTokenSyncOutcome.FetchFailed, outcome);
        Assert.Empty(h.Http.Bodies);
    }

    [Fact]
    public void TheDefaultBound_IsAboutTenSeconds()
    {
        Assert.Equal(TimeSpan.FromSeconds(10), PushTokenSync.DefaultFetchTimeout);
    }

    // ------------------------------------------------------------------
    // the token never reaches the log
    // ------------------------------------------------------------------

    [Fact]
    public async Task ThePushTokenUpdate_LogsTheTokenByLengthOnly()
    {
        var log = new CapturingLogger();
        var http = new FakeBootloader();
        var client = new BootloaderClient(new HttpClient(http), log);

        await client.UpdatePushTokenAsync(Url, new PushTokenUpdateRequest(PhoneId, TokenA, PushPlatform.Fcm), CancellationToken.None);

        Assert.Contains(TokenA, Assert.Single(http.Bodies));
        Assert.NotEmpty(log.Lines);
        Assert.All(log.Lines, line => Assert.DoesNotContain(TokenA, line));
        Assert.Contains(log.Lines, line => line.Contains($"[{TokenA.Length} chars]"));
    }

    [Fact]
    public async Task ARegistrationCarryingAToken_LogsTheTokenByLengthOnly()
    {
        var log = new CapturingLogger();
        var http = new FakeBootloader
        {
            Reply = "{\"registered\":true,\"phone_id\":\"" + PhoneId + "\",\"bootloader_id\":\"b\",\"managed_secrets\":[]}",
        };
        var client = new BootloaderClient(new HttpClient(http), log);

        await client.RegisterAsync(Url, new RegistrationRequest(
            PhoneId, "label", "ipub", new[] { V04Protocol.AlgorithmEcdsaP256 }, V04Protocol.Version,
            new RegistrationProof("c", "s"), PushToken: TokenA, PushPlatform: PushPlatform.Fcm), CancellationToken.None);

        Assert.Contains(TokenA, Assert.Single(http.Bodies));
        Assert.All(log.Lines, line => Assert.DoesNotContain(TokenA, line));
    }

    // --- helpers ---

    private static PairingState Paired(string bootloaderId) =>
        new(PhoneId, bootloaderId, Url, Array.Empty<ManagedSecretRef>(), DateTimeOffset.UnixEpoch,
            PollPublicKeyB64u: "ppub");

    private sealed class Harness
    {
        public FakeTokens Tokens { get; }
        public FakeBootloader Http { get; } = new();
        public RecordingStore Store { get; } = new();
        private readonly PushTokenSync _sync;

        public Harness(string? token, TimeSpan? fetchTimeout = null)
        {
            Tokens = new FakeTokens { Token = token };
            var client = new BootloaderClient(new HttpClient(Http), NullLogger<BootloaderClient>.Instance);
            _sync = new PushTokenSync(Tokens, client, Store, fetchTimeout ?? TimeSpan.FromSeconds(5));
        }

        public Task<PushTokenSyncOutcome> SyncAsync(PairingState? paired, string url, CancellationToken ct)
            => _sync.SyncAsync(paired, url, ct).WaitAsync(TestBound);

        public Task RecordRegistrationAsync(PairingState paired, PushToken? token, CancellationToken ct)
            => _sync.RecordRegistrationAsync(paired, token, ct).WaitAsync(TestBound);
    }

    private sealed class FakeTokens : IPushTokenService
    {
        public string? Token { get; set; }
        public string Platform { get; set; } = PushPlatform.Fcm;
        public bool Never { get; set; }
        public int PromptingCalls;
        public int QuietCalls;
        public int Calls => PromptingCalls + QuietCalls;

        public Task<Result<PushToken?>> GetTokenAsync(CancellationToken ct)
        {
            Interlocked.Increment(ref PromptingCalls);
            return Answer();
        }

        public Task<Result<PushToken?>> GetTokenQuietlyAsync(CancellationToken ct)
        {
            Interlocked.Increment(ref QuietCalls);
            return Answer();
        }

        private Task<Result<PushToken?>> Answer()
        {
            if (Never) return new TaskCompletionSource<Result<PushToken?>>().Task;
            return Task.FromResult(Result.Success<PushToken?>(Token is null ? null : new PushToken(Token, Platform)));
        }
    }

    private sealed class RecordingStore : IPushTokenSendStore
    {
        public Dictionary<string, string> Values { get; } = new();
        public List<(string Key, string? Value)> Writes { get; } = new();

        public Task<string?> GetLastSentHashAsync(string bootloaderKey, CancellationToken ct)
        {
            lock (Values) return Task.FromResult(Values.TryGetValue(bootloaderKey, out var v) ? v : null);
        }

        public Task SetLastSentHashAsync(string bootloaderKey, string tokenHash, CancellationToken ct)
        {
            lock (Values)
            {
                Values[bootloaderKey] = tokenHash;
                Writes.Add((bootloaderKey, tokenHash));
            }
            return Task.CompletedTask;
        }

        public Task ForgetAsync(string bootloaderKey, CancellationToken ct)
        {
            lock (Values)
            {
                Values.Remove(bootloaderKey);
                Writes.Add((bootloaderKey, null));
            }
            return Task.CompletedTask;
        }
    }

    private sealed class FakeBootloader : HttpMessageHandler
    {
        public HttpStatusCode Status { get; set; } = HttpStatusCode.OK;
        public string Reply { get; set; } = "{\"updated\":true,\"phone_id\":\"" + PhoneId + "\"}";
        public TimeSpan Delay { get; set; } = TimeSpan.Zero;
        public List<string> Bodies { get; } = new();
        public List<string> Urls { get; } = new();

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(ct);
            lock (Bodies)
            {
                Bodies.Add(body);
                Urls.Add(request.RequestUri!.ToString());
            }
            if (Delay > TimeSpan.Zero) await Task.Delay(Delay, ct);
            return new HttpResponseMessage(Status)
            {
                Content = new StringContent(Status == HttpStatusCode.OK ? Reply : "{\"error\":\"boom\"}",
                    Encoding.UTF8, "application/json"),
            };
        }
    }

    private sealed class CapturingLogger : ILogger<BootloaderClient>
    {
        public List<string> Lines { get; } = new();
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            lock (Lines) Lines.Add(formatter(state, exception));
        }
    }
}
