using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Recto.Shared.Common;
using Recto.Shared.Models;
using Recto.Shared.Protocol.V04;

namespace Recto.Shared.Services;

/// <summary>
/// THE PUSH TOKEN, KEPT CURRENT. The bootloader can only wake a phone whose
/// registry row holds that phone's current FCM / APNs token. Pairing carries
/// the token once; this class keeps it current afterwards. On every launch and
/// resume of a paired phone (and when the platform reports a new token) it
/// fetches the token, bounded by <see cref="DefaultFetchTimeout"/>, and calls
/// <c>POST /v0.4/manage/push_token</c> (poll-key signed) only when the token
/// differs from the last one this phone sent to that bootloader.
/// <para>
/// Quiet by design: a fetch that fails or times out, or a send the bootloader
/// does not confirm, records nothing and returns an outcome; the next launch
/// or resume tries again. Nothing here throws, prompts, or blocks the UI, and
/// the token is never logged or stored (the store keeps a hash).
/// </para>
/// </summary>
public sealed class PushTokenSync
{
    /// <summary>How long a token fetch may take before it is abandoned.</summary>
    public static readonly TimeSpan DefaultFetchTimeout = TimeSpan.FromSeconds(10);

    private readonly IPushTokenService _tokens;
    private readonly IBootloaderClient _client;
    private readonly IPushTokenSendStore _store;
    private readonly TimeSpan _fetchTimeout;

    // One sync at a time in the process (the page that starts a sync can be
    // replaced while it runs): overlapping syncs run in turn, and the second
    // finds the first one's record.
    private static readonly SemaphoreSlim s_gate = new(1, 1);

    /// <summary>
    /// One constructor, so DI never has two to choose between;
    /// <paramref name="fetchTimeout"/> defaults to <see cref="DefaultFetchTimeout"/>.
    /// </summary>
    public PushTokenSync(
        IPushTokenService tokens, IBootloaderClient client, IPushTokenSendStore store, TimeSpan? fetchTimeout = null)
    {
        _tokens = tokens;
        _client = client;
        _store = store;
        _fetchTimeout = fetchTimeout ?? DefaultFetchTimeout;
    }

    /// <summary>
    /// Fetches this phone's push token and sends it to the paired bootloader
    /// when it changed. Never sends without a real pairing.
    /// </summary>
    /// <param name="paired">The current pairing, or null.</param>
    /// <param name="bootloaderUrl">Where to send (the active failover candidate).</param>
    /// <param name="ct">Cancels the whole sync.</param>
    public async Task<PushTokenSyncOutcome> SyncAsync(PairingState? paired, string bootloaderUrl, CancellationToken ct)
    {
        if (!IsRealPairing(paired)) return PushTokenSyncOutcome.NotPaired;

        try
        {
            await s_gate.WaitAsync(ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return PushTokenSyncOutcome.FetchFailed;
        }
        try
        {
            var fetched = await FetchBoundedAsync(_tokens.GetTokenQuietlyAsync, _fetchTimeout, ct).ConfigureAwait(false);
            if (fetched.IsFailure) return PushTokenSyncOutcome.FetchFailed;
            var token = fetched.Value;
            if (token is null || string.IsNullOrEmpty(token.Token)) return PushTokenSyncOutcome.NoToken;

            var key = StoreKey(paired);
            var hash = TokenHash(token);
            string? last;
            try
            {
                last = await _store.GetLastSentHashAsync(key, ct).ConfigureAwait(false);
            }
            catch
            {
                last = null;
            }
            if (string.Equals(last, hash, StringComparison.Ordinal)) return PushTokenSyncOutcome.Unchanged;

            var sent = await _client.UpdatePushTokenAsync(
                bootloaderUrl,
                new PushTokenUpdateRequest(paired.PhoneId, token.Token, token.Platform),
                ct).ConfigureAwait(false);
            if (sent.IsFailure || !sent.Value.Updated) return PushTokenSyncOutcome.SendFailed;

            try
            {
                await _store.SetLastSentHashAsync(key, hash, ct).ConfigureAwait(false);
            }
            catch
            {
                // Unrecorded: the next sync sends the same token once more.
            }
            return PushTokenSyncOutcome.Sent;
        }
        catch
        {
            return PushTokenSyncOutcome.SendFailed;
        }
        finally
        {
            s_gate.Release();
        }
    }

    /// <summary>
    /// Pairing sent <paramref name="token"/> inside its registration (or no
    /// token at all). Record it, or forget an older record, so the next sync
    /// neither repeats the send nor trusts a record the new registration
    /// replaced.
    /// </summary>
    public async Task RecordRegistrationAsync(PairingState paired, PushToken? token, CancellationToken ct)
    {
        if (!IsRealPairing(paired)) return;
        var key = StoreKey(paired);
        try
        {
            if (token is null || string.IsNullOrEmpty(token.Token))
            {
                await _store.ForgetAsync(key, ct).ConfigureAwait(false);
            }
            else
            {
                await _store.SetLastSentHashAsync(key, TokenHash(token), ct).ConfigureAwait(false);
            }
        }
        catch
        {
            // A missed record costs at most one repeated send.
        }
    }

    /// <summary>
    /// Runs a token fetch with a hard bound. The source is handed a token that
    /// cancels at the bound, and a source that ignores it is abandoned at the
    /// same moment. Every failure (timeout, cancellation, a throw) comes back
    /// as a failed result; nothing escapes.
    /// </summary>
    public static async Task<Result<PushToken?>> FetchBoundedAsync(
        Func<CancellationToken, Task<Result<PushToken?>>> fetch, TimeSpan timeout, CancellationToken ct)
    {
        using var bound = CancellationTokenSource.CreateLinkedTokenSource(ct);
        bound.CancelAfter(timeout);
        try
        {
            return await fetch(bound.Token).WaitAsync(timeout, ct).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            try { bound.Cancel(); } catch { /* already disposed or cancelled */ }
            return Result.Failure<PushToken?>(Error.Failure(
                $"The push token did not arrive within {timeout.TotalSeconds:0.#} s."));
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return Result.Failure<PushToken?>(Error.Failure(
                $"The push token did not arrive within {timeout.TotalSeconds:0.#} s."));
        }
        catch (OperationCanceledException)
        {
            return Result.Failure<PushToken?>(Error.Failure("The push token fetch was cancelled."));
        }
        catch (Exception ex)
        {
            return Result.Failure<PushToken?>(Error.Failure($"The push token fetch failed: {ex.GetType().Name}."));
        }
    }

    /// <summary>
    /// What the store keeps for a sent token: SHA-256 over the platform and
    /// the token, lowercase hex. Equal hashes mean the bootloader already has
    /// this token for this platform.
    /// </summary>
    public static string TokenHash(PushToken token)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"{token.Platform}\n{token.Token}")))
            .ToLowerInvariant();

    /// <summary>The store key: one record per phone id and bootloader id.</summary>
    public static string StoreKey(PairingState paired) => $"{paired.PhoneId}@{paired.BootloaderId}";

    private static bool IsRealPairing([NotNullWhen(true)] PairingState? paired)
        => paired is not null
           && !string.IsNullOrEmpty(paired.PhoneId)
           && !string.IsNullOrEmpty(paired.BootloaderId)
           && paired.BootloaderUrl.StartsWith("http", StringComparison.OrdinalIgnoreCase);
}

/// <summary>What one <see cref="PushTokenSync.SyncAsync"/> did.</summary>
public enum PushTokenSyncOutcome
{
    /// <summary>No real pairing (none, or demo mode): nothing fetched, nothing sent.</summary>
    NotPaired,
    /// <summary>The platform gave no token in time; retried next launch or resume.</summary>
    FetchFailed,
    /// <summary>The platform has no push transport (dev hosts).</summary>
    NoToken,
    /// <summary>The bootloader already has this token.</summary>
    Unchanged,
    /// <summary>The bootloader confirmed the new token.</summary>
    Sent,
    /// <summary>The send did not go through; nothing recorded, retried next launch or resume.</summary>
    SendFailed,
}
