using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Foundation;
using Recto.Shared.Common;
using Recto.Shared.Services;
using UIKit;
using UserNotifications;

namespace Recto.Platforms.iOSImpl;

/// <summary>
/// iOS push-token service that registers with APNs (Apple Push Notification
/// service) and returns the device-token bytes hex-encoded as a string.
/// The bootloader uses this token plus an APNs auth key (.p8 + Team ID +
/// Key ID) to send wakeup pushes.
/// <para>
/// Registration happens on every launch (<see cref="RegisterAtLaunch"/>, from
/// AppDelegate.FinishedLaunching, as Apple advises), and the token iOS hands
/// back is kept for the process: a fetch returns it at once, and a token that
/// differs from the one kept (including one that arrives with no fetch
/// waiting) asks <see cref="PushTokenSync"/> for a send.
/// A fetch that must wait for iOS bridges the AppDelegate callback through a
/// static <see cref="TaskCompletionSource"/>, bounded by
/// <see cref="PushTokenSync.DefaultFetchTimeout"/>.
/// </para>
/// <para>
/// Notification permission does not gate registration: a silent
/// (content-available) wake needs none. Only the pairing path
/// (<see cref="GetTokenAsync"/>) asks for it, and it registers whatever the
/// answer; the launch and resume path (<see cref="GetTokenQuietlyAsync"/>)
/// never asks.
/// </para>
/// </summary>
public sealed class IosApnsPushTokenService : IPushTokenService
{
    // The token iOS last handed over, and the fetch (if any) waiting for one.
    // Both guarded by s_lock; the callbacks arrive on the main thread, the
    // fetches on any thread.
    private static readonly object s_lock = new();
    private static string? s_lastToken;
    private static TaskCompletionSource<string>? s_pendingTokenTcs;

    public Task<Result<PushToken?>> GetTokenAsync(CancellationToken ct) => FetchAsync(askPermission: true, ct);

    public Task<Result<PushToken?>> GetTokenQuietlyAsync(CancellationToken ct) => FetchAsync(askPermission: false, ct);

    /// <summary>
    /// Registers for remote notifications. Called on every launch from the
    /// main thread; the token arrives through
    /// <see cref="OnRegisteredForRemoteNotifications"/>.
    /// </summary>
    public static void RegisterAtLaunch()
    {
        try
        {
            UIApplication.SharedApplication.RegisterForRemoteNotifications();
        }
        catch
        {
            // A launch must not fail on push; the next fetch registers again.
        }
    }

    private static async Task<Result<PushToken?>> FetchAsync(bool askPermission, CancellationToken ct)
    {
        TaskCompletionSource<string>? tcs = null;
        try
        {
            if (askPermission)
            {
                // Shown once by the system; later calls return the stored
                // answer. The answer is not checked: a declined alert
                // permission still allows the silent wake.
                try
                {
                    await UNUserNotificationCenter.Current.RequestAuthorizationAsync(
                        UNAuthorizationOptions.Alert | UNAuthorizationOptions.Sound | UNAuthorizationOptions.Badge);
                }
                catch
                {
                    // Registration below does not depend on it.
                }
            }

            lock (s_lock)
            {
                if (s_lastToken is { } known)
                {
                    return Result.Success<PushToken?>(new PushToken(known, PushPlatform.Apns));
                }
                tcs = s_pendingTokenTcs is { Task.IsCompleted: false } waiting
                    ? waiting
                    : (s_pendingTokenTcs = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously));
            }

            await MainThread.InvokeOnMainThreadAsync(() =>
            {
                UIApplication.SharedApplication.RegisterForRemoteNotifications();
            });

            var hexToken = await tcs.Task.WaitAsync(PushTokenSync.DefaultFetchTimeout, ct).ConfigureAwait(false);
            return Result.Success<PushToken?>(new PushToken(hexToken, PushPlatform.Apns));
        }
        catch (TimeoutException)
        {
            AbandonPending(tcs);
            return Result.Failure<PushToken?>(Error.Failure(
                $"APNs did not answer within {PushTokenSync.DefaultFetchTimeout.TotalSeconds:0} s."));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return Result.Failure<PushToken?>(Error.Failure("APNs token fetch was cancelled."));
        }
        catch (Exception ex)
        {
            AbandonPending(tcs);
            return Result.Failure<PushToken?>(Error.Failure(
                $"APNs token fetch failed: {ex.GetType().Name}: {ex.Message}"));
        }
    }

    // A wait that ended without a token: let the next fetch start a fresh one
    // instead of joining a completion iOS may never deliver.
    private static void AbandonPending(TaskCompletionSource<string>? tcs)
    {
        if (tcs is null) return;
        lock (s_lock)
        {
            if (ReferenceEquals(s_pendingTokenTcs, tcs)) s_pendingTokenTcs = null;
        }
        tcs.TrySetCanceled();
    }

    /// <summary>
    /// Called by AppDelegate's <c>RegisteredForRemoteNotifications</c> export
    /// when iOS hands over the device token. Hex-encodes the bytes, keeps them
    /// for later fetches, resolves the waiting fetch if there is one, and asks
    /// for a send when the token differs from the one kept. The send is safe to
    /// ask twice: <see cref="PushTokenSync"/> serializes syncs and skips a
    /// token the bootloader already has.
    /// </summary>
    public static void OnRegisteredForRemoteNotifications(NSData deviceToken)
    {
        var bytes = deviceToken.ToArray();
        var hex = new StringBuilder(bytes.Length * 2);
        foreach (var b in bytes)
        {
            hex.Append(b.ToString("x2"));
        }
        var token = hex.ToString();

        TaskCompletionSource<string>? tcs;
        bool changed;
        lock (s_lock)
        {
            changed = !string.Equals(s_lastToken, token, StringComparison.Ordinal);
            s_lastToken = token;
            tcs = s_pendingTokenTcs;
            s_pendingTokenTcs = null;
        }

        tcs?.TrySetResult(token);
        if (changed) InMemoryPushTokenRefreshSignal.MarkDueGlobal();
    }

    /// <summary>
    /// Called by AppDelegate's <c>FailedToRegisterForRemoteNotifications</c>
    /// export when iOS reports a registration failure (typically when the
    /// app's entitlements don't include push, or the bundle ID isn't tied
    /// to an APNs-enabled provisioning profile). Fails the waiting fetch, if any.
    /// </summary>
    public static void OnFailedToRegisterForRemoteNotifications(NSError error)
    {
        TaskCompletionSource<string>? tcs;
        lock (s_lock)
        {
            tcs = s_pendingTokenTcs;
            s_pendingTokenTcs = null;
        }
        tcs?.TrySetException(new InvalidOperationException(
            $"APNs registration failed: {error.LocalizedDescription}"));
    }
}
