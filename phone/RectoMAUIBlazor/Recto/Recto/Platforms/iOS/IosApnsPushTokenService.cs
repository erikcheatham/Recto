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
/// Two-phase async: (1) request notification authorization via
/// <see cref="UNUserNotificationCenter"/>, which prompts the user;
/// (2) call <c>UIApplication.RegisterForRemoteNotifications</c>, which
/// resolves through an AppDelegate callback. We bridge the AppDelegate
/// callback through a static <see cref="TaskCompletionSource"/> so the
/// service exposes a clean <c>Task</c> interface.
/// </para>
/// </summary>
public sealed class IosApnsPushTokenService : IPushTokenService
{
    // Static TCS so the AppDelegate's DidRegisterForRemoteNotifications
    // override can complete a pending Get call. Only one fetch in flight
    // at a time; subsequent calls reuse the resolved token from the OS.
    private static TaskCompletionSource<string>? s_pendingTokenTcs;
    private static readonly object s_tcsLock = new();

    public async Task<Result<PushToken?>> GetTokenAsync(CancellationToken ct)
    {
        try
        {
            // Phase 1: request notification authorization (prompts user on first call).
            var authResult = await UNUserNotificationCenter.Current.RequestAuthorizationAsync(
                UNAuthorizationOptions.Alert | UNAuthorizationOptions.Sound | UNAuthorizationOptions.Badge);

            if (!authResult.Item1)
            {
                return Result.Failure<PushToken?>(Error.Failure(
                    $"User declined push notification permission: {authResult.Item2?.LocalizedDescription ?? "(no detail)"}"));
            }

            // Phase 2: register and await the AppDelegate callback.
            TaskCompletionSource<string> tcs;
            lock (s_tcsLock)
            {
                if (s_pendingTokenTcs is { Task.IsCompleted: false })
                {
                    return Result.Failure<PushToken?>(Error.Failure(
                        "Another APNs token fetch is already in flight."));
                }
                tcs = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
                s_pendingTokenTcs = tcs;
            }

            ct.Register(() => tcs.TrySetCanceled(ct));

            await MainThread.InvokeOnMainThreadAsync(() =>
            {
                UIApplication.SharedApplication.RegisterForRemoteNotifications();
            });

            var hexToken = await tcs.Task.ConfigureAwait(false);
            return Result.Success<PushToken?>(new PushToken(hexToken, PushPlatform.Apns));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return Result.Failure<PushToken?>(Error.Failure("APNs token fetch was cancelled."));
        }
        catch (Exception ex)
        {
            return Result.Failure<PushToken?>(Error.Failure(
                $"APNs token fetch failed: {ex.GetType().Name}: {ex.Message}"));
        }
        finally
        {
            lock (s_tcsLock)
            {
                if (s_pendingTokenTcs is { Task.IsCompleted: true })
                {
                    s_pendingTokenTcs = null;
                }
            }
        }
    }

    /// <summary>
    /// Called by AppDelegate's <c>RegisteredForRemoteNotifications</c> override
    /// when iOS hands us the device token. Hex-encodes the bytes and resolves
    /// any pending fetch.
    /// </summary>
    public static void OnRegisteredForRemoteNotifications(NSData deviceToken)
    {
        TaskCompletionSource<string>? tcs;
        lock (s_tcsLock) { tcs = s_pendingTokenTcs; }
        if (tcs is null) return;

        var bytes = deviceToken.ToArray();
        var hex = new StringBuilder(bytes.Length * 2);
        foreach (var b in bytes)
        {
            hex.Append(b.ToString("x2"));
        }
        tcs.TrySetResult(hex.ToString());
    }

    /// <summary>
    /// Called by AppDelegate's <c>FailedToRegisterForRemoteNotifications</c>
    /// override when iOS reports a registration failure (typically when the
    /// app's entitlements don't include push, or the bundle ID isn't tied
    /// to an APNs-enabled provisioning profile).
    /// </summary>
    public static void OnFailedToRegisterForRemoteNotifications(NSError error)
    {
        TaskCompletionSource<string>? tcs;
        lock (s_tcsLock) { tcs = s_pendingTokenTcs; }
        tcs?.TrySetException(new InvalidOperationException(
            $"APNs registration failed: {error.LocalizedDescription}"));
    }
}
