using System.Threading;
using System.Threading.Tasks;
using Recto.Shared.Common;

namespace Recto.Shared.Services;

/// <summary>
/// Phone-side push-notification token registration. The bootloader uses
/// these tokens to wake the phone when a new pending request lands, so the
/// operator-perceived latency drops from "wait up to one 3s poll cycle"
/// to "milliseconds, push wakes the listener immediately."
/// <para>
/// Two transports:
/// <list type="bullet">
/// <item>Android &mdash; FCM (Firebase Cloud Messaging) via the
/// <c>Xamarin.Firebase.Messaging</c> binding. Token rotates occasionally
/// per Google's recommendation; this service exposes a single Get call
/// and the caller refreshes on a heuristic (e.g. on every app startup).</item>
/// <item>iOS &mdash; APNs (Apple Push Notification service) via the
/// platform's native <c>UIApplication.RegisterForRemoteNotifications</c>
/// flow. The token is the device-token bytes hex-encoded.</item>
/// </list>
/// Windows / Mac Catalyst dev hosts have no push transport and the
/// no-op implementation returns null. Pairing still works; the bootloader
/// just falls back to the 3s poll cycle for those phones.
/// </para>
/// </summary>
public interface IPushTokenService
{
    /// <summary>
    /// Returns the current push-notification token + platform identifier.
    /// Triggers OS-level permission prompts on first call (iOS shows
    /// "Allow notifications", Android API 33+ shows POST_NOTIFICATIONS).
    /// Returns success-with-null when the platform has no push support
    /// (Windows / Mac Catalyst dev hosts) so callers can branch cleanly
    /// without distinguishing failure-of-a-transport from no-transport-
    /// available.
    /// </summary>
    Task<Result<PushToken?>> GetTokenAsync(CancellationToken ct);
}

/// <summary>
/// A registered push token. <see cref="Platform"/> matches the
/// <c>push_platform</c> wire field on RegistrationRequest.
/// </summary>
/// <param name="Token">
/// FCM registration token (Android) or APNs device-token hex string (iOS).
/// Opaque to the bootloader; passed verbatim to the push-send pipeline.
/// </param>
/// <param name="Platform">
/// One of <see cref="PushPlatform.Fcm"/> or <see cref="PushPlatform.Apns"/>.
/// </param>
public sealed record PushToken(string Token, string Platform);

public static class PushPlatform
{
    /// <summary>Firebase Cloud Messaging (Android, sometimes web; we use it for Android).</summary>
    public const string Fcm = "fcm";

    /// <summary>Apple Push Notification service (iOS, iPadOS).</summary>
    public const string Apns = "apns";
}
