using Android.App;
using Android.Content;
using Firebase.Messaging;
using Recto.Shared.Services;

namespace Recto.Platforms.AndroidImpl;

/// <summary>
/// Build 12 (2026-07-11, wave-C consumer) — receives silent-push wakes from
/// the bootloader on Android via FCM. The bootloader sends a DATA-only
/// message (no <c>notification</c> block) when a pending request lands;
/// <see cref="OnMessageReceived"/> fires for data messages even when the app
/// is backgrounded, and we raise the process-wide wake signal so Home.razor
/// fetches pending immediately instead of waiting out the poll interval.
///
/// <para>Registered via the <c>[Service]</c> + <c>[IntentFilter]</c>
/// attributes below (MAUI merges these into AndroidManifest.xml at build) —
/// this subclass takes over from FCM's auto-registered default service for
/// the MESSAGING_EVENT action. <c>Exported=false</c>: only the FCM framework
/// dispatches to it.</para>
///
/// <para>Trust posture (Hard Rule #9): the push content is NEVER trusted —
/// we ignore the message body entirely and just nudge an authenticated fetch
/// over the bootloader channel. A spoofed push at worst triggers one extra
/// fetch that finds nothing. Nothing here reads or acts on push data.</para>
/// </summary>
[Service(Exported = false)]
[IntentFilter(new[] { "com.google.firebase.MESSAGING_EVENT" })]
public sealed class RectoFirebaseMessagingService : FirebaseMessagingService
{
    public override void OnMessageReceived(RemoteMessage message)
    {
        // Content-agnostic nudge — see class docs. Raise the wake signal;
        // Home.razor (if mounted) fetches pending, else the next poll tick /
        // app-resume picks it up.
        InMemoryPushWakeSignal.SignalWakeGlobal();
    }

    /// <summary>
    /// FCM rotated the registration token (reinstall, data wipe, restore, or
    /// the first token after install). Ask for a send: a live Home.razor runs
    /// <see cref="PushTokenSync"/> now; with none, the request is kept as due
    /// and the next launch or resume sends it. The token argument is not
    /// stored or logged here: the sync fetches the current token itself and
    /// sends it only when it differs from the last one sent.
    /// </summary>
    public override void OnNewToken(string token)
    {
        InMemoryPushTokenRefreshSignal.MarkDueGlobal();
    }
}
