using System;

namespace Recto.Shared.Services;

/// <summary>
/// Bridge from a platform's "the push token changed" callback (Android
/// <c>FirebaseMessagingService.OnNewToken</c>, an iOS device token that
/// arrives with no fetch waiting) to <see cref="PushTokenSync"/>. The callback
/// carries no token: the sync fetches the current one itself and sends it if
/// it differs from the last one sent.
///
/// <para>Same static-bridge shape as <see cref="IPushWakeSignal"/>: the
/// platform callback can fire before DI exists. With a listener the send runs
/// now; with none the request is kept as due, and the next launch or resume
/// (which syncs anyway) consumes it.</para>
///
/// <para>Listeners MUST tolerate firing on any thread and after their own
/// disposal, as with <see cref="IPushWakeSignal"/>.</para>
/// </summary>
public interface IPushTokenRefreshSignal
{
    /// <summary>Fires when the platform reports a new push token.</summary>
    event Action? RefreshRequested;

    /// <summary>
    /// True once for each request that arrived while nobody listened, then
    /// false until the next one.
    /// </summary>
    bool TryConsumeDue();
}
