using System;

namespace Recto.Shared.Services;

/// <summary>
/// Build 12 (2026-07-11, wave-C consumer) — bridge from a native silent-push
/// wake (APNs / FCM) to the Blazor pending-fetch. The bootloader emits a
/// content-available push when a new pending request is queued (wave C send
/// side); the platform receive handler raises this signal, and Home.razor
/// reacts by fetching pending IMMEDIATELY instead of waiting out the poll
/// interval. Polling stays the fallback — the wake is an accelerant, not a
/// replacement, so nothing breaks when push credentials aren't provisioned
/// yet (Phase 2 APNs .p8 + FCM service-account mints).
///
/// <para>Same static-bridge shape as <see cref="IPairDeepLinkState"/>: the
/// native handler (Android <c>FirebaseMessagingService.OnMessageReceived</c>,
/// iOS <c>AppDelegate.DidReceiveRemoteNotification</c>) can fire without a
/// resolved DI container via the static <c>SignalWakeGlobal</c>, and the
/// DI-injected instance's <see cref="WakeRequested"/> event forwards to the
/// same class-level static field so warm-resume subscribers react even
/// though the handler ran outside any DI scope.</para>
///
/// <para>Subscribers MUST tolerate firing on ANY thread (push handlers run
/// on a platform thread, not the Blazor sync-context — marshal via
/// <c>ComponentBase.InvokeAsync</c>) and AFTER their own disposal (guard with
/// a <c>_disposed</c> flag).</para>
/// </summary>
public interface IPushWakeSignal
{
    /// <summary>Fires when a silent-push wake arrives. Carries no payload —
    /// the push is a "check now" nudge; the phone fetches pending over the
    /// authenticated channel, never trusting push content.</summary>
    event Action? WakeRequested;
}
