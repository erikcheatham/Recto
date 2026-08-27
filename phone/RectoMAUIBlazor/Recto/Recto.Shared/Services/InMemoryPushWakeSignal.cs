using System;

namespace Recto.Shared.Services;

/// <summary>
/// Process-memory implementation of <see cref="IPushWakeSignal"/> (Build 12,
/// 2026-07-11). Singleton-registered; the DI-injected instance's
/// <see cref="WakeRequested"/> event and the static <see cref="SignalWakeGlobal"/>
/// method share one class-level static event field, so a native push handler
/// can nudge the app without a resolved DI container — mirror of
/// <see cref="InMemoryPairDeepLinkState"/>'s static-bridge pattern.
///
/// <para>No payload: a push is a "there's something to fetch" nudge. The
/// phone always fetches pending over the authenticated bootloader channel and
/// never trusts push CONTENT (a spoofed push at worst causes one extra
/// authenticated fetch that finds nothing). This keeps the wake path within
/// Hard Rule #9's trust model.</para>
/// </summary>
public sealed class InMemoryPushWakeSignal : IPushWakeSignal
{
    // Static = single source of truth across the DI-injected instance and any
    // platform-handler caller. Null = no subscribers (default at class-load,
    // well before MAUI bootstraps DI, so a push during cold launch is safe).
    private static event Action? s_wakeRequested;

    /// <summary>
    /// Raise the wake signal from any caller — DI-injected or raw platform
    /// handler. Snapshots the multicast delegate before invoking so a
    /// subscriber unsubscribing mid-fire can't race the null-check. Never
    /// throws (a subscriber exception is swallowed so one bad handler can't
    /// break a push callback the OS is waiting on).
    /// </summary>
    public static void SignalWakeGlobal()
    {
        var handler = s_wakeRequested;
        try
        {
            handler?.Invoke();
        }
        catch
        {
            // Push callbacks run under an OS completion handler; never let a
            // subscriber throw back into the platform.
        }
    }

    public event Action? WakeRequested
    {
        add => s_wakeRequested += value;
        remove => s_wakeRequested -= value;
    }
}
