using System;
using System.Threading;

namespace Recto.Shared.Services;

// ---------------------------------------------------------------------------
// InMemoryPairDeepLinkState — process-lifetime impl of IPairDeepLinkState.
// ---------------------------------------------------------------------------
//
// Backed by a static field + Interlocked.Exchange. The static field is the
// single source of truth; the DI-injected instance and the static SetGlobal
// method both read/write the same field, so platform handlers (iOS
// AppDelegate.OpenUrl, Android MainActivity.OnNewIntent) can push without
// needing a resolved DI container.
//
// Sister of IosApnsPushTokenService's static-bridge pattern (banked Phase H
// of Recto Phone v0.4): the AppDelegate calls
// IosApnsPushTokenService.OnRegisteredForRemoteNotifications(...) directly,
// the DI-injected instance reads the same static TCS. Same shape here for
// deep-link payloads.
//
// Cold-launch race the static fallback defends against:
//
//   1. User taps a recto://pair?... URL in Mail / Messages.
//   2. iOS launches Recto Phone, calls AppDelegate.OpenUrl: BEFORE
//      MauiProgram.CreateMauiApp() has finished bootstrapping DI.
//   3. If we tried IPlatformApplication.Current.Services.GetRequiredService<...>
//      at that moment, we'd race-condition on whether Services is wired up
//      yet. Worse, we'd silently lose the URL on the race-loss.
//   4. Static SetGlobal sidesteps the race entirely — the field exists from
//      class-load time, no DI needed.
//
// Why not a ConcurrentQueue: payloads aren't a stream — only the most recent
// matters. Stacking N pending deep-links would surface stale URLs the user
// long forgot. Last-write-wins is the right shape.
//
// Why not a SemaphoreSlim-based async wait: Home.razor's OnInitializedAsync
// runs once per page mount; it doesn't poll. The pull is synchronous +
// opportunistic.

/// <summary>
/// Process-memory implementation of <see cref="IPairDeepLinkState"/>.
/// Singleton-registered in <c>MauiProgram.cs</c>. The instance methods
/// delegate to a class-level static field via <see cref="Interlocked.Exchange{T}(ref T, T)"/>
/// so platform-specific URL handlers can also push via the
/// <see cref="SetGlobal"/> static method without needing a resolved DI
/// container.
/// </summary>
public sealed class InMemoryPairDeepLinkState : IPairDeepLinkState
{
    // Static = single source of truth across the DI-injected instance and
    // any platform-handler caller (iOS AppDelegate, Android MainActivity).
    // Initialized to null at class-load (well before MAUI bootstraps).
    private static PairDeepLinkPayload? s_pending;

    // Build 6 (2026-06-02): static event field backing the per-instance
    // PayloadArrived event. Subscribers attach via the IPairDeepLinkState
    // interface event (add/remove forwards through to this field) so
    // SetGlobal can fire notifications regardless of whether a DI-injected
    // instance ever existed. Static lifetime matches s_pending — both
    // outlive any single page-mount and survive DI scope teardown.
    //
    // Multicast Action delegate. Null = no subscribers (the default at
    // class-load). The ?.Invoke pattern below handles the null case
    // cleanly so SetGlobal works the same with or without a Home.razor
    // currently subscribed.
    //
    // Subscribers MUST tolerate firing on any thread — platform URL
    // handlers (iOS AppDelegate, Android MainActivity) run on the
    // platform UI thread, NOT the Blazor render sync-context. Blazor
    // consumers must marshal via ComponentBase.InvokeAsync inside their
    // handler before touching component state.
    //
    // Subscribers should also expect to fire AFTER component disposal in
    // the rare case where SetGlobal beats Dispose to the lock. Use a
    // _disposed flag in the handler if mutation might NRE.
    private static event Action<PairDeepLinkPayload>? s_payloadArrived;

    /// <summary>
    /// Push a payload into the holder from any caller — DI-injected or
    /// raw platform-handler. Subsequent <see cref="TryConsume"/> returns
    /// this payload exactly once. Last-write-wins on overlap. Also fires
    /// <see cref="PayloadArrived"/> on all current subscribers so warm-
    /// resume Home.razor instances can react without polling.
    /// </summary>
    public static void SetGlobal(PairDeepLinkPayload? payload)
    {
        if (payload is null) return;
        Interlocked.Exchange(ref s_pending, payload);
        // Snapshot the delegate to a local before invocation so a
        // subscriber that unsubscribes mid-fire doesn't race the
        // null-check. Standard event-handler idiom.
        var handler = s_payloadArrived;
        handler?.Invoke(payload);
    }

    public void Set(PairDeepLinkPayload payload) => SetGlobal(payload);

    public PairDeepLinkPayload? TryConsume()
    {
        // Atomic read-and-clear. The single-consume contract: first
        // caller after a Set sees the payload; every caller thereafter
        // sees null until the next Set.
        return Interlocked.Exchange(ref s_pending, null);
    }

    /// <summary>
    /// Per-interface event accessor. add/remove forwards through to the
    /// class-level static <see cref="s_payloadArrived"/> field so the
    /// subscription survives the DI-instance lifetime — important because
    /// MauiProgram registers IPairDeepLinkState as a Singleton with
    /// process-lifetime, but a defensive subscriber pattern can't depend
    /// on that being the only registration shape.
    /// </summary>
    public event Action<PairDeepLinkPayload>? PayloadArrived
    {
        add => s_payloadArrived += value;
        remove => s_payloadArrived -= value;
    }
}
