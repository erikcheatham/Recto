using System;

namespace Recto.Shared.Services;

// ---------------------------------------------------------------------------
// Pair-a-service deep-link state holder (Task #22 Phase 1, banked 2026-05-31).
// ---------------------------------------------------------------------------
//
// The OS routes recto:// URLs to the Recto Phone app at platform-specific
// touchpoints (iOS: AppDelegate.OpenUrl: selector; Android: MainActivity
// OnCreate/OnNewIntent reading Intent.Data). Those handlers fire OUTSIDE
// the Blazor render lifecycle — the URL arrives before Home.razor mounts
// on cold-launch and asynchronously on warm-launch. We need a singleton
// state holder that the platform handlers push to, and that Home.razor
// pulls from on every OnInitializedAsync.
//
// Single-consume semantics:
//   - The URL fires once; the user shouldn't see a stale pre-filled form
//     when they navigate back to / from elsewhere in the app later.
//   - TryConsume() returns the payload AND atomically clears it. The
//     first caller wins. Subsequent calls return null until the next
//     deep-link arrives.
//
// Lifetime:
//   - Singleton. One per app launch.
//   - State lives in process memory only — never persisted to
//     SecureStorage / Preferences / disk. If the app dies before
//     Home.razor consumes, the URL is lost. Acceptable v1 trade-off:
//     the recto:// URL is operator-driven (they tapped a link in
//     another app); they can re-tap if the cold-launch race loses it.
//
// Future extension (banked):
//   - When v1.1 adds known-consumers allowlist enforcement, this state
//     also carries the deep-linked bootloader URL. v1 captures it
//     opportunistically but Home.razor only reads the code; the
//     bootloader URL is reserved for the v1.1 allowlist check.
//
// Sister-rule: pairing_invite QR payloads share the same body shape
// ({code, bootloader}) as the URL-scheme query params, so the same
// IPairDeepLinkState primitive serves both Phase 1 (URL scheme) AND
// Phase 2 (QR scanner) consumer paths. Both ultimately populate the
// "Pair a service" form's _pairServiceCode field via the same surface.

/// <summary>
/// Payload extracted from a <c>recto://pair?...</c> deep-link OR a
/// scanned <c>pairing_invite</c> QR. Carries the pairing code, the
/// caller-asserted bootloader URL, the kind discriminator that
/// determines which form Home.razor pre-fills on consumption, and
/// (Build 7, 2026-06-02 night) the optional bootstrap-bootloader URL
/// for the end-user first-pair UX.
/// <para>
/// <see cref="Kind"/> was added 2026-06-01 alongside the demo-mode QR
/// primitive (#41). The default value is
/// <see cref="PairDeepLinkKind.Service"/> for back-compat with v0.1 URLs
/// that pre-date the kind extension (and for back-compat with the QR
/// scanner's existing pairing_invite payload shape, which also defaults
/// to service-kind).
/// </para>
/// <para>
/// Code shape varies by kind. <see cref="PairDeepLinkKind.Service"/>:
/// 8 alphanumeric characters. <see cref="PairDeepLinkKind.Bootloader"/>:
/// 6 numeric digits (currently always the demo sentinel <c>"000000"</c>
/// since the bootloader-pair kind has only one canonical use case: the
/// App Store reviewer demo QR). <see cref="PairDeepLinkParser"/> enforces
/// per-kind validation.
/// </para>
/// <para>
/// <see cref="BootstrapBootloaderUrl"/> and <see cref="BootstrapPairCode"/>
/// (Build 7, banked 2026-06-02 night) are the end-user first-pair UX
/// primitives: when both are set on a Service-kind QR AND the receiving
/// phone has no bootloader paired yet, Recto Phone surfaces a
/// confirmation card that pre-fills the bootloader URL + bootloader-pair
/// code from the QR. User taps Pair → bootloader-pair completes → the
/// Service code from <see cref="Code"/> auto-fires the Phase H
/// pair-a-service flow. Single human-in-the-loop step covers both phases.
/// Null on operator-iPhone-style QRs (operator already has a bootloader
/// paired); set on consumer-emitted end-user QRs (consumer hosts a
/// managed bootloader the user shouldn't have to know about). Ignored on
/// Bootloader-kind QRs.
/// </para>
/// </summary>
public sealed record PairDeepLinkPayload(
    string Code,
    string? BootloaderUrl,
    PairDeepLinkKind Kind = PairDeepLinkKind.Service,
    string? BootstrapBootloaderUrl = null,
    string? BootstrapPairCode = null);

/// <summary>
/// Singleton state holder for deferred deep-link payloads. Platform-
/// specific URL handlers push via <see cref="Set"/>; Home.razor pulls
/// via <see cref="TryConsume"/> on render. Single-consume semantics.
/// Thread-safe via atomic-reference swap (deep-link arrivals and Razor
/// reads can race on Android's UI vs Blazor render threads).
/// </summary>
public interface IPairDeepLinkState
{
    /// <summary>
    /// Push a payload into the holder. Subsequent <see cref="TryConsume"/>
    /// returns this payload exactly once. If another payload is already
    /// pending, it's overwritten (last write wins — the operator's most
    /// recent tap is what they want to see, not an unconsumed predecessor).
    /// </summary>
    void Set(PairDeepLinkPayload payload);

    /// <summary>
    /// Atomically retrieve and clear the pending payload. Returns null
    /// when no payload is pending. Idempotent on null state.
    /// </summary>
    PairDeepLinkPayload? TryConsume();

    /// <summary>
    /// Fires whenever a payload is pushed via <see cref="Set"/> (or
    /// <c>InMemoryPairDeepLinkState.SetGlobal</c>). Subscribers receive
    /// the payload synchronously on the thread that called Set — Blazor
    /// consumers MUST marshal back to the render context via
    /// <c>ComponentBase.InvokeAsync</c> before mutating UI state.
    /// <para>
    /// Build 6 (2026-06-02) added this event to close the warm-start
    /// consumer gap. <see cref="TryConsume"/> alone is sufficient for
    /// cold-launch (Home.razor's <c>OnInitializedAsync</c> fires once
    /// per page mount and pulls the payload synchronously), but
    /// <c>OnInitializedAsync</c> does NOT re-run on warm resume —
    /// when the user taps a <c>recto://</c> URL in the iOS Camera app
    /// while Recto Agentic is already foregrounded, the URL fires
    /// <c>AppDelegate.OpenUrl</c> → <c>SetGlobal</c> but no page-mount
    /// happens. Without this event the payload sits in the singleton
    /// forever (or until next cold-launch). Consumers subscribe in
    /// <c>OnInitializedAsync</c>, unsubscribe in <c>DisposeAsync</c>,
    /// and handle warm-resume payloads in the same routing code path
    /// used at cold-launch time.
    /// </para>
    /// <para>
    /// The event also fires for the cold-launch case (subscribers
    /// added after the payload arrives never see THAT payload via the
    /// event; they pick it up via <c>TryConsume</c>) — that's
    /// idempotent and harmless: <c>TryConsume</c> clears the slot,
    /// so a subscriber that ran the cold-launch consume path won't
    /// double-process the same payload from the event arm. The
    /// canonical pattern: <c>TryConsume</c> first (covers any payload
    /// that landed before subscription), then <c>+= handler</c> for
    /// future warm-resume arrivals.
    /// </para>
    /// </summary>
    event Action<PairDeepLinkPayload>? PayloadArrived;
}
