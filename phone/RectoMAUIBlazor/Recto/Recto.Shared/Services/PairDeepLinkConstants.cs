namespace Recto.Shared.Services;

// ---------------------------------------------------------------------------
// PairDeepLinkConstants -- canonical shared values for the pair-a-thing
// deep-link primitive.
// ---------------------------------------------------------------------------
//
// Banked 2026-06-01 alongside the demo-mode QR primitive (#41). Centralizes
// values that previously lived inline in Home.razor's @code block AND in
// PairDeepLinkParser's docstring. Single source of truth for:
//
//   - The recto:// URL scheme + canonical host segment ("pair").
//   - The kind discriminator query param + its two canonical values
//     ("service" -- the Phase H end-user pair-a-service flow that was the
//     original v0.1 of this primitive; "bootloader" -- the bootloader-pair
//     flow the App Store reviewer demo path consumes).
//   - The demo-mode sentinel values previously buried in Home.razor:
//     DemoPairingCode ("000000" -- six zeros, matches the placeholder text
//     reviewers see in the input field), DemoBootloaderUrl
//     ("demo://recto-app-review" -- the sentinel scheme that triggers
//     IsDemoMode in Home.razor), DemoBootloaderId
//     ("demo-bootloader-app-review" -- the persisted bootloader id for the
//     demo pairing row in SecureStorage).
//
// Why a separate file vs adding constants to PairDeepLinkParser: the parser
// is consumed by the platform handlers (iOS AppDelegate, Android
// MainActivity) and by Home.razor; the EMITTER (PairDeepLinkEmitter) is
// consumed by anything that needs to PRODUCE a recto:// URL or QR (the
// downstream-consumer Pair Devices surface, the App Store reviewer
// marketing surface, Recto Phone's own onboarding-demo screen, any
// consumer's integration test harness). Putting the constants in their
// own file lets both consumer paths reference one canonical source without
// either depending on the other.
//
// Sister of how Recto.Capability has its own canonical scope-action-key
// strings centralized in recto/capability/manifest_v1.json rather than
// duplicated across mint + verify code paths.
//
// Cross-references:
//   - URL scheme registration: iOS Platforms/iOS/Info.plist (CFBundleURLTypes)
//    + Android Platforms/Android/MainActivity.cs ([IntentFilter] attributes).
//   - Parser:  PairDeepLinkParser.cs (same folder).
//   - Emitter: PairDeepLinkEmitter.cs (same folder, banked alongside this file).
//   - QR wrapper: ../QR/PairDeepLinkQrEmitter.cs (composes emitter + QrEncoder).
//   - Python sister: ../../../../../recto/qr/pair.py (cross-language parity).
//   - Demo-mode UX: Home.razor's IsDemoMode property + the synthetic
//     SingleSign queued post-pair are the runtime consumers of these
//     sentinels.

/// <summary>
/// Discriminator for which Recto pair-deep-link flow a URL targets.
/// Determines validation rules in <see cref="PairDeepLinkParser"/> and
/// which form Home.razor pre-fills on consumption.
/// </summary>
public enum PairDeepLinkKind
{
    /// <summary>
    /// Phase H end-user "Pair a service" flow. Code is 8 alphanumeric
    /// characters minted by a downstream consumer's
    /// <c>/api/v1/devices/pairing/start</c> endpoint (the canonical Phase H
    /// wire contract; consumers integrate against the same pattern).
    /// Consumed by Home.razor when the phone is already
    /// paired with a real bootloader (<c>_paired is not null &amp;&amp; !IsDemoMode</c>).
    /// Auto-fills <c>_pairServiceCode</c> + opens the "Pair a service"
    /// accordion. This is the default kind for back-compat with v0.1 of
    /// the deep-link primitive (which only had this flow).
    /// </summary>
    Service = 0,

    /// <summary>
    /// Bootloader-pair flow -- the initial trust handshake between the
    /// phone and a bootloader. Code is 6 numeric digits (currently always
    /// the demo sentinel <c>"000000"</c> in this kind's only canonical use
    /// case: the App Store reviewer demo QR). Bootloader URL is required
    /// (the whole point of this kind is to pre-fill the URL field so the
    /// reviewer doesn't type it). Consumed by Home.razor when the phone
    /// is NOT yet paired -- auto-fills <c>_pairingCode</c> +
    /// <c>_bootloaderUrl</c>. Sister to the existing manual flow where the
    /// reviewer types <c>000000</c> + the sentinel URL into the form by hand.
    /// </summary>
    Bootloader = 1,
}

/// <summary>
/// Canonical constants for the Recto pair-deep-link wire format.
/// </summary>
public static class PairDeepLinkConstants
{
    /// <summary>
    /// URL scheme Recto Phone registers on iOS + Android. All deep-link
    /// URLs start with <c>recto://</c>. Lowercase per RFC 3986 (schemes
    /// are case-insensitive but we canonicalize emission to lowercase).
    /// </summary>
    public const string UrlScheme = "recto";

    /// <summary>
    /// Canonical host segment for pair-flow URLs:
    /// <c>recto://pair?...</c>. v1.1+ may add sibling hosts
    /// (<c>recto://approve</c>, <c>recto://revoke</c>) but those are
    /// separate primitives with their own parsers.
    /// </summary>
    public const string PairHost = "pair";

    /// <summary>
    /// Query param name carrying the pairing code. Required.
    /// </summary>
    public const string CodeParamName = "code";

    /// <summary>
    /// Query param name carrying the bootloader URL. Required for
    /// <see cref="PairDeepLinkKind.Bootloader"/>; optional for
    /// <see cref="PairDeepLinkKind.Service"/>.
    /// </summary>
    public const string BootloaderParamName = "bootloader";

    /// <summary>
    /// Query param name carrying the kind discriminator. Optional;
    /// defaults to <see cref="PairDeepLinkKind.Service"/> for back-compat
    /// with v0.1 URLs that pre-date the kind extension.
    /// </summary>
    public const string KindParamName = "kind";

    /// <summary>
    /// Query param name carrying the bootstrap-bootloader URL for the
    /// end-user first-pair UX (Build 7, banked 2026-06-02 night).
    /// Optional; only meaningful on <see cref="PairDeepLinkKind.Service"/>
    /// QRs. When the receiving phone has no bootloader paired yet AND
    /// the QR carries this field, Recto Phone surfaces a first-pair
    /// ceremony that auto-pairs against the bootstrap URL before
    /// proceeding with the Service pair — the end user never types a
    /// bootloader URL by hand.
    /// <para>
    /// Sister of <see cref="BootloaderParamName"/> but with different
    /// semantics: the <c>bootloader=</c> param on Bootloader-kind QRs
    /// is THE bootloader the QR is paired AGAINST (the demo sentinel
    /// for the App Store reviewer flow); <c>bootstrap_bootloader=</c>
    /// on Service-kind QRs is the bootloader the phone should AUTO-PAIR
    /// with before completing the Service pair. The two never coexist
    /// on the same QR — Bootloader-kind QRs pair with a bootloader
    /// (no service-pair to follow); Service-kind QRs pair with a
    /// service (auto-bootstrap-bootloader-pair-first if needed).
    /// </para>
    /// <para>
    /// Architectural rationale: end users don't know what a "bootloader"
    /// is and shouldn't have to. A downstream consumer (the canonical
    /// first integrator at v1) hosts a managed bootloader on its own
    /// domain; the consumer's "Pair my phone" flow emits a Service-kind
    /// QR with this field set. End user scans, Recto Phone detects "no
    /// bootloader paired + bootstrap_bootloader present" and auto-pairs
    /// transparently.
    /// </para>
    /// </summary>
    public const string BootstrapBootloaderParamName = "bootstrap_bootloader";

    /// <summary>
    /// Query param name carrying the bootstrap-bootloader pairing code for
    /// the end-user first-pair UX (Build 7, banked 2026-06-02 night).
    /// Optional; only meaningful on <see cref="PairDeepLinkKind.Service"/>
    /// QRs alongside <see cref="BootstrapBootloaderParamName"/>. Six
    /// numeric digits, same shape as the canonical bootloader-pair code.
    /// <para>
    /// When both <c>bootstrap_bootloader</c> AND <c>bootstrap_pair_code</c>
    /// are present on a Service-kind QR + the receiving phone has no
    /// bootloader paired yet, Recto Phone's first-pair ceremony pre-fills
    /// both fields + surfaces a single confirmation card. User taps Pair,
    /// bootloader-pair completes, then the service-pair code from
    /// <see cref="CodeParamName"/> auto-fires the Phase H end-user
    /// pair-a-service flow. Single human-in-the-loop step covers both
    /// phases.
    /// </para>
    /// <para>
    /// The consumer's QR-emit endpoint is responsible for minting both
    /// codes (bootstrap_pair_code via the bootloader's
    /// <c>/v0.4/register/challenge</c> mint primitive; <c>code</c> via
    /// the consumer's own <c>/api/v1/devices/pairing/start</c>) and
    /// stitching them into one QR payload. End user never sees either
    /// code as a literal value — both are pre-filled from the QR.
    /// </para>
    /// </summary>
    public const string BootstrapPairCodeParamName = "bootstrap_pair_code";

    /// <summary>
    /// Canonical wire value for <see cref="PairDeepLinkKind.Service"/>
    /// in the <c>kind=</c> query param. Lowercase by convention.
    /// </summary>
    public const string KindServiceWireValue = "service";

    /// <summary>
    /// Canonical wire value for <see cref="PairDeepLinkKind.Bootloader"/>
    /// in the <c>kind=</c> query param. Lowercase by convention.
    /// </summary>
    public const string KindBootloaderWireValue = "bootloader";

    // ---- Demo-mode sentinels (App Store reviewer flow) --------------------
    //
    // These values match the placeholder text the reviewer sees in the form
    // input fields, so following the placeholder verbatim works. They were
    // previously buried in Home.razor's @code block; centralizing here lets
    // the emitter ALSO reference the canonical values without duplication.
    // Banked 2026-05-22 evening for the iOS 1.0 (3) submission; centralized
    // 2026-06-01 alongside the demo-mode QR primitive.

    /// <summary>
    /// Demo pairing code. Six zeros. Matches the placeholder text in the
    /// bootloader-pair form input ("000000"). Reviewers (and any real user
    /// typing the placeholder verbatim) enter demo mode by submitting this
    /// value as the pairing code.
    /// </summary>
    public const string DemoPairingCode = "000000";

    /// <summary>
    /// Demo bootloader URL sentinel. The <c>demo://</c> scheme is the
    /// canonical signal Home.razor checks via <c>IsDemoMode</c> to short-
    /// circuit HTTP pairing handshakes. Real bootloaders use http://
    /// or https://; the demo sentinel scheme is impossible to confuse
    /// with a real value.
    /// </summary>
    public const string DemoBootloaderUrl = "demo://recto-app-review";

    /// <summary>
    /// Demo bootloader id. Persisted into Recto Phone's SecureStorage as
    /// the paired bootloader's logical id for the demo pairing row. Sister
    /// of the bootloader-id values a real pairing flow would mint.
    /// </summary>
    public const string DemoBootloaderId = "demo-bootloader-app-review";
}
