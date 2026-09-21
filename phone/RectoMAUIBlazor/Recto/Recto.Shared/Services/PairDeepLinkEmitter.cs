using System;
using System.Text;

namespace Recto.Shared.Services;

// ---------------------------------------------------------------------------
// PairDeepLinkEmitter -- canonical producer for recto://pair?... URLs.
// ---------------------------------------------------------------------------
//
// Sister of PairDeepLinkParser. The parser CONSUMES URLs (iOS AppDelegate +
// Android MainActivity + QR scanner all push payloads into
// InMemoryPairDeepLinkState through the parser); the emitter PRODUCES URLs
// for consumers that need to render a QR or share a deep-link.
//
// Canonical use cases (banked 2026-06-01 for #41):
//
//   1. App Store reviewer demo QR (Recto-side marketing surface, future).
//      BuildDemoBootloaderPairUrl() emits the canonical demo URL with the
//      sentinel "000000" code + "demo://recto-app-review" bootloader.
//      Reviewer scans QR -> Recto Phone opens -> demo mode fires
//      automatically (no typing required).
//
//   2. Downstream-consumer "Pair Devices" surface (per the matching
//      consumer-side task tracked as #39 in the consumer's IM).
//      BuildServicePairUrl(code, bootloaderUrl) emits a Phase H service-
//      pair URL from a freshly-minted 8-char alphanumeric pairing code.
//      The consumer's account-management UI renders this as an inline QR
//      alongside the existing manual-code-entry path.
//
//   3. Downstream consumer integration test harnesses. Any new Recto-paired
//      consumer can mint a test QR with their own bootloader URL by
//      calling BuildServicePairUrl from their own emitter pipeline.
//
// Round-trip contract: every URL produced by this emitter parses cleanly
// back to a PairDeepLinkPayload with byte-identical Code, BootloaderUrl,
// and Kind via PairDeepLinkParser.TryParse. Tests pin this contract for
// both kinds.
//
// Encoding rules:
//   - Code is emitted verbatim (no percent-encoding -- pairing codes are
//     [A-Za-z0-9] for service-kind and [0-9] for bootloader-kind, all of
//     which are URL-safe characters).
//   - Bootloader URL is percent-encoded via Uri.EscapeDataString so
//     "demo://recto-app-review" -> "demo%3A%2F%2Frecto-app-review" and
//     "https://bootloader.example/" -> "https%3A%2F%2Fbootloader.example%2F".
//     The parser uses Uri.UnescapeDataString as the inverse primitive.
//   - Kind is emitted ONLY when non-default (Bootloader). Service-kind
//     URLs omit the kind= param entirely so back-compat URLs produced
//     before the kind extension parse identically to URLs produced now.
//     This keeps emit -> parse byte-identical for v0.1 URLs that didn't
//     have the kind extension.
//
// Sister rule: PairDeepLinkConstants holds all wire-format string
// constants (scheme, host, param names, kind wire values, demo sentinels).
// This emitter never hardcodes string literals; everything routes through
// PairDeepLinkConstants so the parser + emitter share one source of truth.

/// <summary>
/// Stateless emitter for <c>recto://pair?...</c> deep-link URLs. Every URL
/// produced by this class round-trips cleanly through
/// <see cref="PairDeepLinkParser"/>.
/// </summary>
public static class PairDeepLinkEmitter
{
    /// <summary>
    /// Build a service-kind pair URL (Phase H end-user pair-a-service
    /// flow). Code must be 8 alphanumeric characters; bootloader URL is
    /// optional. Sister of <see cref="BuildBootloaderPairUrl"/>.
    /// </summary>
    /// <param name="code">8 alphanumeric characters. Throws on invalid shape.</param>
    /// <param name="bootloaderUrl">Optional URL the calling consumer wants
    /// to suggest as the pairing target. v1 emits this verbatim (no shape
    /// validation); the receiving phone may ignore it per the v1.1
    /// allowlist contract.</param>
    public static string BuildServicePairUrl(string code, string? bootloaderUrl = null)
        => BuildPairUrl(code, bootloaderUrl, PairDeepLinkKind.Service);

    /// <summary>
    /// Build a bootloader-kind pair URL (initial-trust handshake with a
    /// bootloader). Code must be 6 numeric digits; bootloader URL is
    /// REQUIRED. The only canonical use case today is the App Store
    /// reviewer demo flow via <see cref="BuildDemoBootloaderPairUrl"/>;
    /// future real bootloader-pair flows would mint their own 6-digit
    /// codes through this same primitive.
    /// </summary>
    /// <param name="code">6 numeric digits. Throws on invalid shape.</param>
    /// <param name="bootloaderUrl">Required URL the phone should pair
    /// against. Emitted verbatim (the demo sentinel
    /// <c>demo://recto-app-review</c> is intentionally non-HTTP).</param>
    public static string BuildBootloaderPairUrl(string code, string bootloaderUrl)
    {
        if (string.IsNullOrEmpty(bootloaderUrl))
        {
            throw new ArgumentException(
                "bootloaderUrl is required for Bootloader-kind pair URLs.",
                nameof(bootloaderUrl));
        }
        return BuildPairUrl(code, bootloaderUrl, PairDeepLinkKind.Bootloader);
    }

    /// <summary>
    /// Build the canonical App Store reviewer demo URL. Uses the
    /// <see cref="PairDeepLinkConstants.DemoPairingCode"/> +
    /// <see cref="PairDeepLinkConstants.DemoBootloaderUrl"/> sentinels.
    /// Suitable for rendering as a QR on Recto Phone's marketing surface,
    /// the App Store listing screenshots, or any "scan to try" affordance
    /// where the reviewer should land in demo mode without typing.
    /// </summary>
    /// <remarks>
    /// The emitted URL is byte-stable across builds (the underlying
    /// constants don't change without an architectural decision). Tests
    /// pin the exact wire bytes for the canonical demo URL so any
    /// accidental drift in PairDeepLinkConstants or encoding primitives
    /// surfaces at CI time.
    /// </remarks>
    public static string BuildDemoBootloaderPairUrl()
        => BuildBootloaderPairUrl(
            PairDeepLinkConstants.DemoPairingCode,
            PairDeepLinkConstants.DemoBootloaderUrl);

    /// <summary>
    /// Core emitter -- callers typically use <see cref="BuildServicePairUrl"/>
    /// or <see cref="BuildBootloaderPairUrl"/> rather than this primitive
    /// directly. Validates code shape per kind, requires bootloader URL
    /// for Bootloader-kind, percent-encodes the bootloader URL, omits the
    /// kind= query param for Service-kind (back-compat).
    /// </summary>
    public static string BuildPairUrl(string code, string? bootloaderUrl, PairDeepLinkKind kind)
    {
        ValidateCodeShape(code, kind);

        // Pre-allocate roughly. recto://pair? is 13 chars, code is 6 or 8,
        // bootloader URL when present is typically 30-60 chars encoded,
        // kind=bootloader is 16 chars. A 256-char StringBuilder covers
        // every realistic case without growth.
        var sb = new StringBuilder(256);
        sb.Append(PairDeepLinkConstants.UrlScheme).Append("://").Append(PairDeepLinkConstants.PairHost).Append('?');
        sb.Append(PairDeepLinkConstants.CodeParamName).Append('=').Append(code);

        if (!string.IsNullOrEmpty(bootloaderUrl))
        {
            sb.Append('&').Append(PairDeepLinkConstants.BootloaderParamName).Append('=');
            sb.Append(Uri.EscapeDataString(bootloaderUrl));
        }

        // Emit kind= ONLY for non-default kinds. Service-kind URLs omit
        // the param entirely so an emitter-produced URL for service-kind
        // is byte-identical to a v0.1 URL minted before the kind extension
        // existed. This is the back-compat property we want for the URL
        // surface area.
        if (kind != PairDeepLinkKind.Service)
        {
            sb.Append('&').Append(PairDeepLinkConstants.KindParamName).Append('=');
            sb.Append(WireValueForKind(kind));
        }

        return sb.ToString();
    }

    private static void ValidateCodeShape(string code, PairDeepLinkKind kind)
    {
        if (string.IsNullOrEmpty(code))
        {
            throw new ArgumentException(
                $"code is required and must be non-empty (got: empty/null).",
                nameof(code));
        }

        switch (kind)
        {
            case PairDeepLinkKind.Service:
                if (code.Length != 8)
                {
                    throw new ArgumentException(
                        $"Service-kind code must be exactly 8 characters (got {code.Length}).",
                        nameof(code));
                }
                for (int i = 0; i < code.Length; i++)
                {
                    var c = code[i];
                    var ok = (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
                    if (!ok)
                    {
                        throw new ArgumentException(
                            $"Service-kind code must be [A-Za-z0-9]{{8}} (got invalid char at position {i}).",
                            nameof(code));
                    }
                }
                break;
            case PairDeepLinkKind.Bootloader:
                if (code.Length != 6)
                {
                    throw new ArgumentException(
                        $"Bootloader-kind code must be exactly 6 characters (got {code.Length}).",
                        nameof(code));
                }
                for (int i = 0; i < code.Length; i++)
                {
                    var c = code[i];
                    if (c < '0' || c > '9')
                    {
                        throw new ArgumentException(
                            $"Bootloader-kind code must be [0-9]{{6}} (got invalid char at position {i}).",
                            nameof(code));
                    }
                }
                break;
            default:
                throw new ArgumentOutOfRangeException(
                    nameof(kind),
                    kind,
                    "Unknown PairDeepLinkKind.");
        }
    }

    private static string WireValueForKind(PairDeepLinkKind kind) => kind switch
    {
        PairDeepLinkKind.Service => PairDeepLinkConstants.KindServiceWireValue,
        PairDeepLinkKind.Bootloader => PairDeepLinkConstants.KindBootloaderWireValue,
        _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, "Unknown PairDeepLinkKind."),
    };
}
