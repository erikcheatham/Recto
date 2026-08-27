using System;
using System.Collections.Generic;

namespace Recto.Shared.Services;

// ---------------------------------------------------------------------------
// PairDeepLinkParser — parses recto://pair?code=X&bootloader=Y&kind=Z URLs
// into validated PairDeepLinkPayload values. Shared between iOS AppDelegate
// and Android MainActivity so both platforms produce identical typed
// payloads from the same URL.
// ---------------------------------------------------------------------------
//
// URL shape (v1, with kind extension added 2026-06-01 for #41 and
// bootstrap_bootloader extension added Build 7 2026-06-02 night):
//
//   recto://pair?code=ABCD1234&bootloader=https%3A%2F%2Fbootloader.example
//     (kind defaults to "service" -- Phase H end-user pair-a-service flow,
//      operator-iPhone-style QR with phone already paired)
//
//   recto://pair?code=ABCD1234&bootstrap_bootloader=https%3A%2F%2Fbootloader.example.com&bootstrap_pair_code=482917
//     (kind defaults to "service"; bootstrap_bootloader + bootstrap_pair_code
//      signal end-user first-pair UX -- if phone has no bootloader paired
//      yet, the pair card pre-fills the bootloader URL + bootloader-pair
//      code from the QR, user taps Pair, bootloader-pair completes, the
//      Service pair code from code= auto-fires the Phase H end-user
//      pair-a-service flow. Single tap covers both phases. Build 7
//      primitive for consumer-emitted end-user QRs.)
//
//   recto://pair?code=000000&bootloader=demo%3A%2F%2Frecto-app-review&kind=bootloader
//     (kind=bootloader -- App Store reviewer demo flow)
//
// Components:
//   - scheme: "recto" (registered in iOS CFBundleURLTypes + Android intent-
//     filter on the MainActivity).
//   - host: "pair" (route discriminator -- v1.1 may add "approve" or
//     "revoke" hosts for other deep-link kinds; v1 only handles "pair").
//   - query:
//       `code` (required, shape varies by kind -- 8 alphanumeric for
//         service, 6 numeric for bootloader)
//       `bootloader` (optional for service, required for bootloader -- URL)
//       `kind` (optional, defaults to "service" for back-compat with
//         v0.1 URLs that pre-date this extension)
//       `bootstrap_bootloader` (Build 7, optional, Service-kind only --
//         URL the phone should auto-pair against if not yet paired with
//         any bootloader. Silently ignored on Bootloader-kind QRs.)
//       `bootstrap_pair_code` (Build 7, optional, Service-kind only --
//         6-digit bootloader-pair code the consumer pre-minted via the
//         bootloader's challenge-mint primitive. Pre-fills the pairing-
//         code field alongside bootstrap_bootloader's URL pre-fill.
//         Silently dropped on shape-fail or Bootloader-kind QRs.)
//
// Validation:
//   - Reject if scheme != "recto" (defends against accidental routing of
//     unrelated schemes if the OS ever calls our handler for something
//     else -- paranoid since the registration is scheme-specific, but
//     cheap).
//   - Reject if host != "pair" -- future hosts get their own parsers.
//   - Reject if kind is present but not one of the canonical values
//     ("service", "bootloader").
//   - Per-kind code shape: service = [A-Za-z0-9]{8}; bootloader = [0-9]{6}.
//   - For kind=bootloader: bootloader URL is REQUIRED (the whole point of
//     the kind is to pre-fill the URL so the reviewer doesn't type it).
//   - For kind=service: bootloader URL is optional (informational at v1,
//     reserved for v1.1 multi-consumer allowlist).
//   - Bootloader URL itself is accepted as opaque string -- let the
//     consumer worry about URL-shape validation at use-time. The
//     demo://recto-app-review sentinel is a deliberately-non-HTTP shape;
//     gating bootloader to http/https here would break the demo path.
//
// Error handling: returns null on any malformed input. Platform handlers
// log + swallow null returns silently -- the user just sees no pre-fill
// and can type the code manually. We never surface "the URL was malformed"
// errors to the user because there's no UI to surface them in (we have no
// UI thread at the moment the URL fires on cold-launch). Banked as v1.1
// polish: a transient toast when the user reaches Home.razor with no
// pending payload AFTER a deep-link arrival was recorded but rejected.
//
// Sister emitter: PairDeepLinkEmitter.cs (same folder) emits URLs that
// round-trip cleanly through this parser. Tests pin the round-trip in
// PairDeepLinkEmitterTests.cs.

/// <summary>
/// Stateless parser for <c>recto://pair?...</c> deep-link URLs. Returns
/// the typed payload on success, null on any validation failure. Shared
/// between iOS and Android platform handlers so both produce identical
/// payloads from the same URL.
/// </summary>
public static class PairDeepLinkParser
{
    /// <summary>
    /// Parse a <c>recto://pair?code=X&amp;bootloader=Y&amp;kind=Z</c> URL.
    /// Returns null on malformed/wrong-scheme/wrong-host/unknown-kind/
    /// missing-code/bad-code-shape/missing-required-bootloader.
    /// </summary>
    public static PairDeepLinkPayload? TryParse(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)) return null;

        Uri uri;
        try
        {
            uri = new Uri(url, UriKind.Absolute);
        }
        catch
        {
            return null;
        }

        // Scheme + host gate the deep-link to OUR registered routes.
        // Comparison is case-insensitive per RFC 3986 (schemes are case-
        // insensitive; we register lowercase "recto"; some OS layers
        // may pass uppercased forms back).
        if (!string.Equals(uri.Scheme, PairDeepLinkConstants.UrlScheme, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }
        // Authority normalization: Uri.Host is empty for some
        // scheme://host shapes when host parsing fails. Both iOS and
        // Android pass URLs through their own pre-parsers before
        // handing to us, so we accept either Uri.Host being "pair"
        // OR an empty Host with the path starting "pair" as a
        // fallback for edge-case platforms.
        var hostOrPathSegment = uri.Host;
        if (string.IsNullOrEmpty(hostOrPathSegment))
        {
            // recto:/pair?... shape (single-slash) parses to empty Host
            // + AbsolutePath "/pair". Some Android browsers normalize
            // recto://pair?... to this shape; defensively accept.
            var path = uri.AbsolutePath.TrimStart('/');
            var firstSegment = path.Split('/', 2)[0];
            hostOrPathSegment = firstSegment;
        }
        if (!string.Equals(hostOrPathSegment, PairDeepLinkConstants.PairHost, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        // Manual query parser -- avoids the System.Web vs ASP.NET
        // WebUtilities dep question on MAUI. The query shape is small:
        // key=value pairs separated by '&', URL-decoded values, case-
        // insensitive key match.
        var queryDict = ParseQueryString(uri.Query);
        var code = queryDict.TryGetValue(PairDeepLinkConstants.CodeParamName, out var codeVal) ? codeVal.Trim() : string.Empty;
        var bootloader = queryDict.TryGetValue(PairDeepLinkConstants.BootloaderParamName, out var blVal) ? blVal.Trim() : string.Empty;
        var kindRaw = queryDict.TryGetValue(PairDeepLinkConstants.KindParamName, out var kindVal) ? kindVal.Trim() : string.Empty;
        // Build 7 (banked 2026-06-02 night): bootstrap_bootloader +
        // bootstrap_pair_code are the end-user first-pair UX primitives.
        // Both optional on Service-kind QRs; both ignored on Bootloader-
        // kind QRs. Carried through to the payload so Home.razor's
        // first-pair ceremony can pre-fill the bootloader URL +
        // bootloader-pair code, run a single confirm tap, then
        // auto-proceed to the Service pair with the carried code.
        var bootstrapBootloader = queryDict.TryGetValue(PairDeepLinkConstants.BootstrapBootloaderParamName, out var bsVal) ? bsVal.Trim() : string.Empty;
        var bootstrapPairCode = queryDict.TryGetValue(PairDeepLinkConstants.BootstrapPairCodeParamName, out var bpVal) ? bpVal.Trim() : string.Empty;

        // Kind discriminator. Missing/empty defaults to Service for back-
        // compat with v0.1 URLs minted before the kind extension landed.
        // Unknown values reject (paranoid -- we'd rather drop the deep-
        // link than misroute it to the wrong form).
        PairDeepLinkKind kind;
        if (string.IsNullOrEmpty(kindRaw)
            || string.Equals(kindRaw, PairDeepLinkConstants.KindServiceWireValue, StringComparison.OrdinalIgnoreCase))
        {
            kind = PairDeepLinkKind.Service;
        }
        else if (string.Equals(kindRaw, PairDeepLinkConstants.KindBootloaderWireValue, StringComparison.OrdinalIgnoreCase))
        {
            kind = PairDeepLinkKind.Bootloader;
        }
        else
        {
            return null;
        }

        // Per-kind code-shape validation.
        if (kind == PairDeepLinkKind.Service)
        {
            // [A-Za-z0-9]{8}. Pairing codes are operator-printable so we
            // tolerate either case; the consumer-side validation does
            // its own canonicalization (upper-case match per existing
            // _pairServiceCode handling). Sister of the existing manual-
            // input maxlength="8" + autocapitalize="characters" gate in
            // Home.razor.
            if (code.Length != 8)
            {
                return null;
            }
            for (int i = 0; i < code.Length; i++)
            {
                var c = code[i];
                var ok = (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
                if (!ok) return null;
            }
        }
        else // PairDeepLinkKind.Bootloader
        {
            // [0-9]{6}. Bootloader-pair codes are 6 numeric digits (the
            // demo sentinel "000000" is the only canonical use case today;
            // future bootloader-pair codes minted by real bootloaders use
            // the same shape). Sister of Home.razor's manual-input gate:
            // _pairingCode.Length == 6 && _pairingCode.All(char.IsDigit).
            if (code.Length != 6)
            {
                return null;
            }
            for (int i = 0; i < code.Length; i++)
            {
                var c = code[i];
                if (c < '0' || c > '9') return null;
            }
            // Bootloader URL is REQUIRED for this kind. The whole point of
            // the kind is to pre-fill the bootloader URL so the App Store
            // reviewer doesn't have to type it; a kind=bootloader URL
            // without bootloader= is malformed by definition.
            if (string.IsNullOrEmpty(bootloader))
            {
                return null;
            }
        }

        // Bootloader URL: empty string normalizes to null at the payload
        // boundary so consumers can null-check cleanly without
        // distinguishing "missing field" from "empty string". For
        // kind=Bootloader we already rejected empty above, so this only
        // collapses to null on kind=Service. When provided, we DON'T
        // validate URL shape further here (v1 ignores the value for
        // service-kind; bootloader-kind passes it through to
        // _bootloaderUrl in Home.razor which treats it as opaque text).
        var bootloaderForPayload = string.IsNullOrEmpty(bootloader) ? null : bootloader;

        // Build 7 (banked 2026-06-02 night): bootstrap_bootloader +
        // bootstrap_pair_code are ONLY meaningful on Service-kind QRs
        // (end-user first-pair UX where the consumer embeds the
        // bootloader URL + bootloader-pair code the phone should auto-
        // use). Silently drop on Bootloader-kind QRs — those carry their
        // own canonical bootloader URL in the bootloader= field +
        // pairing code in code=. Same empty-string-collapses-to-null
        // normalization as bootloader= above.
        //
        // bootstrap_pair_code shape: same as bootloader-kind code shape
        // (6 numeric digits). Validate when present; silently drop on
        // shape-fail rather than rejecting the whole payload (the
        // service-pair code is the primary payload; bootstrap is
        // optional polish).
        string? bootstrapBootloaderForPayload;
        string? bootstrapPairCodeForPayload;
        if (kind == PairDeepLinkKind.Service)
        {
            bootstrapBootloaderForPayload = string.IsNullOrEmpty(bootstrapBootloader) ? null : bootstrapBootloader;

            // bootstrap_pair_code must be [0-9]{6} when present. On
            // shape-fail, silently drop just this field (the rest of
            // the payload is still usable; user falls back to the
            // operator-mode UX where the service-pair code is the
            // only thing that pre-fills).
            if (string.IsNullOrEmpty(bootstrapPairCode))
            {
                bootstrapPairCodeForPayload = null;
            }
            else if (bootstrapPairCode.Length != 6)
            {
                bootstrapPairCodeForPayload = null;
            }
            else
            {
                bool allDigits = true;
                for (int i = 0; i < bootstrapPairCode.Length; i++)
                {
                    var c = bootstrapPairCode[i];
                    if (c < '0' || c > '9') { allDigits = false; break; }
                }
                bootstrapPairCodeForPayload = allDigits ? bootstrapPairCode : null;
            }
        }
        else
        {
            bootstrapBootloaderForPayload = null;
            bootstrapPairCodeForPayload = null;
        }

        return new PairDeepLinkPayload(
            code,
            bootloaderForPayload,
            kind,
            bootstrapBootloaderForPayload,
            bootstrapPairCodeForPayload);
    }

    // Small manual query parser. The URL.Query property includes the
    // leading '?'; we strip it then split on '&'. Each pair is
    // `key=value` or `key=` (empty value). Values are
    // percent-decoded via Uri.UnescapeDataString which handles the
    // canonical %20 / %2F / etc. shapes the bootloader URL will arrive
    // with. Duplicate keys: last write wins (matches HttpUtility
    // behavior and is conventional for URL queries).
    private static Dictionary<string, string> ParseQueryString(string? query)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrEmpty(query)) return result;
        var trimmed = query.StartsWith('?') ? query.Substring(1) : query;
        if (trimmed.Length == 0) return result;
        foreach (var pair in trimmed.Split('&'))
        {
            if (pair.Length == 0) continue;
            var eq = pair.IndexOf('=');
            string rawKey, rawVal;
            if (eq < 0)
            {
                rawKey = pair;
                rawVal = string.Empty;
            }
            else
            {
                rawKey = pair.Substring(0, eq);
                rawVal = pair.Substring(eq + 1);
            }
            string key, val;
            try
            {
                key = Uri.UnescapeDataString(rawKey);
                val = Uri.UnescapeDataString(rawVal);
            }
            catch
            {
                // Malformed percent-encoding — skip the pair entirely.
                // We never throw out of the parser; missing data
                // collapses to validation failure at the caller layer.
                continue;
            }
            result[key] = val;
        }
        return result;
    }
}
