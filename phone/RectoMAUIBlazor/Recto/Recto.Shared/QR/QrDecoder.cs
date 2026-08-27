using System;
using System.Collections.Generic;
using System.Text.Json;

namespace Recto.Shared.QR;

// ---------------------------------------------------------------------------
// QR decode + envelope validation (Phase 2.D substrate primitive).
// ---------------------------------------------------------------------------
//
// Sister of QrEncoder. The encoder takes a QRPayloadV1 + emits canonical-
// JSON-encoded bytes wrapped in a QR image; this decoder takes the
// canonical-JSON TEXT (extracted from a QR image by a consumer-edge
// scanner like ZXing.Net.Maui) and produces a validated QRPayloadV1 +
// diagnostic on rejection.
//
// Architectural framing:
//   - DECODE = protocol layer (JSON → typed payload + envelope validation).
//     Lives in Recto.Shared.QR as part of the substrate so any consumer
//     adopts the same validation semantics.
//   - IMAGE SCANNING = consumer-edge concern (camera image → text payload).
//     Each consumer picks its own scanner library (ZXing.Net.Maui for
//     MAUI Blazor, html5-qrcode for browser, pyzbar/zxing-cpp for Python
//     server-side). The substrate stays scanner-agnostic.
//
// Pattern Sister of Recto.Shared.Capability.CapabilityVerifier:
//   - Result-shaped record with category-prefixed errors so callers can
//     surface meaningful diagnostics to users ("This QR is expired" vs
//     "This QR is for a different service").
//   - Categories: "shape:" for structural failures (JSON parse, missing
//     fields, wrong types), "claims:" for semantic failures (expired exp,
//     wrong aud, wrong kind, unsupported v).
//   - No "signature:" category here — embedded signed JWS in body.jws (if
//     present) is verified by the existing CapabilityVerifier as a separate
//     concern. This decoder is envelope-validation only.
//
// Cross-references:
//   - Recto/CLAUDE.md "QR-as-visual-transport for capability JWS +
//     signed-payload contracts" — architectural framework.
//   - QrEncoder.cs — sister encoder this decoder round-trips against.
//   - Hard Rule #13 (artifact-as-canonical-record) — the QR's bytes ARE
//     the canonical record; this decoder produces the typed view of those
//     bytes plus envelope validation.

/// <summary>
/// Result of decoding a QR-encoded signed payload. <see cref="Success"/>
/// is true if every validation step passed; <see cref="Payload"/> carries
/// the parsed payload on success. <see cref="Error"/> carries a
/// category-prefixed failure message on failure (<c>shape:</c> for
/// structural failures, <c>claims:</c> for semantic failures) so callers
/// can distinguish failure modes for diagnostic surfaces.
/// </summary>
public sealed record QrDecodeResult(
    bool Success,
    QRPayloadV1? Payload,
    string? Error)
{
    public static QrDecodeResult Ok(QRPayloadV1 payload) => new(true, payload, null);

    public static QrDecodeResult Fail(string error) => new(false, null, error);
}

/// <summary>
/// Text-mode QR decoder + envelope validator. Mirror partner of
/// <see cref="QrEncoder"/>. Takes the canonical-JSON text payload that
/// a consumer-edge scanner extracted from a QR image and produces a
/// validated <see cref="QRPayloadV1"/> + diagnostic on rejection.
/// <para>
/// v1 ships TEXT-MODE decode only (canonical-JSON string ->
/// QRPayloadV1). The PNG-bytes path (decode raw PNG bytes via embedded
/// barcode reader) is reserved for a future sprint if a server-side
/// scanning use case surfaces — most consumers have a scanner-side
/// text-extraction step upstream of this decoder anyway.
/// </para>
/// <para>
/// Validation order:
/// <list type="number">
/// <item>Text is non-empty</item>
/// <item>JSON parses cleanly</item>
/// <item>Root is a JSON object</item>
/// <item>Required fields present (v, kind, iss, aud, iat, exp, jti,
///   body, _qr_meta)</item>
/// <item>Field types match envelope contract (v=int, kind=string,
///   iss=string, aud=array-of-strings, iat=long, exp=long, jti=string,
///   body=object, _qr_meta=object with format+max_size_bytes)</item>
/// <item>Schema version v == <see cref="QRSchema.Version"/> (currently 1)</item>
/// <item>Optional expectedKind match (if supplied)</item>
/// <item>Optional expectedAud membership (if supplied)</item>
/// <item>Time bounds: exp not past now (with clock-skew tolerance),
///   iat not unreasonably in the future</item>
/// </list>
/// </para>
/// </summary>
public static class QrDecoder
{
    /// <summary>
    /// Default clock-skew tolerance for time-bounds validation, in
    /// seconds. 30s matches the canonical CapabilityVerifier tolerance
    /// and accommodates typical NTP drift between phone enclave +
    /// consumer device.
    /// </summary>
    public const long DefaultClockSkewSeconds = 30;

    /// <summary>
    /// Decode a canonical-JSON text payload (extracted from a QR image
    /// by a consumer-edge scanner) and validate the envelope.
    /// </summary>
    /// <param name="scannedText">The canonical-JSON text extracted from
    ///     the QR image. Must be non-empty.</param>
    /// <param name="expectedKind">Optional — if supplied, the payload's
    ///     <c>kind</c> field must equal this value exactly. Use this to
    ///     reject QRs intended for a different consumer surface (e.g. a
    ///     pairing-invite QR scanned by a capability-receipt verifier).</param>
    /// <param name="expectedAud">Optional — if supplied, the payload's
    ///     <c>aud</c> array must contain this value. Use this to reject
    ///     QRs intended for a different service (e.g. one consumer's QR
    ///     scanned by a different consumer).</param>
    /// <param name="now">Optional unix-seconds "now" override for testing
    ///     time-bounds logic. Defaults to <see cref="DateTimeOffset.UtcNow"/>
    ///     when null.</param>
    /// <param name="clockSkewSeconds">Tolerance for exp/iat checks.
    ///     Defaults to <see cref="DefaultClockSkewSeconds"/>.</param>
    /// <returns>A <see cref="QrDecodeResult"/> carrying the parsed
    ///     payload on success or a category-prefixed error on failure.</returns>
    public static QrDecodeResult DecodeText(
        string scannedText,
        string? expectedKind = null,
        string? expectedAud = null,
        long? now = null,
        long clockSkewSeconds = DefaultClockSkewSeconds)
    {
        if (string.IsNullOrEmpty(scannedText))
        {
            return QrDecodeResult.Fail("shape: scanned text is empty");
        }

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(scannedText);
        }
        catch (JsonException ex)
        {
            return QrDecodeResult.Fail($"shape: JSON parse failed: {ex.Message}");
        }

        using (doc)
        {
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return QrDecodeResult.Fail(
                    $"shape: payload root must be a JSON object, got {root.ValueKind}");
            }

            // Required top-level fields. Collect all missing fields up-front
            // so the operator gets a single comprehensive error rather than
            // having to fix them one at a time.
            var missing = new List<string>();
            JsonElement vEl = default, kindEl = default, issEl = default,
                audEl = default, iatEl = default, expEl = default,
                jtiEl = default, bodyEl = default, qrMetaEl = default;
            if (!root.TryGetProperty("v", out vEl)) missing.Add("v");
            if (!root.TryGetProperty("kind", out kindEl)) missing.Add("kind");
            if (!root.TryGetProperty("iss", out issEl)) missing.Add("iss");
            if (!root.TryGetProperty("aud", out audEl)) missing.Add("aud");
            if (!root.TryGetProperty("iat", out iatEl)) missing.Add("iat");
            if (!root.TryGetProperty("exp", out expEl)) missing.Add("exp");
            if (!root.TryGetProperty("jti", out jtiEl)) missing.Add("jti");
            if (!root.TryGetProperty("body", out bodyEl)) missing.Add("body");
            if (!root.TryGetProperty("_qr_meta", out qrMetaEl)) missing.Add("_qr_meta");
            if (missing.Count > 0)
            {
                return QrDecodeResult.Fail(
                    $"shape: payload missing required field(s): {string.Join(", ", missing)}");
            }

            // v: int
            if (vEl.ValueKind != JsonValueKind.Number || !vEl.TryGetInt32(out var v))
            {
                return QrDecodeResult.Fail("shape: 'v' must be an integer");
            }
            if (v != QRSchema.Version)
            {
                return QrDecodeResult.Fail(
                    $"claims: schema version v={v} not supported " +
                    $"(decoder supports v={QRSchema.Version})");
            }

            // kind: string
            if (kindEl.ValueKind != JsonValueKind.String)
            {
                return QrDecodeResult.Fail("shape: 'kind' must be a string");
            }
            var kind = kindEl.GetString()!;

            // iss: string
            if (issEl.ValueKind != JsonValueKind.String)
            {
                return QrDecodeResult.Fail("shape: 'iss' must be a string");
            }
            var iss = issEl.GetString()!;

            // aud: array of strings
            if (audEl.ValueKind != JsonValueKind.Array)
            {
                return QrDecodeResult.Fail("shape: 'aud' must be an array");
            }
            var audList = new List<string>();
            foreach (var item in audEl.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.String)
                {
                    return QrDecodeResult.Fail(
                        "shape: 'aud' must be an array of strings");
                }
                audList.Add(item.GetString()!);
            }

            // iat: long
            if (iatEl.ValueKind != JsonValueKind.Number || !iatEl.TryGetInt64(out var iat))
            {
                return QrDecodeResult.Fail(
                    "shape: 'iat' must be an integer (unix seconds)");
            }

            // exp: long
            if (expEl.ValueKind != JsonValueKind.Number || !expEl.TryGetInt64(out var exp))
            {
                return QrDecodeResult.Fail(
                    "shape: 'exp' must be an integer (unix seconds)");
            }

            // jti: string
            if (jtiEl.ValueKind != JsonValueKind.String)
            {
                return QrDecodeResult.Fail("shape: 'jti' must be a string");
            }
            var jti = jtiEl.GetString()!;

            // body: object
            if (bodyEl.ValueKind != JsonValueKind.Object)
            {
                return QrDecodeResult.Fail("shape: 'body' must be an object");
            }
            var body = JsonElementToDict(bodyEl);

            // _qr_meta: object (format + max_size_bytes required; fragmentation optional)
            if (qrMetaEl.ValueKind != JsonValueKind.Object)
            {
                return QrDecodeResult.Fail("shape: '_qr_meta' must be an object");
            }
            var qrMetaResult = ParseQrMeta(qrMetaEl);
            if (!qrMetaResult.Success)
            {
                return QrDecodeResult.Fail(qrMetaResult.Error!);
            }
            var qrMeta = qrMetaResult.Meta!;

            // expectedKind (if supplied)
            if (expectedKind != null &&
                !string.Equals(kind, expectedKind, StringComparison.Ordinal))
            {
                return QrDecodeResult.Fail(
                    $"claims: kind '{kind}' does not match expected '{expectedKind}'");
            }

            // expectedAud (if supplied)
            if (expectedAud != null && !audList.Contains(expectedAud))
            {
                return QrDecodeResult.Fail(
                    $"claims: aud [{string.Join(",", audList)}] does not contain " +
                    $"expected '{expectedAud}'");
            }

            // Time bounds
            var nowUnix = now ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (exp + clockSkewSeconds < nowUnix)
            {
                return QrDecodeResult.Fail(
                    $"claims: token exp={exp} has passed " +
                    $"(now={nowUnix}, skew={clockSkewSeconds}s)");
            }
            if (iat - clockSkewSeconds > nowUnix)
            {
                return QrDecodeResult.Fail(
                    $"claims: token iat={iat} is in the future " +
                    $"(now={nowUnix}, skew={clockSkewSeconds}s)");
            }

            var payload = new QRPayloadV1(
                V: v,
                Kind: kind,
                Iss: iss,
                Aud: audList,
                Iat: iat,
                Exp: exp,
                Jti: jti,
                Body: body,
                QrMeta: qrMeta);
            return QrDecodeResult.Ok(payload);
        }
    }

    // -----------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------

    private sealed record QrMetaParseResult(bool Success, QRMeta? Meta, string? Error)
    {
        public static QrMetaParseResult Ok(QRMeta meta) => new(true, meta, null);

        public static QrMetaParseResult Fail(string error) => new(false, null, error);
    }

    private static QrMetaParseResult ParseQrMeta(JsonElement el)
    {
        if (!el.TryGetProperty("format", out var formatEl) ||
            formatEl.ValueKind != JsonValueKind.String)
        {
            return QrMetaParseResult.Fail(
                "shape: '_qr_meta.format' must be a string");
        }
        var format = formatEl.GetString()!;

        if (!el.TryGetProperty("max_size_bytes", out var maxSizeEl) ||
            maxSizeEl.ValueKind != JsonValueKind.Number ||
            !maxSizeEl.TryGetInt32(out var maxSize))
        {
            return QrMetaParseResult.Fail(
                "shape: '_qr_meta.max_size_bytes' must be an integer");
        }

        IReadOnlyDictionary<string, int>? fragmentation = null;
        if (el.TryGetProperty("fragmentation", out var fragEl))
        {
            if (fragEl.ValueKind == JsonValueKind.Null)
            {
                fragmentation = null;
            }
            else if (fragEl.ValueKind == JsonValueKind.Object)
            {
                var fragDict = new Dictionary<string, int>();
                foreach (var prop in fragEl.EnumerateObject())
                {
                    if (prop.Value.ValueKind != JsonValueKind.Number ||
                        !prop.Value.TryGetInt32(out var fv))
                    {
                        return QrMetaParseResult.Fail(
                            $"shape: '_qr_meta.fragmentation.{prop.Name}' must be an integer");
                    }
                    fragDict[prop.Name] = fv;
                }
                fragmentation = fragDict;
            }
            else
            {
                return QrMetaParseResult.Fail(
                    "shape: '_qr_meta.fragmentation' must be null or an object");
            }
        }

        return QrMetaParseResult.Ok(new QRMeta(format, maxSize, fragmentation));
    }

    /// <summary>
    /// Convert a JsonElement (object kind) to the IReadOnlyDictionary
    /// shape QRPayloadV1.Body expects. Recursive — nested objects/arrays
    /// preserve structure. Used for the body field which has kind-specific
    /// shape (capability_request body is typically {"jws": "..."}; richer
    /// kinds carry structured payloads).
    /// </summary>
    private static IReadOnlyDictionary<string, object?> JsonElementToDict(JsonElement el)
    {
        var dict = new Dictionary<string, object?>();
        foreach (var prop in el.EnumerateObject())
        {
            dict[prop.Name] = JsonElementToValue(prop.Value);
        }
        return dict;
    }

    private static object? JsonElementToValue(JsonElement el)
    {
        switch (el.ValueKind)
        {
            case JsonValueKind.String:
                return el.GetString();
            case JsonValueKind.Number:
                // Prefer long when possible (matches canonical-JSON's
                // long-only integer contract from the encoder side).
                if (el.TryGetInt64(out var l)) return l;
                if (el.TryGetDouble(out var d)) return d;
                return el.GetRawText();
            case JsonValueKind.True:
                return true;
            case JsonValueKind.False:
                return false;
            case JsonValueKind.Null:
                return null;
            case JsonValueKind.Array:
                var list = new List<object?>();
                foreach (var item in el.EnumerateArray())
                {
                    list.Add(JsonElementToValue(item));
                }
                return list;
            case JsonValueKind.Object:
                return JsonElementToDict(el);
            default:
                return null;
        }
    }
}
