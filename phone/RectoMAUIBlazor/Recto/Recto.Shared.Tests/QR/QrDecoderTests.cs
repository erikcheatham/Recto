using System;
using System.Collections.Generic;
using System.Text;
using Recto.Shared.Capability;
using Recto.Shared.QR;
using Xunit;

namespace Recto.Shared.Tests.QR;

/// <summary>
/// Pins the QrDecoder primitives' behavior. Covers round-trip with the
/// QrEncoder (encoder text → decoder → identical envelope fields),
/// shape rejection (malformed JSON, missing fields, wrong types, _qr_meta
/// shape), and claims rejection (wrong v, wrong kind, wrong aud, expired
/// exp, iat in future). Category-prefixed error messages (<c>shape:</c>
/// vs <c>claims:</c>) verified so callers can surface distinct
/// diagnostics to users.
/// <para>
/// Sister of QrEncoderTests.cs patterns + the eventual Python
/// <c>tests/test_qr_decode.py</c> if a Python decoder ever ships.
/// </para>
/// </summary>
public class QrDecoderTests
{
    // -----------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------

    /// <summary>
    /// Build a canonical QRPayloadV1 + encode to canonical-JSON text
    /// the same way the encoder pipeline does. Sister of the encoder's
    /// EncodeText(EncodePayload(...)) but stops at the text-content
    /// layer so tests don't need to round-trip through PNG.
    /// </summary>
    private static string BuildCanonicalText(
        string kind = "capability_request",
        string iss = "phone:operator:enclave",
        IReadOnlyList<string>? aud = null,
        long iat = 1716200000,
        long exp = 1716203600,
        string jti = "test-jti",
        IReadOnlyDictionary<string, object?>? body = null)
    {
        var payload = QRPayloadV1.Create(
            kind: kind,
            iss: iss,
            aud: aud ?? new List<string> { "allthruit" },
            iat: iat,
            exp: exp,
            jti: jti,
            body: body ?? new Dictionary<string, object?> { ["jws"] = "h.b.s" });

        var dict = QrCanonicalJson.QrPayloadV1ToDict(payload);
        var bytes = CanonicalJson.Encode(dict);
        return Encoding.UTF8.GetString(bytes);
    }

    /// <summary>
    /// "Now" reference used across time-bounds tests. Chosen so the
    /// default iat/exp from <see cref="BuildCanonicalText"/> are
    /// in-window without skew adjustment.
    /// </summary>
    private const long DefaultNow = 1716201000;

    // -----------------------------------------------------------------
    // Round-trip
    // -----------------------------------------------------------------

    [Fact]
    public void DecodeText_RoundTrip_PreservesEnvelopeFields()
    {
        var text = BuildCanonicalText(
            kind: "pairing_invite",
            iss: "allthruit-pairing",
            aud: new List<string> { "allthruit", "recto" },
            iat: 1716200000,
            exp: 1716200300,
            jti: "9c9f8848-7555-4d65-a841-6062c50fd26f",
            body: new Dictionary<string, object?>
            {
                ["bootloader"] = "https://bootloader.allthruit.ai",
                ["code"] = "82HESDZC",
            });

        var result = QrDecoder.DecodeText(text, now: 1716200100);

        Assert.True(result.Success, result.Error);
        Assert.NotNull(result.Payload);
        var p = result.Payload!;
        Assert.Equal(QRSchema.Version, p.V);
        Assert.Equal("pairing_invite", p.Kind);
        Assert.Equal("allthruit-pairing", p.Iss);
        Assert.Equal(new[] { "allthruit", "recto" }, p.Aud);
        Assert.Equal(1716200000L, p.Iat);
        Assert.Equal(1716200300L, p.Exp);
        Assert.Equal("9c9f8848-7555-4d65-a841-6062c50fd26f", p.Jti);
        Assert.Equal("https://bootloader.allthruit.ai", p.Body["bootloader"]);
        Assert.Equal("82HESDZC", p.Body["code"]);
        Assert.Equal(QRFormats.PngV1, p.QrMeta.Format);
        Assert.Equal(QRCapacities.V40L, p.QrMeta.MaxSizeBytes);
        Assert.Null(p.QrMeta.Fragmentation);
    }

    [Fact]
    public void DecodeText_RoundTrip_PreservesNestedBodyStructure()
    {
        // Body with nested object + array — exercises JsonElementToDict
        // recursion path.
        var nestedBody = new Dictionary<string, object?>
        {
            ["jws"] = "h.b.s",
            ["meta"] = new Dictionary<string, object?>
            {
                ["agent"] = "darwin-orchestrator",
                ["tier"] = 1L,
                ["actions"] = new List<object?> { "chat:post_reply", "review:delete" },
            },
        };
        var text = BuildCanonicalText(body: nestedBody);

        var result = QrDecoder.DecodeText(text, now: DefaultNow);

        Assert.True(result.Success, result.Error);
        var p = result.Payload!;
        Assert.Equal("h.b.s", p.Body["jws"]);
        Assert.IsAssignableFrom<IReadOnlyDictionary<string, object?>>(p.Body["meta"]);
        var meta = (IReadOnlyDictionary<string, object?>)p.Body["meta"]!;
        Assert.Equal("darwin-orchestrator", meta["agent"]);
        Assert.Equal(1L, meta["tier"]);
        Assert.IsAssignableFrom<IReadOnlyList<object?>>(meta["actions"]);
    }

    // -----------------------------------------------------------------
    // Shape rejection — JSON / structural
    // -----------------------------------------------------------------

    [Fact]
    public void DecodeText_RejectsEmptyText()
    {
        var result = QrDecoder.DecodeText("");
        Assert.False(result.Success);
        Assert.StartsWith("shape:", result.Error);
        Assert.Contains("empty", result.Error);
    }

    [Fact]
    public void DecodeText_RejectsNullText()
    {
        var result = QrDecoder.DecodeText(null!);
        Assert.False(result.Success);
        Assert.StartsWith("shape:", result.Error);
    }

    [Fact]
    public void DecodeText_RejectsMalformedJson()
    {
        var result = QrDecoder.DecodeText("{not valid json");
        Assert.False(result.Success);
        Assert.StartsWith("shape:", result.Error);
        Assert.Contains("JSON parse failed", result.Error);
    }

    [Fact]
    public void DecodeText_RejectsNonObjectRoot()
    {
        var result = QrDecoder.DecodeText("[1, 2, 3]");
        Assert.False(result.Success);
        Assert.StartsWith("shape:", result.Error);
        Assert.Contains("must be a JSON object", result.Error);
    }

    [Fact]
    public void DecodeText_RejectsMissingRequiredFields()
    {
        // Empty object — every required field is missing.
        var result = QrDecoder.DecodeText("{}");
        Assert.False(result.Success);
        Assert.StartsWith("shape:", result.Error);
        Assert.Contains("missing required field(s)", result.Error);
        // All nine required fields surface in one error.
        Assert.Contains("v", result.Error);
        Assert.Contains("kind", result.Error);
        Assert.Contains("iss", result.Error);
        Assert.Contains("aud", result.Error);
        Assert.Contains("iat", result.Error);
        Assert.Contains("exp", result.Error);
        Assert.Contains("jti", result.Error);
        Assert.Contains("body", result.Error);
        Assert.Contains("_qr_meta", result.Error);
    }

    [Theory]
    [InlineData("v", @"""bad""")]                  // v as string instead of int
    [InlineData("kind", "123")]                    // kind as number
    [InlineData("iss", "true")]                    // iss as bool
    [InlineData("aud", @"""not-an-array""")]       // aud as string
    [InlineData("iat", @"""not-a-number""")]       // iat as string
    [InlineData("exp", "null")]                    // exp as null
    [InlineData("jti", "[]")]                      // jti as array
    [InlineData("body", @"""not-an-object""")]     // body as string
    [InlineData("_qr_meta", "[]")]                 // _qr_meta as array
    public void DecodeText_RejectsWrongFieldType(string field, string badValue)
    {
        // Build a valid payload, then surgically replace one field's
        // value with badValue. Tests that each field's type check fires
        // distinctly.
        var text = BuildCanonicalText();
        var malformed = ReplaceJsonField(text, field, badValue);

        var result = QrDecoder.DecodeText(malformed, now: DefaultNow);
        Assert.False(result.Success);
        Assert.StartsWith("shape:", result.Error);
        Assert.Contains($"'{field}'", result.Error);
    }

    [Fact]
    public void DecodeText_RejectsAudArrayWithNonStringElement()
    {
        // aud is an array but contains a non-string value (number).
        // Sister of the wrong-field-type table above but exercises the
        // per-element type check inside the aud branch.
        var text = BuildCanonicalText();
        var malformed = ReplaceJsonField(text, "aud", @"[""ok"", 42]");
        var result = QrDecoder.DecodeText(malformed, now: DefaultNow);
        Assert.False(result.Success);
        Assert.StartsWith("shape:", result.Error);
        Assert.Contains("aud", result.Error);
    }

    // -----------------------------------------------------------------
    // Shape rejection — _qr_meta
    // -----------------------------------------------------------------

    [Fact]
    public void DecodeText_RejectsQrMetaMissingFormat()
    {
        var text = BuildCanonicalText();
        var malformed = ReplaceJsonField(text, "_qr_meta",
            @"{""max_size_bytes"":2953,""fragmentation"":null}");
        var result = QrDecoder.DecodeText(malformed, now: DefaultNow);
        Assert.False(result.Success);
        Assert.StartsWith("shape:", result.Error);
        Assert.Contains("_qr_meta.format", result.Error);
    }

    [Fact]
    public void DecodeText_RejectsQrMetaMissingMaxSizeBytes()
    {
        var text = BuildCanonicalText();
        var malformed = ReplaceJsonField(text, "_qr_meta",
            @"{""format"":""qr-pngv1"",""fragmentation"":null}");
        var result = QrDecoder.DecodeText(malformed, now: DefaultNow);
        Assert.False(result.Success);
        Assert.StartsWith("shape:", result.Error);
        Assert.Contains("_qr_meta.max_size_bytes", result.Error);
    }

    [Fact]
    public void DecodeText_AcceptsQrMetaWithFragmentationObject()
    {
        var text = BuildCanonicalText();
        var withFrag = ReplaceJsonField(text, "_qr_meta",
            @"{""format"":""qr-pngv1"",""max_size_bytes"":2953,""fragmentation"":{""part_1_of_2"":1,""part_2_of_2"":2}}");
        var result = QrDecoder.DecodeText(withFrag, now: DefaultNow);
        Assert.True(result.Success, result.Error);
        Assert.NotNull(result.Payload!.QrMeta.Fragmentation);
        Assert.Equal(1, result.Payload!.QrMeta.Fragmentation!["part_1_of_2"]);
        Assert.Equal(2, result.Payload!.QrMeta.Fragmentation!["part_2_of_2"]);
    }

    [Fact]
    public void DecodeText_RejectsQrMetaFragmentationWithNonIntValue()
    {
        var text = BuildCanonicalText();
        var bad = ReplaceJsonField(text, "_qr_meta",
            @"{""format"":""qr-pngv1"",""max_size_bytes"":2953,""fragmentation"":{""part_1_of_2"":""one""}}");
        var result = QrDecoder.DecodeText(bad, now: DefaultNow);
        Assert.False(result.Success);
        Assert.StartsWith("shape:", result.Error);
        Assert.Contains("_qr_meta.fragmentation", result.Error);
    }

    // -----------------------------------------------------------------
    // Claims rejection — v / kind / aud / time bounds
    // -----------------------------------------------------------------

    [Fact]
    public void DecodeText_RejectsUnsupportedSchemaVersion()
    {
        var text = BuildCanonicalText();
        // Bump v from 1 to 2.
        var malformed = ReplaceJsonField(text, "v", "2");
        var result = QrDecoder.DecodeText(malformed, now: DefaultNow);
        Assert.False(result.Success);
        Assert.StartsWith("claims:", result.Error);
        Assert.Contains("v=2", result.Error);
        Assert.Contains("not supported", result.Error);
    }

    [Fact]
    public void DecodeText_RejectsKindMismatch()
    {
        var text = BuildCanonicalText(kind: "pairing_invite");
        var result = QrDecoder.DecodeText(
            text,
            expectedKind: "capability_request",
            now: DefaultNow);
        Assert.False(result.Success);
        Assert.StartsWith("claims:", result.Error);
        Assert.Contains("kind 'pairing_invite'", result.Error);
        Assert.Contains("capability_request", result.Error);
    }

    [Fact]
    public void DecodeText_AcceptsKindMatch()
    {
        var text = BuildCanonicalText(kind: "pairing_invite");
        var result = QrDecoder.DecodeText(
            text,
            expectedKind: "pairing_invite",
            now: DefaultNow);
        Assert.True(result.Success, result.Error);
    }

    [Fact]
    public void DecodeText_RejectsAudMissingExpected()
    {
        var text = BuildCanonicalText(
            aud: new List<string> { "recto" });
        var result = QrDecoder.DecodeText(
            text,
            expectedAud: "allthruit",
            now: DefaultNow);
        Assert.False(result.Success);
        Assert.StartsWith("claims:", result.Error);
        Assert.Contains("aud", result.Error);
        Assert.Contains("allthruit", result.Error);
    }

    [Fact]
    public void DecodeText_AcceptsAudContainingExpected()
    {
        var text = BuildCanonicalText(
            aud: new List<string> { "allthruit", "recto" });
        var result = QrDecoder.DecodeText(
            text,
            expectedAud: "allthruit",
            now: DefaultNow);
        Assert.True(result.Success, result.Error);
    }

    [Fact]
    public void DecodeText_RejectsExpiredExp()
    {
        // exp 100s in the past relative to now, well past the default
        // 30s clock skew.
        var text = BuildCanonicalText(
            iat: 1716200000,
            exp: 1716200100);
        var result = QrDecoder.DecodeText(text, now: 1716200300);
        Assert.False(result.Success);
        Assert.StartsWith("claims:", result.Error);
        Assert.Contains("exp", result.Error);
        Assert.Contains("has passed", result.Error);
    }

    [Fact]
    public void DecodeText_AcceptsExpJustInWindowWithSkew()
    {
        // exp is 20s in the past — within the default 30s skew tolerance.
        var text = BuildCanonicalText(
            iat: 1716200000,
            exp: 1716200280);
        var result = QrDecoder.DecodeText(text, now: 1716200300);
        Assert.True(result.Success, result.Error);
    }

    [Fact]
    public void DecodeText_RejectsIatInFuture()
    {
        // iat is 100s in the future — well past skew tolerance.
        var text = BuildCanonicalText(
            iat: 1716200400,
            exp: 1716203000);
        var result = QrDecoder.DecodeText(text, now: 1716200300);
        Assert.False(result.Success);
        Assert.StartsWith("claims:", result.Error);
        Assert.Contains("iat", result.Error);
        Assert.Contains("future", result.Error);
    }

    [Fact]
    public void DecodeText_CustomClockSkewTightensWindow()
    {
        // exp 20s in the past, default 30s skew accepts it; pass
        // clockSkewSeconds=0 to tighten and verify rejection.
        var text = BuildCanonicalText(
            iat: 1716200000,
            exp: 1716200280);
        var result = QrDecoder.DecodeText(
            text,
            now: 1716200300,
            clockSkewSeconds: 0);
        Assert.False(result.Success);
        Assert.StartsWith("claims:", result.Error);
        Assert.Contains("exp", result.Error);
    }

    // -----------------------------------------------------------------
    // Category prefix discipline
    // -----------------------------------------------------------------

    [Fact]
    public void DecodeText_ErrorsAreCategoryPrefixed()
    {
        // shape: errors come from structural failures
        var r1 = QrDecoder.DecodeText("");
        Assert.StartsWith("shape:", r1.Error);

        // claims: errors come from semantic failures
        var text = BuildCanonicalText(kind: "pairing_invite");
        var r2 = QrDecoder.DecodeText(
            text,
            expectedKind: "capability_request",
            now: DefaultNow);
        Assert.StartsWith("claims:", r2.Error);
    }

    // -----------------------------------------------------------------
    // JSON manipulation helper for negative tests
    // -----------------------------------------------------------------

    /// <summary>
    /// Replace the value of a top-level field in a canonical-JSON string
    /// without re-canonicalizing. Used to construct malformed payloads
    /// for negative tests where we want one specific field to be wrong
    /// while the rest stay valid.
    /// <para>
    /// Cheap implementation — string match on <c>"field":</c> and replace
    /// the value up to the next top-level comma or closing brace. Works
    /// for the canonical-JSON-emitter's output shape (no whitespace,
    /// sorted keys) which is exactly what BuildCanonicalText produces.
    /// </para>
    /// </summary>
    private static string ReplaceJsonField(string canonical, string field, string newValue)
    {
        // Canonical JSON has no spaces; field separator is exactly `"<field>":`.
        var marker = $"\"{field}\":";
        var startIdx = canonical.IndexOf(marker, StringComparison.Ordinal);
        if (startIdx < 0)
        {
            throw new InvalidOperationException(
                $"field '{field}' not found in canonical text for negative test");
        }
        var valueStart = startIdx + marker.Length;
        var valueEnd = FindTopLevelValueEnd(canonical, valueStart);
        return canonical.Substring(0, valueStart) +
               newValue +
               canonical.Substring(valueEnd);
    }

    /// <summary>
    /// Given a canonical-JSON string + start index of a top-level field's
    /// value, return the index one-past-the-end of that value. Handles
    /// nested objects/arrays + strings with escapes.
    /// </summary>
    private static int FindTopLevelValueEnd(string s, int start)
    {
        int depth = 0;
        bool inString = false;
        bool escape = false;
        for (int i = start; i < s.Length; i++)
        {
            char c = s[i];
            if (inString)
            {
                if (escape) { escape = false; continue; }
                if (c == '\\') { escape = true; continue; }
                if (c == '"') { inString = false; continue; }
                continue;
            }
            if (c == '"') { inString = true; continue; }
            if (c == '{' || c == '[') { depth++; continue; }
            if (c == '}' || c == ']')
            {
                if (depth == 0) return i;        // closing brace of parent
                depth--;
                continue;
            }
            if (c == ',' && depth == 0) return i;
        }
        return s.Length;
    }
}
