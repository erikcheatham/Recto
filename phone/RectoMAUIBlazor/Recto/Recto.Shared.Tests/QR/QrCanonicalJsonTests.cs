using System.Collections.Generic;
using System.Text;
using Recto.Shared.QR;
using Xunit;

namespace Recto.Shared.Tests.QR;

/// <summary>
/// Pins canonical-JSON byte output for QR-encoded signed payloads
/// against Python's <c>recto.qr.encode</c> module. Cross-language
/// byte-parity is the contract that lets a QR-encoded payload signed
/// on one runtime verify on the other.
/// <para>
/// Each test below has a sister test in
/// <c>tests/test_qr_encode.py</c> (Python) — same input, same
/// expected byte sequence. If these drift, a QR-wrapped capability
/// JWS or multi-witness contract signed on Python won't verify on
/// C# (and vice versa).
/// </para>
/// </summary>
public class QrCanonicalJsonTests
{
    [Fact]
    public void StripQrMeta_RemovesQrMetaKey()
    {
        // Sister of test_strips_qr_meta_from_payload in test_qr_encode.py
        var payload = new Dictionary<string, object?>
        {
            ["v"] = (long)1,
            ["kind"] = "capability_request",
            ["body"] = new Dictionary<string, object?>
            {
                ["jws"] = "header.body.sig",
            },
            ["_qr_meta"] = new Dictionary<string, object?>
            {
                ["format"] = "qr-pngv1",
                ["max_size_bytes"] = (long)2953,
            },
        };
        var stripped = QrCanonicalJson.StripQrMeta(payload);
        Assert.False(stripped.ContainsKey("_qr_meta"));
        Assert.Equal((long)1, stripped["v"]);
        Assert.Equal("capability_request", stripped["kind"]);
    }

    [Fact]
    public void StripQrMeta_NoOpWhenAbsent()
    {
        // Sister of test_no_op_when_qr_meta_absent
        var payload = new Dictionary<string, object?>
        {
            ["v"] = (long)1,
            ["kind"] = "test",
        };
        var stripped = QrCanonicalJson.StripQrMeta(payload);
        Assert.Equal(2, stripped.Count);
        Assert.NotSame(payload, stripped); // returns a copy
    }

    [Fact]
    public void CanonicalSigningInput_StripsQrMetaAndCanonicalEncodes()
    {
        // Sister of test_strips_qr_meta_and_canonical_encodes in
        // test_qr_encode.py. Pin the EXACT byte sequence.
        var body = new Dictionary<string, object?>
        {
            ["jws"] = "header.body.sig",
        };
        var qrMeta = new Dictionary<string, object?>
        {
            ["format"] = "qr-pngv1",
            ["max_size_bytes"] = (long)2953,
        };
        var payload = new Dictionary<string, object?>
        {
            ["v"] = (long)1,
            ["kind"] = "capability_request",
            ["iss"] = "phone:operator:enclave",
            ["iat"] = (long)1716200000,
            ["body"] = body,
            ["_qr_meta"] = qrMeta,
        };

        var result = QrCanonicalJson.CanonicalSigningInput(payload);
        var expected = Encoding.UTF8.GetBytes(
            "{\"body\":{\"jws\":\"header.body.sig\"}," +
            "\"iat\":1716200000," +
            "\"iss\":\"phone:operator:enclave\"," +
            "\"kind\":\"capability_request\"," +
            "\"v\":1}"
        );
        Assert.Equal(expected, result);
    }

    [Fact]
    public void CanonicalSigningInput_ByteIdenticalAcrossDictOrderings()
    {
        // Sister of test_byte_identical_across_payload_dict_orderings.
        // Different insertion orders into the same dict produce
        // identical signing input.
        var p1 = new Dictionary<string, object?>
        {
            ["v"] = (long)1,
            ["kind"] = "test",
            ["iss"] = "a",
            ["body"] = new Dictionary<string, object?>(),
        };
        var p2 = new Dictionary<string, object?>
        {
            ["body"] = new Dictionary<string, object?>(),
            ["iss"] = "a",
            ["kind"] = "test",
            ["v"] = (long)1,
        };
        Assert.Equal(
            QrCanonicalJson.CanonicalSigningInput(p1),
            QrCanonicalJson.CanonicalSigningInput(p2));
    }

    [Fact]
    public void CanonicalSigningInput_ExcludesQrMetaChanges()
    {
        // Sister of test_signing_input_excludes_qr_meta_changes.
        // Two payloads identical except for _qr_meta produce same
        // signing input.
        var baseDict = new Dictionary<string, object?>
        {
            ["v"] = (long)1,
            ["kind"] = "test",
            ["body"] = new Dictionary<string, object?> { ["x"] = (long)1 },
        };
        var withMetaA = new Dictionary<string, object?>(baseDict)
        {
            ["_qr_meta"] = new Dictionary<string, object?>
            {
                ["format"] = "qr-pngv1",
                ["max_size_bytes"] = (long)2953,
            },
        };
        var withMetaB = new Dictionary<string, object?>(baseDict)
        {
            ["_qr_meta"] = new Dictionary<string, object?>
            {
                ["format"] = "qr-svgv1",
                ["max_size_bytes"] = (long)1273,
            },
        };
        Assert.Equal(
            QrCanonicalJson.CanonicalSigningInput(withMetaA),
            QrCanonicalJson.CanonicalSigningInput(withMetaB));
    }

    [Fact]
    public void QrMetaToDict_DefaultProducesExpectedShape()
    {
        var meta = QRMeta.Default();
        var dict = QrCanonicalJson.QrMetaToDict(meta);
        Assert.Equal("qr-pngv1", dict["format"]);
        Assert.Equal((long)2953, dict["max_size_bytes"]);
        Assert.Null(dict["fragmentation"]);
    }

    [Fact]
    public void QrPayloadV1ToDict_RoundTripsThroughCanonicalSigningInput()
    {
        // End-to-end: build a QRPayloadV1 record, convert to dict,
        // compute canonical signing input — output matches the
        // Python-pinned byte sequence.
        var payload = QRPayloadV1.Create(
            kind: "capability_request",
            iss: "phone:operator:enclave",
            aud: new List<string> { "allthruit" },
            iat: 1716200000,
            exp: 1716203600,
            jti: "test-jti",
            body: new Dictionary<string, object?> { ["jws"] = "h.b.s" });
        var dict = QrCanonicalJson.QrPayloadV1ToDict(payload);
        var signing = QrCanonicalJson.CanonicalSigningInput(dict);
        // Pin the exact bytes the JWT signer should sign over
        var expected = Encoding.UTF8.GetBytes(
            "{\"aud\":[\"allthruit\"]," +
            "\"body\":{\"jws\":\"h.b.s\"}," +
            "\"exp\":1716203600," +
            "\"iat\":1716200000," +
            "\"iss\":\"phone:operator:enclave\"," +
            "\"jti\":\"test-jti\"," +
            "\"kind\":\"capability_request\"," +
            "\"v\":1}"
        );
        Assert.Equal(expected, signing);
    }
}
