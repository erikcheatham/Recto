using System;
using System.Collections.Generic;
using System.Text;
using Recto.Shared.QR;
using Xunit;

namespace Recto.Shared.Tests.QR;

/// <summary>
/// Pins the QrEncoder primitives' output behavior. Doesn't verify PNG
/// bytes byte-identically (QR rendering is deterministic for the same
/// input but library-specific compression isn't guaranteed reproducible
/// across QRCoder versions); instead verifies structural properties:
/// non-empty output, PNG magic bytes, no exceptions on canonical
/// inputs, all 4 EC levels work, oversize payloads reject cleanly.
/// <para>
/// Sister of Python's <c>tests/test_qr_encode.py::TestQrEncodeJws</c>
/// and <c>TestQrEncodePayload</c> classes.
/// </para>
/// </summary>
public class QrEncoderTests
{
    // PNG magic bytes: 89 50 4E 47 0D 0A 1A 0A
    private static readonly byte[] PngMagic = new byte[]
    {
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
    };

    private static bool StartsWithPngMagic(byte[] bytes)
    {
        if (bytes == null || bytes.Length < 8) return false;
        for (int i = 0; i < 8; i++)
        {
            if (bytes[i] != PngMagic[i]) return false;
        }
        return true;
    }

    // -----------------------------------------------------------------
    // EncodeText
    // -----------------------------------------------------------------

    [Fact]
    public void EncodeText_ShortJwsToPng_StartsWithPngMagic()
    {
        // Sister of test_encodes_short_jws_to_png (Python)
        const string jws = "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJ0ZXN0In0.signature";
        var pngBytes = QrEncoder.EncodeText(jws);
        Assert.True(pngBytes.Length > 0, "PNG output is empty");
        Assert.True(StartsWithPngMagic(pngBytes),
            $"PNG magic bytes missing; got {BitConverter.ToString(pngBytes[..8])}");
    }

    [Fact]
    public void EncodeText_ShortJwsToSvg_ContainsSvgTag()
    {
        // Sister of test_encodes_short_jws_to_svg
        const string jws = "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJ0ZXN0In0.signature";
        var svgBytes = QrEncoder.EncodeText(jws, imageFormat: "svg");
        Assert.True(svgBytes.Length > 0);
        var svgString = Encoding.UTF8.GetString(svgBytes);
        // SVG output contains an <svg tag (with or without XML declaration)
        Assert.True(
            svgString.Contains("<svg", StringComparison.OrdinalIgnoreCase),
            $"SVG output missing <svg tag; first 200 chars: {svgString[..Math.Min(200, svgString.Length)]}");
    }

    [Fact]
    public void EncodeText_RejectsEmptyText()
    {
        // Sister of test_rejects_empty_jws
        Assert.Throws<ArgumentException>(() => QrEncoder.EncodeText(""));
    }

    [Fact]
    public void EncodeText_RejectsNullText()
    {
        Assert.Throws<ArgumentException>(() => QrEncoder.EncodeText(null!));
    }

    [Fact]
    public void EncodeText_RejectsUnknownImageFormat()
    {
        // Sister of test_rejects_unknown_image_format
        Assert.Throws<ArgumentException>(() =>
            QrEncoder.EncodeText("test.jws.sig", imageFormat: "bmp"));
    }

    [Fact]
    public void EncodeText_RejectsUnknownErrorCorrection()
    {
        // Sister of test_rejects_unknown_error_correction
        Assert.Throws<ArgumentException>(() =>
            QrEncoder.EncodeText("test.jws.sig", errorCorrection: "X"));
    }

    [Theory]
    [InlineData("L")]
    [InlineData("M")]
    [InlineData("Q")]
    [InlineData("H")]
    public void EncodeText_AllErrorCorrectionLevelsWork(string ec)
    {
        // Sister of test_all_error_correction_levels_work
        const string jws = "test.jws.sig";
        var pngBytes = QrEncoder.EncodeText(jws, errorCorrection: ec);
        Assert.True(StartsWithPngMagic(pngBytes));
    }

    [Fact]
    public void EncodeText_TypicalCapabilityJwsLength()
    {
        // Sister of test_long_jws_at_capacity_limit.
        // Typical capability JWS is 400-800 bytes — well under any
        // EC level's capacity.
        var jws = new string('x', 700);
        var pngBytes = QrEncoder.EncodeText(jws);
        Assert.True(StartsWithPngMagic(pngBytes));
    }

    // -----------------------------------------------------------------
    // EncodePayload
    // -----------------------------------------------------------------

    [Fact]
    public void EncodePayload_QRPayloadV1_ProducesPng()
    {
        // Sister of test_encodes_qrpayloadv1_dataclass
        var payload = QRPayloadV1.Create(
            kind: "capability_request",
            iss: "phone:operator:enclave",
            aud: new List<string> { "allthruit" },
            iat: 1716200000,
            exp: 1716203600,
            jti: "test-jti",
            body: new Dictionary<string, object?> { ["jws"] = "header.body.sig" });
        var pngBytes = QrEncoder.EncodePayload(payload);
        Assert.True(StartsWithPngMagic(pngBytes));
    }

    [Fact]
    public void EncodePayload_RejectsNull()
    {
        Assert.Throws<ArgumentNullException>(() =>
            QrEncoder.EncodePayload(null!));
    }

    [Fact]
    public void EncodePayload_RejectsOversizePayload()
    {
        // Sister of test_rejects_oversize_payload.
        // Construct a payload whose canonical-JSON encoding exceeds
        // 2953 bytes (QR v40-L capacity).
        var hugeBody = new Dictionary<string, object?>
        {
            ["data"] = new string('x', 3500),
        };
        var payload = QRPayloadV1.Create(
            kind: "test",
            iss: "x",
            aud: new List<string>(),
            iat: 0,
            exp: 0,
            jti: "j",
            body: hugeBody);
        var ex = Assert.Throws<ArgumentException>(() =>
            QrEncoder.EncodePayload(payload));
        Assert.Contains("exceeds QR", ex.Message);
    }

    // -----------------------------------------------------------------
    // EncodeMultiWitness
    // -----------------------------------------------------------------

    [Fact]
    public void EncodeMultiWitness_PartialContractEncodes()
    {
        // Sister of test_encodes_partial_contract.
        // Partial-signed contracts render fine (passed between
        // witnesses).
        var contract = QrMultiWitness.CreateContract(
            iss: "x",
            subject: new Dictionary<string, object?> { ["id"] = "test" },
            requiredWitnesses: new List<string> { "user:a", "user:b" });
        contract = QrMultiWitness.AddWitnessSignature(
            contract, "user:a", "sig-a", 100);
        var pngBytes = QrEncoder.EncodeMultiWitness(contract);
        Assert.True(StartsWithPngMagic(pngBytes));
    }

    [Fact]
    public void EncodeMultiWitness_CompletedContractEncodes()
    {
        // Sister of test_encodes_completed_contract
        var contract = QrMultiWitness.CreateContract(
            iss: "x",
            subject: new Dictionary<string, object?> { ["id"] = "test" },
            requiredWitnesses: new List<string> { "user:a", "user:b" });
        contract = QrMultiWitness.AddWitnessSignature(
            contract, "user:a", "sig-a", 100);
        contract = QrMultiWitness.AddWitnessSignature(
            contract, "user:b", "sig-b", 200);
        Assert.True(contract.IsComplete());
        var pngBytes = QrEncoder.EncodeMultiWitness(contract);
        Assert.True(StartsWithPngMagic(pngBytes));
    }

    [Fact]
    public void EncodeMultiWitness_SvgOutput()
    {
        // Sister of test_svg_output
        var contract = QrMultiWitness.CreateContract(
            iss: "x",
            subject: new Dictionary<string, object?>(),
            requiredWitnesses: new List<string> { "user:a" });
        var svgBytes = QrEncoder.EncodeMultiWitness(
            contract, imageFormat: "svg");
        var svgString = Encoding.UTF8.GetString(svgBytes);
        Assert.True(svgString.Contains("<svg", StringComparison.OrdinalIgnoreCase));
    }

    // -----------------------------------------------------------------
    // PngBytesToDataUri (Recto Phone integration helper)
    // -----------------------------------------------------------------

    [Fact]
    public void PngBytesToDataUri_ProducesDataUriPrefix()
    {
        var pngBytes = QrEncoder.EncodeText("test.jws.sig");
        var dataUri = QrEncoder.PngBytesToDataUri(pngBytes);
        Assert.StartsWith("data:image/png;base64,", dataUri);
    }

    [Fact]
    public void PngBytesToDataUri_RejectsNull()
    {
        Assert.Throws<ArgumentNullException>(() =>
            QrEncoder.PngBytesToDataUri(null!));
    }

    [Fact]
    public void PngBytesToDataUri_RejectsNonPngBytes()
    {
        var notPng = Encoding.UTF8.GetBytes("not a png");
        Assert.Throws<ArgumentException>(() =>
            QrEncoder.PngBytesToDataUri(notPng));
    }

    // -----------------------------------------------------------------
    // SvgBytesToString
    // -----------------------------------------------------------------

    [Fact]
    public void SvgBytesToString_RoundTripsToText()
    {
        var svgBytes = QrEncoder.EncodeText("test", imageFormat: "svg");
        var svgString = QrEncoder.SvgBytesToString(svgBytes);
        Assert.Contains("<svg", svgString, StringComparison.OrdinalIgnoreCase);
    }
}
