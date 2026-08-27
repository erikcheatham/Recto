using System;
using System.Collections.Generic;
using System.Text;
using QRCoder;
using Recto.Shared.Capability;

namespace Recto.Shared.QR;

/// <summary>
/// QR encoding primitives for signed payloads. Mirror of Python's
/// <c>recto.qr.encode</c> module — same API shape, same conventions,
/// same defaults.
/// <para>
/// Wraps the QRCoder library (pure-managed MIT) with the Recto-side
/// conventions: default error-correction M (15% recovery, balances
/// capacity against scratch/dirt tolerance), default box-size 8
/// (phone-screen scannable), default border 4 (QR spec minimum).
/// PNG output uses <see cref="PngByteQRCode"/> (no System.Drawing
/// dependency — cross-platform MAUI Blazor friendly); SVG output
/// uses <see cref="SvgQRCode"/>.
/// </para>
/// <para>
/// The QR-content layer is byte-equivalent across runtimes: a JWS
/// string encoded by Python's qrcode + this C# QRCoder wrapper carry
/// the same payload bytes at the QR-content layer (the actual PNG
/// byte sequences may differ due to library-specific image compression
/// choices, but the decoded payload bytes from either PNG match
/// byte-for-byte).
/// </para>
/// <para>
/// Protocol-layer DECODE (canonical-JSON text → validated
/// <see cref="QRPayloadV1"/>) ships in <see cref="QrDecoder"/>.
/// Image-pixel SCANNING (camera image → text) remains a
/// consumer-edge concern — Recto Phone uses MAUI CommunityToolkit's
/// CameraView + ZXing.Net.Maui or equivalent; the substrate stays
/// scanner-agnostic.
/// </para>
/// </summary>
public static class QrEncoder
{
    /// <summary>Default error-correction level. M = 15% recovery.</summary>
    public const string DefaultErrorCorrection = "M";

    /// <summary>Default PNG pixels per QR module.</summary>
    public const int DefaultPngPixelsPerModule = 8;

    /// <summary>Default quiet-zone border in modules.</summary>
    public const int DefaultBorder = 4;

    private static QRCodeGenerator.ECCLevel ParseEcLevel(string level)
    {
        if (string.IsNullOrEmpty(level))
        {
            throw new ArgumentException(
                "errorCorrection must be one of L, M, Q, H", nameof(level));
        }
        switch (level.ToUpperInvariant())
        {
            case "L": return QRCodeGenerator.ECCLevel.L;
            case "M": return QRCodeGenerator.ECCLevel.M;
            case "Q": return QRCodeGenerator.ECCLevel.Q;
            case "H": return QRCodeGenerator.ECCLevel.H;
            default:
                throw new ArgumentException(
                    $"Unknown errorCorrection level '{level}'. " +
                    "Must be one of L, M, Q, H.", nameof(level));
        }
    }

    /// <summary>
    /// Encode a string directly as a QR code image. The simplest QR
    /// encoding path: take any string (JWS, URL, plaintext token,
    /// TLS pin) and emit a PNG or SVG. Mirror of Python's
    /// <c>qr_encode_jws</c> — same default args, same output bytes.
    /// </summary>
    /// <param name="text">The string to encode. Typically a JWS,
    ///     TLS pin, or any value worth cross-referencing across
    ///     devices via QR scan.</param>
    /// <param name="imageFormat">"png" (default) or "svg".</param>
    /// <param name="errorCorrection">"L" (7%), "M" (15%, default),
    ///     "Q" (25%), "H" (30%). Higher = more scratch/dirt tolerance
    ///     at cost of capacity.</param>
    /// <param name="pixelsPerModule">PNG pixels per QR module (PNG
    ///     only). 8 = phone-screen scannable; 16-24 = print-ready.</param>
    /// <param name="border">Quiet-zone border in modules. 4 = QR
    ///     spec minimum.</param>
    /// <returns>PNG or SVG bytes ready to write to disk, embed in a
    ///     data URI, or stream as an HTTP response.</returns>
    public static byte[] EncodeText(
        string text,
        string imageFormat = "png",
        string errorCorrection = DefaultErrorCorrection,
        int pixelsPerModule = DefaultPngPixelsPerModule,
        int border = DefaultBorder)
    {
        if (string.IsNullOrEmpty(text))
        {
            throw new ArgumentException(
                "text must be a non-empty string", nameof(text));
        }
        if (imageFormat != "png" && imageFormat != "svg")
        {
            throw new ArgumentException(
                $"Unknown imageFormat '{imageFormat}'. Must be 'png' or 'svg'.",
                nameof(imageFormat));
        }

        var ecLevel = ParseEcLevel(errorCorrection);

        using var generator = new QRCodeGenerator();
        using var qrData = generator.CreateQrCode(text, ecLevel);

        if (imageFormat == "png")
        {
            // PngByteQRCode produces raw PNG bytes without System.Drawing —
            // critical for MAUI Blazor cross-platform compatibility.
            var pngQr = new PngByteQRCode(qrData);
            return pngQr.GetGraphic(pixelsPerModule, drawQuietZones: true);
        }
        else
        {
            // SVG output via QRCoder's SvgQRCode. Returns a string;
            // we convert to UTF-8 bytes for API consistency with the
            // PNG path.
            var svgQr = new SvgQRCode(qrData);
            var svgString = svgQr.GetGraphic(pixelsPerModule);
            return Encoding.UTF8.GetBytes(svgString);
        }
    }

    /// <summary>
    /// Encode a structured <see cref="QRPayloadV1"/> as a QR code
    /// image. The payload is canonical-JSON-encoded (byte-parity with
    /// Python's recto.qr.encode.qr_encode_payload) before rendering,
    /// so the QR's bytes are reproducible across runtimes.
    /// </summary>
    /// <param name="payload">The payload to encode.</param>
    /// <param name="imageFormat">"png" or "svg".</param>
    /// <param name="errorCorrection">"L" / "M" / "Q" / "H".</param>
    /// <param name="pixelsPerModule">PNG pixels per module.</param>
    /// <param name="border">Quiet-zone border in modules.</param>
    public static byte[] EncodePayload(
        QRPayloadV1 payload,
        string imageFormat = "png",
        string errorCorrection = DefaultErrorCorrection,
        int pixelsPerModule = DefaultPngPixelsPerModule,
        int border = DefaultBorder)
    {
        if (payload == null) throw new ArgumentNullException(nameof(payload));

        var dict = QrCanonicalJson.QrPayloadV1ToDict(payload);
        var canonicalBytes = CanonicalJson.Encode(dict);
        var canonicalString = Encoding.UTF8.GetString(canonicalBytes);

        // Sanity check: refuse to encode if the canonical JSON exceeds
        // the QR capacity at the L error-correction level. Sister of
        // Python's qr_encode_payload's same check.
        if (canonicalBytes.Length > QRCapacities.V40L)
        {
            throw new ArgumentException(
                $"payload canonical-JSON encoding is {canonicalBytes.Length} " +
                $"bytes, exceeds QR v40 capacity of {QRCapacities.V40L} bytes " +
                $"(at L error-correction; lower at M/Q/H). Multi-QR " +
                $"fragmentation is reserved for v2.",
                nameof(payload));
        }

        return EncodeText(
            canonicalString,
            imageFormat: imageFormat,
            errorCorrection: errorCorrection,
            pixelsPerModule: pixelsPerModule,
            border: border);
    }

    /// <summary>
    /// Encode a <see cref="MultiWitnessContract"/> as a QR code image.
    /// Sister of Python's
    /// <c>recto.qr.multi_witness.encode_multi_witness_qr</c>.
    /// Encodes regardless of signature completeness — partially-
    /// signed contracts can be rendered + passed to the next witness.
    /// </summary>
    public static byte[] EncodeMultiWitness(
        MultiWitnessContract contract,
        string imageFormat = "png",
        string errorCorrection = DefaultErrorCorrection,
        int pixelsPerModule = DefaultPngPixelsPerModule,
        int border = DefaultBorder)
    {
        if (contract == null) throw new ArgumentNullException(nameof(contract));

        var dict = QrCanonicalJson.MultiWitnessContractToDict(contract);
        var canonicalBytes = CanonicalJson.Encode(dict);
        var canonicalString = Encoding.UTF8.GetString(canonicalBytes);

        if (canonicalBytes.Length > QRCapacities.V40L)
        {
            throw new ArgumentException(
                $"contract canonical-JSON encoding is {canonicalBytes.Length} " +
                $"bytes, exceeds QR v40 capacity of {QRCapacities.V40L} bytes. " +
                $"Multi-QR fragmentation reserved for v2; consider " +
                $"splitting the contract into multiple smaller contracts.",
                nameof(contract));
        }

        return EncodeText(
            canonicalString,
            imageFormat: imageFormat,
            errorCorrection: errorCorrection,
            pixelsPerModule: pixelsPerModule,
            border: border);
    }

    /// <summary>
    /// Encode a PNG byte array as a base64-encoded data URI suitable
    /// for embedding in HTML <c>&lt;img src="..."&gt;</c> tags. Convenience
    /// helper for the Recto Phone Pairing-details [QR] button modal
    /// which needs a renderable data URI for the &lt;img&gt; src
    /// attribute without writing the PNG to disk first.
    /// </summary>
    /// <param name="pngBytes">Raw PNG bytes (typically the output of
    ///     <see cref="EncodeText"/> with imageFormat="png").</param>
    /// <returns>A string like
    ///     "data:image/png;base64,iVBORw0KGgo..." ready to set as
    ///     an &lt;img&gt; src attribute.</returns>
    public static string PngBytesToDataUri(byte[] pngBytes)
    {
        if (pngBytes == null) throw new ArgumentNullException(nameof(pngBytes));
        if (pngBytes.Length < 8)
        {
            throw new ArgumentException(
                "pngBytes too short to be a valid PNG", nameof(pngBytes));
        }
        // PNG magic bytes: 89 50 4E 47 0D 0A 1A 0A
        if (pngBytes[0] != 0x89 || pngBytes[1] != 0x50 ||
            pngBytes[2] != 0x4E || pngBytes[3] != 0x47)
        {
            throw new ArgumentException(
                "pngBytes is not a valid PNG (missing magic bytes)",
                nameof(pngBytes));
        }
        return $"data:image/png;base64,{Convert.ToBase64String(pngBytes)}";
    }

    /// <summary>
    /// Encode an SVG byte array as a UTF-8 string suitable for direct
    /// inline rendering in MAUI Blazor surfaces. Sister convenience
    /// of <see cref="PngBytesToDataUri"/> for the SVG path.
    /// </summary>
    public static string SvgBytesToString(byte[] svgBytes)
    {
        if (svgBytes == null) throw new ArgumentNullException(nameof(svgBytes));
        return Encoding.UTF8.GetString(svgBytes);
    }
}
