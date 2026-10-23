using System;
using Recto.Shared.Services;

namespace Recto.Shared.QR;

// ---------------------------------------------------------------------------
// PairDeepLinkQrEmitter -- composes PairDeepLinkEmitter + QrEncoder.EncodeText
// into one-call convenience methods that return PNG/SVG bytes ready for
// inline rendering.
// ---------------------------------------------------------------------------
//
// Canonical use cases (banked 2026-06-01 for #41):
//
//   1. App Store reviewer demo QR -- call EncodeDemoBootloaderPairQrPng()
//      with no arguments to get the canonical demo PNG bytes. Render as
//      <img src="data:image/png;base64,{b64}"> on any Recto-side marketing
//      surface (onboarding screen, App Store listing image generation,
//      "scan to try" widget).
//
//   2. Downstream-consumer Pair Devices surface (per the matching
//      consumer-side task tracked as #39 in the consumer's IM) -- call
//      EncodeServicePairQrPng(code, bootloaderUrl) with a freshly-minted
//      8-char alphanumeric pairing code + the consumer's bootloader URL.
//      The consumer's account-management UI renders the bytes inline as
//      a data URI.
//
//   3. Downstream consumer integration tests -- same primitive; just feed
//      it the test code + test bootloader URL.
//
// Composition: this class is a thin facade over PairDeepLinkEmitter +
// QrEncoder. The two primitives could be called separately by any consumer
// (and tests do call them separately to verify each layer in isolation),
// but the one-shot convenience methods here are the canonical entry
// points that consumers should reach for first. Sister of how
// QrEncoder.EncodePayload composes CanonicalJson + EncodeText for the
// structured-payload case.
//
// Defaults match QrEncoder's defaults:
//   - imageFormat: "png" (binary bytes, ready for data URI)
//   - errorCorrection: "M" (15% recovery, balanced for scratch tolerance)
//   - pixelsPerModule: 8 (phone-screen scannable from arm's-length)
//   - border: 4 (QR spec minimum quiet zone)
//
// Callers can override these via the EncodePairUrlQr overload if they
// need print-quality (pixelsPerModule=16-24) or a specific error-
// correction level.

/// <summary>
/// Thin composer over <see cref="PairDeepLinkEmitter"/> +
/// <see cref="QrEncoder.EncodeText"/>. One-shot convenience for rendering
/// a recto://pair?... URL as a scannable QR image.
/// </summary>
public static class PairDeepLinkQrEmitter
{
    /// <summary>
    /// Build a service-kind pair URL and encode it as a QR PNG.
    /// </summary>
    /// <param name="code">8 alphanumeric characters.</param>
    /// <param name="bootloaderUrl">Optional consumer bootloader URL.</param>
    /// <returns>PNG bytes ready to write to disk or wrap in a data URI.</returns>
    public static byte[] EncodeServicePairQrPng(string code, string? bootloaderUrl = null)
    {
        var url = PairDeepLinkEmitter.BuildServicePairUrl(code, bootloaderUrl);
        return QrEncoder.EncodeText(url);
    }

    /// <summary>
    /// Build a bootloader-kind pair URL and encode it as a QR PNG.
    /// </summary>
    /// <param name="code">6 numeric digits.</param>
    /// <param name="bootloaderUrl">Required bootloader URL.</param>
    /// <returns>PNG bytes.</returns>
    public static byte[] EncodeBootloaderPairQrPng(string code, string bootloaderUrl)
    {
        var url = PairDeepLinkEmitter.BuildBootloaderPairUrl(code, bootloaderUrl);
        return QrEncoder.EncodeText(url);
    }

    /// <summary>
    /// Build the canonical App Store reviewer demo URL and encode it as a
    /// QR PNG. Uses <see cref="PairDeepLinkConstants.DemoPairingCode"/> +
    /// <see cref="PairDeepLinkConstants.DemoBootloaderUrl"/>. Byte-stable
    /// across builds; tests pin the encoded URL string.
    /// </summary>
    public static byte[] EncodeDemoBootloaderPairQrPng()
    {
        var url = PairDeepLinkEmitter.BuildDemoBootloaderPairUrl();
        return QrEncoder.EncodeText(url);
    }

    /// <summary>
    /// Lower-level overload that exposes QR rendering knobs (format,
    /// error correction, pixel density, border). Callers that need a
    /// print-quality QR (pixelsPerModule=24, errorCorrection="H") or an
    /// SVG output (imageFormat="svg") use this; the higher-level
    /// per-kind methods cover the canonical PNG/M/8/4 case.
    /// </summary>
    public static byte[] EncodePairUrlQr(
        string code,
        string? bootloaderUrl,
        PairDeepLinkKind kind,
        string imageFormat = "png",
        string errorCorrection = "M",
        int pixelsPerModule = 8,
        int border = 4)
    {
        var url = PairDeepLinkEmitter.BuildPairUrl(code, bootloaderUrl, kind);
        return QrEncoder.EncodeText(url, imageFormat, errorCorrection, pixelsPerModule, border);
    }
}
