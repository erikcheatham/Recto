using System;
using Recto.Shared.Services;
using Xunit;

namespace Recto.Shared.Tests.Services;

/// <summary>
/// Pins the wire-format byte shape of <see cref="PairDeepLinkEmitter"/>
/// outputs AND the round-trip contract that every emitter-produced URL
/// parses cleanly back through <see cref="PairDeepLinkParser"/> with
/// byte-identical Code / BootloaderUrl / Kind.
/// <para>
/// Banked 2026-06-01 alongside the demo-mode QR primitive (#41). Sister of
/// the Python tests in <c>tests/test_qr_pair.py</c> (cross-language
/// byte parity).
/// </para>
/// </summary>
public class PairDeepLinkEmitterTests
{
    // ---- Canonical demo URL byte pin --------------------------------------
    //
    // Pins the EXACT wire bytes for BuildDemoBootloaderPairUrl(). Any drift
    // in PairDeepLinkConstants (DemoPairingCode, DemoBootloaderUrl) OR in
    // Uri.EscapeDataString encoding behavior surfaces here at CI time
    // instead of as a "demo QR doesn't work" mystery in production.
    //
    // The demo URL is:
    //   recto://pair?code=000000&bootloader=demo%3A%2F%2Frecto-app-review&kind=bootloader
    //
    // Decoded: scheme=recto, host=pair, code=000000,
    //          bootloader=demo://recto-app-review, kind=bootloader.
    // ----------------------------------------------------------------------

    private const string CanonicalDemoUrl =
        "recto://pair?code=000000&bootloader=demo%3A%2F%2Frecto-app-review&kind=bootloader";

    [Fact]
    public void BuildDemoBootloaderPairUrl_MatchesCanonicalWireBytes()
    {
        var actual = PairDeepLinkEmitter.BuildDemoBootloaderPairUrl();
        Assert.Equal(CanonicalDemoUrl, actual);
    }

    [Fact]
    public void BuildDemoBootloaderPairUrl_RoundTripsViaParser()
    {
        var url = PairDeepLinkEmitter.BuildDemoBootloaderPairUrl();
        var parsed = PairDeepLinkParser.TryParse(url);

        Assert.NotNull(parsed);
        Assert.Equal(PairDeepLinkConstants.DemoPairingCode, parsed!.Code);
        Assert.Equal(PairDeepLinkConstants.DemoBootloaderUrl, parsed.BootloaderUrl);
        Assert.Equal(PairDeepLinkKind.Bootloader, parsed.Kind);
    }

    // ---- Service-kind (Phase H end-user pair-a-service) -------------------

    [Fact]
    public void BuildServicePairUrl_WithBootloader_RoundTripsViaParser()
    {
        const string code = "ABCD1234";
        const string bootloader = "https://bootloader.example/";

        var url = PairDeepLinkEmitter.BuildServicePairUrl(code, bootloader);
        var parsed = PairDeepLinkParser.TryParse(url);

        Assert.NotNull(parsed);
        Assert.Equal(code, parsed!.Code);
        Assert.Equal(bootloader, parsed.BootloaderUrl);
        Assert.Equal(PairDeepLinkKind.Service, parsed.Kind);
    }

    [Fact]
    public void BuildServicePairUrl_WithoutBootloader_OmitsBootloaderParam()
    {
        var url = PairDeepLinkEmitter.BuildServicePairUrl("ABCD1234");

        Assert.Equal("recto://pair?code=ABCD1234", url);
        Assert.DoesNotContain("bootloader=", url);
        Assert.DoesNotContain("kind=", url);
    }

    [Fact]
    public void BuildServicePairUrl_OmitsKindParam_ForBackCompat()
    {
        // Service-kind URLs MUST omit the kind= param so they're byte-
        // identical to v0.1 URLs minted before the kind extension landed.
        var url = PairDeepLinkEmitter.BuildServicePairUrl("ABCD1234", "https://x.example/");

        Assert.DoesNotContain("kind=", url);
    }

    [Theory]
    [InlineData("abcd1234")] // lowercase
    [InlineData("ABCD1234")] // uppercase
    [InlineData("AbCd1234")] // mixed case
    [InlineData("00000000")] // all digits
    [InlineData("ZZZZZZZZ")] // all alpha
    public void BuildServicePairUrl_AcceptsValidAlphanumericCodes(string code)
    {
        var url = PairDeepLinkEmitter.BuildServicePairUrl(code);
        var parsed = PairDeepLinkParser.TryParse(url);

        Assert.NotNull(parsed);
        Assert.Equal(code, parsed!.Code);
    }

    [Theory]
    [InlineData("ABCD123")]   // 7 chars
    [InlineData("ABCD12345")] // 9 chars
    [InlineData("")]          // empty
    [InlineData("ABCD-234")]  // hyphen
    [InlineData("ABCD 234")]  // space
    [InlineData("ABCD!234")]  // punctuation
    public void BuildServicePairUrl_RejectsInvalidCodeShape(string code)
    {
        Assert.Throws<ArgumentException>(
            () => PairDeepLinkEmitter.BuildServicePairUrl(code));
    }

    // ---- Bootloader-kind (initial-trust + demo flow) ----------------------

    [Fact]
    public void BuildBootloaderPairUrl_RoundTripsViaParser()
    {
        const string code = "123456";
        const string bootloader = "https://bootloader.example/";

        var url = PairDeepLinkEmitter.BuildBootloaderPairUrl(code, bootloader);
        var parsed = PairDeepLinkParser.TryParse(url);

        Assert.NotNull(parsed);
        Assert.Equal(code, parsed!.Code);
        Assert.Equal(bootloader, parsed.BootloaderUrl);
        Assert.Equal(PairDeepLinkKind.Bootloader, parsed.Kind);
    }

    [Fact]
    public void BuildBootloaderPairUrl_RequiresBootloaderUrl()
    {
        Assert.Throws<ArgumentException>(
            () => PairDeepLinkEmitter.BuildBootloaderPairUrl("123456", ""));
        Assert.Throws<ArgumentException>(
            () => PairDeepLinkEmitter.BuildBootloaderPairUrl("123456", null!));
    }

    [Fact]
    public void BuildBootloaderPairUrl_EmitsKindParam()
    {
        var url = PairDeepLinkEmitter.BuildBootloaderPairUrl("123456", "https://x.example/");
        Assert.Contains("kind=bootloader", url);
    }

    [Theory]
    [InlineData("12345")]   // 5 digits
    [InlineData("1234567")] // 7 digits
    [InlineData("abcdef")]  // alpha (rejected for bootloader-kind)
    [InlineData("12345A")]  // mixed (rejected -- bootloader requires all digits)
    [InlineData("")]        // empty
    public void BuildBootloaderPairUrl_RejectsInvalidCodeShape(string code)
    {
        Assert.Throws<ArgumentException>(
            () => PairDeepLinkEmitter.BuildBootloaderPairUrl(code, "https://x.example/"));
    }

    // ---- Bootloader URL percent-encoding ----------------------------------

    [Theory]
    [InlineData("https://x.example/", "https%3A%2F%2Fx.example%2F")]
    [InlineData("demo://recto-app-review", "demo%3A%2F%2Frecto-app-review")]
    [InlineData("http://192.0.2.10:8765/", "http%3A%2F%2F192.0.2.10%3A8765%2F")]
    public void BuildPairUrl_PercentEncodesBootloaderUrl(string bootloader, string expectedEncoded)
    {
        var url = PairDeepLinkEmitter.BuildServicePairUrl("ABCD1234", bootloader);
        Assert.Contains($"bootloader={expectedEncoded}", url);

        // And the round-trip decodes back to the original.
        var parsed = PairDeepLinkParser.TryParse(url);
        Assert.NotNull(parsed);
        Assert.Equal(bootloader, parsed!.BootloaderUrl);
    }

    // ---- QR encoder wrapper -----------------------------------------------

    [Fact]
    public void PairDeepLinkQrEmitter_EncodeDemoBootloaderPairQrPng_ProducesValidPng()
    {
        // PNG magic bytes: 89 50 4E 47 0D 0A 1A 0A
        var bytes = Recto.Shared.QR.PairDeepLinkQrEmitter.EncodeDemoBootloaderPairQrPng();
        Assert.NotNull(bytes);
        Assert.True(bytes.Length > 100); // any real QR PNG is well over 100 bytes
        Assert.Equal(0x89, bytes[0]);
        Assert.Equal(0x50, bytes[1]);
        Assert.Equal(0x4E, bytes[2]);
        Assert.Equal(0x47, bytes[3]);
    }

    [Fact]
    public void PairDeepLinkQrEmitter_EncodeServicePairQrPng_ProducesValidPng()
    {
        var bytes = Recto.Shared.QR.PairDeepLinkQrEmitter.EncodeServicePairQrPng(
            "ABCD1234", "https://bootloader.example/");
        Assert.NotNull(bytes);
        Assert.True(bytes.Length > 100);
        Assert.Equal(0x89, bytes[0]);
    }

    // ---- Wire-shape sanity for service-kind (no kind param) ---------------

    [Fact]
    public void BuildServicePairUrl_WithBootloader_CanonicalShape()
    {
        var url = PairDeepLinkEmitter.BuildServicePairUrl(
            "ABCD1234",
            "https://bootloader.example/");

        // Service-kind canonical form: code first, then bootloader, no kind.
        // This is back-compat-byte-identical with v0.1 emitter outputs that
        // pre-dated the kind extension.
        Assert.Equal(
            "recto://pair?code=ABCD1234&bootloader=https%3A%2F%2Fbootloader.example%2F",
            url);
    }
}
