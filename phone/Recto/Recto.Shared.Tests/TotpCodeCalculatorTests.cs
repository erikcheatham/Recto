using System;
using System.Text;
using Recto.Shared.Services;
using Xunit;

namespace Recto.Shared.Tests;

/// <summary>
/// Pins TotpCodeCalculator against RFC 6238's published reference vectors.
/// If any of these break, every TOTP code on every paired phone breaks
/// silently &mdash; the bootloader's verification window catches it but the
/// failure mode is "code never matches" rather than a loud test failure.
/// These tests are the loud-failure backstop.
/// </summary>
public class TotpCodeCalculatorTests
{
    // RFC 6238 Appendix B test secret: ASCII "12345678901234567890" (20 bytes).
    // The RFC's test table is keyed off this exact secret across SHA1 / SHA256
    // / SHA512 lines (the SHA256 / SHA512 lines extend the secret to 32 / 64
    // bytes by repeating the pattern; we only test SHA1 here since that's
    // RFC 6238's default and what the v0.4 mock and phone use).
    private static readonly byte[] RfcSecretSha1 =
        Encoding.ASCII.GetBytes("12345678901234567890");

    [Theory]
    // (unix timestamp, expected 8-digit code) -- RFC 6238 Appendix B SHA1 column.
    [InlineData(59L, "94287082")]
    [InlineData(1111111109L, "07081804")]
    [InlineData(1111111111L, "14050471")]
    [InlineData(1234567890L, "89005924")]
    [InlineData(2000000000L, "69279037")]
    [InlineData(20000000000L, "65353130")]
    public void Generate_MatchesRfc6238_Sha1Vectors(long unixTime, string expected)
    {
        var when = DateTimeOffset.FromUnixTimeSeconds(unixTime);
        var code = TotpCodeCalculator.Generate(
            RfcSecretSha1,
            when,
            periodSeconds: 30,
            digits: 8,
            algorithm: "SHA1");
        Assert.Equal(expected, code);
    }

    [Fact]
    public void Generate_DefaultsTo6DigitsAndSha1()
    {
        // Same vector as the RFC's first SHA1 row (t=59 -> 94287082); take
        // the rightmost 6 digits since digits defaults to 6.
        var when = DateTimeOffset.FromUnixTimeSeconds(59);
        var code = TotpCodeCalculator.Generate(RfcSecretSha1, when);
        Assert.Equal("287082", code);
    }

    [Fact]
    public void Generate_RejectsEmptySecret()
    {
        Assert.Throws<ArgumentException>(() =>
            TotpCodeCalculator.Generate(Array.Empty<byte>(), DateTimeOffset.UtcNow));
    }

    [Fact]
    public void Generate_RejectsZeroPeriod()
    {
        Assert.Throws<ArgumentException>(() =>
            TotpCodeCalculator.Generate(RfcSecretSha1, DateTimeOffset.UtcNow, periodSeconds: 0));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(11)]
    public void Generate_RejectsOutOfRangeDigits(int digits)
    {
        Assert.Throws<ArgumentException>(() =>
            TotpCodeCalculator.Generate(RfcSecretSha1, DateTimeOffset.UtcNow, digits: digits));
    }

    [Fact]
    public void Generate_RejectsUnknownAlgorithm()
    {
        Assert.Throws<ArgumentException>(() =>
            TotpCodeCalculator.Generate(RfcSecretSha1, DateTimeOffset.UtcNow, algorithm: "MD5"));
    }

    [Fact]
    public void Generate_PadsShortCodesWithLeadingZeros()
    {
        // Pick a (secret, time) combo where the truncated value mod 10^6 happens
        // to be < 100000. The exact combo doesn't matter for this assertion --
        // we just need a 6-digit string back, and verify the leading-zero pad.
        // Using t=59 still gives 6-digit codes that are usually full-width;
        // instead, verify directly via length check across many timestamps.
        for (int i = 0; i < 100; i++)
        {
            var when = DateTimeOffset.FromUnixTimeSeconds(i * 30);
            var code = TotpCodeCalculator.Generate(RfcSecretSha1, when, digits: 6);
            Assert.Equal(6, code.Length);
            Assert.Matches("^[0-9]{6}$", code);
        }
    }

    [Theory]
    [InlineData("MZXW6YTBOI", new byte[] { 0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72 })] // "foobar"
    [InlineData("JBSWY3DPEHPK3PXP", new byte[] { 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0xde, 0xad, 0xbe, 0xef })]
    [InlineData("", new byte[0])]
    public void DecodeBase32_HandlesRfc4648Vectors(string b32, byte[] expected)
    {
        var actual = TotpCodeCalculator.DecodeBase32(b32);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void DecodeBase32_StripsPaddingAndCase()
    {
        // "foobar" with mixed case + padding stripping.
        var actual = TotpCodeCalculator.DecodeBase32("mzxw6ytboi==");
        Assert.Equal(new byte[] { 0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72 }, actual);
    }

    [Fact]
    public void DecodeBase32_RejectsInvalidCharacter()
    {
        Assert.Throws<ArgumentException>(() => TotpCodeCalculator.DecodeBase32("MZXW1!"));
    }
}
