using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Recto.Shared.Services;

/// <summary>
/// RFC 6238 TOTP code generator. Pure-math, no platform deps; same
/// implementation runs on the phone (to generate codes from
/// stored secrets) and on the mock bootloader (to verify the
/// codes the phone returns).
/// </summary>
public static class TotpCodeCalculator
{
    /// <summary>
    /// Generates the TOTP code per RFC 6238.
    /// </summary>
    /// <param name="secret">The shared secret (decoded bytes — pass <see cref="DecodeBase32"/> output).</param>
    /// <param name="utcNow">Current time. Caller decides; production always passes <c>DateTimeOffset.UtcNow</c>.</param>
    /// <param name="periodSeconds">Time-step length. RFC 6238 default is 30; most authenticators use it.</param>
    /// <param name="digits">Number of digits in the output code (typically 6, sometimes 8).</param>
    /// <param name="algorithm">HMAC algorithm. <c>"SHA1"</c> (RFC 6238 default), <c>"SHA256"</c>, or <c>"SHA512"</c>.</param>
    public static string Generate(
        byte[] secret,
        DateTimeOffset utcNow,
        int periodSeconds = 30,
        int digits = 6,
        string algorithm = "SHA1")
    {
        if (secret is null || secret.Length == 0)
            throw new ArgumentException("TOTP secret must be non-empty.", nameof(secret));
        if (periodSeconds <= 0)
            throw new ArgumentException("periodSeconds must be > 0.", nameof(periodSeconds));
        if (digits is < 1 or > 10)
            throw new ArgumentException("digits must be between 1 and 10.", nameof(digits));

        long counter = utcNow.ToUnixTimeSeconds() / periodSeconds;

        var counterBytes = new byte[8];
        for (int i = 7; i >= 0; i--)
        {
            counterBytes[i] = (byte)(counter & 0xff);
            counter >>= 8;
        }

        byte[] hash = algorithm.ToUpperInvariant() switch
        {
            "SHA1" => HMACSHA1.HashData(secret, counterBytes),
            "SHA256" => HMACSHA256.HashData(secret, counterBytes),
            "SHA512" => HMACSHA512.HashData(secret, counterBytes),
            _ => throw new ArgumentException($"Unsupported TOTP algorithm: {algorithm}", nameof(algorithm)),
        };

        // Dynamic truncation per RFC 4226 section 5.3.
        int offset = hash[^1] & 0x0f;
        int code = ((hash[offset] & 0x7f) << 24)
                 | ((hash[offset + 1] & 0xff) << 16)
                 | ((hash[offset + 2] & 0xff) << 8)
                 | (hash[offset + 3] & 0xff);

        int mod = 1;
        for (int i = 0; i < digits; i++) mod *= 10;
        return (code % mod).ToString().PadLeft(digits, '0');
    }

    /// <summary>
    /// RFC 4648 base32 decoder. Strips padding and case-normalizes; throws
    /// on any character outside the base32 alphabet.
    /// </summary>
    public static byte[] DecodeBase32(string b32)
    {
        if (b32 is null) throw new ArgumentNullException(nameof(b32));

        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var cleaned = b32.Trim().Replace("=", string.Empty).Replace(" ", string.Empty).ToUpperInvariant();
        if (cleaned.Length == 0) return Array.Empty<byte>();

        var bytes = new List<byte>(cleaned.Length * 5 / 8 + 1);
        int buffer = 0;
        int bits = 0;
        foreach (char c in cleaned)
        {
            int value = alphabet.IndexOf(c);
            if (value < 0)
                throw new ArgumentException($"Invalid base32 character: '{c}'", nameof(b32));
            buffer = (buffer << 5) | value;
            bits += 5;
            if (bits >= 8)
            {
                bits -= 8;
                bytes.Add((byte)((buffer >> bits) & 0xff));
                buffer &= (1 << bits) - 1;
            }
        }
        return bytes.ToArray();
    }
}
