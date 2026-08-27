using System;
using System.Formats.Asn1;

namespace Recto.Shared.Services;

/// <summary>
/// Converts between platform-emitted DER-encoded ECDSA signatures
/// (<c>SEQUENCE { r INTEGER, s INTEGER }</c>) and the v0.4 protocol's
/// raw R || S wire format (each component 32 bytes big-endian for P-256,
/// total 64 bytes &mdash; matches RFC 7515 / RFC 7518's JWS ES256 shape).
/// <para>
/// Both iOS (<c>SecKey.CreateSignature</c>) and Android
/// (<c>Signature.GetInstance("SHA256withECDSA")</c>) emit ECDSA signatures
/// in DER form by default. The protocol wire format is raw for compactness
/// and parity with Ed25519's 64-byte signatures, so phone-side code converts
/// before sending.
/// </para>
/// </summary>
public static class EcdsaSignatureFormat
{
    /// <summary>
    /// Decodes a DER-encoded ECDSA signature into the raw 64-byte R || S
    /// form. Each component is right-aligned into a 32-byte slot (with
    /// leading zero padding if the integer was &lt; 32 bytes; the optional
    /// DER leading 0x00 positive-integer marker is stripped).
    /// </summary>
    public static byte[] DerToRaw(byte[] der)
    {
        if (der is null) throw new ArgumentNullException(nameof(der));

        var reader = new AsnReader(der, AsnEncodingRules.DER);
        var seq = reader.ReadSequence();
        var r = seq.ReadIntegerBytes().ToArray();
        var s = seq.ReadIntegerBytes().ToArray();
        seq.ThrowIfNotEmpty();
        reader.ThrowIfNotEmpty();

        var raw = new byte[64];
        WriteFixed32(r, raw, 0);
        WriteFixed32(s, raw, 32);
        return raw;
    }

    private static void WriteFixed32(byte[] component, byte[] dest, int destOffset)
    {
        int srcOffset = 0;
        int srcLen = component.Length;

        // Strip the leading 0x00 a DER INTEGER includes when the high bit
        // would otherwise mark the value as negative.
        if (srcLen > 32 && component[0] == 0x00)
        {
            srcOffset = 1;
            srcLen--;
        }

        if (srcLen > 32)
        {
            throw new InvalidOperationException($"ECDSA component too long: {srcLen}");
        }

        // Right-align into the 32-byte slot, leaving any leading bytes zero.
        Buffer.BlockCopy(component, srcOffset, dest, destOffset + (32 - srcLen), srcLen);
    }
}
