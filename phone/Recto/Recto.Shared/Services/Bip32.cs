using System;
using System.Globalization;
using System.Security.Cryptography;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace Recto.Shared.Services;

/// <summary>
/// BIP-32 hierarchical deterministic wallet derivation. Takes a 64-byte
/// seed (typically from <see cref="Bip39.MnemonicToSeed"/>) and produces
/// a private key + chain code at any BIP-32 path. Composes with
/// BIP-44 path conventions (<c>m/44'/coin'/account'/change/index</c>)
/// to cleanly partition addresses across coins, accounts, and indices.
///
/// <para>
/// All math is HMAC-SHA512 + secp256k1 modular arithmetic, both already
/// available — HMAC-SHA512 from .NET stdlib (<see cref="HMACSHA512"/>),
/// secp256k1 from BouncyCastle (same curve <see cref="EthSigningOps"/>
/// uses for signing). No new NuGet dependencies.
/// </para>
///
/// <para>
/// Reference: <see href="https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki"/>.
/// Test vectors covering this implementation live in
/// <c>Recto.Shared.Tests/Bip32Tests.cs</c>. Specifically the canonical
/// "abandon abandon ... about" → seed → master →
/// <c>m/44'/60'/0'/0/0</c> private key → public key →
/// 0x9858EfFD232B4033E47d90003D41EC34EcaEda94 (Trezor's reference
/// Ethereum address) confirms the implementation is byte-for-byte
/// interoperable with every other BIP-32 wallet.
/// </para>
///
/// <para>
/// Hardened derivation note: BIP-32 distinguishes "hardened" indices
/// (≥ 2^31, written with an apostrophe in path notation: <c>44'</c>)
/// from "non-hardened" (&lt; 2^31). Hardened derivation does NOT
/// expose the parent's xpub-relative information; this is what BIP-44
/// uses for the purpose / coin / account levels. Non-hardened is used
/// for the change / index levels so a watching wallet (xpub) can
/// derive child addresses without the private key. Recto only signs
/// (not just watches), so this distinction matters for compat with
/// other wallets but not for our own posture.
/// </para>
/// </summary>
public static class Bip32
{
    private static readonly X9ECParameters Secp256k1 =
        Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp256k1");

    private const uint HardenedOffset = 0x80000000u;

    /// <summary>
    /// One node in the BIP-32 derivation tree. Carries the 32-byte
    /// private key + the 32-byte chain code that child derivations
    /// branch off of. Both fields are mutable byte arrays; callers
    /// should <see cref="System.Security.Cryptography.CryptographicOperations.ZeroMemory"/>
    /// them after use.
    /// </summary>
    public sealed class ExtendedKey
    {
        public byte[] PrivateKey { get; }
        public byte[] ChainCode { get; }

        internal ExtendedKey(byte[] privateKey, byte[] chainCode)
        {
            if (privateKey.Length != 32) throw new ArgumentException("BIP-32 private key must be 32 bytes.", nameof(privateKey));
            if (chainCode.Length != 32) throw new ArgumentException("BIP-32 chain code must be 32 bytes.", nameof(chainCode));
            PrivateKey = privateKey;
            ChainCode = chainCode;
        }
    }

    /// <summary>
    /// Derive the master extended key from a 64-byte BIP-39 seed.
    /// Per BIP-32: <c>I = HMAC-SHA512(key="Bitcoin seed", data=seed)</c>;
    /// the high 32 bytes are the master private key, the low 32 are
    /// the master chain code.
    /// </summary>
    public static ExtendedKey MasterFromSeed(byte[] seed)
    {
        if (seed is null || seed.Length != 64)
            throw new ArgumentException("BIP-32 seed must be 64 bytes.", nameof(seed));
        var key = "Bitcoin seed"u8.ToArray();
        using var hmac = new HMACSHA512(key);
        var I = hmac.ComputeHash(seed);
        var IL = new byte[32];
        var IR = new byte[32];
        Buffer.BlockCopy(I, 0, IL, 0, 32);
        Buffer.BlockCopy(I, 32, IR, 0, 32);
        ValidateInRange(IL);
        CryptographicOperations.ZeroMemory(I);
        CryptographicOperations.ZeroMemory(key);
        return new ExtendedKey(IL, IR);
    }

    /// <summary>
    /// Derive the child extended key at <paramref name="index"/> from
    /// <paramref name="parent"/>. Indices ≥ <c>2^31</c> are hardened
    /// (use <see cref="Hardened"/> to compute, or pass values like
    /// <c>0x80000000 | account</c>).
    /// </summary>
    public static ExtendedKey DeriveChild(ExtendedKey parent, uint index)
    {
        // Per BIP-32: I = HMAC-SHA512(key=parent.ChainCode, data=...).
        // Hardened: data = 0x00 || parent.PrivateKey || index_be32.
        // Non-hardened: data = SerializedCompressedPubkey(parent) || index_be32.
        var hardened = (index & HardenedOffset) != 0;
        byte[] data;
        if (hardened)
        {
            data = new byte[1 + 32 + 4];
            data[0] = 0x00;
            Buffer.BlockCopy(parent.PrivateKey, 0, data, 1, 32);
            WriteBigEndianUInt32(data, 33, index);
        }
        else
        {
            var compressedPub = CompressedPublicKey(parent.PrivateKey);
            data = new byte[33 + 4];
            Buffer.BlockCopy(compressedPub, 0, data, 0, 33);
            WriteBigEndianUInt32(data, 33, index);
            CryptographicOperations.ZeroMemory(compressedPub);
        }

        using var hmac = new HMACSHA512(parent.ChainCode);
        var I = hmac.ComputeHash(data);
        var IL = new byte[32];
        var IR = new byte[32];
        Buffer.BlockCopy(I, 0, IL, 0, 32);
        Buffer.BlockCopy(I, 32, IR, 0, 32);
        CryptographicOperations.ZeroMemory(I);
        CryptographicOperations.ZeroMemory(data);

        // Child private key = (parse256(IL) + parent.PrivateKey) mod n.
        // If IL ≥ n or the result is 0, the index is invalid and the
        // caller must skip to the next index per BIP-32. In practice
        // this happens with probability ~2^-127; we surface a clear
        // error if it does so the operator can pick a different index
        // rather than getting silently-wrong derivation.
        var n = Secp256k1.N;
        var ilInt = new BigInteger(1, IL);
        if (ilInt.CompareTo(n) >= 0)
        {
            CryptographicOperations.ZeroMemory(IL);
            CryptographicOperations.ZeroMemory(IR);
            throw new InvalidOperationException(
                $"BIP-32 child derivation: IL ≥ n at index {index}. Skip to next index per BIP-32 spec.");
        }
        var parentInt = new BigInteger(1, parent.PrivateKey);
        var childInt = ilInt.Add(parentInt).Mod(n);
        if (childInt.SignValue == 0)
        {
            CryptographicOperations.ZeroMemory(IL);
            CryptographicOperations.ZeroMemory(IR);
            throw new InvalidOperationException(
                $"BIP-32 child derivation: child private key = 0 at index {index}. Skip to next index.");
        }
        var childPrivKey = UnsignedFixed32(childInt);
        CryptographicOperations.ZeroMemory(IL);
        return new ExtendedKey(childPrivKey, IR);
    }

    /// <summary>
    /// Derive the extended key at a BIP-32 path string like
    /// <c>m/44'/60'/0'/0/0</c>. The leading <c>m</c> is optional
    /// (matches the BIP-32 convention but not required). Hardened
    /// segments end with <c>'</c> or <c>h</c>; non-hardened don't.
    /// </summary>
    public static ExtendedKey DeriveAtPath(byte[] seed, string path)
    {
        var indices = ParsePath(path);
        var node = MasterFromSeed(seed);
        foreach (var idx in indices)
        {
            var next = DeriveChild(node, idx);
            // Wipe the intermediate node's private key once we've moved past it.
            CryptographicOperations.ZeroMemory(node.PrivateKey);
            node = next;
        }
        return node;
    }

    /// <summary>
    /// Convert a non-hardened index to the equivalent hardened index by
    /// setting the high bit. Useful in test fixtures where the path is
    /// expressed as <c>Hardened(44)</c> rather than the raw uint.
    /// </summary>
    public static uint Hardened(uint index)
    {
        if ((index & HardenedOffset) != 0)
            throw new ArgumentException(
                $"Index {index} already has the hardened bit set.", nameof(index));
        return index | HardenedOffset;
    }

    /// <summary>
    /// Parse a BIP-32 path string into a sequence of derivation indices.
    /// Accepts leading <c>m</c> or <c>m/</c> (optional); accepts both
    /// <c>'</c> and <c>h</c> as hardened markers; rejects anything else.
    /// </summary>
    public static uint[] ParsePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException("Derivation path is required.", nameof(path));
        var trimmed = path.Trim();
        if (trimmed.StartsWith("m/", StringComparison.OrdinalIgnoreCase))
            trimmed = trimmed[2..];
        else if (trimmed.Equals("m", StringComparison.OrdinalIgnoreCase))
            return Array.Empty<uint>();

        var segments = trimmed.Split('/', StringSplitOptions.RemoveEmptyEntries);
        var indices = new uint[segments.Length];
        for (int i = 0; i < segments.Length; i++)
        {
            var seg = segments[i];
            bool hardened = false;
            if (seg.EndsWith('\'') || seg.EndsWith('h') || seg.EndsWith('H'))
            {
                hardened = true;
                seg = seg[..^1];
            }
            if (!uint.TryParse(seg, NumberStyles.Integer, CultureInfo.InvariantCulture, out var idx))
                throw new ArgumentException(
                    $"BIP-32 path segment '{segments[i]}' is not a valid uint.",
                    nameof(path));
            if ((idx & HardenedOffset) != 0)
                throw new ArgumentException(
                    $"BIP-32 path segment '{segments[i]}' overflows uint31; index must be < 2^31 before the hardened bit is applied.",
                    nameof(path));
            indices[i] = hardened ? (idx | HardenedOffset) : idx;
        }
        return indices;
    }

    // ---------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------

    private static byte[] CompressedPublicKey(byte[] privateKey)
    {
        // Compressed pub = 0x02 (even y) or 0x03 (odd y) || 32-byte X.
        var d = new BigInteger(1, privateKey);
        var domain = new ECDomainParameters(Secp256k1.Curve, Secp256k1.G, Secp256k1.N, Secp256k1.H);
        var Q = domain.G.Multiply(d).Normalize();
        var x = UnsignedFixed32(Q.AffineXCoord.ToBigInteger());
        var y = Q.AffineYCoord.ToBigInteger();
        var compressed = new byte[33];
        compressed[0] = (byte)(y.TestBit(0) ? 0x03 : 0x02);
        Buffer.BlockCopy(x, 0, compressed, 1, 32);
        return compressed;
    }

    private static void ValidateInRange(byte[] privateKey)
    {
        // Master derivation: per BIP-32, IL must be in [1, n-1]. The
        // probability of failing this check on a fresh seed is ~2^-127.
        // We surface a clear error if it ever happens so the operator
        // can regenerate from a fresh mnemonic rather than getting an
        // invalid-curve key.
        var n = Secp256k1.N;
        var k = new BigInteger(1, privateKey);
        if (k.SignValue == 0 || k.CompareTo(n) >= 0)
        {
            CryptographicOperations.ZeroMemory(privateKey);
            throw new InvalidOperationException(
                "BIP-32 master derivation produced an out-of-range key. Regenerate from a fresh seed.");
        }
    }

    private static byte[] UnsignedFixed32(BigInteger value)
    {
        var bytes = value.ToByteArrayUnsigned();
        if (bytes.Length == 32) return bytes;
        if (bytes.Length > 32) throw new InvalidOperationException("Value exceeds 32 bytes.");
        var padded = new byte[32];
        Buffer.BlockCopy(bytes, 0, padded, 32 - bytes.Length, bytes.Length);
        return padded;
    }

    private static void WriteBigEndianUInt32(byte[] dest, int offset, uint value)
    {
        dest[offset + 0] = (byte)((value >> 24) & 0xFF);
        dest[offset + 1] = (byte)((value >> 16) & 0xFF);
        dest[offset + 2] = (byte)((value >> 8) & 0xFF);
        dest[offset + 3] = (byte)(value & 0xFF);
    }
}
