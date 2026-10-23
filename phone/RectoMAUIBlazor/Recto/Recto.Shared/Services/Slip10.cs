using System;
using System.Globalization;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Recto.Shared.Services;

/// <summary>
/// SLIP-0010 hierarchical deterministic wallet derivation for ed25519
/// (curve "ed25519"). Sister implementation to <see cref="Bip32"/> for
/// the secp256k1 curve.
///
/// <para>
/// Reference: <see href="https://github.com/satoshilabs/slips/blob/master/slip-0010.md"/>.
/// Test vectors covering this implementation live in
/// <c>Recto.Shared.Tests/Slip10Tests.cs</c>.
/// </para>
///
/// <para>
/// Critical difference from BIP-32: SLIP-0010 ed25519 supports ONLY
/// hardened derivation (every index ≥ <c>2^31</c>). The non-hardened
/// branch BIP-32 uses for secp256k1 is algebraically undefined for
/// ed25519 because the curve uses a different group structure. Path
/// strings for SOL / XLM / XRP all-hardened reflect this:
/// <list type="bullet">
/// <item>SOL: <c>m/44'/501'/N'/0'</c> (Phantom / Solflare)</item>
/// <item>XLM: <c>m/44'/148'/N'</c> (SEP-0005)</item>
/// <item>XRP-ed25519: <c>m/44'/144'/0'/0'/N'</c> (Xumm / XRPL ed25519)</item>
/// </list>
/// Passing a non-hardened index throws <see cref="ArgumentException"/>
/// so a typo doesn't silently produce a different (invalid) address.
/// </para>
///
/// <para>
/// The HMAC key for the master step is the literal byte string
/// <c>"ed25519 seed"</c> (NOT <c>"Bitcoin seed"</c>). This is what
/// makes the same BIP-39 seed produce different keypairs under
/// SLIP-0010 ed25519 vs BIP-32 secp256k1 — so the operator's mnemonic
/// covers both curve families without cross-derivation collision.
/// </para>
/// </summary>
public static class Slip10
{
    /// <summary>The HMAC-SHA512 key used by SLIP-0010 master derivation
    /// for the ed25519 curve. Per SLIP-0010 §"Master key generation".</summary>
    private static readonly byte[] Ed25519SeedKey = "ed25519 seed"u8.ToArray();

    private const uint HardenedOffset = 0x80000000u;

    /// <summary>
    /// One node in the SLIP-0010 ed25519 derivation tree. Carries the
    /// 32-byte private key (an ed25519 seed in this curve's parlance —
    /// the value that gets fed to ed25519 sign operations) and the
    /// 32-byte chain code that child derivations branch off of. Both
    /// fields are mutable byte arrays; callers should
    /// <see cref="System.Security.Cryptography.CryptographicOperations.ZeroMemory"/>
    /// them after use.
    /// </summary>
    public sealed class ExtendedKey
    {
        /// <summary>32-byte ed25519 seed (raw private key — feed to
        /// ed25519 sign operations or to <see cref="GetPublicKey"/>).</summary>
        public byte[] PrivateKey { get; }

        /// <summary>32-byte chain code (parent material for the next
        /// child derivation step).</summary>
        public byte[] ChainCode { get; }

        internal ExtendedKey(byte[] privateKey, byte[] chainCode)
        {
            if (privateKey.Length != 32) throw new ArgumentException("SLIP-0010 ed25519 private key must be 32 bytes.", nameof(privateKey));
            if (chainCode.Length != 32) throw new ArgumentException("SLIP-0010 chain code must be 32 bytes.", nameof(chainCode));
            PrivateKey = privateKey;
            ChainCode = chainCode;
        }
    }

    /// <summary>
    /// Derive the master extended key from a 64-byte BIP-39 seed.
    /// Per SLIP-0010 ed25519: <c>I = HMAC-SHA512(key="ed25519 seed", data=seed)</c>;
    /// the high 32 bytes are the master private key, the low 32 are
    /// the master chain code.
    ///
    /// <para>
    /// Unlike BIP-32, SLIP-0010 ed25519 imposes NO range check on the
    /// master private key — any 32-byte value is a valid ed25519 seed
    /// (the curve's group structure means there are no out-of-range
    /// scalars to worry about). The "regenerate from a fresh seed"
    /// failure mode that BIP-32 master derivation can hit ~2^-127 of
    /// the time doesn't apply here.
    /// </para>
    /// </summary>
    public static ExtendedKey MasterFromSeed(byte[] seed)
    {
        if (seed is null || seed.Length != 64)
            throw new ArgumentException("SLIP-0010 seed must be 64 bytes.", nameof(seed));
        using var hmac = new HMACSHA512(Ed25519SeedKey);
        var I = hmac.ComputeHash(seed);
        var IL = new byte[32];
        var IR = new byte[32];
        Buffer.BlockCopy(I, 0, IL, 0, 32);
        Buffer.BlockCopy(I, 32, IR, 0, 32);
        CryptographicOperations.ZeroMemory(I);
        return new ExtendedKey(IL, IR);
    }

    /// <summary>
    /// Derive the child extended key at <paramref name="index"/> from
    /// <paramref name="parent"/>. SLIP-0010 ed25519 only supports
    /// hardened indices (≥ <c>2^31</c>); passing a non-hardened
    /// index throws.
    ///
    /// <para>
    /// Per SLIP-0010 ed25519:
    /// <c>I = HMAC-SHA512(key=parent.ChainCode, data=0x00 || parent.PrivateKey || index_be32)</c>.
    /// IL becomes the child private key directly (no scalar addition
    /// like BIP-32 secp256k1 does); IR becomes the child chain code.
    /// </para>
    /// </summary>
    public static ExtendedKey DeriveChild(ExtendedKey parent, uint index)
    {
        if ((index & HardenedOffset) == 0)
        {
            throw new ArgumentException(
                $"SLIP-0010 ed25519 only supports hardened derivation; index {index} is not hardened. " +
                $"Use Hardened({index}) or pass an index ≥ 2^31.",
                nameof(index));
        }
        var data = new byte[1 + 32 + 4];
        data[0] = 0x00;
        Buffer.BlockCopy(parent.PrivateKey, 0, data, 1, 32);
        WriteBigEndianUInt32(data, 33, index);

        using var hmac = new HMACSHA512(parent.ChainCode);
        var I = hmac.ComputeHash(data);
        var IL = new byte[32];
        var IR = new byte[32];
        Buffer.BlockCopy(I, 0, IL, 0, 32);
        Buffer.BlockCopy(I, 32, IR, 0, 32);
        CryptographicOperations.ZeroMemory(I);
        CryptographicOperations.ZeroMemory(data);
        return new ExtendedKey(IL, IR);
    }

    /// <summary>
    /// Derive the extended key at a SLIP-0010 path string like
    /// <c>m/44'/501'/0'/0'</c>. Every segment MUST be hardened (end
    /// with <c>'</c> or <c>h</c>); anything non-hardened throws.
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
    /// Compute the 32-byte ed25519 public key from a 32-byte ed25519
    /// seed (the SLIP-0010 derivation output's <see cref="ExtendedKey.PrivateKey"/>).
    ///
    /// <para>
    /// Per RFC 8032: hash the seed with SHA-512, clamp the lower
    /// 32 bytes per the standard ed25519 clamping rules, then scalar-
    /// multiply the basepoint to get the public key. Delegates to
    /// BouncyCastle's <c>Ed25519PrivateKeyParameters.GeneratePublicKey</c>
    /// since that's the canonical primitive for the operation; same
    /// code path the rest of Recto's ed25519 work runs through.
    /// </para>
    /// </summary>
    public static byte[] GetPublicKey(byte[] privateKey32)
    {
        if (privateKey32 is null || privateKey32.Length != 32)
            throw new ArgumentException("ed25519 private key (seed) must be 32 bytes.", nameof(privateKey32));
        var priv = new Ed25519PrivateKeyParameters(privateKey32, 0);
        var pub = priv.GeneratePublicKey();
        return pub.GetEncoded();
    }

    /// <summary>
    /// Sign a message with the ed25519 seed at the given path.
    /// Convenience helper around <see cref="DeriveAtPath"/> +
    /// <see cref="Ed25519Signer"/>. Returns a 64-byte raw signature
    /// (R || S, no header / recovery id — ed25519 doesn't have those).
    /// </summary>
    public static byte[] SignMessage(byte[] seed, string path, byte[] message)
    {
        if (message is null) throw new ArgumentNullException(nameof(message));
        ExtendedKey? leaf = null;
        try
        {
            leaf = DeriveAtPath(seed, path);
            var priv = new Ed25519PrivateKeyParameters(leaf.PrivateKey, 0);
            var signer = new Ed25519Signer();
            signer.Init(forSigning: true, priv);
            signer.BlockUpdate(message, 0, message.Length);
            return signer.GenerateSignature();
        }
        finally
        {
            if (leaf is not null)
            {
                CryptographicOperations.ZeroMemory(leaf.PrivateKey);
                CryptographicOperations.ZeroMemory(leaf.ChainCode);
            }
        }
    }

    /// <summary>
    /// Convert a non-hardened index to the equivalent hardened index by
    /// setting the high bit. For SLIP-0010 ed25519 every path segment
    /// must be hardened, so this helper is the canonical way to express
    /// indices in test fixtures.
    /// </summary>
    public static uint Hardened(uint index)
    {
        if ((index & HardenedOffset) != 0)
            throw new ArgumentException(
                $"Index {index} already has the hardened bit set.", nameof(index));
        return index | HardenedOffset;
    }

    /// <summary>
    /// Parse a SLIP-0010 path string into a sequence of derivation indices.
    /// Accepts leading <c>m</c> or <c>m/</c> (optional); accepts both
    /// <c>'</c> and <c>h</c>/<c>H</c> as hardened markers; REJECTS any
    /// non-hardened segment with a clear error.
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
            if (!hardened)
            {
                throw new ArgumentException(
                    $"SLIP-0010 ed25519 only supports hardened paths; segment '{segments[i]}' is non-hardened. " +
                    $"Add a trailing apostrophe (e.g. '{segments[i]}'') to mark it hardened.",
                    nameof(path));
            }
            if (!uint.TryParse(seg, NumberStyles.Integer, CultureInfo.InvariantCulture, out var idx))
                throw new ArgumentException(
                    $"SLIP-0010 path segment '{segments[i]}' is not a valid uint.",
                    nameof(path));
            if ((idx & HardenedOffset) != 0)
                throw new ArgumentException(
                    $"SLIP-0010 path segment '{segments[i]}' overflows uint31; index must be < 2^31 before the hardened bit is applied.",
                    nameof(path));
            indices[i] = idx | HardenedOffset;
        }
        return indices;
    }

    private static void WriteBigEndianUInt32(byte[] dest, int offset, uint value)
    {
        dest[offset + 0] = (byte)((value >> 24) & 0xFF);
        dest[offset + 1] = (byte)((value >> 16) & 0xFF);
        dest[offset + 2] = (byte)((value >> 8) & 0xFF);
        dest[offset + 3] = (byte)(value & 0xFF);
    }
}
