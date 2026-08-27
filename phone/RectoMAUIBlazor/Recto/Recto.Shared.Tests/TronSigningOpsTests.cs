using System;
using Recto.Shared.Services;
using Xunit;

namespace Recto.Shared.Tests;

/// <summary>
/// Pins the C# TRON primitives against the same canonical reference
/// values that <c>tests/test_tron.py</c> pins (Wave 9 part 1). The
/// generator-G TRON address is the central pin: any drift between
/// the C# base58check encoder, the Keccak-256 slice, or the version-
/// byte composition would change the output, and the test catches
/// it before a phone build with a mis-shaped address can mint a
/// signature that no TronWeb / Tronscan / tronpy verifier accepts.
/// </summary>
public class TronSigningOpsTests
{
    // secp256k1 generator point G in uncompressed (X||Y) form. Pinned
    // against any standard secp256k1 reference. Same value as the Python
    // test's GENERATOR_PUBKEY64 -- both sides must agree to the byte.
    private const string GeneratorPubkey64Hex =
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
      + "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

    // Canonical TRON address for the generator G. Cross-pinned with
    // tests/test_tron.py::GENERATOR_TRON_ADDRESS. If either side
    // drifts, both tests fail in lockstep, which is the point.
    private const string GeneratorTronAddress = "TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC";

    // Well-known ETH address bytes for the generator (last 20 of
    // keccak256(pubkey64)). These are the same 20 bytes as the
    // canonical 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf ETH
    // address; TRON prefixes them with 0x41 and base58check-encodes.
    private const string GeneratorEthLast20Hex = "7e5f4552091a69125d5dfcb7b8c2659029395bdf";

    [Fact]
    public void DefaultDerivationPath_IsSlip0044CoinType195()
    {
        Assert.Equal("m/44'/195'/0'/0/0", TronSigningOps.DefaultDerivationPath);
    }

    [Fact]
    public void Tip191Preamble_IsBareString_NoLeading0x19()
    {
        // The MESSAGE_PREAMBLE constant is the bare TIP-191 preamble
        // ("TRON Signed Message:\n") without the leading 0x19.
        // SignedMessageHash() adds the byte itself.
        Assert.Equal("TRON Signed Message:\n", TronSigningOps.Tip191Preamble);
        // Pin to ordinal comparison. string.StartsWith(string) defaults
        // to CurrentCulture which treats control char U+0019 as
        // ignorable under culture-sensitive collation -- without
        // StringComparison.Ordinal the assertion would always be True
        // for any string (including this one) regardless of its actual
        // first byte, defeating the test's intent.
        Assert.False(TronSigningOps.Tip191Preamble.StartsWith(
            "\x19", System.StringComparison.Ordinal));
    }

    [Fact]
    public void VersionByteMainnet_Is0x41()
    {
        // 0x41 mainnet version byte -- shared by Shasta and Nile
        // testnets. base58check'ing always produces a 'T' prefix.
        Assert.Equal((byte)0x41, TronSigningOps.VersionByteMainnet);
    }

    [Fact]
    public void SignedMessageHash_DiffersFromEip191_ForSameInput()
    {
        // TIP-191 and EIP-191 share structure but use different
        // preamble strings -- their digests MUST differ for the
        // same input message. Catches accidental preamble-swap
        // (the same class of bug that bit Wave-7 BIP-137 header
        // dispatch -- "shared primitive across coins must
        // dispatch on the discriminator at every layer").
        var msg = "login to dapp.example at 2026-04-30";
        var tronHash = TronSigningOps.SignedMessageHash(msg);
        var ethHash = EthSigningOps.PersonalSignHash(msg);
        Assert.NotEqual(
            Convert.ToHexString(tronHash),
            Convert.ToHexString(ethHash));
    }

    [Fact]
    public void SignedMessageHash_LengthByteIsAsciiDecimal_NotBinary()
    {
        // TIP-191 (like EIP-191) encodes message length as ASCII
        // decimal, NOT as a single binary byte. A 32-byte message
        // contributes "32" (two bytes 0x33 0x32) to the hash
        // preimage, not 0x20.
        var msg = new string('x', 32);
        var hash = TronSigningOps.SignedMessageHash(msg);
        // Recompute with explicit ASCII-decimal length to confirm.
        var expectedPreimage = new System.IO.MemoryStream();
        expectedPreimage.WriteByte(0x19);
        var prefix = System.Text.Encoding.UTF8.GetBytes("TRON Signed Message:\n32");
        expectedPreimage.Write(prefix, 0, prefix.Length);
        var msgBytes = System.Text.Encoding.UTF8.GetBytes(msg);
        expectedPreimage.Write(msgBytes, 0, msgBytes.Length);
        var expectedHash = EthSigningOps.Keccak256(expectedPreimage.ToArray());
        Assert.Equal(
            Convert.ToHexString(expectedHash),
            Convert.ToHexString(hash));
    }

    [Fact]
    public void SignedMessageHash_DifferentMessages_ProduceDifferentHashes()
    {
        var h1 = TronSigningOps.SignedMessageHash("hello");
        var h2 = TronSigningOps.SignedMessageHash("world");
        Assert.NotEqual(Convert.ToHexString(h1), Convert.ToHexString(h2));
    }

    [Fact]
    public void AddressFromPublicKey_GeneratorG_MatchesCanonicalTronAddress()
    {
        // Cross-pinned with tests/test_tron.py. C# and Python sides
        // must agree on this exact 34-char address; any drift in the
        // base58check encoder, the Keccak slice, or the version-byte
        // composition would change the output.
        var pub64 = Convert.FromHexString(GeneratorPubkey64Hex);
        var addr = TronSigningOps.AddressFromPublicKey(pub64);
        Assert.Equal(GeneratorTronAddress, addr);
    }

    [Fact]
    public void AddressFromPublicKey_GeneratorG_KeccakSliceMatchesEthAddress()
    {
        // Sanity: the 20-byte hash160-equivalent that TRON 0x41-
        // prefixes is identical to Ethereum's address bytes for the
        // same pubkey. Confirms the cross-EVM interoperability claim
        // in the docs (TRON addresses are the same 20 bytes as ETH,
        // re-encoded).
        var pub64 = Convert.FromHexString(GeneratorPubkey64Hex);
        var keccak = EthSigningOps.Keccak256(pub64);
        var last20 = new byte[20];
        Buffer.BlockCopy(keccak, 12, last20, 0, 20);
        Assert.Equal(GeneratorEthLast20Hex, Convert.ToHexString(last20).ToLowerInvariant());
    }

    [Fact]
    public void AddressFromPublicKey_AlwaysStartsWithT_AndIs34CharsLong()
    {
        // 0x41 || 20-byte hash || 4-byte checksum = 25 bytes;
        // base58 of 25 bytes is always 33-34 chars and always
        // starts with 'T' for the 0x41 mainnet version byte.
        var rng = new Random(42);
        for (int i = 0; i < 50; i++)
        {
            var x = new byte[32];
            var y = new byte[32];
            rng.NextBytes(x);
            rng.NextBytes(y);
            x[0] |= 1;  // avoid all-zeros
            y[0] |= 1;
            var pub64 = new byte[64];
            Buffer.BlockCopy(x, 0, pub64, 0, 32);
            Buffer.BlockCopy(y, 0, pub64, 32, 32);
            var addr = TronSigningOps.AddressFromPublicKey(pub64);
            Assert.StartsWith("T", addr);
            Assert.InRange(addr.Length, 33, 34);
        }
    }

    [Fact]
    public void AddressFromPublicKey_RejectsWrongLength()
    {
        Assert.Throws<ArgumentException>(
            () => TronSigningOps.AddressFromPublicKey(new byte[33]));
        Assert.Throws<ArgumentException>(
            () => TronSigningOps.AddressFromPublicKey(new byte[65]));
    }

    [Fact]
    public void Base58CheckEncode_WithVersion0x41_AlwaysProducesT()
    {
        // The "T..." visual signature is what makes a TRON address
        // recognizable at a glance. Pin: any 20-byte payload prefixed
        // with 0x41 and base58check'd starts with 'T'.
        var rng = new Random(7);
        for (int i = 0; i < 20; i++)
        {
            var hash20 = new byte[20];
            rng.NextBytes(hash20);
            var payload = new byte[21];
            payload[0] = 0x41;
            Buffer.BlockCopy(hash20, 0, payload, 1, 20);
            var addr = TronSigningOps.Base58CheckEncode(payload);
            Assert.StartsWith("T", addr);
        }
    }

    [Fact]
    public void SignWithRecovery_RoundTripRecoversTronAddress()
    {
        // Generate a fresh secp256k1 key, sign the TIP-191 hash,
        // run TronSigningOps.RecoverAddress, confirm we get back the
        // address that TronSigningOps.AddressFromPublicKey would
        // derive from the corresponding pubkey.
        var priv = EthSigningOps.GeneratePrivateKey();
        var pub64 = EthSigningOps.PublicKeyFromPrivate(priv);
        var expectedAddr = TronSigningOps.AddressFromPublicKey(pub64);
        var msg = "Login to dapp.example at 2026-04-30 (TRON)";
        var msgHash = TronSigningOps.SignedMessageHash(msg);
        var rsv = TronSigningOps.SignWithRecovery(msgHash, priv);
        Assert.Equal(65, rsv.Length);
        // v byte must be 27 or 28 (canonical legacy encoding).
        Assert.True(rsv[64] is 27 or 28);
        var recovered = TronSigningOps.RecoverAddress(msgHash, rsv);
        Assert.Equal(expectedAddr, recovered);
    }
}
