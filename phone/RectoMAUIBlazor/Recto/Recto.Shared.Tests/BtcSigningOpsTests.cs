using System;
using System.Linq;
using System.Text;
using Recto.Shared.Services;
using Xunit;

namespace Recto.Shared.Tests;

/// <summary>
/// Pins the C# Bitcoin primitives against canonical reference vectors.
/// Specifically the BIP-173 test vector
/// (<c>bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4</c> from
/// <c>HASH160(secp256k1 generator G)</c>) — if our impl produces this
/// exact address string, the entire RIPEMD-160 + SHA-256 + bech32 +
/// public-key-compression stack is byte-for-byte interoperable with
/// every Bitcoin wallet on Earth.
/// </summary>
public class BtcSigningOpsTests
{
    // secp256k1 generator G in Ethereum's 64-byte uncompressed format.
    private static readonly byte[] _generatorUncompressed =
        Convert.FromHexString(
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798" +
            "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");

    [Fact]
    public void Ripemd160_EmptyString_MatchesCanonicalValue()
    {
        // Reference: ripemd160("") = 9c1185a5c5e9fc54612808977ee8f548b2258d31
        var hash = BtcSigningOps.Ripemd160(Array.Empty<byte>());
        Assert.Equal(
            "9c1185a5c5e9fc54612808977ee8f548b2258d31",
            Convert.ToHexString(hash).ToLowerInvariant());
    }

    [Fact]
    public void Ripemd160_AbcAscii_MatchesCanonicalValue()
    {
        // Reference: ripemd160("abc") = 8eb208f7e05d987a9b044a8e98c6b087f15a0bfc
        var hash = BtcSigningOps.Ripemd160(Encoding.ASCII.GetBytes("abc"));
        Assert.Equal(
            "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
            Convert.ToHexString(hash).ToLowerInvariant());
    }

    [Fact]
    public void Hash160_ComposesRipemd160OfSha256()
    {
        // Definition test: HASH160(x) MUST equal RIPEMD-160(SHA-256(x)).
        var data = Encoding.UTF8.GetBytes("hello");
        var sha = System.Security.Cryptography.SHA256.HashData(data);
        var expected = BtcSigningOps.Ripemd160(sha);
        Assert.Equal(
            Convert.ToHexString(expected),
            Convert.ToHexString(BtcSigningOps.Hash160(data)));
    }

    [Fact]
    public void DoubleSha256_EmptyString_MatchesCanonicalValue()
    {
        Assert.Equal(
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456",
            Convert.ToHexString(BtcSigningOps.DoubleSha256(Array.Empty<byte>())).ToLowerInvariant());
    }

    [Fact]
    public void CompressPublicKey_GeneratorYIsEven_PrefixIs02()
    {
        var compressed = BtcSigningOps.CompressPublicKey(_generatorUncompressed);
        Assert.Equal(33, compressed.Length);
        Assert.Equal(0x02, compressed[0]);
        Assert.Equal(
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            Convert.ToHexString(compressed[1..]).ToLowerInvariant());
    }

    [Fact]
    public void Bech32Encode_Bip173MainnetCanonical()
    {
        // BIP-173 canonical test vector: HASH160 of compressed-G's
        // raw bytes = 751e76e8199196d454941c45d1b3a323f1433bd6.
        var program = Convert.FromHexString("751e76e8199196d454941c45d1b3a323f1433bd6");
        var addr = BtcSigningOps.Bech32Encode("bc", 0, program);
        Assert.Equal("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", addr);
    }

    [Fact]
    public void Bech32Encode_Bip173TestnetCanonical()
    {
        var program = Convert.FromHexString("751e76e8199196d454941c45d1b3a323f1433bd6");
        var addr = BtcSigningOps.Bech32Encode("tb", 0, program);
        Assert.Equal("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", addr);
    }

    [Fact]
    public void AddressFromPublicKeyP2wpkh_GeneratorMainnet_MatchesBip173()
    {
        // End-to-end: 64-byte uncompressed G → compressed → HASH160 →
        // bech32 P2WPKH → bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4.
        var addr = BtcSigningOps.AddressFromPublicKeyP2wpkh(_generatorUncompressed, "mainnet");
        Assert.Equal("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", addr);
    }

    [Fact]
    public void AddressFromPublicKeyP2wpkh_GeneratorTestnet_MatchesBip173()
    {
        var addr = BtcSigningOps.AddressFromPublicKeyP2wpkh(_generatorUncompressed, "testnet");
        Assert.Equal("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", addr);
    }

    [Fact]
    public void AddressFromPublicKeyP2wpkh_UnknownNetwork_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
            BtcSigningOps.AddressFromPublicKeyP2wpkh(_generatorUncompressed, "satoshinet"));
    }

    [Fact]
    public void SignedMessageHash_ProducesValid32Bytes()
    {
        var hash = BtcSigningOps.SignedMessageHash("hello");
        Assert.Equal(32, hash.Length);
    }

    [Fact]
    public void SignedMessageHash_DifferentMessagesProduceDifferentHashes()
    {
        var h1 = BtcSigningOps.SignedMessageHash("hello");
        var h2 = BtcSigningOps.SignedMessageHash("world");
        Assert.NotEqual(Convert.ToHexString(h1), Convert.ToHexString(h2));
    }

    [Fact]
    public void SignCompactBip137_ReturnsP2wpkhHeaderInRange()
    {
        var priv = EthSigningOps.GeneratePrivateKey();
        var msgHash = BtcSigningOps.SignedMessageHash("test message");
        var sig = BtcSigningOps.SignCompactBip137(msgHash, priv);
        Assert.Equal(65, sig.Length);
        // P2WPKH header byte is 39..42 (= 27 + 12 + recovery_id, recId 0..3).
        // We only emit recIds 0-1, so 39..40 in practice. BTC default coin.
        Assert.True(sig[0] is 39 or 40,
            $"BTC P2WPKH header byte should be 39 or 40, got {sig[0]}.");
    }

    [Theory]
    [InlineData("btc",  "Bitcoin Signed Message",  39, 40)]   // P2WPKH (native SegWit)
    [InlineData("ltc",  "Litecoin Signed Message", 39, 40)]   // P2WPKH (native SegWit)
    [InlineData("doge", "Dogecoin Signed Message", 31, 32)]   // P2PKH compressed (no SegWit)
    [InlineData("bch",  "Bitcoin Cash Signed Msg", 31, 32)]   // P2PKH compressed (no SegWit)
    public void SignCompactBip137_HeaderByteDispatchesOnCoin(
        string coin, string scenario, int expectedHi, int expectedLo)
    {
        // Wave-7-retroactive regression test (banked 2026-04-30 after the
        // test device smoke surfaced "address recovery failed: <coin> does not
        // support native SegWit (P2WPKH); use kind='p2pkh' instead" on
        // BCH + DOGE while signatures themselves verified). The phone
        // had been hardcoding the P2WPKH header byte (39..42) regardless
        // of coin, which encodes "this is a SegWit signature" into the
        // sig itself; recover_address(coin=...) on the verifier then
        // tried to encode the recovered hash160 as bech32, which fails
        // for coins with no bech32 HRP (DOGE, BCH).
        //
        // Pin per-coin header-byte ranges so the next time a Wave-7-
        // style "share the primitive across coins" sprint lands, this
        // test is the canary that catches the same class of bug.
        var priv = EthSigningOps.GeneratePrivateKey();
        var msgHash = BtcSigningOps.SignedMessageHash("hdr byte coin " + coin, coin);
        var sig = BtcSigningOps.SignCompactBip137(msgHash, priv, coin);
        Assert.Equal(65, sig.Length);
        Assert.True(
            sig[0] == expectedHi || sig[0] == expectedLo,
            $"{scenario}: coin='{coin}' expected header byte {expectedHi} or {expectedLo}, got {sig[0]}.");
    }

    [Fact]
    public void SignCompactBip137_UnknownCoinThrows()
    {
        var priv = EthSigningOps.GeneratePrivateKey();
        var msgHash = BtcSigningOps.SignedMessageHash("unknown coin");
        Assert.Throws<ArgumentException>(
            () => BtcSigningOps.SignCompactBip137(msgHash, priv, "xrp"));
    }

    [Fact]
    public void SignCompactBip137_DeterministicForSameInput()
    {
        // RFC 6979 deterministic-k: same priv + same hash → same signature.
        var priv = EthSigningOps.GeneratePrivateKey();
        var msgHash = BtcSigningOps.SignedMessageHash("deterministic test");
        var sigA = BtcSigningOps.SignCompactBip137(msgHash, priv);
        var sigB = BtcSigningOps.SignCompactBip137(msgHash, priv);
        Assert.Equal(Convert.ToHexString(sigA), Convert.ToHexString(sigB));
    }

    [Fact]
    public void SignCompactBip137_LowSCanonicalized()
    {
        var priv = EthSigningOps.GeneratePrivateKey();
        var msgHash = BtcSigningOps.SignedMessageHash("low-s canonical");
        var sig = BtcSigningOps.SignCompactBip137(msgHash, priv);
        // s value high bit must be 0 (low-s form). Imperfect — n/2
        // is slightly less than 2^255 — but catches obvious failures.
        Assert.True((sig[33] & 0x80) == 0,
            $"BIP-137 s high bit set (high-s); sig[33] = 0x{sig[33]:X2}.");
    }
}
