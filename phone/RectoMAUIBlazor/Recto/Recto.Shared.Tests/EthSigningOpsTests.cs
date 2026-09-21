using System;
using System.Linq;
using System.Text;
using Recto.Shared.Services;
using Xunit;

namespace Recto.Shared.Tests;

/// <summary>
/// Pins the secp256k1 + Keccak primitives against well-known test
/// vectors. The Keccak-256 of an empty string is one of the most-cited
/// reference values in Ethereum tooling; sign-then-recover round trips
/// confirm the v-recovery byte selection works correctly.
/// </summary>
public class EthSigningOpsTests
{
    [Fact]
    public void Keccak256_EmptyString_MatchesReferenceValue()
    {
        // Reference: keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        // (NOT the SHA3-256 value 0xa7ff...; Keccak-256 uses original
        // 0x01 padding, SHA3-256 uses 0x06).
        var hash = EthSigningOps.Keccak256(Array.Empty<byte>());
        Assert.Equal(
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
            Convert.ToHexString(hash).ToLowerInvariant());
    }

    [Fact]
    public void Keccak256_AbcAscii_MatchesReferenceValue()
    {
        // Reference: keccak256("abc") = 4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45
        var hash = EthSigningOps.Keccak256(Encoding.ASCII.GetBytes("abc"));
        Assert.Equal(
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
            Convert.ToHexString(hash).ToLowerInvariant());
    }

    [Fact]
    public void PersonalSignHash_HelloMessage_MatchesEip191()
    {
        // EIP-191 prefix: "\x19Ethereum Signed Message:\n" + len + msg
        // For "hello" (5 bytes): "\x19Ethereum Signed Message:\n5hello"
        // Pre-computed via geth/ethers: 50b2c43fd39106bafbba0da34fc430e1f91e3c96ea2acee2bc34119f92b37750
        var hash = EthSigningOps.PersonalSignHash("hello");
        Assert.Equal(
            "50b2c43fd39106bafbba0da34fc430e1f91e3c96ea2acee2bc34119f92b37750",
            Convert.ToHexString(hash).ToLowerInvariant());
    }

    [Fact]
    public void GeneratePrivateKey_ReturnsValidLength()
    {
        var key = EthSigningOps.GeneratePrivateKey();
        Assert.Equal(32, key.Length);
        // Almost-certain nonzero (failure rate ≈ 2^-256).
        Assert.Contains(key, b => b != 0);
    }

    [Fact]
    public void GeneratePrivateKey_ProducesUniqueValues()
    {
        var a = EthSigningOps.GeneratePrivateKey();
        var b = EthSigningOps.GeneratePrivateKey();
        Assert.NotEqual(Convert.ToHexString(a), Convert.ToHexString(b));
    }

    [Fact]
    public void PublicKeyFromPrivate_Returns64Bytes()
    {
        var priv = EthSigningOps.GeneratePrivateKey();
        var pub = EthSigningOps.PublicKeyFromPrivate(priv);
        Assert.Equal(64, pub.Length);
    }

    [Fact]
    public void AddressFromPublicKey_ReturnsLowercaseHex42Chars()
    {
        var priv = EthSigningOps.GeneratePrivateKey();
        var pub = EthSigningOps.PublicKeyFromPrivate(priv);
        var addr = EthSigningOps.AddressFromPublicKey(pub);
        Assert.Equal(42, addr.Length);
        Assert.StartsWith("0x", addr);
        Assert.All(addr[2..], c => Assert.True(
            (c is >= '0' and <= '9') || (c is >= 'a' and <= 'f'),
            $"Address char '{c}' is not lowercase hex."));
    }

    [Fact]
    public void SignWithRecovery_RoundTripsThroughRecoverPublicKey()
    {
        // Generate keypair, sign a message, recover public key, assert equal.
        var priv = EthSigningOps.GeneratePrivateKey();
        var pub = EthSigningOps.PublicKeyFromPrivate(priv);
        var msgHash = EthSigningOps.PersonalSignHash("the quick brown fox jumps over the lazy dog");

        var rsv = EthSigningOps.SignWithRecovery(msgHash, priv);
        Assert.Equal(65, rsv.Length);
        Assert.True(rsv[64] is 27 or 28, $"v byte should be 27 or 28 (canonical legacy); got {rsv[64]}.");

        var recoveredPub = EthSigningOps.RecoverPublicKey(msgHash, rsv);
        Assert.NotNull(recoveredPub);
        Assert.Equal(Convert.ToHexString(pub), Convert.ToHexString(recoveredPub!));
    }

    [Fact]
    public void SignWithRecovery_DeterministicForSameInput()
    {
        // RFC 6979 deterministic-k: same priv + same hash → same signature.
        var priv = EthSigningOps.GeneratePrivateKey();
        var msgHash = EthSigningOps.PersonalSignHash("repeatable");
        var sigA = EthSigningOps.SignWithRecovery(msgHash, priv);
        var sigB = EthSigningOps.SignWithRecovery(msgHash, priv);
        Assert.Equal(Convert.ToHexString(sigA), Convert.ToHexString(sigB));
    }

    [Fact]
    public void SignWithRecovery_LowSCanonicalized()
    {
        // s value MUST be in [1, n/2]; high-s signatures are rejected
        // by Ethereum (post-EIP-2). Verify our output stays in the
        // low-s half by checking the high bit of byte 32 is 0 (not a
        // perfect check — n/2 is slightly less than 2^255 — but
        // catches obvious non-canonicalization).
        var priv = EthSigningOps.GeneratePrivateKey();
        var msgHash = EthSigningOps.PersonalSignHash("low-s");
        var rsv = EthSigningOps.SignWithRecovery(msgHash, priv);
        Assert.True((rsv[32] & 0x80) == 0,
            $"s value high bit set (high-s); rsv = 0x{Convert.ToHexString(rsv)}.");
    }

    [Fact]
    public void RecoverPublicKey_WithMalformedSignature_ReturnsNull()
    {
        var msgHash = new byte[32];  // any 32 bytes
        var bogus = new byte[65];    // all zeros, not a valid signature
        bogus[64] = 27;
        Assert.Null(EthSigningOps.RecoverPublicKey(msgHash, bogus));
    }
}
