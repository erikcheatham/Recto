using System;
using System.Linq;
using Recto.Shared.Services;
using Xunit;

namespace Recto.Shared.Tests;

/// <summary>
/// Pins SLIP-0010 ed25519 derivation behavior. Sister tests to
/// <see cref="Bip32Tests"/> for the secp256k1 curve.
///
/// <para>
/// Critical SLIP-0010 ed25519 properties under test:
/// <list type="bullet">
/// <item>Master derivation uses HMAC key <c>"ed25519 seed"</c> (NOT
/// <c>"Bitcoin seed"</c>) so the same BIP-39 seed produces different
/// keypairs under SLIP-0010 ed25519 vs BIP-32 secp256k1.</item>
/// <item>Hardened-only — every path segment must be hardened. Non-
/// hardened indices throw.</item>
/// <item>Chain trees for SOL / XLM / XRP-ed25519 are deterministic
/// (same mnemonic + path always yields the same keypair) and
/// distinct (different paths yield different keypairs).</item>
/// </list>
/// </para>
///
/// <para>
/// Mnemonic-to-known-external-address pinning (Phantom / SEP-0005 /
/// Xumm cross-wallet interop) is deferred until the operator can verify
/// values against real wallets. For now we pin internal consistency
/// + the structural properties that distinguish SLIP-0010 from BIP-32.
/// </para>
/// </summary>
public class Slip10Tests
{
    private const string ZeroEntropyMnemonic12 =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    [Fact]
    public void MasterFromSeed_RejectsNullOrWrongLength()
    {
        Assert.Throws<ArgumentException>(() => Slip10.MasterFromSeed(null!));
        Assert.Throws<ArgumentException>(() => Slip10.MasterFromSeed(new byte[63]));
        Assert.Throws<ArgumentException>(() => Slip10.MasterFromSeed(new byte[65]));
    }

    [Fact]
    public void MasterFromSeed_DifferentFromBip32_ForSameInput()
    {
        // The HMAC key differs ("ed25519 seed" vs "Bitcoin seed") so
        // the master private key MUST differ for any non-trivial input.
        // Without this property, deriving SOL and ETH from the same
        // mnemonic at the same path would collide on the same scalar.
        var seed = Bip39.MnemonicToSeed(ZeroEntropyMnemonic12, passphrase: "");
        var ed = Slip10.MasterFromSeed(seed);
        var bip32 = Bip32.MasterFromSeed(seed);
        Assert.False(ed.PrivateKey.SequenceEqual(bip32.PrivateKey),
            "SLIP-0010 ed25519 and BIP-32 secp256k1 master keys must differ for the same seed.");
        Assert.False(ed.ChainCode.SequenceEqual(bip32.ChainCode),
            "SLIP-0010 ed25519 and BIP-32 secp256k1 chain codes must differ for the same seed.");
    }

    [Fact]
    public void DeriveAtPath_HardenedOnly_RejectsNonHardenedSegment()
    {
        var seed = Bip39.MnemonicToSeed(ZeroEntropyMnemonic12, passphrase: "");
        // BIP-32-style path (last two segments non-hardened) — must throw.
        var ex = Assert.Throws<ArgumentException>(() =>
            Slip10.DeriveAtPath(seed, "m/44'/501'/0'/0/0"));
        Assert.Contains("hardened", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DeriveAtPath_AllHardened_Succeeds()
    {
        var seed = Bip39.MnemonicToSeed(ZeroEntropyMnemonic12, passphrase: "");
        // SOL canonical Phantom path — all hardened.
        var leaf = Slip10.DeriveAtPath(seed, "m/44'/501'/0'/0'");
        Assert.Equal(32, leaf.PrivateKey.Length);
        Assert.Equal(32, leaf.ChainCode.Length);
    }

    [Fact]
    public void DeriveAtPath_SamePathTwice_ProducesSameKey()
    {
        var seed = Bip39.MnemonicToSeed(ZeroEntropyMnemonic12, passphrase: "");
        var a = Slip10.DeriveAtPath(seed, "m/44'/148'/0'");
        var b = Slip10.DeriveAtPath(seed, "m/44'/148'/0'");
        Assert.True(a.PrivateKey.SequenceEqual(b.PrivateKey));
        Assert.True(a.ChainCode.SequenceEqual(b.ChainCode));
    }

    [Fact]
    public void DeriveAtPath_DifferentChainPaths_ProduceDifferentKeys()
    {
        var seed = Bip39.MnemonicToSeed(ZeroEntropyMnemonic12, passphrase: "");
        var sol = Slip10.DeriveAtPath(seed, "m/44'/501'/0'/0'");
        var xlm = Slip10.DeriveAtPath(seed, "m/44'/148'/0'");
        var xrp = Slip10.DeriveAtPath(seed, "m/44'/144'/0'/0'/0'");
        Assert.False(sol.PrivateKey.SequenceEqual(xlm.PrivateKey),
            "SOL and XLM keys must differ from the same mnemonic.");
        Assert.False(sol.PrivateKey.SequenceEqual(xrp.PrivateKey),
            "SOL and XRP keys must differ from the same mnemonic.");
        Assert.False(xlm.PrivateKey.SequenceEqual(xrp.PrivateKey),
            "XLM and XRP keys must differ from the same mnemonic.");
    }

    [Fact]
    public void GetPublicKey_IsConsistent_AcrossCalls()
    {
        var seed = Bip39.MnemonicToSeed(ZeroEntropyMnemonic12, passphrase: "");
        var leaf = Slip10.DeriveAtPath(seed, "m/44'/501'/0'/0'");
        var pub1 = Slip10.GetPublicKey(leaf.PrivateKey);
        var pub2 = Slip10.GetPublicKey(leaf.PrivateKey);
        Assert.Equal(32, pub1.Length);
        Assert.True(pub1.SequenceEqual(pub2));
    }

    [Fact]
    public void Hardened_HelperToggleBitCorrectly()
    {
        Assert.Equal(0x80000000u, Slip10.Hardened(0));
        Assert.Equal(0x800001f5u, Slip10.Hardened(501));
        Assert.Throws<ArgumentException>(() => Slip10.Hardened(0x80000000u));
    }

    [Fact]
    public void ParsePath_AcceptsBothApostropheAndHsuffix()
    {
        var withApostrophe = Slip10.ParsePath("m/44'/501'/0'/0'");
        var withH = Slip10.ParsePath("m/44h/501h/0h/0h");
        Assert.Equal(withApostrophe, withH);
    }

    [Fact]
    public void ParsePath_RejectsNonHardenedAtAnyPosition()
    {
        Assert.Throws<ArgumentException>(() => Slip10.ParsePath("m/44/501'/0'/0'"));
        Assert.Throws<ArgumentException>(() => Slip10.ParsePath("m/44'/501'/0'/0"));
    }
}
