using System;
using System.Linq;
using Recto.Shared.Services;
using Xunit;

namespace Recto.Shared.Tests;

/// <summary>
/// Pins BIP-32 hierarchical-deterministic derivation against published
/// reference vectors. The most-cited cross-wallet sanity check is:
///
/// <list type="number">
/// <item>Mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" (12-word zero-entropy).</item>
/// <item>Passphrase: empty.</item>
/// <item>Path: m/44'/60'/0'/0/0.</item>
/// <item>Derived ETH address: 0x9858EfFD232B4033E47d90003D41EC34EcaEda94.</item>
/// </list>
///
/// If our impl produces this exact address for that input, the BIP-39
/// + BIP-32 + secp256k1 + Keccak stack is byte-for-byte interoperable
/// with MetaMask / Ledger / Trezor / every other wallet that derives
/// from the same canonical inputs.
/// </summary>
public class Bip32Tests
{
    private const string ZeroEntropyMnemonic12 =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    [Fact]
    public void DeriveAtPath_TrezorAbandonAboutEthAccount0_MatchesKnownAddress()
    {
        var seed = Bip39.MnemonicToSeed(ZeroEntropyMnemonic12, passphrase: "");
        var leaf = Bip32.DeriveAtPath(seed, "m/44'/60'/0'/0/0");
        var pub = EthSigningOps.PublicKeyFromPrivate(leaf.PrivateKey);
        var address = EthSigningOps.AddressFromPublicKey(pub);
        // Compare lowercase since AddressFromPublicKey emits lowercase
        // hex (canonical comparison form; EIP-55 mixed case is for
        // display only).
        Assert.Equal(
            "0x9858effd232b4033e47d90003d41ec34ecaeda94",
            address);
    }

    [Fact]
    public void DeriveAtPath_DifferentIndices_ProduceDifferentAddresses()
    {
        var seed = Bip39.MnemonicToSeed(ZeroEntropyMnemonic12, passphrase: "");
        var leaf0 = Bip32.DeriveAtPath(seed, "m/44'/60'/0'/0/0");
        var leaf1 = Bip32.DeriveAtPath(seed, "m/44'/60'/0'/0/1");
        var addr0 = EthSigningOps.AddressFromPublicKey(EthSigningOps.PublicKeyFromPrivate(leaf0.PrivateKey));
        var addr1 = EthSigningOps.AddressFromPublicKey(EthSigningOps.PublicKeyFromPrivate(leaf1.PrivateKey));
        Assert.NotEqual(addr0, addr1);
    }

    [Fact]
    public void DeriveAtPath_SamePathTwice_ProducesSameAddress()
    {
        var seed = Bip39.MnemonicToSeed(ZeroEntropyMnemonic12, passphrase: "");
        var leafA = Bip32.DeriveAtPath(seed, "m/44'/60'/0'/0/0");
        var leafB = Bip32.DeriveAtPath(seed, "m/44'/60'/0'/0/0");
        var addrA = EthSigningOps.AddressFromPublicKey(EthSigningOps.PublicKeyFromPrivate(leafA.PrivateKey));
        var addrB = EthSigningOps.AddressFromPublicKey(EthSigningOps.PublicKeyFromPrivate(leafB.PrivateKey));
        Assert.Equal(addrA, addrB);
    }

    [Fact]
    public void DeriveAtPath_MnemonicChange_ProducesDifferentAddress()
    {
        var seedA = Bip39.MnemonicToSeed(ZeroEntropyMnemonic12, passphrase: "");
        // Generate a mnemonic with non-zero entropy → different seed → different address tree.
        var entropy = new byte[16];
        entropy[15] = 0x01;
        var differentMnemonic = Bip39.MnemonicFromEntropy(entropy);
        var seedB = Bip39.MnemonicToSeed(differentMnemonic, passphrase: "");
        Assert.NotEqual(Convert.ToHexString(seedA), Convert.ToHexString(seedB));

        var leafA = Bip32.DeriveAtPath(seedA, "m/44'/60'/0'/0/0");
        var leafB = Bip32.DeriveAtPath(seedB, "m/44'/60'/0'/0/0");
        var addrA = EthSigningOps.AddressFromPublicKey(EthSigningOps.PublicKeyFromPrivate(leafA.PrivateKey));
        var addrB = EthSigningOps.AddressFromPublicKey(EthSigningOps.PublicKeyFromPrivate(leafB.PrivateKey));
        Assert.NotEqual(addrA, addrB);
    }

    [Fact]
    public void MasterFromSeed_ProducesValidExtendedKey()
    {
        var seed = Bip39.MnemonicToSeed(ZeroEntropyMnemonic12, passphrase: "");
        var master = Bip32.MasterFromSeed(seed);
        Assert.Equal(32, master.PrivateKey.Length);
        Assert.Equal(32, master.ChainCode.Length);
        // Master key is non-zero (would only happen with probability 2^-127).
        Assert.Contains(master.PrivateKey, b => b != 0);
    }

    [Theory]
    [InlineData("m", new uint[] { })]
    [InlineData("m/0", new uint[] { 0 })]
    [InlineData("m/0/1/2", new uint[] { 0, 1, 2 })]
    [InlineData("m/44'/60'/0'/0/0", new uint[] { 0x8000002C, 0x8000003C, 0x80000000, 0, 0 })]
    [InlineData("m/44h/60h/0h/0/0", new uint[] { 0x8000002C, 0x8000003C, 0x80000000, 0, 0 })]
    [InlineData("44'/60'/0'/0/0", new uint[] { 0x8000002C, 0x8000003C, 0x80000000, 0, 0 })]
    public void ParsePath_HandlesCanonicalShapes(string path, uint[] expected)
    {
        var parsed = Bip32.ParsePath(path);
        Assert.Equal(expected, parsed);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("m/abc")]
    [InlineData("m/-1")]
    [InlineData("m/2147483648'")] // 2^31 ≥ uint31 cap before hardened bit
    public void ParsePath_RejectsInvalidShapes(string path)
    {
        Assert.Throws<ArgumentException>(() => Bip32.ParsePath(path));
    }

    [Fact]
    public void Hardened_SetsHighBit()
    {
        Assert.Equal(0x8000002Cu, Bip32.Hardened(44));
        Assert.Equal(0x80000000u, Bip32.Hardened(0));
    }

    [Fact]
    public void Hardened_RejectsAlreadyHardenedIndex()
    {
        Assert.Throws<ArgumentException>(() => Bip32.Hardened(0x80000000u));
    }
}
