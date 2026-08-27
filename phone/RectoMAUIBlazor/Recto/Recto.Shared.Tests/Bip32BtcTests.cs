using System;
using Recto.Shared.Services;
using Xunit;

namespace Recto.Shared.Tests;

/// <summary>
/// Pins BIP-32 derivation at the Bitcoin native-SegWit BIP-44 path
/// (<c>m/84'/0'/0'/0/0</c>) against a known reference vector. The
/// canonical "abandon abandon abandon abandon abandon abandon abandon
/// abandon abandon abandon abandon about" 12-word zero-entropy
/// mnemonic with empty passphrase derives at <c>m/84'/0'/0'/0/0</c>
/// to the bech32 P2WPKH address
/// <c>bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu</c> (Trezor reference
/// fixture for BIP-84). If our impl produces this exact address, the
/// entire BIP-39 + BIP-32 + secp256k1 + bech32 stack is byte-for-byte
/// interoperable with every other BIP-39/BIP-84 wallet.
/// </summary>
public class Bip32BtcTests
{
    private const string ZeroEntropyMnemonic12 =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    [Fact]
    public void DeriveAtPath_BipAbandonAboutBtcAccount0_MatchesKnownAddress()
    {
        var seed = Bip39.MnemonicToSeed(ZeroEntropyMnemonic12, passphrase: "");
        var leaf = Bip32.DeriveAtPath(seed, "m/84'/0'/0'/0/0");
        var pub = EthSigningOps.PublicKeyFromPrivate(leaf.PrivateKey);
        var address = BtcSigningOps.AddressFromPublicKeyP2wpkh(pub, "mainnet");
        // Canonical BIP-84 reference vector from the Trezor fixture.
        Assert.Equal(
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
            address);
    }

    [Fact]
    public void DeriveAtPath_BipAbandonAboutBtcAccount0_TestnetMatchesKnownAddress()
    {
        var seed = Bip39.MnemonicToSeed(ZeroEntropyMnemonic12, passphrase: "");
        var leaf = Bip32.DeriveAtPath(seed, "m/84'/1'/0'/0/0");  // 1' for testnet per BIP-44
        var pub = EthSigningOps.PublicKeyFromPrivate(leaf.PrivateKey);
        var address = BtcSigningOps.AddressFromPublicKeyP2wpkh(pub, "testnet");
        // Format check only — no published reference vector for this
        // exact path with this mnemonic across all wallets, but the
        // address must start with tb1q (testnet bech32 P2WPKH).
        Assert.StartsWith("tb1q", address);
    }

    [Fact]
    public void DifferentBtcIndices_ProduceDifferentAddresses()
    {
        var seed = Bip39.MnemonicToSeed(ZeroEntropyMnemonic12, passphrase: "");
        var leaf0 = Bip32.DeriveAtPath(seed, "m/84'/0'/0'/0/0");
        var leaf1 = Bip32.DeriveAtPath(seed, "m/84'/0'/0'/0/1");
        var addr0 = BtcSigningOps.AddressFromPublicKeyP2wpkh(
            EthSigningOps.PublicKeyFromPrivate(leaf0.PrivateKey), "mainnet");
        var addr1 = BtcSigningOps.AddressFromPublicKeyP2wpkh(
            EthSigningOps.PublicKeyFromPrivate(leaf1.PrivateKey), "mainnet");
        Assert.NotEqual(addr0, addr1);
    }

    [Fact]
    public void OneMnemonic_BothCoinsDerivable_DifferentAddresses()
    {
        // The whole point of wave-5: same mnemonic, two BIP-44 trees,
        // both addresses derivable from a single 24-word backup.
        var seed = Bip39.MnemonicToSeed(ZeroEntropyMnemonic12, passphrase: "");

        // ETH at m/44'/60'/0'/0/0 → known canonical address.
        var ethLeaf = Bip32.DeriveAtPath(seed, "m/44'/60'/0'/0/0");
        var ethPub = EthSigningOps.PublicKeyFromPrivate(ethLeaf.PrivateKey);
        var ethAddr = EthSigningOps.AddressFromPublicKey(ethPub);
        Assert.Equal(
            "0x9858effd232b4033e47d90003d41ec34ecaeda94",
            ethAddr);

        // BTC at m/84'/0'/0'/0/0 → known canonical address.
        var btcLeaf = Bip32.DeriveAtPath(seed, "m/84'/0'/0'/0/0");
        var btcPub = EthSigningOps.PublicKeyFromPrivate(btcLeaf.PrivateKey);
        var btcAddr = BtcSigningOps.AddressFromPublicKeyP2wpkh(btcPub, "mainnet");
        Assert.Equal(
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
            btcAddr);

        // Different addresses (different paths produce different keys).
        Assert.NotEqual(ethAddr.ToLower(), btcAddr.ToLower());
    }
}
