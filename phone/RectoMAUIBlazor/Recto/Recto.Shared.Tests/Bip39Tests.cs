using System;
using System.Linq;
using System.Text;
using Recto.Shared.Services;
using Xunit;

namespace Recto.Shared.Tests;

/// <summary>
/// Pins the BIP-39 implementation against the published reference
/// vectors. If any of these break, every mnemonic Recto produces
/// silently diverges from every other BIP-39 wallet — operator can
/// never recover their addresses outside Recto. These tests are the
/// loud-failure backstop.
///
/// <para>
/// Reference: <see href="https://github.com/trezor/python-mnemonic/blob/master/vectors.json"/>
/// (Trezor's reference test fixtures, the de-facto standard everyone
/// validates against). The "abandon abandon ... about" 12-word
/// mnemonic with passphrase "TREZOR" is the most-cited single vector.
/// </para>
/// </summary>
public class Bip39Tests
{
    // 12-word zero-entropy mnemonic. Canonical BIP-39 test vector
    // (Trezor + every other reference impl). Generated from
    // entropy = 16 bytes of 0x00 + checksum.
    private const string ZeroEntropyMnemonic12 =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    // 24-word zero-entropy mnemonic. Generated from
    // entropy = 32 bytes of 0x00 + checksum.
    private const string ZeroEntropyMnemonic24 =
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        + "abandon abandon abandon abandon abandon abandon abandon abandon "
        + "abandon abandon abandon abandon abandon abandon abandon art";

    [Fact]
    public void GenerateMnemonic_DefaultsTo24WordsAnd256BitEntropy()
    {
        var mnemonic = Bip39.GenerateMnemonic();
        var words = mnemonic.Split(' ');
        Assert.Equal(24, words.Length);
        Assert.True(Bip39.ValidateMnemonic(mnemonic),
            $"Generated mnemonic failed self-validation: {mnemonic}");
    }

    [Theory]
    [InlineData(12)]
    [InlineData(15)]
    [InlineData(18)]
    [InlineData(21)]
    [InlineData(24)]
    public void GenerateMnemonic_AllPermittedWordCounts_RoundTrip(int wordCount)
    {
        var mnemonic = Bip39.GenerateMnemonic(wordCount);
        var words = mnemonic.Split(' ');
        Assert.Equal(wordCount, words.Length);
        Assert.True(Bip39.ValidateMnemonic(mnemonic));
    }

    [Theory]
    [InlineData(11)]
    [InlineData(13)]
    [InlineData(20)]
    [InlineData(25)]
    public void GenerateMnemonic_RejectsInvalidWordCount(int wordCount)
    {
        Assert.Throws<ArgumentException>(() => Bip39.GenerateMnemonic(wordCount));
    }

    [Fact]
    public void MnemonicFromEntropy_ZeroEntropy16Bytes_ProducesKnown12WordMnemonic()
    {
        var entropy = new byte[16];  // 16 zero bytes
        var mnemonic = Bip39.MnemonicFromEntropy(entropy);
        Assert.Equal(ZeroEntropyMnemonic12, mnemonic);
    }

    [Fact]
    public void MnemonicFromEntropy_ZeroEntropy32Bytes_ProducesKnown24WordMnemonic()
    {
        var entropy = new byte[32];  // 32 zero bytes
        var mnemonic = Bip39.MnemonicFromEntropy(entropy);
        Assert.Equal(ZeroEntropyMnemonic24, mnemonic);
    }

    [Fact]
    public void TryRecoverEntropy_ZeroEntropyMnemonic12_RecoversZeroBytes()
    {
        var ok = Bip39.TryRecoverEntropy(ZeroEntropyMnemonic12, out var entropy);
        Assert.True(ok);
        Assert.Equal(16, entropy.Length);
        Assert.All(entropy, b => Assert.Equal((byte)0, b));
    }

    [Fact]
    public void TryRecoverEntropy_ZeroEntropyMnemonic24_RecoversZeroBytes()
    {
        var ok = Bip39.TryRecoverEntropy(ZeroEntropyMnemonic24, out var entropy);
        Assert.True(ok);
        Assert.Equal(32, entropy.Length);
        Assert.All(entropy, b => Assert.Equal((byte)0, b));
    }

    [Fact]
    public void ValidateMnemonic_RejectsBadChecksum()
    {
        // Last word swapped to a non-checksum-valid alternative.
        var bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        Assert.False(Bip39.ValidateMnemonic(bad));
    }

    [Fact]
    public void ValidateMnemonic_RejectsUnknownWord()
    {
        var bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon NOT_A_BIP39_WORD";
        Assert.False(Bip39.ValidateMnemonic(bad));
    }

    [Fact]
    public void ValidateMnemonic_RejectsWrongLength()
    {
        Assert.False(Bip39.ValidateMnemonic("abandon abandon abandon"));    // 3 words
        Assert.False(Bip39.ValidateMnemonic(""));
        Assert.False(Bip39.ValidateMnemonic("   "));
    }

    [Fact]
    public void MnemonicToSeed_ZeroEntropy12Words_TrezorPassphrase_MatchesKnownSeed()
    {
        // Trezor's canonical test fixture:
        // mnemonic: ZeroEntropyMnemonic12
        // passphrase: "TREZOR"
        // seed: c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04
        var seed = Bip39.MnemonicToSeed(ZeroEntropyMnemonic12, "TREZOR");
        var hex = Convert.ToHexString(seed).ToLowerInvariant();
        Assert.Equal(
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
            hex);
    }

    [Fact]
    public void MnemonicToSeed_DifferentPassphrasesProduceDifferentSeeds()
    {
        var seedA = Bip39.MnemonicToSeed(ZeroEntropyMnemonic12, "");
        var seedB = Bip39.MnemonicToSeed(ZeroEntropyMnemonic12, "TREZOR");
        Assert.NotEqual(Convert.ToHexString(seedA), Convert.ToHexString(seedB));
    }

    [Fact]
    public void MnemonicToSeed_Always64Bytes()
    {
        var seed = Bip39.MnemonicToSeed(ZeroEntropyMnemonic24, "");
        Assert.Equal(64, seed.Length);
    }

    [Fact]
    public void Wordlist_ContainsExactly2048Words()
    {
        Assert.Equal(2048, Bip39Wordlist.Words.Length);
    }

    [Fact]
    public void Wordlist_StartsWithAbandonEndsWithZoo()
    {
        // The canonical BIP-0039 English wordlist is alphabetically
        // sorted; first word is "abandon", last is "zoo".
        Assert.Equal("abandon", Bip39Wordlist.Words[0]);
        Assert.Equal("zoo", Bip39Wordlist.Words[2047]);
    }

    [Fact]
    public void Wordlist_IndexOfAbandon_IsZero()
    {
        Assert.Equal(0, Bip39Wordlist.IndexOf("abandon"));
    }

    [Fact]
    public void Wordlist_IndexOfUnknown_IsMinusOne()
    {
        Assert.Equal(-1, Bip39Wordlist.IndexOf("zzzzznotaword"));
    }
}
