using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Recto.Shared.Services;

/// <summary>
/// BIP-39 mnemonic generation, validation, and seed derivation. Pure
/// math + the canonical English wordlist (loaded by
/// <see cref="Bip39Wordlist"/>); no platform-specific code, works
/// identically on every MAUI target.
///
/// <para>
/// Three operations make up the public surface:
/// <list type="number">
/// <item><see cref="GenerateMnemonic"/>: CSPRNG entropy → words.</item>
/// <item><see cref="ValidateMnemonic"/>: words → entropy + checksum verify.</item>
/// <item><see cref="MnemonicToSeed"/>: words + passphrase → 64-byte seed
/// for <see cref="Bip32"/> master-key derivation.</item>
/// </list>
/// All three follow the BIP-39 spec verbatim (§Generating the mnemonic
/// + §From mnemonic to seed). Test vectors in
/// <c>Recto.Shared.Tests/Bip39Tests.cs</c> confirm cross-wallet interop
/// (Trezor's "abandon abandon ... about" → known seed).
/// </para>
///
/// <para>
/// Threat model: the mnemonic IS the master secret. Once generated it
/// must be displayed exactly once to the operator (backup ceremony) and
/// never logged. <see cref="GenerateMnemonic"/> returns a plain
/// <c>string</c> for caller composition; the caller is responsible for
/// not echoing it into logs / stack traces / crash reports. The MAUI
/// orchestrator's storage path keeps the mnemonic in
/// <c>SecureStorage</c> with no in-memory caching beyond the per-call
/// derivation window.
/// </para>
/// </summary>
public static class Bip39
{
    /// <summary>
    /// Generate a fresh BIP-39 mnemonic from CSPRNG entropy.
    ///
    /// <para>
    /// Word counts permitted by BIP-39: 12, 15, 18, 21, 24 — corresponding
    /// to 128, 160, 192, 224, 256 bits of entropy. Recto defaults to 24
    /// words (256-bit) since that's what every modern wallet defaults to
    /// for new generations and it's the right posture for production
    /// custody — extra entropy costs the operator one screen of words
    /// to write down once and buys them a 128-bit security margin
    /// against hypothetical future cryptanalytic advances.
    /// </para>
    /// </summary>
    /// <param name="wordCount">12, 15, 18, 21, or 24. Default 24.</param>
    /// <returns>Mnemonic as a single string of space-separated lowercase words.</returns>
    public static string GenerateMnemonic(int wordCount = 24)
    {
        var entropyBits = wordCount switch
        {
            12 => 128,
            15 => 160,
            18 => 192,
            21 => 224,
            24 => 256,
            _ => throw new ArgumentException(
                $"BIP-39 word count must be one of 12/15/18/21/24; got {wordCount}.",
                nameof(wordCount)),
        };
        var entropyBytes = entropyBits / 8;
        var entropy = new byte[entropyBytes];
        RandomNumberGenerator.Fill(entropy);
        try
        {
            return MnemonicFromEntropy(entropy);
        }
        finally
        {
            // Minimize exposure window of the raw entropy in heap.
            CryptographicOperations.ZeroMemory(entropy);
        }
    }

    /// <summary>
    /// Convert a fixed entropy buffer to a mnemonic. Used by
    /// <see cref="GenerateMnemonic"/> and by tests with known entropy
    /// fixtures.
    /// </summary>
    public static string MnemonicFromEntropy(byte[] entropy)
    {
        if (entropy is null) throw new ArgumentNullException(nameof(entropy));
        var lengthBits = entropy.Length * 8;
        if (lengthBits is not (128 or 160 or 192 or 224 or 256))
            throw new ArgumentException(
                $"BIP-39 entropy must be 128/160/192/224/256 bits; got {lengthBits}.",
                nameof(entropy));

        // Checksum: first ENT/32 bits of SHA-256(entropy), appended to
        // the entropy bits, then sliced into 11-bit groups indexing the
        // wordlist.
        var checksumBits = lengthBits / 32;
        var hash = SHA256.HashData(entropy);
        var totalBits = lengthBits + checksumBits;
        var bits = new bool[totalBits];
        for (int i = 0; i < lengthBits; i++)
            bits[i] = ((entropy[i / 8] >> (7 - (i % 8))) & 1) == 1;
        for (int i = 0; i < checksumBits; i++)
            bits[lengthBits + i] = ((hash[i / 8] >> (7 - (i % 8))) & 1) == 1;

        var wordCount = totalBits / 11;
        var words = new string[wordCount];
        for (int w = 0; w < wordCount; w++)
        {
            int idx = 0;
            for (int b = 0; b < 11; b++)
            {
                idx <<= 1;
                if (bits[w * 11 + b]) idx |= 1;
            }
            words[w] = Bip39Wordlist.Word(idx);
        }
        return string.Join(' ', words);
    }

    /// <summary>
    /// Validate a mnemonic: every word must be in the canonical English
    /// wordlist and the trailing checksum bits must verify against
    /// SHA-256 of the recovered entropy. Returns true iff the mnemonic
    /// could have been produced by <see cref="GenerateMnemonic"/>.
    /// </summary>
    public static bool ValidateMnemonic(string mnemonic)
    {
        return TryRecoverEntropy(mnemonic, out _);
    }

    /// <summary>
    /// Validate a mnemonic and recover the original entropy bytes (used
    /// by tests and by potential v0.6+ "show me my seed" diagnostic UI).
    /// </summary>
    public static bool TryRecoverEntropy(string mnemonic, out byte[] entropy)
    {
        entropy = Array.Empty<byte>();
        if (string.IsNullOrWhiteSpace(mnemonic)) return false;
        var words = mnemonic.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (words.Length is not (12 or 15 or 18 or 21 or 24)) return false;

        var totalBits = words.Length * 11;
        var bits = new bool[totalBits];
        for (int w = 0; w < words.Length; w++)
        {
            var idx = Bip39Wordlist.IndexOf(words[w]);
            if (idx < 0) return false;
            for (int b = 0; b < 11; b++)
            {
                bits[w * 11 + b] = ((idx >> (10 - b)) & 1) == 1;
            }
        }

        var checksumBits = totalBits / 33;          // ENT/32 = (totalBits - ENT)
        var entropyBits = totalBits - checksumBits;
        var entropyBytes = entropyBits / 8;
        var ent = new byte[entropyBytes];
        for (int i = 0; i < entropyBits; i++)
            if (bits[i]) ent[i / 8] |= (byte)(1 << (7 - (i % 8)));

        // Recompute checksum and compare bit-for-bit.
        var hash = SHA256.HashData(ent);
        for (int i = 0; i < checksumBits; i++)
        {
            var expected = ((hash[i / 8] >> (7 - (i % 8))) & 1) == 1;
            if (bits[entropyBits + i] != expected)
            {
                CryptographicOperations.ZeroMemory(ent);
                return false;
            }
        }
        entropy = ent;
        return true;
    }

    /// <summary>
    /// Derive a 64-byte seed from a mnemonic + optional passphrase. This
    /// is what BIP-32 consumes as the master-key input (the "Bitcoin seed"
    /// chain). Per BIP-39:
    /// <c>seed = PBKDF2-HMAC-SHA512(mnemonic_bytes, "mnemonic" + passphrase, 2048 iter, 64 bytes)</c>.
    ///
    /// <para>
    /// The passphrase (called "BIP-39 25th word" colloquially) is
    /// optional; pass empty string for the standard mnemonic-only flow.
    /// Distinct passphrases yield distinct seeds yield distinct address
    /// trees from the same mnemonic — useful for plausible-deniability
    /// schemes but not relevant to Recto's v0.5+ scope (we use the
    /// empty passphrase consistently).
    /// </para>
    ///
    /// <para>
    /// Both the mnemonic and the salt are NFKD-normalized per BIP-39.
    /// The wordlist is already lowercase ASCII so for English mnemonics
    /// NFKD is a no-op, but we run it anyway for correctness with the
    /// passphrase (which the operator might paste from anywhere).
    /// </para>
    /// </summary>
    public static byte[] MnemonicToSeed(string mnemonic, string passphrase = "")
    {
        if (string.IsNullOrWhiteSpace(mnemonic))
            throw new ArgumentException("Mnemonic is required.", nameof(mnemonic));

        // Normalize whitespace: BIP-39 specifies single spaces between
        // words; collapse any tab/multi-space/newline a clipboard might
        // have introduced before NFKD.
        var normalizedMnemonic = string.Join(' ', mnemonic.Trim()
            .Split(new[] { ' ', '\t', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries))
            .Normalize(NormalizationForm.FormKD);
        var normalizedPassphrase = (passphrase ?? string.Empty).Normalize(NormalizationForm.FormKD);

        var passwordBytes = Encoding.UTF8.GetBytes(normalizedMnemonic);
        var saltBytes = Encoding.UTF8.GetBytes("mnemonic" + normalizedPassphrase);

        // BouncyCastle PBKDF2 with HMAC-SHA512 — the .NET stdlib's
        // Rfc2898DeriveBytes uses HMAC-SHA1/256 only.
        var generator = new Pkcs5S2ParametersGenerator(new Sha512Digest());
        generator.Init(passwordBytes, saltBytes, iterationCount: 2048);
        var keyParam = (KeyParameter)generator.GenerateDerivedMacParameters(64 * 8);
        var seed = keyParam.GetKey();

        CryptographicOperations.ZeroMemory(passwordBytes);
        return seed;
    }
}
