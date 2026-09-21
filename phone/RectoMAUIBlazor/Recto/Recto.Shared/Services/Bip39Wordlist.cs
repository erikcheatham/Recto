using System;
using System.IO;
using System.Reflection;
using System.Text;

namespace Recto.Shared.Services;

/// <summary>
/// The canonical BIP-0039 English wordlist (2048 words), loaded once
/// from the embedded resource <c>Resources/Bip39/english.txt</c> at
/// first access and cached for the lifetime of the process.
///
/// <para>
/// Source: <see href="https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt"/>.
/// Mnemonics generated against this wordlist are byte-for-byte
/// interoperable with every other BIP-39 wallet — drop a Recto-produced
/// mnemonic into MetaMask / Ledger / Trezor and the same address derives.
/// </para>
///
/// <para>
/// Why an embedded resource and not a <c>static readonly string[]</c>
/// inlined in code: a 2048-word inline literal is ~14KB of source
/// that's hard to review by eye for typos. Loading from a file means
/// we trust the upstream bitcoin/bips repo as the canonical source,
/// not whoever last touched the C# file. The csproj's
/// <c>&lt;EmbeddedResource&gt;</c> entry bakes the file into the
/// assembly so deployment doesn't have to copy it separately.
/// </para>
/// </summary>
public static class Bip39Wordlist
{
    /// <summary>BIP-39 English wordlist, 2048 entries (indices 0..2047).</summary>
    public static string[] Words => _words.Value;

    /// <summary>
    /// Resolve a wordlist index (11-bit, range 0..2047) to its word.
    /// Throws if the index is out of range — call sites should already
    /// have masked to 11 bits before reaching here.
    /// </summary>
    public static string Word(int index)
    {
        var w = Words;
        if ((uint)index >= (uint)w.Length)
            throw new ArgumentOutOfRangeException(
                nameof(index),
                $"BIP-39 wordlist index must be in [0, {w.Length}); got {index}.");
        return w[index];
    }

    /// <summary>
    /// Reverse-lookup a word to its 11-bit wordlist index. Returns -1
    /// if the word isn't in the canonical English wordlist (caller
    /// should treat this as an invalid mnemonic and surface a clear
    /// error to the operator).
    /// </summary>
    public static int IndexOf(string word)
    {
        if (string.IsNullOrEmpty(word)) return -1;
        // Linear scan is fine — 2048 entries, single comparison per
        // word, mnemonic validation runs at most 24 times per import.
        // A pre-built Dictionary buys nothing at this scale.
        var w = Words;
        for (int i = 0; i < w.Length; i++)
        {
            if (w[i] == word) return i;
        }
        return -1;
    }

    private static readonly Lazy<string[]> _words = new(LoadWordlist, isThreadSafe: true);

    private static string[] LoadWordlist()
    {
        // Resource path is "<RootNamespace>.<Folder>.<File>" — for
        // Recto.Shared that's "Recto.Shared.Resources.Bip39.english.txt".
        // Using GetManifestResourceNames() at startup makes any path drift
        // (e.g. someone reorganizes Resources/) loud rather than silent.
        var asm = typeof(Bip39Wordlist).Assembly;
        const string expectedName = "Recto.Shared.Resources.Bip39.english.txt";
        using var stream = asm.GetManifestResourceStream(expectedName)
            ?? throw new InvalidOperationException(
                $"BIP-39 wordlist resource '{expectedName}' not found in assembly. " +
                "Did the canonical wordlist file get dropped into Resources/Bip39/english.txt? " +
                "See the wave-4 sprint notes — one-time `Invoke-WebRequest` against " +
                "raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt.");
        using var reader = new StreamReader(stream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false), detectEncodingFromByteOrderMarks: true);
        var content = reader.ReadToEnd();

        // Split on either CR/LF or LF — accept both line endings so a
        // contributor on Windows checking the file out doesn't break
        // the lookup. Empty trailing lines (from a trailing newline,
        // which the canonical file has) are dropped.
        var lines = content.Replace("\r\n", "\n").Split('\n', StringSplitOptions.RemoveEmptyEntries);
        if (lines.Length != 2048)
        {
            throw new InvalidOperationException(
                $"BIP-39 wordlist must contain exactly 2048 words; got {lines.Length}. " +
                "The embedded Resources/Bip39/english.txt is corrupt or has been edited. " +
                "Restore from https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt.");
        }

        // Defensive: ensure every entry is a single-token lowercase ASCII
        // word. Catches BOM / whitespace / mojibake at startup. The
        // canonical wordlist obeys this; a mismatched file would not.
        for (int i = 0; i < lines.Length; i++)
        {
            var w = lines[i].Trim();
            if (w.Length == 0)
            {
                throw new InvalidOperationException(
                    $"BIP-39 wordlist line {i + 1} is empty after trim.");
            }
            for (int j = 0; j < w.Length; j++)
            {
                var c = w[j];
                if (c is < 'a' or > 'z')
                {
                    throw new InvalidOperationException(
                        $"BIP-39 wordlist line {i + 1} ('{lines[i]}') contains non-lowercase-ASCII char '{c}' at position {j}. " +
                        "Wordlist file is not the canonical BIP-0039 English list.");
                }
            }
            lines[i] = w;
        }

        return lines;
    }
}
