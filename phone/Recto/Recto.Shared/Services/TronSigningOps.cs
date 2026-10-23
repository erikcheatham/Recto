using System;
using System.Security.Cryptography;
using System.Text;

namespace Recto.Shared.Services;

/// <summary>
/// Pure-math TRON signing primitives the phone-side
/// <c>ITronSignService</c> impl composes. TIP-191 message hash,
/// base58check address encoding, secp256k1 ECDSA sign with v-recovery
/// (delegated to <c>EthSigningOps</c> since both chains share the
/// same curve + Keccak-256 hash + uncompressed-pubkey format), TRON
/// address derivation from a 64-byte uncompressed public key.
///
/// <para>
/// What's the same as ETH: secp256k1 curve, Keccak-256 hash, RFC 6979
/// deterministic-k signing, uncompressed pubkey shape (X||Y, no 0x04
/// prefix), 65-byte r||s||v signature format with v in {27, 28}, the
/// 20-byte hash160-equivalent (<c>keccak256(pubkey64)[-20:]</c>).
/// </para>
///
/// <para>
/// What's different from ETH: TIP-191 preamble
/// (<c>"TRON Signed Message:\n"</c>) instead of EIP-191's
/// (<c>"Ethereum Signed Message:\n"</c>); base58check address
/// encoding with version byte <c>0x41</c> instead of EIP-55 hex.
/// </para>
///
/// <para>
/// Wave 9 part 2 home: this class lives in <c>Recto.Shared</c> so
/// <c>Recto.Shared.Tests</c> can pin against it, and so the
/// platform-specific orchestrator (<c>MauiTronSignService</c>) in
/// the host project can compose it without per-platform crypto code.
/// All math is BouncyCastle-backed (via <c>EthSigningOps</c>) so this
/// works identically across every MAUI target (Windows, Mac
/// Catalyst, iOS Simulator, iOS device, Android).
/// </para>
/// </summary>
public static class TronSigningOps
{
    /// <summary>TIP-191 preamble. <c>SignedMessageHash</c> adds the leading <c>0x19</c> byte itself.</summary>
    public const string Tip191Preamble = "TRON Signed Message:\n";

    /// <summary>TRON mainnet base58check version byte. base58check'ing
    /// produces the canonical <c>T...</c> address prefix. Shasta and
    /// Nile testnets use the same version byte.</summary>
    public const byte VersionByteMainnet = 0x41;

    /// <summary>Standard SLIP-0044 coin-type 195 BIP-44 path for TRON.</summary>
    public const string DefaultDerivationPath = "m/44'/195'/0'/0/0";

    private static readonly byte[] _Base58Alphabet =
        Encoding.ASCII.GetBytes("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz");

    // ---------------------------------------------------------------
    // TIP-191 message hash
    // ---------------------------------------------------------------

    /// <summary>
    /// TIP-191 signed-message hash:
    /// <c>keccak256(0x19 || "TRON Signed Message:\n" || ascii(len(msg)) || msg)</c>.
    /// Structurally identical to EIP-191 with the preamble swapped.
    /// Modern TronWeb's <c>signMessageV2</c> produces signatures over
    /// this exact digest; verifiers (TronLink / Tronscan / tronpy)
    /// recompose the same preamble before recovering the signer.
    /// The leading <c>0x19</c> byte is the version-discriminator and
    /// is non-negotiable -- omitting it produces signatures that
    /// recover to a different pubkey than what TronWeb computes.
    /// </summary>
    public static byte[] SignedMessageHash(string message)
    {
        if (message is null) throw new ArgumentNullException(nameof(message));
        var msgBytes = Encoding.UTF8.GetBytes(message);
        var prefix = $"{Tip191Preamble}{msgBytes.Length}";
        var prefixBytes = Encoding.UTF8.GetBytes(prefix);
        // Layout: [0x19] || prefix bytes || message bytes.
        var combined = new byte[1 + prefixBytes.Length + msgBytes.Length];
        combined[0] = 0x19;
        Buffer.BlockCopy(prefixBytes, 0, combined, 1, prefixBytes.Length);
        Buffer.BlockCopy(msgBytes, 0, combined, 1 + prefixBytes.Length, msgBytes.Length);
        return EthSigningOps.Keccak256(combined);
    }

    // ---------------------------------------------------------------
    // Address derivation: keccak256(pubkey64)[-20:] -> 0x41-prefix -> base58check
    // ---------------------------------------------------------------

    /// <summary>
    /// Derive a TRON base58check address from a 64-byte uncompressed
    /// secp256k1 public key (X||Y, big-endian, no leading <c>0x04</c>
    /// byte).
    /// <para>
    /// Layout:
    /// <c>last20 = keccak256(pubkey64)[-20:];
    /// payload = [0x41] || last20;
    /// return base58check(payload)</c>.
    /// </para>
    /// The first 12 bytes of the keccak digest are discarded, exactly
    /// as Ethereum does -- TRON's hash160-equivalent is
    /// EVM-interoperable. The visible difference is the version byte
    /// (0x41 vs ETH's implicit none) and the encoding (base58check vs
    /// EIP-55 hex). Output is always 34 ASCII chars starting with
    /// <c>T</c>.
    /// </summary>
    public static string AddressFromPublicKey(byte[] pubkey64)
    {
        if (pubkey64 is null || pubkey64.Length != 64)
            throw new ArgumentException("Public key must be 64 bytes (X||Y).", nameof(pubkey64));
        var keccak = EthSigningOps.Keccak256(pubkey64);
        var payload = new byte[21];
        payload[0] = VersionByteMainnet;
        Buffer.BlockCopy(keccak, 12, payload, 1, 20);
        return Base58CheckEncode(payload);
    }

    /// <summary>
    /// base58check-encode <paramref name="payload"/> (typically 21
    /// bytes: <c>version_byte || hash160-equivalent</c>).
    /// <para>
    /// Layout: <c>base58(payload || double_sha256(payload)[:4])</c>.
    /// </para>
    /// Leading <c>0x00</c> bytes in the payload + checksum prefix map
    /// to leading <c>"1"</c> characters in the output -- the standard
    /// base58 leading-zero preservation.
    /// </summary>
    public static string Base58CheckEncode(byte[] payload)
    {
        if (payload is null) throw new ArgumentNullException(nameof(payload));
        var checksum = DoubleSha256(payload).AsSpan(0, 4).ToArray();
        var data = new byte[payload.Length + 4];
        Buffer.BlockCopy(payload, 0, data, 0, payload.Length);
        Buffer.BlockCopy(checksum, 0, data, payload.Length, 4);

        // Count leading zero bytes for the leading-1s prefix.
        int leadingZeros = 0;
        for (int i = 0; i < data.Length && data[i] == 0; i++) leadingZeros++;

        // Base-58 conversion via repeated division on the base-256
        // big-int representation. We work on a copy that gets mutated
        // in-place as the long-division progresses.
        var input = new byte[data.Length];
        Buffer.BlockCopy(data, 0, input, 0, data.Length);
        var encoded = new byte[data.Length * 138 / 100 + 1];  // log(256)/log(58) bound
        int outIdx = encoded.Length;
        int startAt = leadingZeros;
        while (startAt < input.Length)
        {
            int remainder = 0;
            for (int i = startAt; i < input.Length; i++)
            {
                int num = (remainder << 8) + (input[i] & 0xFF);
                input[i] = (byte)(num / 58);
                remainder = num % 58;
            }
            encoded[--outIdx] = _Base58Alphabet[remainder];
            if (input[startAt] == 0) startAt++;
        }

        // Skip leading zeros in the encoded output.
        while (outIdx < encoded.Length && encoded[outIdx] == _Base58Alphabet[0])
            outIdx++;

        // Prepend "1" for each leading zero byte in the original input.
        var result = new StringBuilder(leadingZeros + (encoded.Length - outIdx));
        for (int i = 0; i < leadingZeros; i++) result.Append('1');
        for (int i = outIdx; i < encoded.Length; i++) result.Append((char)encoded[i]);
        return result.ToString();
    }

    private static byte[] DoubleSha256(byte[] data)
    {
        using var sha = SHA256.Create();
        var h1 = sha.ComputeHash(data);
        return sha.ComputeHash(h1);
    }

    // ---------------------------------------------------------------
    // Sign + recover (delegated to EthSigningOps)
    // ---------------------------------------------------------------

    /// <summary>
    /// Sign <paramref name="msgHash"/> (32 bytes, typically output of
    /// <see cref="SignedMessageHash"/>) with secp256k1 ECDSA + RFC 6979
    /// deterministic-k. Returns a 65-byte <c>r||s||v</c> signature with
    /// <c>v</c> in <c>{27, 28}</c>. Delegates to
    /// <see cref="EthSigningOps.SignWithRecovery"/> -- TRON and Ethereum
    /// share the secp256k1 + low-s canonicalization + v-recovery
    /// pipeline byte-for-byte.
    /// </summary>
    public static byte[] SignWithRecovery(byte[] msgHash, byte[] privateKey)
        => EthSigningOps.SignWithRecovery(msgHash, privateKey);

    /// <summary>
    /// Recover the signer's TRON base58check address from
    /// <paramref name="msgHash"/> + <paramref name="rsv"/>. Combines
    /// <see cref="EthSigningOps.RecoverPublicKey"/> with
    /// <see cref="AddressFromPublicKey"/>. Returns null if recovery
    /// fails (malformed signature, point at infinity, etc.) -- callers
    /// should branch on null rather than catch ValueError.
    /// </summary>
    public static string? RecoverAddress(byte[] msgHash, byte[] rsv)
    {
        var pub = EthSigningOps.RecoverPublicKey(msgHash, rsv);
        return pub is null ? null : AddressFromPublicKey(pub);
    }
}
