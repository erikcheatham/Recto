using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Recto.Shared.Services;

/// <summary>
/// Pure-C# (BouncyCastle for ed25519, .NET stdlib for SHA-256 / HMAC)
/// signing operations for the ed25519-chain credential family —
/// Solana, Stellar, and XRP-ed25519. Sister implementation to
/// <see cref="EthSigningOps"/> (secp256k1) and <see cref="BtcSigningOps"/>
/// (secp256k1, BIP-137 family).
///
/// <para>
/// One static class covers all three chains via a per-chain
/// <see cref="ChainConfig"/> table. The crypto primitive (raw 64-byte
/// ed25519 signature over a 32-byte chain-specific message hash) is
/// identical across the family; what varies is the SLIP-0010
/// derivation path, the address encoding, and the message preamble.
/// Adding a fourth ed25519 chain (e.g. TON, NEAR) is one entry in
/// <see cref="ChainConfigs"/> plus a test vector.
/// </para>
///
/// <para>
/// Pure-C# (no native dependencies). BouncyCastle ed25519 is the
/// canonical primitive (same library Bip32 uses for secp256k1). All
/// hashing is .NET stdlib SHA-256.
/// </para>
///
/// <para>
/// Threat model: private keys are 32-byte ed25519 seeds derived from
/// the operator's BIP-39 mnemonic via SLIP-0010 (see
/// <see cref="Slip10"/>). They live for the duration of one signing
/// call inside <see cref="SignMessage"/> and get
/// <see cref="CryptographicOperations.ZeroMemory"/>-wiped before the
/// method returns. Mnemonic stays in <c>SecureStorage</c> under the
/// SAME entry as the eth/btc services share.
/// </para>
/// </summary>
public static class Ed25519ChainSigningOps
{
    /// <summary>Per-chain config: SLIP-0010 default path, signed-
    /// message preamble, BIP-44 coin type. The <see cref="AddressEncoder"/>
    /// closure produces the chain-encoded address from the 32-byte
    /// ed25519 public key.</summary>
    public sealed record ChainConfig(
        string Name,
        string DefaultPath,
        byte[] MessagePreamble,
        uint Bip44CoinType,
        Func<byte[], string> AddressEncoder);

    /// <summary>Per-chain config table. Add a new ed25519 chain by
    /// adding an entry here.</summary>
    public static readonly IReadOnlyDictionary<string, ChainConfig> ChainConfigs =
        new Dictionary<string, ChainConfig>(StringComparer.Ordinal)
        {
            ["sol"] = new ChainConfig(
                Name: "Solana",
                DefaultPath: "m/44'/501'/0'/0'",
                MessagePreamble: Encoding.UTF8.GetBytes("Solana signed message:\n"),
                Bip44CoinType: 501,
                AddressEncoder: SolAddressFromPublicKey),
            ["xlm"] = new ChainConfig(
                Name: "Stellar",
                DefaultPath: "m/44'/148'/0'",
                MessagePreamble: Encoding.UTF8.GetBytes("Stellar signed message:\n"),
                Bip44CoinType: 148,
                AddressEncoder: XlmAddressFromPublicKey),
            ["xrp"] = new ChainConfig(
                Name: "XRP",
                DefaultPath: "m/44'/144'/0'/0'/0'",
                MessagePreamble: Encoding.UTF8.GetBytes("XRP signed message:\n"),
                Bip44CoinType: 144,
                AddressEncoder: XrpAddressFromPublicKey),
        };

    /// <summary>Look up the config for a chain key, throwing a clear
    /// error on unknown chains.</summary>
    public static ChainConfig GetChainConfig(string chain)
    {
        if (chain is null) throw new ArgumentNullException(nameof(chain));
        if (ChainConfigs.TryGetValue(chain, out var cfg)) return cfg;
        throw new ArgumentException(
            $"Unknown ed25519 chain '{chain}'. Valid: {string.Join(", ", ChainConfigs.Keys)}.",
            nameof(chain));
    }

    // ------------------------------------------------------------------
    // High-level dispatch
    // ------------------------------------------------------------------

    /// <summary>Compute the chain-specific signed-message hash:
    /// <c>SHA-256(chain_preamble || message)</c>. Mirrors
    /// <c>recto.solana.signed_message_hash</c> /
    /// <c>recto.stellar.signed_message_hash</c> /
    /// <c>recto.ripple.signed_message_hash</c> exactly.</summary>
    public static byte[] SignedMessageHash(string message, string chain)
    {
        if (message is null) throw new ArgumentNullException(nameof(message));
        var cfg = GetChainConfig(chain);
        var msgBytes = Encoding.UTF8.GetBytes(message);
        var buf = new byte[cfg.MessagePreamble.Length + msgBytes.Length];
        Buffer.BlockCopy(cfg.MessagePreamble, 0, buf, 0, cfg.MessagePreamble.Length);
        Buffer.BlockCopy(msgBytes, 0, buf, cfg.MessagePreamble.Length, msgBytes.Length);
        return SHA256.HashData(buf);
    }

    /// <summary>Derive the chain-encoded address from a 32-byte
    /// ed25519 public key.</summary>
    public static string AddressFromPublicKey(byte[] publicKey32, string chain)
    {
        if (publicKey32 is null || publicKey32.Length != 32)
            throw new ArgumentException("ed25519 public key must be 32 bytes.", nameof(publicKey32));
        var cfg = GetChainConfig(chain);
        return cfg.AddressEncoder(publicKey32);
    }

    /// <summary>Sign a chain-specific message with the ed25519 seed
    /// derived from <paramref name="seed"/> at <paramref name="path"/>.
    /// Returns a raw 64-byte ed25519 signature.</summary>
    public static byte[] SignMessage(byte[] seed, string path, string message, string chain)
    {
        var msgHash = SignedMessageHash(message, chain);
        Slip10.ExtendedKey? leaf = null;
        try
        {
            leaf = Slip10.DeriveAtPath(seed, path);
            var priv = new Ed25519PrivateKeyParameters(leaf.PrivateKey, 0);
            var signer = new Ed25519Signer();
            signer.Init(forSigning: true, priv);
            signer.BlockUpdate(msgHash, 0, msgHash.Length);
            return signer.GenerateSignature();
        }
        finally
        {
            if (leaf is not null)
            {
                CryptographicOperations.ZeroMemory(leaf.PrivateKey);
                CryptographicOperations.ZeroMemory(leaf.ChainCode);
            }
        }
    }

    // ==================================================================
    // Solana — base58 of raw 32-byte pubkey, no checksum
    // ==================================================================

    private static readonly byte[] BitcoinBase58Alphabet =
        Encoding.ASCII.GetBytes("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz");

    public static string SolAddressFromPublicKey(byte[] pubkey32)
    {
        if (pubkey32 is null || pubkey32.Length != 32)
            throw new ArgumentException("SOL public key must be 32 bytes.", nameof(pubkey32));
        return Base58EncodeNoChecksum(pubkey32, BitcoinBase58Alphabet);
    }

    public static byte[] SolPublicKeyFromAddress(string address)
    {
        var raw = Base58DecodeNoChecksum(address, BitcoinBase58Alphabet);
        if (raw.Length != 32)
            throw new ArgumentException(
                $"SOL address must decode to 32 bytes, got {raw.Length} (input: '{address}').",
                nameof(address));
        return raw;
    }

    // ==================================================================
    // Stellar — StrKey: base32(version_byte || pubkey || crc16xmodem)
    // ==================================================================

    public const byte XlmVersionByteAccountPublic = 6 << 3;  // 0x30, → 'G' prefix

    public static string XlmAddressFromPublicKey(byte[] pubkey32)
    {
        if (pubkey32 is null || pubkey32.Length != 32)
            throw new ArgumentException("XLM public key must be 32 bytes.", nameof(pubkey32));
        return StrKeyEncode(XlmVersionByteAccountPublic, pubkey32);
    }

    public static byte[] XlmPublicKeyFromAddress(string address)
    {
        var (versionByte, payload) = StrKeyDecode(address);
        if (versionByte != XlmVersionByteAccountPublic)
            throw new ArgumentException(
                $"XLM address must be an account public key (G…); got version byte 0x{versionByte:X2}.",
                nameof(address));
        if (payload.Length != 32)
            throw new ArgumentException(
                $"XLM account public key payload must be 32 bytes, got {payload.Length}.",
                nameof(address));
        return payload;
    }

    /// <summary>Encode <paramref name="payload"/> as a Stellar StrKey
    /// with the given version byte. Layout:
    /// <c>base32(version_byte || payload || crc16xmodem(version_byte || payload))</c>
    /// with no '=' padding, uppercase A-Z + 2-7. CRC is little-endian
    /// (low byte first) per SEP-0023.</summary>
    public static string StrKeyEncode(byte versionByte, byte[] payload)
    {
        if (payload is null) throw new ArgumentNullException(nameof(payload));
        var head = new byte[1 + payload.Length];
        head[0] = versionByte;
        Buffer.BlockCopy(payload, 0, head, 1, payload.Length);
        var crc = Crc16Xmodem(head);
        var full = new byte[head.Length + 2];
        Buffer.BlockCopy(head, 0, full, 0, head.Length);
        full[full.Length - 2] = (byte)(crc & 0xFF);
        full[full.Length - 1] = (byte)((crc >> 8) & 0xFF);
        return Base32EncodeRfc4648(full);
    }

    /// <summary>Decode a Stellar StrKey, returning <c>(versionByte, payload)</c>.
    /// Throws on bad checksum / bad length / invalid base32.</summary>
    public static (byte VersionByte, byte[] Payload) StrKeyDecode(string text)
    {
        if (text is null) throw new ArgumentNullException(nameof(text));
        var raw = Base32DecodeRfc4648(text.Trim());
        if (raw.Length < 3)
            throw new ArgumentException($"StrKey too short for a checksum: {raw.Length} bytes.", nameof(text));
        var expectedCrc = (ushort)(raw[raw.Length - 2] | (raw[raw.Length - 1] << 8));
        var head = new byte[raw.Length - 2];
        Buffer.BlockCopy(raw, 0, head, 0, raw.Length - 2);
        var actualCrc = Crc16Xmodem(head);
        if (expectedCrc != actualCrc)
            throw new ArgumentException(
                $"StrKey CRC mismatch: expected 0x{expectedCrc:X4}, got 0x{actualCrc:X4}.",
                nameof(text));
        var versionByte = head[0];
        var payload = new byte[head.Length - 1];
        Buffer.BlockCopy(head, 1, payload, 0, head.Length - 1);
        return (versionByte, payload);
    }

    /// <summary>CRC16-XMODEM (poly 0x1021, init 0x0000, no reflection,
    /// no final XOR). Bit-by-bit reference impl. Pinned against the
    /// canonical "123456789" → 0x31C3 vector in Slip10Tests.</summary>
    public static ushort Crc16Xmodem(byte[] data)
    {
        ushort crc = 0;
        foreach (var b in data)
        {
            crc ^= (ushort)((b & 0xFF) << 8);
            for (int i = 0; i < 8; i++)
            {
                if ((crc & 0x8000) != 0)
                    crc = (ushort)((crc << 1) ^ 0x1021);
                else
                    crc = (ushort)(crc << 1);
            }
        }
        return crc;
    }

    private static readonly char[] Base32Rfc4648Alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".ToCharArray();
    private static readonly Dictionary<char, int> Base32Rfc4648Index = BuildBase32Index();

    private static Dictionary<char, int> BuildBase32Index()
    {
        var d = new Dictionary<char, int>(32);
        for (int i = 0; i < Base32Rfc4648Alphabet.Length; i++)
            d[Base32Rfc4648Alphabet[i]] = i;
        return d;
    }

    /// <summary>RFC-4648 base32 encoder (uppercase A-Z + 2-7), no '=' padding.</summary>
    public static string Base32EncodeRfc4648(byte[] data)
    {
        if (data.Length == 0) return string.Empty;
        var sb = new StringBuilder((data.Length * 8 + 4) / 5);
        int buffer = 0;
        int bitsInBuffer = 0;
        foreach (var b in data)
        {
            buffer = (buffer << 8) | (b & 0xFF);
            bitsInBuffer += 8;
            while (bitsInBuffer >= 5)
            {
                bitsInBuffer -= 5;
                int idx = (buffer >> bitsInBuffer) & 0x1F;
                sb.Append(Base32Rfc4648Alphabet[idx]);
            }
        }
        if (bitsInBuffer > 0)
        {
            int idx = (buffer << (5 - bitsInBuffer)) & 0x1F;
            sb.Append(Base32Rfc4648Alphabet[idx]);
        }
        return sb.ToString();
    }

    /// <summary>RFC-4648 base32 decoder (uppercase A-Z + 2-7). Accepts
    /// strings with or without trailing '=' padding.</summary>
    public static byte[] Base32DecodeRfc4648(string text)
    {
        if (text is null) throw new ArgumentNullException(nameof(text));
        // Strip padding; we don't need it for decode.
        var trimmed = text.TrimEnd('=');
        var output = new List<byte>((trimmed.Length * 5 + 7) / 8);
        int buffer = 0;
        int bitsInBuffer = 0;
        foreach (var c in trimmed)
        {
            if (!Base32Rfc4648Index.TryGetValue(c, out var v))
                throw new ArgumentException(
                    $"Invalid base32 character '{c}' in input.", nameof(text));
            buffer = (buffer << 5) | v;
            bitsInBuffer += 5;
            if (bitsInBuffer >= 8)
            {
                bitsInBuffer -= 8;
                output.Add((byte)((buffer >> bitsInBuffer) & 0xFF));
            }
        }
        return output.ToArray();
    }

    // ==================================================================
    // XRP — base58check (Ripple alphabet) of (0x00 || RIPEMD160(SHA256(0xED || pubkey)))
    // ==================================================================

    /// <summary>XRP's leading byte for ed25519 public keys. secp256k1
    /// keys start with 0x02 / 0x03; ed25519 keys are prefixed with
    /// 0xED so they're also 33 bytes total but distinguishable. The
    /// prefix is INCLUDED when computing AccountID.</summary>
    public const byte XrpEd25519PubkeyPrefix = 0xED;

    /// <summary>Version byte prepended to AccountID when encoding a
    /// classic XRP address. 0x00 in XRP's base58 alphabet encodes to
    /// 'r', hence the 'r…' addresses.</summary>
    public const byte XrpAccountIdVersion = 0x00;

    /// <summary>XRP's base58 alphabet — distinct from Bitcoin's.
    /// Position 0 is 'r'.</summary>
    public const string RippleBase58Alphabet =
        "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";
    private static readonly byte[] RippleBase58AlphabetBytes =
        Encoding.ASCII.GetBytes(RippleBase58Alphabet);

    public static string XrpAddressFromPublicKey(byte[] pubkey32)
    {
        if (pubkey32 is null || pubkey32.Length != 32)
            throw new ArgumentException("XRP ed25519 public key must be 32 bytes.", nameof(pubkey32));
        var prefixed = new byte[1 + 32];
        prefixed[0] = XrpEd25519PubkeyPrefix;
        Buffer.BlockCopy(pubkey32, 0, prefixed, 1, 32);
        var sha = SHA256.HashData(prefixed);
        var accountId = Ripemd160(sha);  // 20 bytes
        var versionedAccountId = new byte[1 + 20];
        versionedAccountId[0] = XrpAccountIdVersion;
        Buffer.BlockCopy(accountId, 0, versionedAccountId, 1, 20);
        return Base58CheckEncode(versionedAccountId, RippleBase58AlphabetBytes);
    }

    /// <summary>Recover the 20-byte AccountID from a classic XRP address.
    /// NOTE — this does NOT recover the underlying public key. XRP
    /// addresses are one-way HASH160s; the verifier must receive the
    /// public key separately when validating ed_sign responses.</summary>
    public static byte[] XrpAccountIdFromAddress(string address)
    {
        var payload = Base58CheckDecode(address, RippleBase58AlphabetBytes);
        if (payload.Length != 21)
            throw new ArgumentException(
                $"XRP classic-address payload must be 21 bytes, got {payload.Length}.",
                nameof(address));
        if (payload[0] != XrpAccountIdVersion)
            throw new ArgumentException(
                $"XRP classic-address version byte must be 0x{XrpAccountIdVersion:X2}, got 0x{payload[0]:X2}.",
                nameof(address));
        var accountId = new byte[20];
        Buffer.BlockCopy(payload, 1, accountId, 0, 20);
        return accountId;
    }

    private static byte[] Ripemd160(byte[] data)
    {
        var d = new RipeMD160Digest();
        d.BlockUpdate(data, 0, data.Length);
        var result = new byte[d.GetDigestSize()];
        d.DoFinal(result, 0);
        return result;
    }

    // ==================================================================
    // Generic base58 helpers (alphabet-parameterized)
    // ==================================================================

    /// <summary>Encode raw bytes in the supplied base58 alphabet, NO
    /// checksum. Leading zero bytes preserve as leading-alphabet[0] chars.</summary>
    public static string Base58EncodeNoChecksum(byte[] data, byte[] alphabet)
    {
        if (alphabet.Length != 58)
            throw new ArgumentException("Base58 alphabet must be 58 chars.", nameof(alphabet));
        if (data.Length == 0) return string.Empty;
        int leadingZeros = 0;
        foreach (var b in data)
        {
            if (b == 0) leadingZeros++;
            else break;
        }
        // Convert to base 58 via repeated divmod on a big integer.
        var n = new System.Numerics.BigInteger(data, isUnsigned: true, isBigEndian: true);
        var sb = new StringBuilder();
        while (n > 0)
        {
            n = System.Numerics.BigInteger.DivRem(n, 58, out var rem);
            sb.Append((char)alphabet[(int)rem]);
        }
        // Reverse + prepend leading-1s.
        var body = new char[sb.Length];
        for (int i = 0; i < sb.Length; i++) body[i] = sb[sb.Length - 1 - i];
        var leading = new string((char)alphabet[0], leadingZeros);
        return leading + new string(body);
    }

    /// <summary>Decode a base58 string in the supplied alphabet, NO
    /// checksum. Leading-alphabet[0] chars become leading zero bytes.</summary>
    public static byte[] Base58DecodeNoChecksum(string text, byte[] alphabet)
    {
        if (alphabet.Length != 58)
            throw new ArgumentException("Base58 alphabet must be 58 chars.", nameof(alphabet));
        if (text is null) throw new ArgumentNullException(nameof(text));
        var index = new Dictionary<char, int>(58);
        for (int i = 0; i < 58; i++) index[(char)alphabet[i]] = i;

        int leadingFirstChar = 0;
        char first = (char)alphabet[0];
        foreach (var c in text)
        {
            if (c == first) leadingFirstChar++;
            else break;
        }
        var n = System.Numerics.BigInteger.Zero;
        foreach (var c in text)
        {
            if (!index.TryGetValue(c, out var v))
                throw new ArgumentException(
                    $"Base58 character '{c}' not in alphabet.", nameof(text));
            n = n * 58 + v;
        }
        var bodyBytes = n == 0 ? Array.Empty<byte>() : n.ToByteArray(isUnsigned: true, isBigEndian: true);
        var result = new byte[leadingFirstChar + bodyBytes.Length];
        // leading bytes are already 0 (default) — body sits after them.
        Buffer.BlockCopy(bodyBytes, 0, result, leadingFirstChar, bodyBytes.Length);
        return result;
    }

    /// <summary>Base58Check encode: append <c>double_sha256(payload)[:4]</c>
    /// and encode in the supplied alphabet.</summary>
    public static string Base58CheckEncode(byte[] payload, byte[] alphabet)
    {
        var checksum = SHA256.HashData(SHA256.HashData(payload));
        var full = new byte[payload.Length + 4];
        Buffer.BlockCopy(payload, 0, full, 0, payload.Length);
        Buffer.BlockCopy(checksum, 0, full, payload.Length, 4);
        return Base58EncodeNoChecksum(full, alphabet);
    }

    /// <summary>Base58Check decode in the supplied alphabet, verify
    /// the 4-byte checksum, return the payload (without checksum).</summary>
    public static byte[] Base58CheckDecode(string text, byte[] alphabet)
    {
        var raw = Base58DecodeNoChecksum(text, alphabet);
        if (raw.Length < 5)
            throw new ArgumentException(
                $"Base58Check string too short for a checksum ({raw.Length} bytes).",
                nameof(text));
        var payload = new byte[raw.Length - 4];
        Buffer.BlockCopy(raw, 0, payload, 0, payload.Length);
        var checksum = new byte[4];
        Buffer.BlockCopy(raw, raw.Length - 4, checksum, 0, 4);
        var expected = SHA256.HashData(SHA256.HashData(payload));
        for (int i = 0; i < 4; i++)
        {
            if (checksum[i] != expected[i])
                throw new ArgumentException(
                    $"Base58Check checksum mismatch.", nameof(text));
        }
        return payload;
    }
}
