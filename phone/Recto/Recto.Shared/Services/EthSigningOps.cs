using System;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

namespace Recto.Shared.Services;

/// <summary>
/// Pure-math Ethereum signing primitives the phone-side
/// <c>IEthSignService</c> impl composes. Keccak-256, secp256k1 ECDSA
/// sign with RFC 6979 deterministic-k + v-recovery, EIP-191 hash,
/// public-key + address derivation from a 32-byte private key.
///
/// <para>
/// All math is BouncyCastle-backed so this works identically across
/// every MAUI target (Windows, Mac Catalyst, iOS Simulator, iOS
/// device, Android). No platform-specific crypto. No
/// <c>System.Security.Cryptography</c> for the curve work — .NET
/// stdlib doesn't ship secp256k1 (the curve is intentionally absent
/// because of historical concerns; Ethereum / Bitcoin use it anyway,
/// so we reach for BC).
/// </para>
///
/// <para>
/// Wave-4 home: this class lives in Recto.Shared so Recto.Shared.Tests
/// can reach it via the existing project reference. Cross-platform
/// math has no MAUI deps; the platform-specific orchestrator
/// (<c>MauiEthSignService</c>) stays in the host project where
/// <c>Microsoft.Maui.Storage.SecureStorage</c> is available.
/// </para>
/// </summary>
public static class EthSigningOps
{
    private static readonly X9ECParameters Secp256k1 =
        Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp256k1");

    private static readonly ECDomainParameters Domain =
        new(Secp256k1.Curve, Secp256k1.G, Secp256k1.N, Secp256k1.H);

    /// <summary>
    /// Generate a fresh 32-byte secp256k1 private key from a CSPRNG.
    /// The key value is in <c>[1, n-1]</c> per ECDSA convention.
    /// </summary>
    public static byte[] GeneratePrivateKey()
    {
        var rng = new SecureRandom();
        BigInteger d;
        do
        {
            var bytes = new byte[32];
            rng.NextBytes(bytes);
            d = new BigInteger(1, bytes);
        }
        while (d.SignValue == 0 || d.CompareTo(Secp256k1.N) >= 0);
        return UnsignedFixed32(d);
    }

    /// <summary>
    /// Compute the 64-byte uncompressed public key (X || Y, big-endian,
    /// no <c>0x04</c> prefix, no DER) from a 32-byte private key.
    /// This is Ethereum's wire format, not Bitcoin's compressed form.
    /// </summary>
    public static byte[] PublicKeyFromPrivate(byte[] privateKey)
    {
        if (privateKey is null || privateKey.Length != 32)
            throw new ArgumentException("Private key must be 32 bytes.", nameof(privateKey));
        var d = new BigInteger(1, privateKey);
        var q = Domain.G.Multiply(d).Normalize();
        var x = UnsignedFixed32(q.AffineXCoord.ToBigInteger());
        var y = UnsignedFixed32(q.AffineYCoord.ToBigInteger());
        var pub = new byte[64];
        Buffer.BlockCopy(x, 0, pub, 0, 32);
        Buffer.BlockCopy(y, 0, pub, 32, 32);
        return pub;
    }

    /// <summary>
    /// Keccak-256 (32-byte digest). Original-Keccak padding (<c>0x01</c>),
    /// NOT FIPS-202 SHA3-256 padding (<c>0x06</c>). Ethereum addresses,
    /// EIP-191 hashes, EIP-712 hashes, transaction hashes, contract
    /// function selectors all use this exact variant.
    /// </summary>
    public static byte[] Keccak256(byte[] data)
    {
        var d = new KeccakDigest(256);
        d.BlockUpdate(data, 0, data.Length);
        var output = new byte[32];
        d.DoFinal(output, 0);
        return output;
    }

    /// <summary>
    /// EIP-191 personal_sign hash:
    /// <c>keccak256(0x19 || "Ethereum Signed Message:\n" || len(message) || message)</c>.
    /// Matches what every consumer-grade ETH wallet (MetaMask, Trust,
    /// Coinbase Wallet, Ledger Live) computes when the user clicks
    /// "Sign Message" on a string. The leading <c>0x19</c> byte is
    /// the EIP-191 version byte and is non-negotiable — without it,
    /// signatures produced here recover to a different public key
    /// than what Solidity's <c>ECDSA.recover()</c> +
    /// <c>MessageHashUtils.toEthSignedMessageHash()</c> compute,
    /// breaking cross-wallet / on-chain verification.
    /// </summary>
    public static byte[] PersonalSignHash(string message)
    {
        var msgBytes = System.Text.Encoding.UTF8.GetBytes(message);
        var prefix = $"Ethereum Signed Message:\n{msgBytes.Length}";
        var prefixBytes = System.Text.Encoding.UTF8.GetBytes(prefix);
        // Layout: [0x19] || prefix bytes || message bytes.
        // The 0x19 version byte is per EIP-191 §"Specification of the
        // Initial Version" (version byte = 0x45 for 'E', NO, wait —
        // the version byte is 0x45 for EIP-191 V1; the leading 0x19
        // is the "validator" / structured-data discriminator that
        // distinguishes EIP-191 envelopes from other signing forms.
        // Reference:
        // https://eips.ethereum.org/EIPS/eip-191#specification-of-the-initial-version)
        var combined = new byte[1 + prefixBytes.Length + msgBytes.Length];
        combined[0] = 0x19;
        Buffer.BlockCopy(prefixBytes, 0, combined, 1, prefixBytes.Length);
        Buffer.BlockCopy(msgBytes, 0, combined, 1 + prefixBytes.Length, msgBytes.Length);
        return Keccak256(combined);
    }

    /// <summary>
    /// 0x-prefixed lowercase hex Ethereum address derived from a
    /// 64-byte uncompressed public key. Address is the last 20 bytes
    /// of <c>keccak256(pubkey64)</c>.
    /// </summary>
    public static string AddressFromPublicKey(byte[] pubkey64)
    {
        if (pubkey64 is null || pubkey64.Length != 64)
            throw new ArgumentException("Public key must be 64 bytes.", nameof(pubkey64));
        var h = Keccak256(pubkey64);
        var addrBytes = new byte[20];
        Buffer.BlockCopy(h, 12, addrBytes, 0, 20);
        return "0x" + ToLowerHex(addrBytes);
    }

    /// <summary>
    /// Sign a 32-byte message hash with secp256k1 ECDSA + RFC 6979
    /// deterministic-k. Returns a 65-byte <c>r||s||v</c> signature.
    /// The <c>s</c> value is canonicalized to the low-s form
    /// (<c>s &lt; n/2</c>) per Ethereum's signature acceptance rules.
    /// The <c>v</c> byte is <c>27</c> or <c>28</c> (legacy
    /// canonical encoding); add the chain id prefix at the consumer
    /// layer if EIP-155 replay protection is needed.
    /// </summary>
    /// <param name="msgHash">32-byte hash the signer is signing (e.g. output of <see cref="PersonalSignHash"/>).</param>
    /// <param name="privateKey">32-byte secp256k1 private key.</param>
    /// <returns>65 bytes: <c>r</c> (32) || <c>s</c> (32) || <c>v</c> (1).</returns>
    public static byte[] SignWithRecovery(byte[] msgHash, byte[] privateKey)
    {
        if (msgHash is null || msgHash.Length != 32)
            throw new ArgumentException("Message hash must be 32 bytes.", nameof(msgHash));
        if (privateKey is null || privateKey.Length != 32)
            throw new ArgumentException("Private key must be 32 bytes.", nameof(privateKey));

        var d = new BigInteger(1, privateKey);
        var signer = new ECDsaSigner(new HMacDsaKCalculator(new Sha256Digest()));
        signer.Init(true, new ECPrivateKeyParameters(d, Domain));
        var sig = signer.GenerateSignature(msgHash);
        var r = sig[0];
        var s = sig[1];

        // Canonicalize to low-s: if s > n/2, replace with n - s.
        // Ethereum (post-EIP-2) rejects high-s signatures.
        var halfN = Secp256k1.N.ShiftRight(1);
        if (s.CompareTo(halfN) > 0)
            s = Secp256k1.N.Subtract(s);

        // Compute the expected public key once so v-recovery can compare.
        var expectedPub = PublicKeyFromPrivate(privateKey);

        // Try recovery ids 0 and 1; whichever recovers the right pub key wins.
        for (int recId = 0; recId < 2; recId++)
        {
            var recovered = TryRecoverPublicKey(msgHash, r, s, recId);
            if (recovered is not null && BytesEqual(recovered, expectedPub))
            {
                var rsv = new byte[65];
                CopyFixed32(r, rsv, 0);
                CopyFixed32(s, rsv, 32);
                rsv[64] = (byte)(27 + recId); // legacy canonical v
                return rsv;
            }
        }
        throw new InvalidOperationException("v-recovery failed: neither recId 0 nor 1 recovered the signing public key.");
    }

    /// <summary>
    /// Recover the signer's public key from <c>(msg_hash, r, s, v)</c>.
    /// Returns 64 bytes <c>X||Y</c>. Returns null if recovery fails
    /// (e.g. <c>r</c> not on curve, recovered point at infinity).
    /// Used internally for v-recovery; exposed for completeness.
    /// </summary>
    public static byte[]? RecoverPublicKey(byte[] msgHash, byte[] rsv)
    {
        if (msgHash is null || msgHash.Length != 32) return null;
        if (rsv is null || rsv.Length != 65) return null;
        var r = new BigInteger(1, rsv.AsSpan(0, 32).ToArray());
        var s = new BigInteger(1, rsv.AsSpan(32, 32).ToArray());
        var v = rsv[64];
        var recId = v >= 27 ? v - 27 : v;
        if (recId is < 0 or > 1) return null; // recIds 2/3 cover r >= n; rare, rejected for parity with Ethereum canonical acceptance.
        return TryRecoverPublicKey(msgHash, r, s, recId);
    }

    // ---------------------------------------------------------------
    // Private helpers
    // ---------------------------------------------------------------

    private static byte[]? TryRecoverPublicKey(byte[] msgHash, BigInteger r, BigInteger s, int recId)
    {
        // Reference: SEC1 §4.1.6, with the recId bit selecting Y parity.
        // We only call this with recId ∈ {0, 1}; recId 2/3 (covering r >= n)
        // is rare on secp256k1 and explicitly rejected at the public surface
        // for parity with Ethereum's canonical signature acceptance.
        var n = Secp256k1.N;
        var i = BigInteger.ValueOf(recId / 2);
        var x = r.Add(i.Multiply(n));
        // Curve field characteristic — public API regardless of the
        // curve's concrete subtype. (`SecP256K1Curve` itself is internal
        // in BouncyCastle.Cryptography 2.x; reaching for it directly
        // breaks the build.)
        var p = Secp256k1.Curve.Field.Characteristic;
        if (x.CompareTo(p) >= 0) return null;

        ECPoint R;
        try { R = DecompressPoint(recId & 1, x); }
        catch { return null; }
        if (R is null) return null;

        // nR == infinity check
        var nR = R.Multiply(n).Normalize();
        if (!nR.IsInfinity) return null;

        var e = new BigInteger(1, msgHash);
        var eInvNeg = BigInteger.Zero.Subtract(e).Mod(n);
        var rInv = r.ModInverse(n);
        var srInv = rInv.Multiply(s).Mod(n);
        var eInvrInv = rInv.Multiply(eInvNeg).Mod(n);

        // Q = r^-1 (sR - eG)
        var Q = ECAlgorithms.SumOfTwoMultiplies(Domain.G, eInvrInv, R, srInv).Normalize();
        if (Q.IsInfinity) return null;

        var qx = UnsignedFixed32(Q.AffineXCoord.ToBigInteger());
        var qy = UnsignedFixed32(Q.AffineYCoord.ToBigInteger());
        var pub = new byte[64];
        Buffer.BlockCopy(qx, 0, pub, 0, 32);
        Buffer.BlockCopy(qy, 0, pub, 32, 32);
        return pub;
    }

    private static ECPoint DecompressPoint(int yParity, BigInteger x)
    {
        // Compressed point form: 0x02 = even y, 0x03 = odd y.
        var compressed = new byte[33];
        compressed[0] = (byte)(0x02 + yParity);
        var xBytes = UnsignedFixed32(x);
        Buffer.BlockCopy(xBytes, 0, compressed, 1, 32);
        return Secp256k1.Curve.DecodePoint(compressed);
    }

    private static byte[] UnsignedFixed32(BigInteger value)
    {
        var bytes = value.ToByteArrayUnsigned();
        if (bytes.Length == 32) return bytes;
        if (bytes.Length > 32) throw new InvalidOperationException("Value exceeds 32 bytes.");
        var padded = new byte[32];
        Buffer.BlockCopy(bytes, 0, padded, 32 - bytes.Length, bytes.Length);
        return padded;
    }

    private static void CopyFixed32(BigInteger value, byte[] dest, int offset)
    {
        var bytes = UnsignedFixed32(value);
        Buffer.BlockCopy(bytes, 0, dest, offset, 32);
    }

    private static bool BytesEqual(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return false;
        for (int i = 0; i < a.Length; i++)
            if (a[i] != b[i]) return false;
        return true;
    }

    private static string ToLowerHex(byte[] bytes)
    {
        var hex = new char[bytes.Length * 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            var b = bytes[i];
            hex[i * 2] = ToHexChar(b >> 4);
            hex[i * 2 + 1] = ToHexChar(b & 0xF);
        }
        return new string(hex);
    }

    private static char ToHexChar(int nibble) => (char)(nibble < 10 ? '0' + nibble : 'a' + nibble - 10);

    // -----------------------------------------------------------------
    // EIP-712 typed-data hashing
    // Reference: https://eips.ethereum.org/EIPS/eip-712
    // -----------------------------------------------------------------

    /// <summary>
    /// Compute the EIP-712 digest for a typed-data document. Mirrors
    /// <c>recto.ethereum.typed_data_hash</c> in Python — produces the
    /// same 32-byte digest given the same JSON input. Cross-language
    /// interop is verified by tests using the canonical EIP-712 "Mail"
    /// example from the spec.
    ///
    /// Layout:
    ///   keccak256(0x19 || 0x01 || domainSeparator || structHash(primaryType, message))
    /// </summary>
    /// <param name="typedDataJson">
    /// JSON string with the canonical EIP-712 shape:
    /// <c>{"types":{...}, "primaryType":"...", "domain":{...}, "message":{...}}</c>.
    /// </param>
    /// <returns>32-byte digest the signer signs.</returns>
    public static byte[] TypedDataHash(string typedDataJson)
    {
        if (string.IsNullOrWhiteSpace(typedDataJson))
            throw new ArgumentException("typedDataJson is required.", nameof(typedDataJson));
        using var doc = System.Text.Json.JsonDocument.Parse(typedDataJson);
        var root = doc.RootElement;
        if (!root.TryGetProperty("types", out var typesElem))
            throw new ArgumentException("typed_data.types missing", nameof(typedDataJson));
        if (!root.TryGetProperty("primaryType", out var primaryElem) || primaryElem.ValueKind != System.Text.Json.JsonValueKind.String)
            throw new ArgumentException("typed_data.primaryType missing", nameof(typedDataJson));
        if (!root.TryGetProperty("domain", out var domainElem))
            throw new ArgumentException("typed_data.domain missing", nameof(typedDataJson));
        if (!root.TryGetProperty("message", out var messageElem))
            throw new ArgumentException("typed_data.message missing", nameof(typedDataJson));
        if (!typesElem.TryGetProperty("EIP712Domain", out _))
            throw new ArgumentException("typed_data.types.EIP712Domain missing", nameof(typedDataJson));
        var primaryType = primaryElem.GetString()!;
        if (!typesElem.TryGetProperty(primaryType, out _))
            throw new ArgumentException($"typed_data.primaryType {primaryType} not present in types", nameof(typedDataJson));

        var domainSeparator = StructHash("EIP712Domain", domainElem, typesElem);
        var structHash = StructHash(primaryType, messageElem, typesElem);
        var combined = new byte[2 + 32 + 32];
        combined[0] = 0x19;
        combined[1] = 0x01;
        Buffer.BlockCopy(domainSeparator, 0, combined, 2, 32);
        Buffer.BlockCopy(structHash, 0, combined, 34, 32);
        return Keccak256(combined);
    }

    private static byte[] StructHash(string structName, System.Text.Json.JsonElement value, System.Text.Json.JsonElement types)
    {
        var typeHash = Keccak256(System.Text.Encoding.UTF8.GetBytes(EncodeType(structName, types)));
        if (!types.TryGetProperty(structName, out var fields))
            throw new InvalidOperationException($"Type {structName} not in types schema.");
        using var stream = new System.IO.MemoryStream();
        stream.Write(typeHash, 0, typeHash.Length);
        foreach (var field in fields.EnumerateArray())
        {
            var fieldName = field.GetProperty("name").GetString()!;
            var fieldType = field.GetProperty("type").GetString()!;
            if (!value.TryGetProperty(fieldName, out var fieldValue))
                throw new InvalidOperationException($"struct {structName} field {fieldName} missing from value");
            var encoded = EncodeValue(fieldType, fieldValue, types);
            stream.Write(encoded, 0, encoded.Length);
        }
        return Keccak256(stream.ToArray());
    }

    private static string EncodeType(string primaryType, System.Text.Json.JsonElement types)
    {
        var deps = new System.Collections.Generic.SortedSet<string>(StringComparer.Ordinal);
        FindTypeDependencies(primaryType, types, deps);
        deps.Remove(primaryType);
        var ordered = new System.Collections.Generic.List<string> { primaryType };
        ordered.AddRange(deps);
        var sb = new StringBuilder();
        foreach (var dep in ordered)
        {
            if (!types.TryGetProperty(dep, out var fields))
                throw new InvalidOperationException($"type {dep} referenced from {primaryType} not present in types");
            sb.Append(dep);
            sb.Append('(');
            bool first = true;
            foreach (var f in fields.EnumerateArray())
            {
                if (!first) sb.Append(',');
                sb.Append(f.GetProperty("type").GetString());
                sb.Append(' ');
                sb.Append(f.GetProperty("name").GetString());
                first = false;
            }
            sb.Append(')');
        }
        return sb.ToString();
    }

    private static void FindTypeDependencies(string primaryType, System.Text.Json.JsonElement types, System.Collections.Generic.SortedSet<string> found)
    {
        var bracketIdx = primaryType.IndexOf('[');
        var baseType = bracketIdx < 0 ? primaryType : primaryType[..bracketIdx];
        if (found.Contains(baseType)) return;
        if (!types.TryGetProperty(baseType, out var fields)) return; // atomic, not a dep
        found.Add(baseType);
        foreach (var f in fields.EnumerateArray())
        {
            FindTypeDependencies(f.GetProperty("type").GetString()!, types, found);
        }
    }

    private static byte[] EncodeValue(string fieldType, System.Text.Json.JsonElement value, System.Text.Json.JsonElement types)
    {
        // Array types T[] or T[N]
        if (fieldType.EndsWith(']'))
        {
            var bracketIdx = fieldType.LastIndexOf('[');
            var innerType = fieldType[..bracketIdx];
            if (value.ValueKind != System.Text.Json.JsonValueKind.Array)
                throw new InvalidOperationException($"array field of type {fieldType} requires array value");
            using var stream = new System.IO.MemoryStream();
            foreach (var item in value.EnumerateArray())
            {
                var enc = EncodeValue(innerType, item, types);
                stream.Write(enc, 0, enc.Length);
            }
            return Keccak256(stream.ToArray());
        }
        // Struct type
        if (types.TryGetProperty(fieldType, out _))
        {
            return StructHash(fieldType, value, types);
        }
        // Atomic types
        if (fieldType == "string")
        {
            var s = value.GetString() ?? throw new InvalidOperationException("string field requires string value");
            return Keccak256(System.Text.Encoding.UTF8.GetBytes(s));
        }
        if (fieldType == "bytes")
        {
            return Keccak256(HexOrBytesToBytes(value));
        }
        if (fieldType.StartsWith("bytes"))
        {
            // bytes1..bytes32 fixed-length, right-padded to 32 bytes
            var n = int.Parse(fieldType[5..]);
            if (n < 1 || n > 32) throw new InvalidOperationException($"bytes{n} out of range 1..32");
            var raw = HexOrBytesToBytes(value);
            if (raw.Length > n) throw new InvalidOperationException($"bytes{n} value too long: {raw.Length} bytes");
            var padded = new byte[32];
            Buffer.BlockCopy(raw, 0, padded, 0, raw.Length);
            return padded;
        }
        if (fieldType == "address")
        {
            var s = value.GetString() ?? throw new InvalidOperationException("address field requires hex string");
            var cleaned = s.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? s[2..] : s;
            if (cleaned.Length != 40) throw new InvalidOperationException($"address must be 40 hex chars after 0x prefix, got {cleaned.Length}");
            var addrBytes = Convert.FromHexString(cleaned);
            var padded = new byte[32];
            Buffer.BlockCopy(addrBytes, 0, padded, 12, 20);
            return padded;
        }
        if (fieldType == "bool")
        {
            var b = value.GetBoolean();
            var padded = new byte[32];
            padded[31] = (byte)(b ? 1 : 0);
            return padded;
        }
        if (fieldType.StartsWith("uint") || fieldType.StartsWith("int"))
        {
            var isSigned = fieldType.StartsWith("int");
            var bitsStr = isSigned ? fieldType[3..] : fieldType[4..];
            var bits = string.IsNullOrEmpty(bitsStr) ? 256 : int.Parse(bitsStr);
            if (bits < 8 || bits > 256 || bits % 8 != 0)
                throw new InvalidOperationException($"unsupported integer type {fieldType}");
            BigInteger n;
            if (value.ValueKind == System.Text.Json.JsonValueKind.Number)
            {
                n = new BigInteger(value.GetInt64().ToString());
            }
            else
            {
                var s = value.GetString()!;
                if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                {
                    n = new BigInteger(s[2..], 16);
                }
                else
                {
                    n = new BigInteger(s);
                }
            }
            if (isSigned && n.SignValue < 0)
            {
                // Two's complement to 256 bits
                var twoTo256 = BigInteger.One.ShiftLeft(256);
                n = twoTo256.Add(n);
            }
            else if (!isSigned && n.SignValue < 0)
            {
                throw new InvalidOperationException($"uint{bits} cannot be negative");
            }
            return UnsignedFixed32(n);
        }
        throw new InvalidOperationException($"unsupported EIP-712 type {fieldType}");
    }

    private static byte[] HexOrBytesToBytes(System.Text.Json.JsonElement value)
    {
        var s = value.GetString() ?? throw new InvalidOperationException("bytes field requires hex string");
        var cleaned = s.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? s[2..] : s;
        return cleaned.Length == 0 ? Array.Empty<byte>() : Convert.FromHexString(cleaned);
    }

    // -----------------------------------------------------------------
    // RLP encoding (used by EIP-1559 transaction hashing below)
    // Reference: https://eth.wiki/fundamentals/rlp
    // -----------------------------------------------------------------

    /// <summary>
    /// RLP-encode a structured value. Items can be byte arrays, ints
    /// (non-negative), or lists of items. Mirrors
    /// <c>recto.ethereum.rlp_encode</c> in Python.
    /// </summary>
    public static byte[] RlpEncode(object item)
    {
        if (item is byte[] bytes)
            return RlpEncodeString(bytes);
        if (item is int i)
            return RlpEncodeInteger(new BigInteger(i.ToString()));
        if (item is long l)
            return RlpEncodeInteger(new BigInteger(l.ToString()));
        if (item is BigInteger bi)
            return RlpEncodeInteger(bi);
        if (item is string s)
            return RlpEncodeString(System.Text.Encoding.UTF8.GetBytes(s));
        if (item is System.Collections.IList list)
        {
            using var stream = new System.IO.MemoryStream();
            foreach (var x in list)
            {
                var enc = RlpEncode(x!);
                stream.Write(enc, 0, enc.Length);
            }
            var encoded = stream.ToArray();
            var lenPrefix = RlpEncodeLength(encoded.Length, 0xC0);
            var result = new byte[lenPrefix.Length + encoded.Length];
            Buffer.BlockCopy(lenPrefix, 0, result, 0, lenPrefix.Length);
            Buffer.BlockCopy(encoded, 0, result, lenPrefix.Length, encoded.Length);
            return result;
        }
        throw new InvalidOperationException($"RLP cannot encode {item?.GetType().Name ?? "null"}");
    }

    private static byte[] RlpEncodeInteger(BigInteger value)
    {
        if (value.SignValue < 0) throw new InvalidOperationException("RLP cannot encode negative int");
        if (value.SignValue == 0) return RlpEncodeString(Array.Empty<byte>());
        return RlpEncodeString(value.ToByteArrayUnsigned());
    }

    private static byte[] RlpEncodeString(byte[] data)
    {
        if (data.Length == 1 && data[0] < 0x80) return data;
        var lenPrefix = RlpEncodeLength(data.Length, 0x80);
        var result = new byte[lenPrefix.Length + data.Length];
        Buffer.BlockCopy(lenPrefix, 0, result, 0, lenPrefix.Length);
        Buffer.BlockCopy(data, 0, result, lenPrefix.Length, data.Length);
        return result;
    }

    private static byte[] RlpEncodeLength(int length, int offset)
    {
        if (length < 56) return new[] { (byte)(offset + length) };
        // length-of-length encoding
        var lenBytes = new BigInteger(length.ToString()).ToByteArrayUnsigned();
        var result = new byte[1 + lenBytes.Length];
        result[0] = (byte)(offset + 55 + lenBytes.Length);
        Buffer.BlockCopy(lenBytes, 0, result, 1, lenBytes.Length);
        return result;
    }

    // -----------------------------------------------------------------
    // EIP-1559 transaction hashing (type 0x02)
    // Reference: https://eips.ethereum.org/EIPS/eip-1559
    // -----------------------------------------------------------------

    /// <summary>
    /// Compute the keccak256 digest of an EIP-1559 (type 0x02)
    /// transaction for signing. Mirrors
    /// <c>recto.ethereum.transaction_hash_eip1559</c> in Python.
    ///
    /// Encoding: <c>0x02 || rlp([chain_id, nonce, max_priority_fee_per_gas,
    /// max_fee_per_gas, gas_limit, to, value, data, access_list])</c>
    ///
    /// The signer signs this digest with secp256k1 ECDSA + RFC 6979
    /// deterministic-k. The signature uses raw recovery_id (0 or 1)
    /// for v, NOT 27+recid like the legacy/EIP-191 forms.
    /// </summary>
    public static byte[] TransactionHashEip1559(string txJson)
    {
        if (string.IsNullOrWhiteSpace(txJson))
            throw new ArgumentException("txJson is required.", nameof(txJson));
        using var doc = System.Text.Json.JsonDocument.Parse(txJson);
        var tx = doc.RootElement;

        var chainId = ReadIntField(tx, "chainId", required: true)!;
        var nonce = ReadIntField(tx, "nonce", required: true)!;
        var maxPriority = ReadIntField(tx, "maxPriorityFeePerGas", required: true)!;
        var maxFee = ReadIntField(tx, "maxFeePerGas", required: true)!;
        var gas = ReadIntField(tx, "gas", required: false) ?? ReadIntField(tx, "gasLimit", required: true)!;
        var value = ReadIntField(tx, "value", required: false) ?? BigInteger.Zero;

        byte[] toBytes;
        if (tx.TryGetProperty("to", out var toElem) && toElem.ValueKind == System.Text.Json.JsonValueKind.String && !string.IsNullOrEmpty(toElem.GetString()))
        {
            var s = toElem.GetString()!;
            var cleaned = s.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? s[2..] : s;
            if (cleaned.Length != 40) throw new InvalidOperationException($"transaction.to must be 40 hex chars, got {cleaned.Length}");
            toBytes = Convert.FromHexString(cleaned);
        }
        else
        {
            toBytes = Array.Empty<byte>(); // contract creation
        }

        byte[] dataBytes;
        if (tx.TryGetProperty("data", out var dataElem) && dataElem.ValueKind == System.Text.Json.JsonValueKind.String)
        {
            var s = dataElem.GetString() ?? "";
            var cleaned = s.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? s[2..] : s;
            dataBytes = cleaned.Length == 0 ? Array.Empty<byte>() : Convert.FromHexString(cleaned);
        }
        else
        {
            dataBytes = Array.Empty<byte>();
        }

        // Access list — list of [address_bytes, [storage_key_bytes, ...]] entries
        var accessList = new System.Collections.Generic.List<object>();
        if (tx.TryGetProperty("accessList", out var aclElem) && aclElem.ValueKind == System.Text.Json.JsonValueKind.Array)
        {
            foreach (var entry in aclElem.EnumerateArray())
            {
                string addrStr;
                System.Text.Json.JsonElement keysArr;
                if (entry.ValueKind == System.Text.Json.JsonValueKind.Object)
                {
                    addrStr = entry.GetProperty("address").GetString() ?? "";
                    keysArr = entry.GetProperty("storageKeys");
                }
                else if (entry.ValueKind == System.Text.Json.JsonValueKind.Array)
                {
                    var arr = entry.EnumerateArray().ToArray();
                    addrStr = arr[0].GetString() ?? "";
                    keysArr = arr[1];
                }
                else
                {
                    throw new InvalidOperationException("accessList entry must be object or array");
                }
                var addrCleaned = addrStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? addrStr[2..] : addrStr;
                if (addrCleaned.Length != 40) throw new InvalidOperationException("accessList address must be 40 hex chars");
                var addrBytes = Convert.FromHexString(addrCleaned);
                var storageList = new System.Collections.Generic.List<object>();
                foreach (var key in keysArr.EnumerateArray())
                {
                    var k = key.GetString()!;
                    var kc = k.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? k[2..] : k;
                    if (kc.Length != 64) throw new InvalidOperationException("accessList storage key must be 64 hex chars");
                    storageList.Add(Convert.FromHexString(kc));
                }
                accessList.Add(new object[] { addrBytes, storageList });
            }
        }

        var payload = new System.Collections.Generic.List<object>
        {
            chainId, nonce, maxPriority, maxFee, gas, toBytes, value, dataBytes, accessList,
        };
        var rlpBytes = RlpEncode(payload);
        var encoded = new byte[1 + rlpBytes.Length];
        encoded[0] = 0x02;
        Buffer.BlockCopy(rlpBytes, 0, encoded, 1, rlpBytes.Length);
        return Keccak256(encoded);
    }

    private static BigInteger? ReadIntField(System.Text.Json.JsonElement obj, string name, bool required)
    {
        if (!obj.TryGetProperty(name, out var elem) || elem.ValueKind == System.Text.Json.JsonValueKind.Null)
        {
            if (required) throw new InvalidOperationException($"transaction.{name} is required");
            return null;
        }
        if (elem.ValueKind == System.Text.Json.JsonValueKind.Number)
        {
            return new BigInteger(elem.GetInt64().ToString());
        }
        if (elem.ValueKind == System.Text.Json.JsonValueKind.String)
        {
            var s = elem.GetString()!;
            if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                return new BigInteger(s[2..], 16);
            return new BigInteger(s);
        }
        throw new InvalidOperationException($"transaction.{name} must be number or string");
    }

    /// <summary>
    /// Sign an EIP-1559 transaction hash with secp256k1 ECDSA. The
    /// returned 65-byte r||s||v uses raw recovery_id (0 or 1) for v,
    /// per EIP-1559 — NOT 27+recid like personal_sign / EIP-712.
    /// EIP-155 chain-id replay protection is already baked into the
    /// hash itself (chainId is the first RLP field), so v doesn't
    /// need to encode it separately.
    /// </summary>
    public static byte[] SignTransactionEip1559(byte[] msgHash, byte[] privateKey)
    {
        // Reuse the same secp256k1 signing primitive but rewrite the
        // v byte to raw recovery_id at the end.
        var rsv = SignWithRecovery(msgHash, privateKey);
        if (rsv[64] >= 27) rsv[64] = (byte)(rsv[64] - 27);
        return rsv;
    }

    /// <summary>
    /// Build the full signed raw transaction bytes for an EIP-1559
    /// (type-2) transaction. Parses the JSON, computes the hash,
    /// signs, and appends [yParity, r, s] to the RLP payload, returning
    /// the complete <c>0x02 || rlp([..., yParity, r, s])</c> bytes
    /// ready to hand to <c>eth_sendRawTransaction</c>.
    /// </summary>
    public static byte[] SignAndEncodeTransactionEip1559(string txJson, byte[] privateKey)
    {
        if (string.IsNullOrWhiteSpace(txJson))
            throw new ArgumentException("txJson is required.", nameof(txJson));
        using var doc = System.Text.Json.JsonDocument.Parse(txJson);
        var tx = doc.RootElement;

        var chainId = ReadIntField(tx, "chainId", required: true)!;
        var nonce = ReadIntField(tx, "nonce", required: true)!;
        var maxPriority = ReadIntField(tx, "maxPriorityFeePerGas", required: true)!;
        var maxFee = ReadIntField(tx, "maxFeePerGas", required: true)!;
        var gas = ReadIntField(tx, "gas", required: false) ?? ReadIntField(tx, "gasLimit", required: true)!;
        var value = ReadIntField(tx, "value", required: false) ?? BigInteger.Zero;

        byte[] toBytes;
        if (tx.TryGetProperty("to", out var toElem) && toElem.ValueKind == System.Text.Json.JsonValueKind.String && !string.IsNullOrEmpty(toElem.GetString()))
        {
            var s = toElem.GetString()!;
            var cleaned = s.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? s[2..] : s;
            if (cleaned.Length != 40) throw new InvalidOperationException($"transaction.to must be 40 hex chars, got {cleaned.Length}");
            toBytes = Convert.FromHexString(cleaned);
        }
        else
        {
            toBytes = Array.Empty<byte>();
        }

        byte[] dataBytes;
        if (tx.TryGetProperty("data", out var dataElem) && dataElem.ValueKind == System.Text.Json.JsonValueKind.String)
        {
            var s = dataElem.GetString() ?? "";
            var cleaned = s.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? s[2..] : s;
            dataBytes = cleaned.Length == 0 ? Array.Empty<byte>() : Convert.FromHexString(cleaned);
        }
        else
        {
            dataBytes = Array.Empty<byte>();
        }

        var accessList = new System.Collections.Generic.List<object>();
        if (tx.TryGetProperty("accessList", out var aclElem) && aclElem.ValueKind == System.Text.Json.JsonValueKind.Array)
        {
            foreach (var entry in aclElem.EnumerateArray())
            {
                string addrStr;
                System.Text.Json.JsonElement keysArr;
                if (entry.ValueKind == System.Text.Json.JsonValueKind.Object)
                {
                    addrStr = entry.GetProperty("address").GetString() ?? "";
                    keysArr = entry.GetProperty("storageKeys");
                }
                else if (entry.ValueKind == System.Text.Json.JsonValueKind.Array)
                {
                    var arr = entry.EnumerateArray().ToArray();
                    addrStr = arr[0].GetString() ?? "";
                    keysArr = arr[1];
                }
                else
                {
                    throw new InvalidOperationException("accessList entry must be object or array");
                }
                var addrCleaned = addrStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? addrStr[2..] : addrStr;
                if (addrCleaned.Length != 40) throw new InvalidOperationException("accessList address must be 40 hex chars");
                var addrBytes = Convert.FromHexString(addrCleaned);
                var storageList = new System.Collections.Generic.List<object>();
                foreach (var key in keysArr.EnumerateArray())
                {
                    var k = key.GetString()!;
                    var kc = k.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? k[2..] : k;
                    if (kc.Length != 64) throw new InvalidOperationException("accessList storage key must be 64 hex chars");
                    storageList.Add(Convert.FromHexString(kc));
                }
                accessList.Add(new object[] { addrBytes, storageList });
            }
        }

        var payload = new System.Collections.Generic.List<object>
        {
            chainId, nonce, maxPriority, maxFee, gas, toBytes, value, dataBytes, accessList,
        };
        var rlpPayload = RlpEncode(payload);
        var hashInput = new byte[1 + rlpPayload.Length];
        hashInput[0] = 0x02;
        Buffer.BlockCopy(rlpPayload, 0, hashInput, 1, rlpPayload.Length);
        var hash = Keccak256(hashInput);

        // Sign with raw recovery_id (0 or 1) for EIP-1559's yParity.
        var rsv = SignTransactionEip1559(hash, privateKey);
        var sigR = new byte[32]; Buffer.BlockCopy(rsv, 0, sigR, 0, 32);
        var sigS = new byte[32]; Buffer.BlockCopy(rsv, 32, sigS, 0, 32);
        int yParity = rsv[64];

        // Strip leading zero bytes from r and s for canonical RLP integer
        // encoding. r/s are produced as fixed-width 32-byte arrays from
        // SignWithRecovery, but RLP integers are big-endian with no
        // leading-zero padding.
        var payloadWithSig = new System.Collections.Generic.List<object>(payload)
        {
            new BigInteger(yParity.ToString()),
            new BigInteger(1, sigR),
            new BigInteger(1, sigS),
        };
        var rlpFinal = RlpEncode(payloadWithSig);
        var signedRaw = new byte[1 + rlpFinal.Length];
        signedRaw[0] = 0x02;
        Buffer.BlockCopy(rlpFinal, 0, signedRaw, 1, rlpFinal.Length);
        return signedRaw;
    }
}
