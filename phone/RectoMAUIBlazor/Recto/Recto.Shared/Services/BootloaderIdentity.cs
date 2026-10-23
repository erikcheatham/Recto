using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Recto.Shared.Protocol.V04;

namespace Recto.Shared.Services;

public enum BootloaderIdentityStatus
{
    /// <summary>The id makes no derivation claim (not rb1-): legacy or demo.
    /// There is nothing to check, which is different from a check passing.</summary>
    NoClaim,

    /// <summary>The id recomputed from the presented key set. Arithmetic, not trust.</summary>
    Verified,

    /// <summary>The claim failed: wrong recomputation, missing inputs, or an
    /// unknown derivation version. The pairing must not proceed.</summary>
    Refused
}

public sealed record BootloaderIdentityCheck(
    BootloaderIdentityStatus Status,
    string? Reason = null);

/// <summary>
/// The C# sister of the bootloader's id derivation. The Python side pins the
/// cross-language contract (an operator key of bytes 0..63 derives
/// <c>rb1-1f344bc9162a781dff78b772d05c17e4</c>); the test suite here asserts
/// the same vectors. If the two ever disagree, the C# is wrong — or the
/// derivation changed without bumping its version string. Never repair a
/// parity failure by editing the pin.
/// </summary>
public static class BootloaderIdentity
{
    public const string DerivationV1 = "recto-bootloader-id-v1";
    public const string Prefix = "rb1-";

    /// <summary>
    /// Derive the bootloader id from the key set: SHA-256 over the version
    /// string then each key (de-duplicated, sorted bytewise) prefixed by its
    /// 4-byte big-endian length; first 128 bits as lowercase hex behind
    /// <see cref="Prefix"/>. Mirrors the server's three load-bearing
    /// properties: domain separated, order independent, length prefixed.
    /// </summary>
    public static string Derive(byte[] operatorPubkey, IEnumerable<byte[]>? memberPubkeys = null)
    {
        if (operatorPubkey is null || operatorPubkey.Length == 0)
        {
            throw new ArgumentException(
                "cannot derive a bootloader id with no operator pubkey",
                nameof(operatorPubkey));
        }

        var keys = new List<byte[]> { operatorPubkey };
        if (memberPubkeys is not null)
        {
            keys.AddRange(memberPubkeys);
        }

        // De-duplicate by content, then sort bytewise (shorter prefix first
        // on ties) — the same order Python's sorted() gives bytes.
        var set = keys
            .GroupBy(k => Convert.ToHexString(k))
            .Select(g => g.First())
            .ToList();
        set.Sort(CompareBytes);

        using var sha = SHA256.Create();
        var domain = Encoding.ASCII.GetBytes(DerivationV1);
        sha.TransformBlock(domain, 0, domain.Length, null, 0);
        foreach (var k in set)
        {
            var len = new byte[4];
            len[0] = (byte)(k.Length >> 24);
            len[1] = (byte)(k.Length >> 16);
            len[2] = (byte)(k.Length >> 8);
            len[3] = (byte)k.Length;
            sha.TransformBlock(len, 0, 4, null, 0);
            sha.TransformBlock(k, 0, k.Length, null, 0);
        }
        sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        var digest = sha.Hash!;
        return Prefix + Convert.ToHexString(digest, 0, 16).ToLowerInvariant();
    }

    /// <summary>
    /// The pairing-time gate: an id claiming to be derived (rb1-) must
    /// arrive with inputs that recompute to it. Fail closed: missing inputs,
    /// an unknown derivation version, or a mismatch all REFUSE — a claimed
    /// identity the phone cannot check is treated as a wrong one, because
    /// "receive-only makes the gate a label nobody checks".
    /// </summary>
    public static BootloaderIdentityCheck Check(string? claimedId, BootloaderIdentityInfo? identity)
    {
        if (string.IsNullOrEmpty(claimedId) || !claimedId.StartsWith(Prefix, StringComparison.Ordinal))
        {
            return new BootloaderIdentityCheck(BootloaderIdentityStatus.NoClaim);
        }

        if (identity is null)
        {
            return new BootloaderIdentityCheck(
                BootloaderIdentityStatus.Refused,
                "The bootloader claims a derived identity (rb1-…) but sent no key set to recompute it from. Refusing to pair.");
        }

        if (!string.Equals(identity.Derivation, DerivationV1, StringComparison.Ordinal))
        {
            return new BootloaderIdentityCheck(
                BootloaderIdentityStatus.Refused,
                $"Unknown identity derivation \"{identity.Derivation}\" — this app can only verify {DerivationV1}. Refusing to pair.");
        }

        byte[] operatorKey;
        List<byte[]> memberKeys;
        try
        {
            operatorKey = FromB64u(identity.OperatorPubkeyB64u);
            memberKeys = (identity.MemberPubkeysB64u ?? Array.Empty<string>())
                .Select(FromB64u)
                .ToList();
        }
        catch (FormatException)
        {
            return new BootloaderIdentityCheck(
                BootloaderIdentityStatus.Refused,
                "The bootloader's identity key set is malformed. Refusing to pair.");
        }

        if (operatorKey.Length == 0)
        {
            return new BootloaderIdentityCheck(
                BootloaderIdentityStatus.Refused,
                "The bootloader's identity key set is empty. Refusing to pair.");
        }

        var recomputed = Derive(operatorKey, memberKeys);
        if (!string.Equals(recomputed, claimedId, StringComparison.Ordinal))
        {
            return new BootloaderIdentityCheck(
                BootloaderIdentityStatus.Refused,
                $"Bootloader identity mismatch: it claims {claimedId} but its key set derives {recomputed}. " +
                "This is not the bootloader those keys constitute. Refusing to pair.");
        }

        return new BootloaderIdentityCheck(BootloaderIdentityStatus.Verified);
    }

    /// <summary>
    /// True when <paramref name="myPubkey"/> is one of the member keys the
    /// bootloader's identity derives from. A phone that finds ITS OWN key in
    /// a verified identity is a genesis member — this is how membership is
    /// discovered at pairing time: by arithmetic over the presented set,
    /// never by being told. Callers use it to arm the genesis marker after
    /// a Verified check.
    /// </summary>
    public static bool IsMemberOfIdentity(byte[]? myPubkey, BootloaderIdentityInfo? identity)
    {
        if (myPubkey is null || myPubkey.Length == 0 || identity?.MemberPubkeysB64u is null)
        {
            return false;
        }
        var mine = ToB64u(myPubkey);
        return identity.MemberPubkeysB64u.Any(
            k => string.Equals(k, mine, StringComparison.Ordinal));
    }

    private static string ToB64u(byte[] b) =>
        Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static int CompareBytes(byte[] a, byte[] b)
    {
        var n = Math.Min(a.Length, b.Length);
        for (var i = 0; i < n; i++)
        {
            if (a[i] != b[i]) return a[i] - b[i];
        }
        return a.Length - b.Length;
    }

    private static byte[] FromB64u(string s)
    {
        if (s is null) throw new FormatException("null base64url value");
        var padded = s.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(padded.PadRight(padded.Length + (4 - padded.Length % 4) % 4, '='));
    }
}
