using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Recto.Shared.Protocol.V04;

namespace Recto.Shared.Capability;

/// <summary>One row of a user-vault card: a signed field, its label and the text the person sees.</summary>
public sealed record UserVaultCardRow(string Field, string Label, string Value, bool IsHandle);

/// <summary>
/// The user-vault grant and revoke cards (R-series step 3): the records the
/// phone signs with its identity key, built byte-for-byte as the bootloader
/// rebuilds them (<c>recto/user_vault/grant_record.py</c>), and the two
/// rules the card stands on.
/// <para>
/// HARD RULE 15.x: a card that cannot render a signed field refuses to
/// sign. <see cref="RowsFor"/> renders the record the phone is about to
/// sign; a field with no renderer, or a value that fails its grammar,
/// returns null and the card offers no Approve. The service's words
/// (<see cref="Purpose"/>, <see cref="AgentName"/>) are never signed. The
/// window choices only shorten the proposal.
/// </para>
/// <para>
/// HARD RULE 15.y: nothing from a card persists after the tap. The model
/// lives in memory, takes no storage dependency, and <see cref="Drop"/>
/// clears the service's words on approve, deny, expiry or close.
/// </para>
/// </summary>
public sealed class UserVaultCardModel
{
    public const string GrantPrefix = "recto-user-vault-grant-v1|";
    public const string RevokePrefix = "recto-user-vault-revoke-v1|";
    public const string RevokeKeyPrefix = "recto-user-vault-revoke-key-v1|";
    public const string GrantsListPrefix = "recto-user-vault-grants-v1|";

    public const long GrantMaxSeconds = 365L * 86400;
    public const long ActWindowSeconds = 300;
    public const int HandlePrefixLength = 8;

    public const string ActionGrant = "grant";
    public const string ActionRevoke = "revoke";

    /// <summary>The window chips, in days. Only those SHORTER than the proposal are offered beside it.</summary>
    public static readonly IReadOnlyList<int> ChipDays = [90, 30, 7];

    private static readonly Regex HandleRe = new("^[A-Za-z0-9_-]{43}$", RegexOptions.CultureInvariant);
    private static readonly Regex KeyRe = new("^[a-z0-9][a-z0-9_-]{0,63}$", RegexOptions.CultureInvariant);
    private static readonly Regex ScopeRe = new("^[A-Za-z0-9_.:-]{1,64}$", RegexOptions.CultureInvariant);
    private static readonly Regex NonceRe = new("^[A-Za-z0-9_-]{16,64}$", RegexOptions.CultureInvariant);
    private static readonly Regex GrantIdRe = new("^[0-9a-f]{64}$", RegexOptions.CultureInvariant);
    private static readonly Regex TokenRe = new("^[\\x21-\\x7e]{1,128}$", RegexOptions.CultureInvariant);

    /// <summary>The renderer for every field a card may sign. A field missing here cannot be shown, so it cannot be signed.</summary>
    private static readonly IReadOnlyDictionary<string, (string Label, Func<object?, string?> Render, bool IsHandle)> Renderers =
        new Dictionary<string, (string, Func<object?, string?>, bool)>(StringComparer.Ordinal)
        {
            ["agent_handle"] = ("Agent", v => Handle(v), true),
            ["key"] = ("Key", v => v is string s && KeyRe.IsMatch(s) ? s : null, false),
            ["scope"] = ("For", v => v is string s && ScopeRe.IsMatch(s) ? s : null, false),
            ["not_after"] = ("Until", v => v is long t && t > 0 ? FormatUtc(t) : null, false),
            ["subject"] = ("You, here", v => Handle(v), true),
            ["bootloader_id"] = ("Vault", v => v is string s && TokenRe.IsMatch(s) ? s : null, false),
            ["consumer"] = ("Service", v => v is string s && IsConsumerUrl(s) ? s : null, false),
            ["nonce"] = ("Nonce", v => v is string s && NonceRe.IsMatch(s) ? s : null, false),
            ["grant_id"] = ("Grant", v => v is string s && GrantIdRe.IsMatch(s) ? s : null, false),
        };

    public string RequestId { get; }
    public string Action { get; }
    public string BootloaderId { get; }
    public string Consumer { get; }
    public string Subject { get; }
    public string AgentHandle { get; }
    public string Key { get; }
    public string Scope { get; }
    public long ProposedNotAfter { get; }
    public long ExpiresAtUnix { get; }
    public string? GrantId { get; }
    public long? AdmittedAtUnix { get; }

    /// <summary>The service's words about why. Shown labelled as the service's; never signed; dropped with the card.</summary>
    public string? Purpose { get; private set; }

    /// <summary>The service's name for the agent - its claim, not Recto's. Never signed; dropped with the card.</summary>
    public string? AgentName { get; private set; }

    public bool IsDropped { get; private set; }

    private UserVaultCardModel(string requestId, UserVaultGrantContext c)
    {
        RequestId = requestId;
        Action = c.Action;
        BootloaderId = c.BootloaderId;
        Consumer = c.Consumer;
        Subject = c.Subject;
        AgentHandle = c.AgentHandle;
        Key = c.Key;
        Scope = c.Scope;
        ProposedNotAfter = c.NotAfter;
        ExpiresAtUnix = c.ExpiresAtUnix;
        GrantId = c.GrantId;
        AdmittedAtUnix = c.AdmittedAtUnix;
        Purpose = c.Purpose;
        AgentName = c.AgentName;
    }

    public static bool IsUserVaultKind(string? kind)
        => kind == PendingRequestKind.UserVaultGrant || kind == PendingRequestKind.UserVaultRevoke;

    /// <summary>
    /// The card for <paramref name="req"/>, or null with the reason when it
    /// cannot be shown whole (hard rule 15.x): a missing context, an action
    /// that does not match the kind, a proposal already past or past the
    /// cap, or a request whose own window closed.
    /// </summary>
    public static UserVaultCardModel? TryBuild(PendingRequest req, long nowUnix, out string? refusal)
    {
        refusal = null;
        var c = req.Context?.UserVaultGrant;
        if (c is null)
        {
            refusal = "The card carries no grant record.";
            return null;
        }
        var expected = req.Kind == PendingRequestKind.UserVaultGrant ? ActionGrant
            : req.Kind == PendingRequestKind.UserVaultRevoke ? ActionRevoke : null;
        if (expected is null || c.Action != expected)
        {
            refusal = "The card's action does not match its kind.";
            return null;
        }
        if (c.ExpiresAtUnix <= nowUnix)
        {
            refusal = "This request's window closed.";
            return null;
        }
        if (expected == ActionGrant && (c.NotAfter <= nowUnix || c.NotAfter > nowUnix + GrantMaxSeconds))
        {
            refusal = "The proposed date is past or beyond the 365-day cap.";
            return null;
        }
        if (expected == ActionRevoke && c.GrantId is null)
        {
            refusal = "The revoke card names no grant.";
            return null;
        }
        var model = new UserVaultCardModel(req.RequestId, c);
        var probe = expected == ActionGrant
            ? model.GrantRecord(c.NotAfter, "probe-nonce-0000000000")
            : model.RevokeRecord("probe-nonce-0000000000");
        if (RowsFor(probe) is null)
        {
            refusal = "A field of this record cannot be shown, so it cannot be signed.";
            return null;
        }
        return model;
    }

    /// <summary>
    /// The window choices: the proposal itself, then each chip shorter than
    /// it. Never longer than the proposal, never past the cap (hard rule 15.x).
    /// </summary>
    public IReadOnlyList<long> WindowChoices(long nowUnix)
    {
        var cap = Math.Min(ProposedNotAfter, nowUnix + GrantMaxSeconds);
        var choices = new List<long> { cap };
        foreach (var days in ChipDays)
        {
            var t = nowUnix + days * 86400L;
            if (t < cap) choices.Add(t);
        }
        return choices;
    }

    /// <summary>The grant record the phone signs. Refuses a date past the proposal, past the cap, or already past.</summary>
    public IReadOnlyDictionary<string, object?> GrantRecord(long notAfter, string nonce, long? nowUnix = null)
    {
        if (Action != ActionGrant) throw new InvalidOperationException("Not a grant card.");
        if (notAfter > ProposedNotAfter)
            throw new ArgumentOutOfRangeException(nameof(notAfter), "A chip only shortens the proposal.");
        if (nowUnix is { } now && (notAfter <= now || notAfter > now + GrantMaxSeconds))
            throw new ArgumentOutOfRangeException(nameof(notAfter), "The date is past or beyond the cap.");
        return new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["agent_handle"] = AgentHandle,
            ["bootloader_id"] = BootloaderId,
            ["consumer"] = Consumer,
            ["key"] = Key,
            ["nonce"] = nonce,
            ["not_after"] = notAfter,
            ["scope"] = Scope,
            ["subject"] = Subject,
        };
    }

    public IReadOnlyDictionary<string, object?> RevokeRecord(string nonce)
    {
        if (Action != ActionRevoke || GrantId is null) throw new InvalidOperationException("Not a revoke card.");
        return BuildRevokeRecord(BootloaderId, Consumer, Subject, GrantId, nonce);
    }

    public static IReadOnlyDictionary<string, object?> BuildRevokeRecord(
        string bootloaderId, string consumer, string subject, string grantId, string nonce)
        => new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["bootloader_id"] = bootloaderId,
            ["consumer"] = consumer,
            ["grant_id"] = grantId,
            ["nonce"] = nonce,
            ["subject"] = subject,
        };

    public static IReadOnlyDictionary<string, object?> BuildRevokeKeyRecord(
        string bootloaderId, string consumer, string subject, string key, long notAfter, string nonce)
        => new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["bootloader_id"] = bootloaderId,
            ["consumer"] = consumer,
            ["key"] = key,
            ["nonce"] = nonce,
            ["not_after"] = notAfter,
            ["subject"] = subject,
        };

    public static IReadOnlyDictionary<string, object?> BuildGrantsListRequest(
        string bootloaderId, string phoneId, long issuedAt, string nonce)
        => new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["bootloader_id"] = bootloaderId,
            ["issued_at"] = issuedAt,
            ["nonce"] = nonce,
            ["phone_id"] = phoneId,
        };

    /// <summary>The bytes the identity key signs: the domain tag, then the canonical record.</summary>
    public static byte[] SignedMessage(string prefix, IReadOnlyDictionary<string, object?> record)
    {
        var tag = Encoding.ASCII.GetBytes(prefix);
        var body = CanonicalJson.Encode(record);
        var message = new byte[tag.Length + body.Length];
        tag.CopyTo(message, 0);
        body.CopyTo(message, tag.Length);
        return message;
    }

    /// <summary>A grant's id, as the bootloader names it: SHA-256 hex of the canonical record.</summary>
    public static string GrantIdOf(IReadOnlyDictionary<string, object?> grantRecord)
        => Convert.ToHexString(SHA256.HashData(CanonicalJson.Encode(grantRecord))).ToLowerInvariant();

    /// <summary>
    /// The rows of the record about to be signed - every field, in the
    /// card's order - or null when any field has no renderer or a value
    /// that fails its grammar (hard rule 15.x: then the card offers no Approve).
    /// </summary>
    public static IReadOnlyList<UserVaultCardRow>? RowsFor(IReadOnlyDictionary<string, object?> record)
    {
        var order = new[] { "agent_handle", "key", "scope", "grant_id", "not_after", "subject", "bootloader_id",
                            "consumer", "nonce" };
        if (record.Keys.Any(k => !Renderers.ContainsKey(k))) return null;
        var rows = new List<UserVaultCardRow>();
        foreach (var field in order.Where(record.ContainsKey))
        {
            var (label, render, isHandle) = Renderers[field];
            var value = render(record[field]);
            if (value is null) return null;
            rows.Add(new UserVaultCardRow(field, label, value, isHandle));
        }
        return rows.Count == record.Count ? rows : null;
    }

    /// <summary>A fresh nonce: 16 random bytes, base64url.</summary>
    public static string NewNonce() => B64u(RandomNumberGenerator.GetBytes(16));

    public static string HandlePrefix(string handle)
        => handle.Length <= HandlePrefixLength ? handle : handle[..HandlePrefixLength] + "…";

    /// <summary>Hard rule 15.y: the service's words leave with the card.</summary>
    public void Drop()
    {
        Purpose = null;
        AgentName = null;
        IsDropped = true;
    }

    public static string FormatUtc(long unix)
        => DateTimeOffset.FromUnixTimeSeconds(unix).UtcDateTime.ToString("d MMM yyyy, HH:mm 'UTC'",
            System.Globalization.CultureInfo.InvariantCulture);

    private static string? Handle(object? v)
    {
        if (v is not string s || !HandleRe.IsMatch(s)) return null;
        // Canonical only: 32 bytes that re-encode to the same 43 characters, as the bootloader checks.
        try
        {
            var padded = s.Replace('-', '+').Replace('_', '/') + "=";
            var raw = Convert.FromBase64String(padded);
            return raw.Length == 32 && B64u(raw) == s ? s : null;
        }
        catch (FormatException)
        {
            return null;
        }
    }

    private static bool IsConsumerUrl(string s)
        => Uri.TryCreate(s, UriKind.Absolute, out var u)
           && (u.Scheme == Uri.UriSchemeHttps || (u.Scheme == Uri.UriSchemeHttp && u.IsLoopback))
           && s.All(ch => ch > 0x20 && ch < 0x7f);

    private static string B64u(byte[] raw) => Convert.ToBase64String(raw).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
