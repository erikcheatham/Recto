using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Recto.Shared.Common;

namespace Recto.Shared.Services;

/// <summary>
/// Phone-side half of the signed-poll protocol (2026-08-13, "phone_id
/// split: reference vs capability").
/// <para>
/// The bootloader's possession-of-phone_id read surfaces
/// (<c>GET /v0.4/pending</c>, <c>GET /v0.4/manage/phones</c>,
/// <c>POST /v0.4/manage/push_token</c>) accept two headers:
/// <c>X-Recto-Phone-Sig</c> (base64url, 64-byte raw signature) and
/// <c>X-Recto-Phone-Ts</c> (unix seconds). The signing input is the
/// ASCII string <c>recto-poll-v1|{phone_id}|{ts}|{path}</c> where
/// <c>path</c> is the URL path only (no query string). The server
/// verifies against the registration's pubkey + declared algorithm
/// with a &plusmn;120s freshness window.
/// </para>
/// <para>
/// Server mode is <c>advisory</c> today (unsigned polls still read;
/// verdicts are logged). When the operator flips <c>required</c>,
/// unsigned polls 401 &mdash; so wiring these headers into the poll
/// call sites is the Build 13 increment that makes the flip safe.
/// </para>
/// <para>
/// THE POLL KEY (hard rule 14.2, 2026-09-21). The identity key
/// is per-use biometric-gated on both shipped platforms, so it cannot
/// sign a poll tick; that is why this helper shipped in 1.1.0 with no
/// caller. Reads are signed instead by a second, enclave-resident,
/// NON-gated key under <see cref="PollKeyAlias"/>
/// (<see cref="IEnclaveKeyService.GenerateDeviceKeyAsync"/>), which the
/// identity key delegates ONCE at pairing by signing
/// <see cref="BuildDelegationPayload"/>. The bootloader verifies reads
/// against the poll key from then on and refuses the identity key for
/// them. The poll key authenticates the DEVICE; it never signs an
/// approval. <see cref="IReadSigner"/> is the call-site seam.
/// </para>
/// </summary>
public static class PollSigning
{
    /// <summary>Signing-input prefix; mirrors the server's POLL_SIG_PREFIX.</summary>
    public const string Prefix = "recto-poll-v1";

    /// <summary>Enclave alias of the poll key. Distinct from the identity alias by construction.</summary>
    public const string PollKeyAlias = "recto.phone.poll";

    /// <summary>Delegation prefix; mirrors the server's POLL_KEY_DELEGATION_PREFIX.</summary>
    public const string DelegationPrefix = "recto-poll-key-v1";

    /// <summary>
    /// The bytes the IDENTITY key signs to delegate a poll key:
    /// <c>recto-poll-key-v1|{identityPubB64u}|{pollPubB64u}</c> (ASCII).
    /// Mirrors the server's poll_key_delegation_payload byte for byte.
    /// </summary>
    public static byte[] BuildDelegationPayload(string identityPubB64u, string pollPubB64u)
        => Encoding.ASCII.GetBytes($"{DelegationPrefix}|{identityPubB64u}|{pollPubB64u}");

    /// <summary>Slot-replacement prefix; mirrors the server's SLOT_REPLACE_PREFIX (hard rule 14.4).</summary>
    public const string SlotReplacePrefix = "recto-slot-replace-v1";

    /// <summary>
    /// The bytes the incoming IDENTITY key signs to displace a slot's occupant:
    /// <c>recto-slot-replace-v1|{slot}|{occupantPhoneRef}|{incomingPubB64u}</c>.
    /// Mirrors the server's slot_replace_payload byte for byte.
    /// </summary>
    public static byte[] BuildSlotReplacePayload(string slot, string occupantPhoneRef, string incomingPubB64u)
        => Encoding.ASCII.GetBytes($"{SlotReplacePrefix}|{slot}|{occupantPhoneRef}|{incomingPubB64u}");

    /// <summary>Signature header; mirrors the server's POLL_SIG_HEADER.</summary>
    public const string SignatureHeader = "X-Recto-Phone-Sig";

    /// <summary>Timestamp header; mirrors the server's POLL_SIG_TS_HEADER.</summary>
    public const string TimestampHeader = "X-Recto-Phone-Ts";

    /// <summary>
    /// The canonical signing input:
    /// <c>recto-poll-v1|{phoneId}|{ts}|{path}</c>. Deterministic and
    /// ASCII so the Python verifier reconstructs byte-identically.
    /// </summary>
    public static string BuildPayload(string phoneId, long tsUnix, string path)
        => $"{Prefix}|{phoneId}|{tsUnix}|{path}";

    /// <summary>
    /// Signs a poll for <paramref name="path"/> with the enclave key
    /// under <paramref name="keyAlias"/> at the current time. Returns
    /// the header pair to attach to the request. May trigger a
    /// biometric prompt on hardware-enclave platforms (see class
    /// remarks before wiring into a poll loop).
    /// </summary>
    public static async Task<Result<PollSignatureHeaders>> SignPollAsync(
        IEnclaveKeyService enclave,
        string keyAlias,
        string phoneId,
        string path,
        CancellationToken ct)
    {
        var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var payload = Encoding.ASCII.GetBytes(BuildPayload(phoneId, ts, path));
        var signed = await enclave.SignAsync(keyAlias, payload, ct).ConfigureAwait(false);
        if (signed.IsFailure)
        {
            return Result.Failure<PollSignatureHeaders>(signed.Error);
        }
        var sigB64u = Convert.ToBase64String(signed.Value)
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');
        return Result.Success(new PollSignatureHeaders(sigB64u, ts));
    }
}

/// <summary>
/// The signed-poll header pair: base64url signature + the unix-seconds
/// timestamp that is bound inside the signed payload. Attach as
/// <see cref="PollSigning.SignatureHeader"/> /
/// <see cref="PollSigning.TimestampHeader"/>.
/// </summary>
public sealed record PollSignatureHeaders(string SignatureB64u, long TsUnix);
