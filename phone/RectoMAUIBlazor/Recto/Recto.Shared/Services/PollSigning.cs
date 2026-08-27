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
/// CALL-SITE CAUTION (why this ships as a helper + TODO map rather
/// than pre-wired): <see cref="IEnclaveKeyService.SignAsync"/> is
/// biometric-gated on hardware-enclave platforms (iOS Secure Enclave
/// <c>BiometryCurrentSet</c> ACL; Android
/// <c>setUserAuthenticationRequired</c>). Signing EVERY poll tick
/// would fire a biometric prompt per tick. Wiring therefore needs a
/// per-platform decision first: a second, non-biometric-gated poll
/// key (enclave-resident, no user-auth ACL &mdash; authenticates the
/// DEVICE, not the operator's presence), or platform-specific auth
/// validity windows. The software-backed dev paths (Windows / Mac
/// Catalyst) sign silently and can wire directly.
/// </para>
/// </summary>
public static class PollSigning
{
    /// <summary>Signing-input prefix; mirrors the server's POLL_SIG_PREFIX.</summary>
    public const string Prefix = "recto-poll-v1";

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
