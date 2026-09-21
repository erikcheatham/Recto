using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Recto.Shared.Common;

namespace Recto.Shared.Services;

/// <summary>
/// Phone-side construction of a WebAuthn assertion (FIDO2 / RFC 8809). The
/// bootloader stands in as the authenticator from the relying-party web
/// app's perspective; the phone produces the actual cryptographic material:
/// <list type="bullet">
/// <item><c>clientDataJSON</c> &mdash; UTF-8-encoded JSON object with
/// <c>type: "webauthn.get"</c>, the RP-supplied <c>challenge</c> (b64url),
/// and the calling page's <c>origin</c>.</item>
/// <item><c>authenticatorData</c> &mdash; 37 bytes: 32-byte SHA-256 of the
/// RP ID + 1 flags byte + 4-byte big-endian counter. We always set the UP
/// (user present) and UV (user verified) flags since the phone gates the
/// signing on a per-use BiometricPrompt.</item>
/// <item>The signature over <c>authenticatorData || sha256(clientDataJSON)</c>
/// produced by the phone's enclave key.</item>
/// </list>
/// Wire format: returns the three byte-blobs as base64url strings ready to
/// drop into <c>RespondRequest.WebAuthnClientDataB64u</c>,
/// <c>WebAuthnAuthenticatorDataB64u</c>, and <c>SignatureB64u</c>.
/// </summary>
public static class WebAuthnAssertionBuilder
{
    /// <summary>UP (User Present) flag bit per WebAuthn spec section 6.1.</summary>
    public const byte FlagUserPresent = 0x01;

    /// <summary>UV (User Verified) flag bit per WebAuthn spec section 6.1.</summary>
    public const byte FlagUserVerified = 0x04;

    /// <summary>
    /// Builds, signs, and returns a WebAuthn-shaped assertion.
    /// </summary>
    /// <param name="enclave">Enclave service that performs the actual signing.</param>
    /// <param name="keyAlias">Phone's enclave key alias.</param>
    /// <param name="rpId">The relying-party ID (typically the RP web app's hostname).</param>
    /// <param name="origin">Origin of the calling page (e.g. <c>https://app.example.com</c>).</param>
    /// <param name="challengeB64u">The RP-supplied challenge in base64url-no-padding form (passed through verbatim into clientDataJSON).</param>
    /// <param name="counter">Authenticator signature counter. We don't track this in v0.4; pass 0 (RFC permits 0 if not maintained).</param>
    /// <param name="ct">Cancellation token threaded into the enclave sign call.</param>
    public static async Task<Result<Assertion>> BuildAsync(
        IEnclaveKeyService enclave,
        string keyAlias,
        string rpId,
        string origin,
        string challengeB64u,
        uint counter,
        CancellationToken ct)
    {
        try
        {
            var clientDataJson = BuildClientDataJson(challengeB64u, origin);
            var authenticatorData = BuildAuthenticatorData(rpId, counter);

            var clientDataHash = SHA256.HashData(clientDataJson);
            var signingInput = new byte[authenticatorData.Length + clientDataHash.Length];
            Buffer.BlockCopy(authenticatorData, 0, signingInput, 0, authenticatorData.Length);
            Buffer.BlockCopy(clientDataHash, 0, signingInput, authenticatorData.Length, clientDataHash.Length);

            var signResult = await enclave.SignAsync(keyAlias, signingInput, ct).ConfigureAwait(false);
            if (signResult.IsFailure)
            {
                return Result.Failure<Assertion>(signResult.Error);
            }

            return Result.Success(new Assertion(
                ClientDataB64u: Base64UrlEncode(clientDataJson),
                AuthenticatorDataB64u: Base64UrlEncode(authenticatorData),
                SignatureB64u: Base64UrlEncode(signResult.Value)));
        }
        catch (Exception ex)
        {
            return Result.Failure<Assertion>(Error.Failure(
                $"WebAuthn assertion build failed: {ex.GetType().Name}: {ex.Message}"));
        }
    }

    /// <summary>
    /// Builds the canonical clientDataJSON byte string. Property order
    /// matters because the relying party will hash these exact bytes during
    /// verification &mdash; if we re-order or re-format, the signature
    /// won't validate. WebAuthn spec section 5.8.1 specifies <c>type</c>,
    /// <c>challenge</c>, <c>origin</c>, <c>crossOrigin</c> in that order.
    /// </summary>
    public static byte[] BuildClientDataJson(string challengeB64u, string origin)
    {
        // Hand-write the JSON to keep property order deterministic. The
        // System.Text.Json default order is reliable for record types but
        // less so for object literals; explicit construction is safer.
        var sb = new StringBuilder(160);
        sb.Append("{\"type\":\"webauthn.get\",\"challenge\":");
        sb.Append(JsonSerializer.Serialize(challengeB64u));
        sb.Append(",\"origin\":");
        sb.Append(JsonSerializer.Serialize(origin));
        sb.Append(",\"crossOrigin\":false}");
        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    /// <summary>
    /// Builds the 37-byte authenticatorData blob. Layout:
    /// <list type="bullet">
    /// <item>Bytes 0..31 &mdash; SHA-256 of the RP ID (UTF-8).</item>
    /// <item>Byte 32 &mdash; flags. We set UP | UV since phone-side
    /// BiometricPrompt is a per-use user-verification gate.</item>
    /// <item>Bytes 33..36 &mdash; signature counter, big-endian uint32.</item>
    /// </list>
    /// Attested-credential-data and extensions sections are NOT included
    /// (those only appear in <c>create()</c> registration responses, not
    /// <c>get()</c> assertion responses; the assertion path always returns
    /// the minimal 37-byte form).
    /// </summary>
    public static byte[] BuildAuthenticatorData(string rpId, uint counter)
    {
        var rpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes(rpId));
        var data = new byte[37];
        Buffer.BlockCopy(rpIdHash, 0, data, 0, 32);
        data[32] = (byte)(FlagUserPresent | FlagUserVerified);
        data[33] = (byte)((counter >> 24) & 0xFF);
        data[34] = (byte)((counter >> 16) & 0xFF);
        data[35] = (byte)((counter >> 8) & 0xFF);
        data[36] = (byte)(counter & 0xFF);
        return data;
    }

    private static string Base64UrlEncode(byte[] data)
    {
        var b64 = Convert.ToBase64String(data);
        return b64.TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    /// <summary>
    /// The three components of a WebAuthn assertion that the phone returns
    /// to the bootloader for relay back to the relying party.
    /// </summary>
    public sealed record Assertion(
        string ClientDataB64u,
        string AuthenticatorDataB64u,
        string SignatureB64u);
}
