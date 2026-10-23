using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Recto.Shared.Common;
using Recto.Shared.Protocol.V04;

namespace Recto.Shared.Services;

/// <summary>
/// Builds and signs Recto capability JWTs without going through
/// <c>System.IdentityModel.Tokens.Jwt</c>'s <c>SignatureProvider</c> seam &mdash;
/// the JWT format is just <c>base64url(header).base64url(claims).base64url(signature)</c>,
/// and the signature step delegates straight to <see cref="IEnclaveKeyService.SignAsync"/>
/// (which already produces the right wire format: 64 bytes raw for both
/// Ed25519 and ECDSA P-256 raw R||S, exactly what JWS expects for EdDSA / ES256).
/// </summary>
public static class CapabilityJwtBuilder
{
    /// <summary>
    /// Computes the phone-public-key fingerprint used as the JWT <c>iss</c>
    /// claim. SHA-256 of the raw public-key bytes, base64url-encoded
    /// (no padding). Self-verifying: anyone with the JWT and the phone's
    /// public key can recompute the fingerprint and confirm match.
    /// </summary>
    public static string Fingerprint(byte[] publicKey)
    {
        var hash = SHA256.HashData(publicKey);
        return Base64UrlEncode(hash);
    }

    /// <summary>
    /// Builds a signed capability JWT. <paramref name="enclave"/> handles
    /// the actual signature; the algorithm (Ed25519 or ECDSA P-256) is
    /// derived from <see cref="IEnclaveKeyService.Algorithm"/> and translated
    /// to the JWS <c>alg</c> name (EdDSA / ES256).
    /// </summary>
    public static async Task<Result<string>> BuildAsync(
        IEnclaveKeyService enclave,
        string keyAlias,
        CapabilityJwtClaims claims,
        CancellationToken ct)
    {
        try
        {
            string jwsAlg = enclave.Algorithm switch
            {
                V04Protocol.AlgorithmEd25519 => "EdDSA",
                V04Protocol.AlgorithmEcdsaP256 => "ES256",
                _ => throw new InvalidOperationException(
                    $"No JWS alg mapping for enclave algorithm '{enclave.Algorithm}'."),
            };

            var headerJson = JsonSerializer.Serialize(new JwtHeader(jwsAlg, "JWT"));
            var headerB64 = Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));

            var claimsJson = JsonSerializer.Serialize(claims);
            var claimsB64 = Base64UrlEncode(Encoding.UTF8.GetBytes(claimsJson));

            var signingInput = $"{headerB64}.{claimsB64}";
            var signResult = await enclave.SignAsync(
                keyAlias,
                Encoding.UTF8.GetBytes(signingInput),
                ct).ConfigureAwait(false);

            if (signResult.IsFailure)
            {
                return Result.Failure<string>(signResult.Error);
            }

            var signatureB64 = Base64UrlEncode(signResult.Value);
            return Result.Success($"{signingInput}.{signatureB64}");
        }
        catch (Exception ex)
        {
            return Result.Failure<string>(Error.Failure(
                $"JWT build failed: {ex.GetType().Name}: {ex.Message}"));
        }
    }

    private static string Base64UrlEncode(byte[] data)
    {
        var b64 = Convert.ToBase64String(data);
        return b64.TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    /// <summary>JWT header. Order matters for the signing input determinism, so
    /// keep alg first and typ second &mdash; matches what most JWT libraries emit.</summary>
    private sealed record JwtHeader(
        [property: System.Text.Json.Serialization.JsonPropertyName("alg")] string Alg,
        [property: System.Text.Json.Serialization.JsonPropertyName("typ")] string Typ);
}
