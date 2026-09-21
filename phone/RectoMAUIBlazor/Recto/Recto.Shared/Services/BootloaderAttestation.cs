using System;
using System.Security.Cryptography;
using System.Text.Json;
using Recto.Shared.Capability;
using Recto.Shared.Protocol.V04;

namespace Recto.Shared.Services;

/// <summary>
/// The server identity the phone trusts ABOVE TLS (2026-09-16).
/// <para>
/// Until this build the phone pinned the bootloader's TLS leaf (SPKI) at
/// pairing and refused any other certificate for the rest of the pairing's
/// life. Cloudflare reissued the edge certificate for the bootloader host on
/// its own schedule and every paired phone lost the bootloader below HTTP;
/// the only way back was a hand re-pair, and the pairing flow ran through
/// the same pinned branch so even that failed until the pin was cleared.
/// A leaf is the CA's lease, not our identity (the same lesson the feed
/// signer learned on 09-03 with Azure's three-day leaves).
/// </para>
/// <para>
/// Identity is the bootloader's OWN secp256k1 signing key: minted by us,
/// rotated by us, published on <c>/v0.4/health</c>, carried in the
/// registration response and pinned here at pairing. When the phone sees
/// the certificate chain drift, it sends a fresh nonce to
/// <c>GET /v0.4/attest</c> and accepts only an ES256K JWS by that key over
/// that nonce. Verified: re-pin the new SPKI and carry on. Not verified:
/// stop and tell the user to re-pair -- never adopt a key from the wire.
/// </para>
/// </summary>
public static class BootloaderAttestation
{
    public const string Action = "bootloader:attest";
    public const string PendingAction = "bootloader:pending";
    public const string Audience = "recto-phone";
    public const int NonceBytes = 32;

    public static string NewNonceB64u()
    {
        var nonce = new byte[NonceBytes];
        RandomNumberGenerator.Fill(nonce);
        return CapabilityJws.Base64UrlEncode(nonce);
    }

    /// <summary>
    /// Verifies an attest response against the key and id pinned at pairing.
    /// Every check is by name: a failure string says which invariant broke.
    /// </summary>
    /// <param name="response">What <c>/v0.4/attest</c> answered.</param>
    /// <param name="expectedPubkeyHex">The pinned signing pubkey (128 hex).</param>
    /// <param name="expectedBootloaderId">The pinned bootloader id.</param>
    /// <param name="nonceB64u">The nonce THIS phone sent.</param>
    /// <param name="now">Unix seconds; null = wall clock.</param>
    public static AttestationResult Verify(
        AttestResponse response,
        string? expectedPubkeyHex,
        string expectedBootloaderId,
        string nonceB64u,
        long? now = null)
    {
        if (response is null) return AttestationResult.Fail("shape: no response");
        if (string.IsNullOrEmpty(expectedPubkeyHex))
        {
            // A pairing made before this build (or against an unsigned
            // bootloader) holds no key to verify against. Refuse by name;
            // the caller offers a one-time re-pair. Never TOFU the key from
            // the response -- that is the attacker's easiest move.
            return AttestationResult.Fail("pin: no bootloader signing key pinned at pairing (re-pair once)");
        }
        if (!string.Equals(response.Nonce, nonceB64u, StringComparison.Ordinal))
        {
            return AttestationResult.Fail("nonce: response echoes a different nonce");
        }
        if (!string.Equals(response.BootloaderId, expectedBootloaderId, StringComparison.Ordinal))
        {
            return AttestationResult.Fail(
                $"identity: bootloader_id '{response.BootloaderId}' != pinned '{expectedBootloaderId}'");
        }

        byte[] pubkey;
        try
        {
            pubkey = Convert.FromHexString(expectedPubkeyHex);
        }
        catch (FormatException)
        {
            return AttestationResult.Fail("pin: pinned pubkey is not hex");
        }
        if (pubkey.Length != 64)
        {
            return AttestationResult.Fail($"pin: pinned pubkey is {pubkey.Length} bytes, expected 64");
        }

        var verifier = new Es256kCapabilityVerifier(pubkey, profileLookup: null);
        var verified = verifier.VerifyJws(response.AttestJws, expectedAud: Audience, now: now);
        if (!verified.Success || verified.Claims is null)
        {
            return AttestationResult.Fail($"signature: {verified.Error}");
        }
        var claims = verified.Claims;

        var expectedIss = $"bootloader:{expectedBootloaderId}";
        if (!string.Equals(claims.Iss, expectedIss, StringComparison.Ordinal))
        {
            return AttestationResult.Fail($"claims: iss '{claims.Iss}' != '{expectedIss}'");
        }
        if (claims.Cap.AllowActions.Count != 1
            || !string.Equals(claims.Cap.AllowActions[0], Action, StringComparison.Ordinal))
        {
            return AttestationResult.Fail("claims: allow_actions is not exactly [bootloader:attest]");
        }

        // The nonce binding lives in cap.scope.payload_sha256 (the phone's
        // typed CapabilityScope does not carry it -- read the raw payload).
        string? payloadSha;
        try
        {
            var parts = CapabilityJws.ParseJws(response.AttestJws);
            payloadSha = parts.PayloadRoot.TryGetProperty("cap", out var cap)
                && cap.TryGetProperty("scope", out var scope)
                && scope.TryGetProperty("payload_sha256", out var sha)
                && sha.ValueKind == JsonValueKind.String
                ? sha.GetString() : null;
        }
        catch (Exception ex)
        {
            return AttestationResult.Fail($"shape: {ex.Message}");
        }
        byte[] nonceBytes;
        try
        {
            nonceBytes = CapabilityJws.Base64UrlDecode(nonceB64u);
        }
        catch (FormatException)
        {
            return AttestationResult.Fail("nonce: not base64url");
        }
        var expectedSha = Convert.ToHexString(SHA256.HashData(nonceBytes)).ToLowerInvariant();
        if (!string.Equals(payloadSha, expectedSha, StringComparison.OrdinalIgnoreCase))
        {
            return AttestationResult.Fail("nonce: signature does not cover this nonce");
        }

        return AttestationResult.Ok();
    }

    /// <summary>
    /// SERVER-SIGNED CARDS (2026-09-16). Verifies the bootloader's envelope over a
    /// <c>/v0.4/pending</c> response: an ES256K JWS by the pinned key, iss =
    /// bootloader:&lt;pinned id&gt;, sub = phone:&lt;this phone&gt;, allow_actions =
    /// [bootloader:pending], cap.scope.payload_sha256 = SHA-256 of the exact
    /// <c>requests</c> text as received. Attest proves who the server is; this
    /// proves each CARD came from it -- an interposer that relays attest still
    /// cannot make a card render. The caller renders nothing on a failure.
    /// </summary>
    public static AttestationResult VerifyPendingEnvelope(
        PendingRequestsResponse response,
        string? expectedPubkeyHex,
        string expectedBootloaderId,
        string phoneId,
        long? now = null)
    {
        if (response is null) return AttestationResult.Fail("shape: no response");
        if (string.IsNullOrEmpty(expectedPubkeyHex))
        {
            return AttestationResult.Fail("pin: no bootloader signing key pinned at pairing (re-pair once)");
        }
        if (string.IsNullOrEmpty(response.PendingJws))
        {
            return AttestationResult.Fail("envelope: the bootloader sent unsigned cards (pending_jws missing)");
        }
        if (response.RequestsRawJson is null)
        {
            return AttestationResult.Fail("envelope: the raw requests text was not captured");
        }

        byte[] pubkey;
        try { pubkey = Convert.FromHexString(expectedPubkeyHex); }
        catch (FormatException) { return AttestationResult.Fail("pin: pinned pubkey is not hex"); }
        if (pubkey.Length != 64)
        {
            return AttestationResult.Fail($"pin: pinned pubkey is {pubkey.Length} bytes, expected 64");
        }

        var verifier = new Es256kCapabilityVerifier(pubkey, profileLookup: null);
        var verified = verifier.VerifyJws(response.PendingJws, expectedAud: Audience, now: now);
        if (!verified.Success || verified.Claims is null)
        {
            return AttestationResult.Fail($"signature: {verified.Error}");
        }
        var claims = verified.Claims;

        var expectedIss = $"bootloader:{expectedBootloaderId}";
        if (!string.Equals(claims.Iss, expectedIss, StringComparison.Ordinal))
        {
            return AttestationResult.Fail($"claims: iss '{claims.Iss}' != '{expectedIss}'");
        }
        var expectedSub = $"phone:{phoneId}";
        if (!string.Equals(claims.Sub, expectedSub, StringComparison.Ordinal))
        {
            return AttestationResult.Fail($"claims: sub '{claims.Sub}' != '{expectedSub}' (another phone's envelope)");
        }
        if (claims.Cap.AllowActions.Count != 1
            || !string.Equals(claims.Cap.AllowActions[0], PendingAction, StringComparison.Ordinal))
        {
            return AttestationResult.Fail("claims: allow_actions is not exactly [bootloader:pending]");
        }

        string? payloadSha;
        try
        {
            var parts = CapabilityJws.ParseJws(response.PendingJws);
            payloadSha = parts.PayloadRoot.TryGetProperty("cap", out var cap)
                && cap.TryGetProperty("scope", out var scope)
                && scope.TryGetProperty("payload_sha256", out var sha)
                && sha.ValueKind == JsonValueKind.String
                ? sha.GetString() : null;
        }
        catch (Exception ex)
        {
            return AttestationResult.Fail($"shape: {ex.Message}");
        }
        var actual = Convert.ToHexString(
            SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(response.RequestsRawJson))).ToLowerInvariant();
        if (!string.Equals(payloadSha, actual, StringComparison.OrdinalIgnoreCase))
        {
            return AttestationResult.Fail("envelope: the signature does not cover these cards");
        }

        return AttestationResult.Ok();
    }
}

public sealed record AttestationResult(bool Verified, string? Error)
{
    public static AttestationResult Ok() => new(true, null);
    public static AttestationResult Fail(string error) => new(false, error);
}
