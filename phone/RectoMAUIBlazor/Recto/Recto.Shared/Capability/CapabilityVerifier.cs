using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Recto.Shared.Services;

namespace Recto.Shared.Capability;

// ---------------------------------------------------------------------------
// Capability JWS (JSON Web Signature) — parse / verify / build / assemble.
// Mirror of recto.capability.jwt in Python.
// ---------------------------------------------------------------------------
//
// Algorithm: ES256K (RFC 8812) — secp256k1 ECDSA with SHA-256 over the
// JWS signing input. The same primitive Wave 6 introduced for ETH /
// EIP-191 / EIP-712; the operator's BIP-39-derived secp256k1 key
// already lives in the phone enclave from Wave 7's iPhone deploy. No new
// cryptographic dependencies; secp256k1 math comes from EthSigningOps
// (BouncyCastle-backed).
//
// Production minting always happens phone-side via the Secure Enclave with
// biometric gating &mdash; this file is verify-side. The host-side helpers
// (BuildSigningInput / AssembleJws) exist for the phone build flow where
// the host constructs the signing input, hands it to the enclave for
// signing, and then assembles the final JWS string.

/// <summary>
/// Result of verifying a capability JWS. <see cref="Success"/> is true if
/// every validation step passed; <see cref="Claims"/> carries the parsed
/// claims on success. <see cref="Error"/> carries a category-prefixed
/// failure message on failure (<c>shape:</c> / <c>signature:</c> /
/// <c>claims:</c>) so callers can distinguish failure modes.
/// </summary>
public sealed record CapabilityVerificationResult(
    bool Success,
    CapabilityClaims? Claims,
    string? Error)
{
    public static CapabilityVerificationResult Ok(CapabilityClaims claims)
        => new(true, claims, null);

    public static CapabilityVerificationResult Fail(string error)
        => new(false, null, error);
}

/// <summary>
/// Verifier for capability JWTs. Verifies signatures against a known
/// expected operator public key.
/// </summary>
public interface ICapabilityVerifier
{
    /// <summary>
    /// Verify a capability JWS and return the parsed claims on success.
    /// <para>
    /// Validation steps (all must pass):
    /// <list type="number">
    /// <item>JWS structure is well-formed</item>
    /// <item>Header declares <c>alg: ES256K</c> and <c>typ: JWT</c>
    /// (or omits typ)</item>
    /// <item>Signature recovers to the expected operator public key</item>
    /// <item>Standard claims time bounds (nbf &le; now &lt; exp)</item>
    /// <item>If <paramref name="expectedAud"/> is provided, verify it
    /// appears in <c>claims.aud</c></item>
    /// </list>
    /// </para>
    /// <para>
    /// Note: this method does NOT consult the revocation list. Callers
    /// are responsible for checking <c>jti</c> against revocation state
    /// before accepting the capability for use.
    /// </para>
    /// </summary>
    /// <param name="token">The JWS string to verify.</param>
    /// <param name="expectedAud">Optional &mdash; if provided, the
    /// audience claim must contain this value.</param>
    /// <param name="now">Optional unix-seconds "now" override for testing
    /// time-bounds logic. Defaults to <see cref="DateTimeOffset.UtcNow"/>
    /// when null.</param>
    CapabilityVerificationResult VerifyJws(
        string token,
        string? expectedAud = null,
        long? now = null);
}

/// <summary>
/// Result of looking up a profile by its <c>profile_id</c> for the
/// Phase 2.0.C wave C.2 <c>parent_profile</c> verifier extension.
/// Returned by <see cref="IProfileLookup.GetProfile"/>. Null result
/// (the lookup itself returning null) means the profile is not known
/// to the verifier's master &mdash; a distinct case from a known-but-
/// revoked profile (which returns a populated result with
/// <c>Revoked=true</c>).
/// </summary>
public sealed record ProfileLookupResult(
    string? DerivedPubkeyHex,
    bool Revoked,
    IReadOnlyList<string> DenyActionsInherited);

/// <summary>
/// Resolver interface for the Phase 2.0.C wave C.2 <c>parent_profile</c>
/// dispatch path. Consumers (downstream apps verifying capability JWSes)
/// supply an implementation that maps a <c>profile_id</c> claim to the
/// profile's stored state (derived pubkey hex, revoked flag, SCIM-pushed
/// deny-action set). The bootloader's own verifier uses a direct
/// <c>master_identity.json</c>-reading implementation; consumer apps
/// typically wire a cached-HTTP-fetch implementation pointing at their
/// bootloader's identity-query endpoint.
/// <para>
/// When <see cref="Es256kCapabilityVerifier"/> is constructed WITHOUT
/// an <see cref="IProfileLookup"/>, JWSes carrying a non-null
/// <c>parent_profile</c> claim fail verification with a clear
/// "verifier not configured for parent_profile" error &mdash; the
/// equivalent of Python <c>verify_jws</c>'s "state_dir kwarg was not
/// supplied" path.
/// </para>
/// </summary>
public interface IProfileLookup
{
    /// <summary>
    /// Look up a profile by its opaque <c>profile_id</c>. Returns null
    /// when the profile is not known to this verifier's master;
    /// returns a populated result with <c>Revoked=true</c> when the
    /// profile is known but revoked.
    /// </summary>
    ProfileLookupResult? GetProfile(string profileId);
}

/// <summary>
/// ES256K (secp256k1) implementation of <see cref="ICapabilityVerifier"/>
/// using the existing <see cref="EthSigningOps"/> primitives for
/// signature recovery. Bound to a single expected operator public key
/// at construction.
/// </summary>
public sealed class Es256kCapabilityVerifier : ICapabilityVerifier
{
    private readonly byte[] _expectedPubkey;
    private readonly IProfileLookup? _profileLookup;

    /// <param name="expectedPubkey">64-byte uncompressed secp256k1 public
    /// key (X || Y, no <c>0x04</c> prefix &mdash; the format
    /// <see cref="EthSigningOps.PublicKeyFromPrivate"/> emits).</param>
    public Es256kCapabilityVerifier(byte[] expectedPubkey)
        : this(expectedPubkey, profileLookup: null)
    {
    }

    /// <summary>
    /// Constructor with optional <see cref="IProfileLookup"/> resolver
    /// for the Phase 2.0.C wave C.2 <c>parent_profile</c> dispatch
    /// path. When supplied, JWSes carrying a non-null
    /// <c>parent_profile</c> claim resolve to the named profile's
    /// derived pubkey and recover signature against THAT pubkey
    /// (NOT the master operator pubkey).
    /// </summary>
    /// <param name="expectedPubkey">64-byte uncompressed secp256k1
    /// operator master pubkey (used when <c>parent_profile</c> is
    /// null or missing &mdash; the v1.x / v2.0.B path).</param>
    /// <param name="profileLookup">Optional resolver for
    /// <c>parent_profile</c> dispatch. When null, JWSes with
    /// <c>parent_profile</c> set fail with a clear configuration
    /// error.</param>
    public Es256kCapabilityVerifier(
        byte[] expectedPubkey,
        IProfileLookup? profileLookup)
    {
        if (expectedPubkey is null || expectedPubkey.Length != 64)
        {
            throw new ArgumentException(
                "Expected public key must be 64 bytes (uncompressed X||Y).",
                nameof(expectedPubkey));
        }
        _expectedPubkey = (byte[])expectedPubkey.Clone();
        _profileLookup = profileLookup;
    }

    public CapabilityVerificationResult VerifyJws(
        string token,
        string? expectedAud = null,
        long? now = null)
    {
        // 1. Parse
        JwsParts parts;
        try
        {
            parts = CapabilityJws.ParseJws(token);
        }
        catch (Exception ex)
        {
            return CapabilityVerificationResult.Fail(
                $"shape: {ex.Message}");
        }

        // 2. Header validation
        if (!parts.HeaderRoot.TryGetProperty("alg", out var algElem)
            || algElem.ValueKind != JsonValueKind.String
            || algElem.GetString() != "ES256K")
        {
            var algStr = parts.HeaderRoot.TryGetProperty("alg", out var a)
                ? a.ToString() : "<missing>";
            return CapabilityVerificationResult.Fail(
                $"shape: unsupported alg '{algStr}' (expected ES256K)");
        }
        if (parts.HeaderRoot.TryGetProperty("typ", out var typElem))
        {
            if (typElem.ValueKind != JsonValueKind.String
                || typElem.GetString() != "JWT")
            {
                return CapabilityVerificationResult.Fail(
                    $"shape: unsupported typ '{typElem.ToString()}'");
            }
        }

        // 3. Signature validation
        if (parts.Signature.Length != 64)
        {
            return CapabilityVerificationResult.Fail(
                $"signature: expected 64-byte raw r||s, got "
                + $"{parts.Signature.Length} bytes");
        }
        var digest = SHA256.HashData(parts.SigningInput);

        // Phase 2.0.C wave C.2: parent_profile dispatch. When the JWS
        // payload has a non-null parent_profile claim, the JWS was
        // minted under a child profile's derived secp256k1 key (NOT
        // the operator's master root). Look up the profile via the
        // injected IProfileLookup and use ITS DerivedPubkeyHex as the
        // recovery target. Mirrors Python verify_jws's parent_profile
        // branch (recto/capability/jwt.py).
        string? parentProfileClaim = null;
        if (parts.PayloadRoot.TryGetProperty("parent_profile", out var ppElem)
            && ppElem.ValueKind == JsonValueKind.String)
        {
            parentProfileClaim = ppElem.GetString();
            if (string.IsNullOrEmpty(parentProfileClaim))
            {
                parentProfileClaim = null;
            }
        }

        byte[] targetPubkey;
        if (parentProfileClaim is null)
        {
            // v1.x / v2.0.B path -- recover against operator master root.
            targetPubkey = _expectedPubkey;
        }
        else
        {
            if (_profileLookup is null)
            {
                return CapabilityVerificationResult.Fail(
                    $"claims: JWS has parent_profile claim "
                    + $"'{parentProfileClaim}' but no IProfileLookup was "
                    + "supplied to the verifier at construction; verifier "
                    + "cannot resolve profile derived_pubkey_hex. Pass an "
                    + "IProfileLookup to Es256kCapabilityVerifier's "
                    + "constructor to enable parent_profile dispatch.");
            }
            ProfileLookupResult? lookupResult;
            try
            {
                lookupResult = _profileLookup.GetProfile(parentProfileClaim);
            }
            catch (Exception ex)
            {
                return CapabilityVerificationResult.Fail(
                    $"claims: parent_profile '{parentProfileClaim}' lookup "
                    + $"failed: {ex.Message}");
            }
            if (lookupResult is null)
            {
                return CapabilityVerificationResult.Fail(
                    $"claims: parent_profile '{parentProfileClaim}' not "
                    + "found under master (IProfileLookup returned null)");
            }
            if (lookupResult.Revoked)
            {
                return CapabilityVerificationResult.Fail(
                    $"claims: parent_profile '{parentProfileClaim}' is "
                    + "revoked");
            }
            if (string.IsNullOrEmpty(lookupResult.DerivedPubkeyHex))
            {
                return CapabilityVerificationResult.Fail(
                    $"claims: parent_profile '{parentProfileClaim}' has "
                    + "no derived_pubkey_hex (v2.0.B-era row created "
                    + "before Phase 2.0.C wave C.1's schema bump). Run "
                    + "the future `recto profile derive-pubkey` admin "
                    + "command to opt-in backfill.");
            }
            // Normalize hex (strip optional 0x / 0x04 prefix) before
            // parsing -- matches Python verify_jws's tolerance.
            var cleaned = lookupResult.DerivedPubkeyHex.Trim().ToLowerInvariant();
            if (cleaned.StartsWith("0x"))
            {
                cleaned = cleaned.Substring(2);
            }
            if (cleaned.StartsWith("04") && cleaned.Length == 130)
            {
                cleaned = cleaned.Substring(2);
            }
            if (cleaned.Length != 128)
            {
                return CapabilityVerificationResult.Fail(
                    $"claims: parent_profile '{parentProfileClaim}' has "
                    + "malformed derived_pubkey_hex (must be 128 hex "
                    + $"chars after optional prefix strip; got {cleaned.Length})");
            }
            try
            {
                targetPubkey = HexToBytes(cleaned);
            }
            catch (Exception ex)
            {
                return CapabilityVerificationResult.Fail(
                    $"claims: parent_profile '{parentProfileClaim}' "
                    + $"derived_pubkey_hex parse failed: {ex.Message}");
            }
        }

        bool matched = false;
        // Try both rec_id candidates by constructing a synthetic 65-byte
        // r||s||v signature with v = 27 + rec_id. EthSigningOps.RecoverPublicKey
        // takes the same legacy v convention. Mirrors recto.ethereum's
        // recover_public_key surface verbatim.
        for (int recId = 0; recId < 2; recId++)
        {
            var rsv = new byte[65];
            Buffer.BlockCopy(parts.Signature, 0, rsv, 0, 64);
            rsv[64] = (byte)(27 + recId);
            byte[]? recovered;
            try
            {
                recovered = EthSigningOps.RecoverPublicKey(digest, rsv);
            }
            catch
            {
                continue;
            }
            if (recovered is not null && BytesEqual(recovered, targetPubkey))
            {
                matched = true;
                break;
            }
        }
        if (!matched)
        {
            if (parentProfileClaim is null)
            {
                return CapabilityVerificationResult.Fail(
                    "signature: did not recover to expected operator public key");
            }
            return CapabilityVerificationResult.Fail(
                $"signature: did not recover to parent_profile "
                + $"'{parentProfileClaim}' derived_pubkey_hex");
        }

        // 4. Time bounds
        long currentNow = now
            ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        long nbf = ReadLongClaim(parts.PayloadRoot, "nbf", 0);
        long exp = ReadLongClaim(parts.PayloadRoot, "exp", 0);
        if (currentNow < nbf)
        {
            return CapabilityVerificationResult.Fail(
                $"claims: token nbf={nbf} is in the future (now={currentNow})");
        }
        if (currentNow >= exp)
        {
            return CapabilityVerificationResult.Fail(
                $"claims: token exp={exp} has passed (now={currentNow})");
        }

        // 5. Audience check (if requested)
        if (expectedAud is not null)
        {
            if (!parts.PayloadRoot.TryGetProperty("aud", out var audElem)
                || audElem.ValueKind != JsonValueKind.Array)
            {
                return CapabilityVerificationResult.Fail(
                    $"claims: expected_aud '{expectedAud}' check failed; "
                    + "aud is missing or not an array");
            }
            bool found = false;
            foreach (var item in audElem.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.String
                    && item.GetString() == expectedAud)
                {
                    found = true;
                    break;
                }
            }
            if (!found)
            {
                return CapabilityVerificationResult.Fail(
                    $"claims: expected_aud '{expectedAud}' not in token aud");
            }
        }

        // 6. Convert to typed claims
        CapabilityClaims claims;
        try
        {
            claims = CapabilityJws.PayloadToClaims(parts.PayloadRoot);
        }
        catch (Exception ex)
        {
            return CapabilityVerificationResult.Fail(
                $"claims: {ex.Message}");
        }

        return CapabilityVerificationResult.Ok(claims);
    }

    private static long ReadLongClaim(JsonElement payload, string name, long defaultValue)
    {
        if (!payload.TryGetProperty(name, out var elem)) return defaultValue;
        if (elem.ValueKind == JsonValueKind.Number
            && elem.TryGetInt64(out var n)) return n;
        if (elem.ValueKind == JsonValueKind.String
            && long.TryParse(elem.GetString(), out var s)) return s;
        return defaultValue;
    }

    private static byte[] HexToBytes(string hex)
    {
        if (hex.Length % 2 != 0)
        {
            throw new FormatException(
                $"hex string length must be even (got {hex.Length})");
        }
        var bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        }
        return bytes;
    }

    private static bool BytesEqual(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return false;
        for (int i = 0; i < a.Length; i++)
        {
            if (a[i] != b[i]) return false;
        }
        return true;
    }
}

/// <summary>
/// Parsed components of a JWS token. Returned by
/// <see cref="CapabilityJws.ParseJws"/>.
/// </summary>
public sealed record JwsParts(
    JsonElement HeaderRoot,
    JsonElement PayloadRoot,
    byte[] Signature,
    byte[] SigningInput);

/// <summary>
/// JWS (JSON Web Signature) parsing, signing-input construction, and
/// final-token assembly helpers. Pure shape ops &mdash; no key material
/// required, no signature creation. Mint flows live phone-side
/// (Wave B) through the Secure Enclave.
/// <para>
/// Mirrors recto.capability.jwt's <c>parse_jws</c> /
/// <c>build_signing_input</c> / <c>assemble_jws</c> functions.
/// </para>
/// </summary>
public static class CapabilityJws
{
    /// <summary>
    /// Split a JWS token into header / payload / signature bytes plus
    /// the signing input bytes (<c>header_b64.payload_b64</c>).
    /// <para>
    /// Throws <see cref="FormatException"/> on malformed input
    /// (wrong number of dot-separated parts, invalid base64url).
    /// </para>
    /// </summary>
    public static JwsParts ParseJws(string token)
    {
        if (token is null) throw new ArgumentNullException(nameof(token));
        var parts = token.Split('.');
        if (parts.Length != 3)
        {
            throw new FormatException(
                $"Malformed JWS: expected 3 dot-separated parts, "
                + $"got {parts.Length}");
        }
        var headerB64 = parts[0];
        var payloadB64 = parts[1];
        var sigB64 = parts[2];

        byte[] headerBytes;
        byte[] payloadBytes;
        byte[] signatureBytes;
        try
        {
            headerBytes = Base64UrlDecode(headerB64);
            payloadBytes = Base64UrlDecode(payloadB64);
            signatureBytes = Base64UrlDecode(sigB64);
        }
        catch (FormatException ex)
        {
            throw new FormatException($"Malformed JWS: {ex.Message}", ex);
        }

        // Parse the JSON. We allocate JsonDocument here and clone the
        // root JsonElement so the document can be safely disposed; clones
        // are detached and remain valid past the using-block.
        JsonElement headerRoot;
        JsonElement payloadRoot;
        try
        {
            using var headerDoc = JsonDocument.Parse(headerBytes);
            using var payloadDoc = JsonDocument.Parse(payloadBytes);
            headerRoot = headerDoc.RootElement.Clone();
            payloadRoot = payloadDoc.RootElement.Clone();
        }
        catch (JsonException ex)
        {
            throw new FormatException(
                $"Malformed JWS: JSON parse failed: {ex.Message}", ex);
        }

        var signingInput = Encoding.ASCII.GetBytes(
            $"{headerB64}.{payloadB64}");

        return new JwsParts(headerRoot, payloadRoot, signatureBytes, signingInput);
    }

    /// <summary>
    /// Build the unsigned signing input for a capability JWT.
    /// <para>
    /// Returns the SHA-256 digest the signer signs over, plus the
    /// base64url-encoded header and payload segments. The phone-side
    /// mint flow (Wave B) feeds the digest to the Secure Enclave for
    /// signing, then assembles the final JWS via
    /// <see cref="AssembleJws"/>.
    /// </para>
    /// </summary>
    public static (byte[] Digest, string HeaderB64, string PayloadB64)
        BuildSigningInput(CapabilityClaims claims)
    {
        var headerDict = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["alg"] = "ES256K",
            ["typ"] = "JWT",
        };
        var headerBytes = CanonicalJson.Encode(headerDict);
        var headerB64 = Base64UrlEncode(headerBytes);

        var payloadDict = ClaimsToCanonicalDict(claims);
        var payloadBytes = CanonicalJson.Encode(payloadDict);
        var payloadB64 = Base64UrlEncode(payloadBytes);

        var signingInput = Encoding.ASCII.GetBytes(
            $"{headerB64}.{payloadB64}");
        var digest = SHA256.HashData(signingInput);
        return (digest, headerB64, payloadB64);
    }

    /// <summary>
    /// Assemble the final JWS string from already-encoded header / payload
    /// segments and a 64-byte raw <c>r||s</c> signature.
    /// <para>
    /// Useful for the phone-side mint flow (Wave B) where the Secure
    /// Enclave produces the signature and the host assembles the JWS.
    /// </para>
    /// <para>
    /// Throws <see cref="ArgumentException"/> if the signature is not
    /// exactly 64 bytes.
    /// </para>
    /// </summary>
    public static string AssembleJws(
        string headerB64, string payloadB64, byte[] signature)
    {
        if (signature is null || signature.Length != 64)
        {
            throw new ArgumentException(
                $"signature must be 64 raw bytes (r||s); got "
                + $"{signature?.Length ?? 0}",
                nameof(signature));
        }
        return $"{headerB64}.{payloadB64}.{Base64UrlEncode(signature)}";
    }

    /// <summary>
    /// Convert a parsed JWS payload <see cref="JsonElement"/> into a
    /// strongly-typed <see cref="CapabilityClaims"/>. Used by the verifier
    /// after signature validation succeeds. Throws
    /// <see cref="InvalidDataException"/> on missing required claims or
    /// shape problems.
    /// </summary>
    public static CapabilityClaims PayloadToClaims(JsonElement payload)
    {
        var required = new[] { "iss", "sub", "aud", "iat", "nbf", "exp", "jti", "cap", "purpose" };
        var missing = new List<string>();
        foreach (var field in required)
        {
            if (!payload.TryGetProperty(field, out _))
            {
                missing.Add(field);
            }
        }
        if (missing.Count > 0)
        {
            missing.Sort(StringComparer.Ordinal);
            throw new System.IO.InvalidDataException(
                $"Capability JWT missing required claims: [{string.Join(", ", missing)}]");
        }

        var iss = payload.GetProperty("iss").GetString()!;
        var sub = payload.GetProperty("sub").GetString()!;

        var audList = new List<string>();
        foreach (var item in payload.GetProperty("aud").EnumerateArray())
        {
            audList.Add(item.GetString()!);
        }

        var iat = payload.GetProperty("iat").GetInt64();
        var nbf = payload.GetProperty("nbf").GetInt64();
        var exp = payload.GetProperty("exp").GetInt64();
        var jti = payload.GetProperty("jti").GetString()!;
        var purpose = payload.GetProperty("purpose").GetString()!;

        // cap subobject
        var capElem = payload.GetProperty("cap");
        var clause = ParseClause(capElem);

        string? parentCap = null;
        if (payload.TryGetProperty("parent_cap", out var parentElem)
            && parentElem.ValueKind == JsonValueKind.String)
        {
            parentCap = parentElem.GetString();
        }

        long? maxUses = null;
        if (payload.TryGetProperty("max_uses", out var maxElem)
            && maxElem.ValueKind == JsonValueKind.Number
            && maxElem.TryGetInt64(out var mu))
        {
            maxUses = mu;
        }

        // Phase 2.0.C wave C.2: parent_profile is an optional v2.0
        // claim. Reader tolerates absence (defaults to null -- v1.x /
        // v2.0.B path); reader picks it up when present (v2.0.C-and-
        // later mints).
        string? parentProfile = null;
        if (payload.TryGetProperty("parent_profile", out var ppElem)
            && ppElem.ValueKind == JsonValueKind.String)
        {
            parentProfile = ppElem.GetString();
        }

        return new CapabilityClaims(
            Iss: iss,
            Sub: sub,
            Aud: audList,
            Iat: iat,
            Nbf: nbf,
            Exp: exp,
            Jti: jti,
            Cap: clause,
            Purpose: purpose,
            ParentCap: parentCap,
            MaxUses: maxUses,
            ParentProfile: parentProfile);
    }

    private static CapabilityClause ParseClause(JsonElement cap)
    {
        var tier = cap.GetProperty("tier").GetInt32();
        var registryVersion = cap.GetProperty("registry_version").GetString()!;

        var groups = ReadStringList(cap, "groups");
        var allow = ReadStringList(cap, "allow_actions");
        var deny = ReadStringList(cap, "deny_actions");

        var scope = CapabilityScope.Empty;
        if (cap.TryGetProperty("scope", out var scopeElem)
            && scopeElem.ValueKind == JsonValueKind.Object)
        {
            scope = new CapabilityScope(
                Env: ReadStringList(scopeElem, "env"),
                Services: ReadStringList(scopeElem, "services"),
                Repos: ReadStringList(scopeElem, "repos"));
        }

        var limits = CapabilityLimits.Empty;
        if (cap.TryGetProperty("limits", out var limitsElem)
            && limitsElem.ValueKind == JsonValueKind.Object)
        {
            limits = new CapabilityLimits(
                PerHour: ReadStringLongDict(limitsElem, "per_hour"),
                PerDay: ReadStringLongDict(limitsElem, "per_day"),
                PerSession: ReadStringLongDict(limitsElem, "per_session"));
        }

        return new CapabilityClause(
            Tier: tier,
            RegistryVersion: registryVersion,
            Groups: groups,
            Scope: scope,
            AllowActions: allow,
            DenyActions: deny,
            Limits: limits);
    }

    private static IReadOnlyList<string> ReadStringList(JsonElement parent, string name)
    {
        if (!parent.TryGetProperty(name, out var elem)
            || elem.ValueKind != JsonValueKind.Array)
        {
            return Array.Empty<string>();
        }
        var list = new List<string>();
        foreach (var item in elem.EnumerateArray())
        {
            if (item.ValueKind == JsonValueKind.String)
            {
                list.Add(item.GetString()!);
            }
        }
        return list;
    }

    private static IReadOnlyDictionary<string, long> ReadStringLongDict(
        JsonElement parent, string name)
    {
        if (!parent.TryGetProperty(name, out var elem)
            || elem.ValueKind != JsonValueKind.Object)
        {
            return new Dictionary<string, long>();
        }
        var dict = new Dictionary<string, long>(StringComparer.Ordinal);
        foreach (var prop in elem.EnumerateObject())
        {
            if (prop.Value.ValueKind == JsonValueKind.Number
                && prop.Value.TryGetInt64(out var v))
            {
                dict[prop.Name] = v;
            }
        }
        return dict;
    }

    /// <summary>
    /// Convert a <see cref="CapabilityClaims"/> into the canonical
    /// dictionary that gets fed to <see cref="CanonicalJson.Encode"/>.
    /// Mirrors Python's <c>_claims_to_dict</c> &mdash; in particular,
    /// <c>parent_cap</c>, <c>max_uses</c>, and <c>parent_profile</c>
    /// are omitted when null so the canonical signing input matches
    /// Python's byte-for-byte AND so existing v1.x JWS signatures
    /// continue to verify (the v2.0 forward-compat reservation for
    /// <c>parent_profile</c> must NOT change the signing-input bytes
    /// when the field is left absent at v1.x).
    /// </summary>
    internal static IReadOnlyDictionary<string, object?> ClaimsToCanonicalDict(
        CapabilityClaims claims)
    {
        var dict = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["iss"] = claims.Iss,
            ["sub"] = claims.Sub,
            ["aud"] = claims.Aud,
            ["iat"] = claims.Iat,
            ["nbf"] = claims.Nbf,
            ["exp"] = claims.Exp,
            ["jti"] = claims.Jti,
            ["cap"] = ClauseToCanonicalDict(claims.Cap),
            ["purpose"] = claims.Purpose,
        };
        if (claims.ParentCap is not null) dict["parent_cap"] = claims.ParentCap;
        if (claims.MaxUses is not null) dict["max_uses"] = claims.MaxUses.Value;
        if (claims.ParentProfile is not null) dict["parent_profile"] = claims.ParentProfile;
        return dict;
    }

    private static IReadOnlyDictionary<string, object?> ClauseToCanonicalDict(
        CapabilityClause clause)
    {
        return new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["tier"] = (long)clause.Tier,
            ["registry_version"] = clause.RegistryVersion,
            ["groups"] = clause.Groups,
            ["scope"] = ScopeToCanonicalDict(clause.Scope),
            ["allow_actions"] = clause.AllowActions,
            ["deny_actions"] = clause.DenyActions,
            ["limits"] = LimitsToCanonicalDict(clause.Limits),
        };
    }

    private static IReadOnlyDictionary<string, object?> ScopeToCanonicalDict(
        CapabilityScope scope)
    {
        return new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["env"] = scope.Env,
            ["services"] = scope.Services,
            ["repos"] = scope.Repos,
        };
    }

    private static IReadOnlyDictionary<string, object?> LimitsToCanonicalDict(
        CapabilityLimits limits)
    {
        return new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["per_hour"] = LongDictToObjDict(limits.PerHour),
            ["per_day"] = LongDictToObjDict(limits.PerDay),
            ["per_session"] = LongDictToObjDict(limits.PerSession),
        };
    }

    private static IReadOnlyDictionary<string, object?> LongDictToObjDict(
        IReadOnlyDictionary<string, long> source)
    {
        var dict = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (var kv in source)
        {
            dict[kv.Key] = kv.Value;
        }
        return dict;
    }

    // ---------------------------------------------------------------
    // Base64url helpers (RFC 7515 §2 — no padding, '+'/'/' substitutes)
    // ---------------------------------------------------------------

    public static string Base64UrlEncode(byte[] data)
    {
        var b64 = Convert.ToBase64String(data);
        return b64.TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    public static byte[] Base64UrlDecode(string s)
    {
        // Restore standard base64 alphabet + padding
        var swapped = s.Replace('-', '+').Replace('_', '/');
        var pad = (4 - (swapped.Length % 4)) % 4;
        if (pad > 0) swapped += new string('=', pad);
        return Convert.FromBase64String(swapped);
    }
}
