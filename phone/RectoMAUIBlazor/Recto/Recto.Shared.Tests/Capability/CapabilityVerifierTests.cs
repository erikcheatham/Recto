using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using Recto.Shared.Capability;
using Recto.Shared.Services;
using Xunit;

namespace Recto.Shared.Tests.Capability;

/// <summary>
/// Pins the C# capability JWS layer against the Python implementation in
/// <c>recto/capability/jwt.py</c>. The canonical-byte pins below
/// (<see cref="BuildSigningInput_MatchesPythonCanonicalPayload"/> and
/// <see cref="BuildSigningInput_MatchesPythonCanonicalDigest"/>) are the
/// load-bearing cross-language interop tests &mdash; if these fail,
/// capability JWTs minted on one runtime will fail to verify on the
/// other. The pinned values were emitted by the Python build_signing_input
/// running on the same fixture (timestamp 2026-05-05, fixture name
/// <c>example_claims</c>).
///
/// The sign-then-verify round-trip
/// (<see cref="VerifyJws_RoundTripsWithEthSigningOps"/>) closes the
/// internal-consistency gap that <c>tests/test_capability.py</c> defers
/// to "Wave A continuation" &mdash; we have BouncyCastle's secp256k1
/// signing primitive available via
/// <see cref="EthSigningOps.SignWithRecovery"/>, and we use it to
/// produce a real signature for round-trip verification.
/// </summary>
public class CapabilityVerifierTests
{
    // -----------------------------------------------------------------
    // Cross-language byte-parity pins (load-bearing).
    // The Python output for the example_claims fixture is captured here
    // verbatim; if a C# encoding bug shifts the bytes, these tests fail
    // before any signature would silently mis-verify.
    // -----------------------------------------------------------------

    private const string ExpectedHeaderB64 =
        "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ";

    private const string ExpectedPayloadB64 =
        "eyJhdWQiOlsiY29uc3VtZXItYXBwIiwicmVjdG86dmF1bHQiXSwiY2FwIjp7ImFsbG93X2FjdGlvbnMiOltdLCJkZW55X2FjdGlvbnMiOltdLCJncm91cHMiOlsiZGFyd2luOmRvYy1lZGl0cyIsImRhcndpbjpzdGFnaW5nLWRlcGxveXMiXSwibGltaXRzIjp7InBlcl9kYXkiOnt9LCJwZXJfaG91ciI6eyJkZXBsb3k6c3RhZ2luZyI6NX0sInBlcl9zZXNzaW9uIjp7fX0sInJlZ2lzdHJ5X3ZlcnNpb24iOiIyMDI2LTA1LTA1Iiwic2NvcGUiOnsiZW52IjpbInN0YWdpbmciXSwicmVwb3MiOlsicmVjdG8iXSwic2VydmljZXMiOlsid2ViIl19LCJ0aWVyIjoxfSwiZXhwIjoxNzE1MDg2NDAwLCJpYXQiOjE3MTUwMDAwMDAsImlzcyI6InBob25lOm9wZXJhdG9yOmVuY2xhdmUiLCJqdGkiOiJjYXBfMjAyNi0wNS0wNV90ZXN0IiwibmJmIjoxNzE1MDAwMDAwLCJwdXJwb3NlIjoiVGVzdCBjYXBhYmlsaXR5IGZpeHR1cmUiLCJzdWIiOiJhZ2VudDpkYXJ3aW5Ac3RhZ2luZyJ9";

    private const string ExpectedDigestHex =
        "e500695bf8a41f37f41997bffa0b6a9cfaae1809ad8263e770e0db72e82e693c";

    /// <summary>The reference fixture used by every byte-pin test.
    /// Mirrors Python's <c>example_claims</c> in
    /// <c>tests/test_capability.py</c>.</summary>
    private static CapabilityClaims ExampleClaims() => new(
        Iss: "phone:operator:enclave",
        Sub: "agent:darwin@staging",
        Aud: new[] { "consumer-app", "recto:vault" },
        Iat: 1715000000L,
        Nbf: 1715000000L,
        Exp: 1715086400L,
        Jti: "cap_2026-05-05_test",
        Cap: new CapabilityClause(
            Tier: 1,
            RegistryVersion: "2026-05-05",
            Groups: new[] { "darwin:doc-edits", "darwin:staging-deploys" },
            Scope: new CapabilityScope(
                Env: new[] { "staging" },
                Services: new[] { "web" },
                Repos: new[] { "recto" }),
            AllowActions: Array.Empty<string>(),
            DenyActions: Array.Empty<string>(),
            Limits: new CapabilityLimits(
                PerHour: new Dictionary<string, long> { ["deploy:staging"] = 5L },
                PerDay: new Dictionary<string, long>(),
                PerSession: new Dictionary<string, long>())),
        Purpose: "Test capability fixture",
        ParentCap: null,
        MaxUses: null);

    [Fact]
    public void BuildSigningInput_MatchesPythonCanonicalHeader()
    {
        var (_, headerB64, _) = CapabilityJws.BuildSigningInput(ExampleClaims());
        Assert.Equal(ExpectedHeaderB64, headerB64);
    }

    [Fact]
    public void BuildSigningInput_MatchesPythonCanonicalPayload()
    {
        // Load-bearing: this test failing means the C# canonical JSON
        // encoder produced different bytes than Python for the same
        // claims input. Capability JWTs minted on either runtime would
        // fail to verify on the other.
        var (_, _, payloadB64) = CapabilityJws.BuildSigningInput(ExampleClaims());
        Assert.Equal(ExpectedPayloadB64, payloadB64);
    }

    [Fact]
    public void BuildSigningInput_MatchesPythonCanonicalDigest()
    {
        var (digest, _, _) = CapabilityJws.BuildSigningInput(ExampleClaims());
        Assert.Equal(ExpectedDigestHex, Convert.ToHexString(digest).ToLowerInvariant());
    }

    [Fact]
    public void BuildSigningInput_OmitsNullParentCapAndMaxUses()
    {
        // Python's _claims_to_dict strips None-valued top-level optionals
        // before canonical encoding. The C# mirror uses the same rule.
        var (_, _, payloadB64) = CapabilityJws.BuildSigningInput(ExampleClaims());
        var payloadBytes = CapabilityJws.Base64UrlDecode(payloadB64);
        var payloadStr = Encoding.UTF8.GetString(payloadBytes);
        Assert.DoesNotContain("\"parent_cap\"", payloadStr);
        Assert.DoesNotContain("\"max_uses\"", payloadStr);
    }

    [Fact]
    public void BuildSigningInput_Deterministic()
    {
        // Same claims → same digest + b64 segments. Required for signature
        // stability and external cross-check reproducibility.
        var claims = ExampleClaims();
        var (digest1, h1, p1) = CapabilityJws.BuildSigningInput(claims);
        var (digest2, h2, p2) = CapabilityJws.BuildSigningInput(claims);
        Assert.Equal(digest1, digest2);
        Assert.Equal(h1, h2);
        Assert.Equal(p1, p2);
        Assert.Equal(32, digest1.Length); // SHA-256
    }

    [Fact]
    public void BuildSigningInput_HeaderDecodesToCanonicalForm()
    {
        var (_, headerB64, _) = CapabilityJws.BuildSigningInput(ExampleClaims());
        var headerBytes = CapabilityJws.Base64UrlDecode(headerB64);
        var headerStr = Encoding.UTF8.GetString(headerBytes);
        // Pinned exactly &mdash; alg before typ (canonical sort order).
        Assert.Equal("{\"alg\":\"ES256K\",\"typ\":\"JWT\"}", headerStr);
    }

    [Fact]
    public void BuildSigningInput_PayloadCarriesAllRequiredClaims()
    {
        var (_, _, payloadB64) = CapabilityJws.BuildSigningInput(ExampleClaims());
        var payloadBytes = CapabilityJws.Base64UrlDecode(payloadB64);
        using var doc = JsonDocument.Parse(payloadBytes);
        var root = doc.RootElement;
        Assert.Equal("phone:operator:enclave", root.GetProperty("iss").GetString());
        Assert.Equal("agent:darwin@staging", root.GetProperty("sub").GetString());
        Assert.Equal("cap_2026-05-05_test", root.GetProperty("jti").GetString());
        Assert.Equal(1L, root.GetProperty("cap").GetProperty("tier").GetInt64());
        Assert.Equal("2026-05-05",
            root.GetProperty("cap").GetProperty("registry_version").GetString());
    }

    // -----------------------------------------------------------------
    // ParseJws structural validation
    // -----------------------------------------------------------------

    [Fact]
    public void ParseJws_RejectsTooFewParts()
    {
        var ex = Assert.Throws<FormatException>(() => CapabilityJws.ParseJws("only.two"));
        Assert.Contains("3 dot-separated", ex.Message);
    }

    [Fact]
    public void ParseJws_RejectsTooManyParts()
    {
        var ex = Assert.Throws<FormatException>(() => CapabilityJws.ParseJws("a.b.c.d"));
        Assert.Contains("3 dot-separated", ex.Message);
    }

    [Fact]
    public void ParseJws_RejectsInvalidBase64()
    {
        // The header segment '!!!' is not valid base64url.
        Assert.Throws<FormatException>(
            () => CapabilityJws.ParseJws("!!!.eyJhIjoxfQ.AA"));
    }

    [Fact]
    public void ParseJws_SucceedsOnWellFormedInput()
    {
        var headerB64 = CapabilityJws.Base64UrlEncode(
            CanonicalJson.Encode(new Dictionary<string, object?>
            {
                ["alg"] = "ES256K",
                ["typ"] = "JWT",
            }));
        var payloadB64 = CapabilityJws.Base64UrlEncode(
            CanonicalJson.Encode(new Dictionary<string, object?>
            {
                ["hello"] = "world",
            }));
        var sigB64 = CapabilityJws.Base64UrlEncode(new byte[64]);
        var token = $"{headerB64}.{payloadB64}.{sigB64}";

        var parts = CapabilityJws.ParseJws(token);
        Assert.Equal("ES256K", parts.HeaderRoot.GetProperty("alg").GetString());
        Assert.Equal("world", parts.PayloadRoot.GetProperty("hello").GetString());
        Assert.Equal(64, parts.Signature.Length);
        Assert.Equal($"{headerB64}.{payloadB64}",
            Encoding.ASCII.GetString(parts.SigningInput));
    }

    // -----------------------------------------------------------------
    // AssembleJws
    // -----------------------------------------------------------------

    [Fact]
    public void AssembleJws_RejectsWrongSignatureLength()
    {
        var ex = Assert.Throws<ArgumentException>(
            () => CapabilityJws.AssembleJws("h", "p", new byte[32]));
        Assert.Contains("64 raw bytes", ex.Message);
    }

    [Fact]
    public void AssembleJws_RoundTripsThroughParseJws()
    {
        var (digest, headerB64, payloadB64) = CapabilityJws.BuildSigningInput(
            ExampleClaims());
        var fakeSig = new byte[64];
        for (int i = 0; i < 64; i++) fakeSig[i] = (byte)i;

        var token = CapabilityJws.AssembleJws(headerB64, payloadB64, fakeSig);
        var parts = CapabilityJws.ParseJws(token);

        Assert.Equal("ES256K", parts.HeaderRoot.GetProperty("alg").GetString());
        Assert.Equal("cap_2026-05-05_test",
            parts.PayloadRoot.GetProperty("jti").GetString());
        Assert.Equal(fakeSig, parts.Signature);
        // signing_input matches what BuildSigningInput would feed to SHA-256
        var recomputed = System.Security.Cryptography.SHA256.HashData(parts.SigningInput);
        Assert.Equal(digest, recomputed);
    }

    // -----------------------------------------------------------------
    // VerifyJws — full sign-then-verify round-trip
    //
    // Uses EthSigningOps.SignWithRecovery() to produce a real ES256K
    // signature, then verifies via Es256kCapabilityVerifier. Closes the
    // internal-consistency gap Python defers to Wave A continuation
    // (Python's mint primitive isn't yet implemented; C# has it for
    // free via the BouncyCastle path Wave 6 introduced).
    // -----------------------------------------------------------------

    private static string MintRoundTripJws(
        CapabilityClaims claims,
        byte[] privateKey,
        out byte[] publicKey)
    {
        publicKey = EthSigningOps.PublicKeyFromPrivate(privateKey);
        var (digest, headerB64, payloadB64) = CapabilityJws.BuildSigningInput(claims);
        // SignWithRecovery returns 65 bytes (r||s||v with v=27 or 28). For
        // the JWS signature we only want the 64-byte r||s; the verifier's
        // recovery loop tries both v values to find the right one.
        var rsv = EthSigningOps.SignWithRecovery(digest, privateKey);
        var rs = new byte[64];
        Buffer.BlockCopy(rsv, 0, rs, 0, 64);
        return CapabilityJws.AssembleJws(headerB64, payloadB64, rs);
    }

    [Fact]
    public void VerifyJws_RoundTripsWithEthSigningOps()
    {
        var priv = EthSigningOps.GeneratePrivateKey();
        var token = MintRoundTripJws(ExampleClaims(), priv, out var pub);
        var verifier = new Es256kCapabilityVerifier(pub);

        var result = verifier.VerifyJws(
            token,
            now: 1715000001L); // just past nbf

        Assert.True(result.Success, $"verify failed: {result.Error}");
        Assert.NotNull(result.Claims);
        Assert.Equal("cap_2026-05-05_test", result.Claims!.Jti);
        Assert.Equal(1, result.Claims.Cap.Tier);
        Assert.Equal("2026-05-05", result.Claims.Cap.RegistryVersion);
    }

    [Fact]
    public void VerifyJws_FailsForWrongPublicKey()
    {
        var signingPriv = EthSigningOps.GeneratePrivateKey();
        var attackerPriv = EthSigningOps.GeneratePrivateKey();
        var attackerPub = EthSigningOps.PublicKeyFromPrivate(attackerPriv);

        var token = MintRoundTripJws(ExampleClaims(), signingPriv, out _);
        // Verifier expects attackerPub but the token was signed by signingPriv,
        // so neither rec_id will recover to attackerPub.
        var verifier = new Es256kCapabilityVerifier(attackerPub);

        var result = verifier.VerifyJws(token, now: 1715000001L);
        Assert.False(result.Success);
        Assert.NotNull(result.Error);
        Assert.StartsWith("signature:", result.Error);
    }

    [Fact]
    public void VerifyJws_FailsForExpiredToken()
    {
        var priv = EthSigningOps.GeneratePrivateKey();
        var token = MintRoundTripJws(ExampleClaims(), priv, out var pub);
        var verifier = new Es256kCapabilityVerifier(pub);

        // exp=1715086400; supply now well past it.
        var result = verifier.VerifyJws(token, now: 1715086500L);
        Assert.False(result.Success);
        Assert.StartsWith("claims:", result.Error);
        Assert.Contains("exp=1715086400", result.Error);
    }

    [Fact]
    public void VerifyJws_FailsForNbfInTheFuture()
    {
        var priv = EthSigningOps.GeneratePrivateKey();
        var token = MintRoundTripJws(ExampleClaims(), priv, out var pub);
        var verifier = new Es256kCapabilityVerifier(pub);

        // nbf=1715000000; supply now BEFORE that.
        var result = verifier.VerifyJws(token, now: 1714999999L);
        Assert.False(result.Success);
        Assert.StartsWith("claims:", result.Error);
        Assert.Contains("future", result.Error);
    }

    [Fact]
    public void VerifyJws_AcceptsExpectedAudienceMatch()
    {
        var priv = EthSigningOps.GeneratePrivateKey();
        var token = MintRoundTripJws(ExampleClaims(), priv, out var pub);
        var verifier = new Es256kCapabilityVerifier(pub);

        var result = verifier.VerifyJws(
            token,
            expectedAud: "recto:vault",
            now: 1715000001L);
        Assert.True(result.Success, $"verify failed: {result.Error}");
    }

    [Fact]
    public void VerifyJws_RejectsAudienceMismatch()
    {
        var priv = EthSigningOps.GeneratePrivateKey();
        var token = MintRoundTripJws(ExampleClaims(), priv, out var pub);
        var verifier = new Es256kCapabilityVerifier(pub);

        var result = verifier.VerifyJws(
            token,
            expectedAud: "some-other-app",
            now: 1715000001L);
        Assert.False(result.Success);
        Assert.StartsWith("claims:", result.Error);
        Assert.Contains("some-other-app", result.Error);
    }

    [Fact]
    public void VerifyJws_RejectsTamperedPayload()
    {
        // Mint a real token, flip a single bit in the payload segment,
        // and watch the signature recovery fail.
        var priv = EthSigningOps.GeneratePrivateKey();
        var token = MintRoundTripJws(ExampleClaims(), priv, out var pub);

        var parts = token.Split('.');
        // Mutate one character of the payload segment.
        var p = parts[1].ToCharArray();
        p[5] = p[5] == 'A' ? 'B' : 'A';
        parts[1] = new string(p);
        var tampered = string.Join('.', parts);

        var verifier = new Es256kCapabilityVerifier(pub);
        var result = verifier.VerifyJws(tampered, now: 1715000001L);
        Assert.False(result.Success);
        // Could fail at shape (parse failure on broken b64) or at signature
        // recovery (digest changed) — either is acceptable; the point is
        // we don't accept it.
    }

    [Fact]
    public void VerifyJws_RejectsWrongAlg()
    {
        // Build a token with alg=HS256 (not ES256K) and verify it's
        // rejected at the shape check.
        var headerB64 = CapabilityJws.Base64UrlEncode(
            CanonicalJson.Encode(new Dictionary<string, object?>
            {
                ["alg"] = "HS256",
                ["typ"] = "JWT",
            }));
        var (_, _, payloadB64) = CapabilityJws.BuildSigningInput(ExampleClaims());
        var sigB64 = CapabilityJws.Base64UrlEncode(new byte[64]);
        var token = $"{headerB64}.{payloadB64}.{sigB64}";

        var verifier = new Es256kCapabilityVerifier(new byte[64]);
        var result = verifier.VerifyJws(token, now: 1715000001L);
        Assert.False(result.Success);
        Assert.StartsWith("shape:", result.Error);
        Assert.Contains("HS256", result.Error);
    }

    [Fact]
    public void Constructor_RejectsWrongPublicKeyLength()
    {
        Assert.Throws<ArgumentException>(
            () => new Es256kCapabilityVerifier(new byte[32]));
    }

    // -----------------------------------------------------------------
    // Phase 2.0.C wave C.2 -- parent_profile dispatch via IProfileLookup
    //
    // Mirrors the Python verify_jws extension in
    // recto/capability/jwt.py. Tests pin the same six failure modes
    // + the positive happy-path case.
    // -----------------------------------------------------------------

    private sealed class FakeProfileLookup : IProfileLookup
    {
        private readonly Dictionary<string, ProfileLookupResult> _profiles
            = new();

        public void AddProfile(
            string profileId,
            string? derivedPubkeyHex,
            bool revoked = false,
            IReadOnlyList<string>? denyActions = null)
        {
            _profiles[profileId] = new ProfileLookupResult(
                derivedPubkeyHex,
                revoked,
                denyActions ?? Array.Empty<string>());
        }

        public ProfileLookupResult? GetProfile(string profileId)
        {
            return _profiles.TryGetValue(profileId, out var p) ? p : null;
        }
    }

    private static CapabilityClaims ClaimsWithParentProfile(string? parentProfile)
    {
        var baseClaims = ExampleClaims();
        return baseClaims with { ParentProfile = parentProfile };
    }

    [Fact]
    public void VerifyJws_C2_RoundTripsWithChildKey_WhenParentProfileSet()
    {
        // Set up a child keypair, mint a JWS under the child's key
        // with parent_profile set, register the child's pubkey on a
        // fake lookup. Verifier should recover signature against the
        // CHILD key (not the operator master).
        var childPriv = EthSigningOps.GeneratePrivateKey();
        var childPub = EthSigningOps.PublicKeyFromPrivate(childPriv);

        var operatorMasterPriv = EthSigningOps.GeneratePrivateKey();
        var operatorMasterPub = EthSigningOps.PublicKeyFromPrivate(operatorMasterPriv);

        var lookup = new FakeProfileLookup();
        lookup.AddProfile(
            "child-profile-id",
            derivedPubkeyHex: BytesToHex(childPub));

        var token = MintRoundTripJws(
            ClaimsWithParentProfile("child-profile-id"),
            childPriv,
            out _);

        var verifier = new Es256kCapabilityVerifier(operatorMasterPub, lookup);
        var result = verifier.VerifyJws(token, now: 1715000001L);

        Assert.True(result.Success, $"verify failed: {result.Error}");
        Assert.Equal("child-profile-id", result.Claims!.ParentProfile);
    }

    [Fact]
    public void VerifyJws_C2_NullParentProfile_UsesOperatorKey()
    {
        // Backward compat: JWS with parent_profile = null still
        // verifies against the operator master pubkey (v1.x / v2.0.B
        // behavior unchanged).
        var operatorPriv = EthSigningOps.GeneratePrivateKey();
        var token = MintRoundTripJws(ExampleClaims(), operatorPriv, out var operatorPub);

        var lookup = new FakeProfileLookup();
        var verifier = new Es256kCapabilityVerifier(operatorPub, lookup);

        var result = verifier.VerifyJws(token, now: 1715000001L);
        Assert.True(result.Success, $"verify failed: {result.Error}");
        Assert.Null(result.Claims!.ParentProfile);
    }

    [Fact]
    public void VerifyJws_C2_FailsWhenParentProfileSetButNoLookupConfigured()
    {
        var childPriv = EthSigningOps.GeneratePrivateKey();
        var childPub = EthSigningOps.PublicKeyFromPrivate(childPriv);

        var token = MintRoundTripJws(
            ClaimsWithParentProfile("some-profile-id"),
            childPriv,
            out _);

        // Verifier constructed WITHOUT IProfileLookup -- uses the
        // single-arg constructor that nulls the resolver.
        var verifier = new Es256kCapabilityVerifier(childPub);

        var result = verifier.VerifyJws(token, now: 1715000001L);
        Assert.False(result.Success);
        Assert.StartsWith("claims:", result.Error);
        Assert.Contains("IProfileLookup", result.Error);
    }

    [Fact]
    public void VerifyJws_C2_FailsForUnknownParentProfile()
    {
        var childPriv = EthSigningOps.GeneratePrivateKey();
        var childPub = EthSigningOps.PublicKeyFromPrivate(childPriv);
        var operatorPriv = EthSigningOps.GeneratePrivateKey();
        var operatorPub = EthSigningOps.PublicKeyFromPrivate(operatorPriv);

        // Lookup knows nothing about "nonexistent-id".
        var lookup = new FakeProfileLookup();
        lookup.AddProfile("other-id", derivedPubkeyHex: BytesToHex(childPub));

        var token = MintRoundTripJws(
            ClaimsWithParentProfile("nonexistent-id"),
            childPriv,
            out _);

        var verifier = new Es256kCapabilityVerifier(operatorPub, lookup);
        var result = verifier.VerifyJws(token, now: 1715000001L);

        Assert.False(result.Success);
        Assert.StartsWith("claims:", result.Error);
        Assert.Contains("not found", result.Error);
    }

    [Fact]
    public void VerifyJws_C2_FailsForRevokedParentProfile()
    {
        var childPriv = EthSigningOps.GeneratePrivateKey();
        var childPub = EthSigningOps.PublicKeyFromPrivate(childPriv);
        var operatorPriv = EthSigningOps.GeneratePrivateKey();
        var operatorPub = EthSigningOps.PublicKeyFromPrivate(operatorPriv);

        var lookup = new FakeProfileLookup();
        lookup.AddProfile(
            "revoked-id",
            derivedPubkeyHex: BytesToHex(childPub),
            revoked: true);

        var token = MintRoundTripJws(
            ClaimsWithParentProfile("revoked-id"),
            childPriv,
            out _);

        var verifier = new Es256kCapabilityVerifier(operatorPub, lookup);
        var result = verifier.VerifyJws(token, now: 1715000001L);

        Assert.False(result.Success);
        Assert.StartsWith("claims:", result.Error);
        Assert.Contains("revoked", result.Error);
    }

    [Fact]
    public void VerifyJws_C2_FailsWhenProfileLacksDerivedPubkeyHex()
    {
        var childPriv = EthSigningOps.GeneratePrivateKey();
        var operatorPriv = EthSigningOps.GeneratePrivateKey();
        var operatorPub = EthSigningOps.PublicKeyFromPrivate(operatorPriv);

        // Simulate a v2.0.B-era profile row (no derived_pubkey_hex).
        var lookup = new FakeProfileLookup();
        lookup.AddProfile("v20b-profile-id", derivedPubkeyHex: null);

        var token = MintRoundTripJws(
            ClaimsWithParentProfile("v20b-profile-id"),
            childPriv,
            out _);

        var verifier = new Es256kCapabilityVerifier(operatorPub, lookup);
        var result = verifier.VerifyJws(token, now: 1715000001L);

        Assert.False(result.Success);
        Assert.StartsWith("claims:", result.Error);
        Assert.Contains("derived_pubkey_hex", result.Error);
    }

    [Fact]
    public void VerifyJws_C2_FailsWhenSignedByWrongChildKey()
    {
        // Profile is registered with childPub_A, but the JWS is
        // signed under childPub_B. Signature recovery yields B; the
        // verifier expects A.
        var realChildPriv = EthSigningOps.GeneratePrivateKey();
        var realChildPub = EthSigningOps.PublicKeyFromPrivate(realChildPriv);
        var impostorPriv = EthSigningOps.GeneratePrivateKey();
        var operatorPriv = EthSigningOps.GeneratePrivateKey();
        var operatorPub = EthSigningOps.PublicKeyFromPrivate(operatorPriv);

        var lookup = new FakeProfileLookup();
        lookup.AddProfile(
            "real-profile-id",
            derivedPubkeyHex: BytesToHex(realChildPub));

        // Mint with the IMPOSTOR key.
        var token = MintRoundTripJws(
            ClaimsWithParentProfile("real-profile-id"),
            impostorPriv,
            out _);

        var verifier = new Es256kCapabilityVerifier(operatorPub, lookup);
        var result = verifier.VerifyJws(token, now: 1715000001L);

        Assert.False(result.Success);
        Assert.StartsWith("signature:", result.Error);
        Assert.Contains("parent_profile", result.Error);
    }

    [Fact]
    public void VerifyJws_C2_AcceptsDerivedPubkeyHexWith0xPrefix()
    {
        // Normalization: 0x-prefixed pubkey hex is accepted and
        // stripped server-side before parsing.
        var childPriv = EthSigningOps.GeneratePrivateKey();
        var childPub = EthSigningOps.PublicKeyFromPrivate(childPriv);
        var operatorPriv = EthSigningOps.GeneratePrivateKey();
        var operatorPub = EthSigningOps.PublicKeyFromPrivate(operatorPriv);

        var lookup = new FakeProfileLookup();
        lookup.AddProfile(
            "child-with-prefix",
            derivedPubkeyHex: "0x" + BytesToHex(childPub));

        var token = MintRoundTripJws(
            ClaimsWithParentProfile("child-with-prefix"),
            childPriv,
            out _);

        var verifier = new Es256kCapabilityVerifier(operatorPub, lookup);
        var result = verifier.VerifyJws(token, now: 1715000001L);

        Assert.True(result.Success, $"verify failed: {result.Error}");
    }

    private static string BytesToHex(byte[] bytes)
    {
        var sb = new System.Text.StringBuilder(bytes.Length * 2);
        foreach (var b in bytes)
        {
            sb.Append(b.ToString("x2"));
        }
        return sb.ToString();
    }
}
