using System.Text.Json;
using Recto.Shared.Capability;
using Recto.Shared.Protocol.V04;
using Xunit;

namespace Recto.Shared.Tests.Capability;

/// <summary>
/// Pins the C# protocol-DTO shape for Phase 2.0.B's
/// <c>profile_create</c> kind against the Python wire shape in
/// <c>recto/bootloader/state.py</c>, <c>recto/bootloader/server.py</c>,
/// and the new <c>recto/profile/</c> package. Any drift between the
/// C# DTOs and the Python emit-keys would silently break end-to-end
/// routing — the phone would receive a profile_create request with
/// empty candidate_* fields, fail to reconstruct the canonical signing
/// input, and refuse to sign.
///
/// <para>
/// Sister to <see cref="CapabilityRequestProtocolTests"/>; same byte-
/// parity discipline applied to the new profile_create surface.
/// </para>
/// </summary>
public class ProfileCreateProtocolTests
{
    // -----------------------------------------------------------------
    // PendingRequestKind constant — the discriminator value
    // -----------------------------------------------------------------

    [Fact]
    public void PendingRequestKind_ProfileCreate_HasExpectedString()
    {
        Assert.Equal("profile_create", PendingRequestKind.ProfileCreate);
    }

    // -----------------------------------------------------------------
    // ProfileKind canonical strings — must match recto/profile/types.py
    // -----------------------------------------------------------------

    [Fact]
    public void ProfileKind_CanonicalStrings_MatchPythonConstants()
    {
        Assert.Equal("personal:master", ProfileKind.PersonalMaster);
        Assert.Equal("personal:child", ProfileKind.PersonalChild);
        Assert.Equal("work", ProfileKind.Work);
        Assert.Equal("school", ProfileKind.School);
        Assert.Equal("contractor", ProfileKind.Contractor);
    }

    // -----------------------------------------------------------------
    // PendingRequestContext — candidate_* JSON property names + round-trip
    // -----------------------------------------------------------------

    [Fact]
    public void PendingRequestContext_SerializesCandidateFieldsAsSnakeCase()
    {
        var ctx = new PendingRequestContext(
            ChildPid: 0,
            ChildArgv0: "(external-agent)",
            RequestedAtUnix: 1715000000L,
            OperationDescription: "profile_create from cli-agent: personal:child / Pseudonym",
            PayloadHashB64u: "ZGlnZXN0LWJ5dGVz",
            // capability_request and profile_create share cap_payload_b64
            // for the canonical signing-input stash. Phone signs
            // SHA-256(decoded(cap_payload_b64)) for profile_create.
            CapPayloadB64: "eyJjYW5kaWRhdGVfcHJvZmlsZV9pZCI6IngifQ",
            CapAgentId: "cli-agent",
            CandidateProfileId: "abc-123-uuid",
            CandidateKind: "personal:child",
            CandidateDisplayName: "Personal pseudonym",
            CandidateDerivationPurpose: 0x72656374L,
            CandidateDerivationCoinType: 1,
            CandidateDerivationIndex: 0,
            CandidateThemeHint: "neutral-dark",
            CandidateScimProvider: null);

        var json = JsonSerializer.Serialize(ctx);

        Assert.Contains("\"candidate_profile_id\":\"abc-123-uuid\"", json);
        Assert.Contains("\"candidate_kind\":\"personal:child\"", json);
        Assert.Contains("\"candidate_display_name\":\"Personal pseudonym\"", json);
        Assert.Contains("\"candidate_derivation_purpose\":1919247220", json); // 0x72656374
        Assert.Contains("\"candidate_derivation_coin_type\":1", json);
        Assert.Contains("\"candidate_derivation_index\":0", json);
        Assert.Contains("\"candidate_theme_hint\":\"neutral-dark\"", json);
    }

    [Fact]
    public void PendingRequestContext_DeserializesCandidateFieldsFromPythonShape()
    {
        // Mirror of the wire shape Python emits via _pending_to_wire
        // for kind == "profile_create". Pin protects against a
        // JsonPropertyName drift that would silently leave the
        // candidate_* fields null on the C# side.
        const string pythonWire = """
        {
          "child_pid": 0,
          "child_argv0": "(external-agent)",
          "requested_at_unix": 1715000000,
          "operation_description": "profile_create from cli-agent: work / Acme Corp",
          "payload_hash_b64u": "ZGlnZXN0LWZpeHR1cmU",
          "cap_payload_b64": "eyJjYW5kaWRhdGVfcHJvZmlsZV9pZCI6InRlc3QtaWQifQ",
          "cap_agent_id": "cli-agent",
          "candidate_profile_id": "test-id",
          "candidate_kind": "work",
          "candidate_display_name": "Acme Corp",
          "candidate_derivation_purpose": 1919249780,
          "candidate_derivation_coin_type": 2,
          "candidate_derivation_index": 0,
          "candidate_theme_hint": "blue",
          "candidate_scim_provider": "azure-ad:tenant-123"
        }
        """;

        var ctx = JsonSerializer.Deserialize<PendingRequestContext>(pythonWire);
        Assert.NotNull(ctx);
        Assert.Equal("test-id", ctx!.CandidateProfileId);
        Assert.Equal("work", ctx.CandidateKind);
        Assert.Equal("Acme Corp", ctx.CandidateDisplayName);
        Assert.Equal(1919249780L, ctx.CandidateDerivationPurpose);
        Assert.Equal(2, ctx.CandidateDerivationCoinType);
        Assert.Equal(0, ctx.CandidateDerivationIndex);
        Assert.Equal("blue", ctx.CandidateThemeHint);
        Assert.Equal("azure-ad:tenant-123", ctx.CandidateScimProvider);
    }

    [Fact]
    public void PendingRequestContext_NonProfileCreateRequestsLeaveCandidateFieldsNull()
    {
        // Regression-pin: a single_sign or capability_request payload
        // should NOT populate any candidate_* fields. Without this
        // pin a future field-add drift could accidentally leak
        // candidate metadata into unrelated kinds.
        var ctx = new PendingRequestContext(
            ChildPid: 0,
            ChildArgv0: "test-child",
            RequestedAtUnix: 1715000000L,
            OperationDescription: "single_sign request",
            PayloadHashB64u: "aGFzaA");

        Assert.Null(ctx.CandidateProfileId);
        Assert.Null(ctx.CandidateKind);
        Assert.Null(ctx.CandidateDisplayName);
        Assert.Null(ctx.CandidateDerivationPurpose);
        Assert.Null(ctx.CandidateDerivationCoinType);
        Assert.Null(ctx.CandidateDerivationIndex);
        Assert.Null(ctx.CandidateThemeHint);
        Assert.Null(ctx.CandidateScimProvider);
    }

    // -----------------------------------------------------------------
    // ProfileCreateRequest — POST body shape
    // -----------------------------------------------------------------

    [Fact]
    public void ProfileCreateRequest_SerializesAsSnakeCase()
    {
        var req = new ProfileCreateRequest(
            PhoneId: "phone-abc",
            CandidateProfileId: "caller-uuid-001",
            Kind: "personal:child",
            DisplayName: "Personal pseudonym",
            ThemeHint: "dark",
            ScimProvider: null,
            TtlSeconds: 600,
            OperationDescription: "Test profile create",
            Service: "recto",
            Secret: "profile");

        var json = JsonSerializer.Serialize(req);

        Assert.Contains("\"phone_id\":\"phone-abc\"", json);
        Assert.Contains("\"candidate_profile_id\":\"caller-uuid-001\"", json);
        Assert.Contains("\"kind\":\"personal:child\"", json);
        Assert.Contains("\"display_name\":\"Personal pseudonym\"", json);
        Assert.Contains("\"theme_hint\":\"dark\"", json);
        Assert.Contains("\"ttl_seconds\":600", json);
        Assert.Contains("\"operation_description\":\"Test profile create\"", json);
        Assert.Contains("\"service\":\"recto\"", json);
        Assert.Contains("\"secret\":\"profile\"", json);
    }

    [Fact]
    public void ProfileCreateRequest_MinimalBodyOmitsOptionalFields()
    {
        // Only the required fields. Optional fields serialize as null
        // (System.Text.Json default) — the Python endpoint tolerates
        // both omission and explicit null per its body validators.
        var req = new ProfileCreateRequest(
            PhoneId: "phone-abc",
            CandidateProfileId: "caller-uuid-002",
            Kind: "work",
            DisplayName: "Acme");

        var json = JsonSerializer.Serialize(req);

        Assert.Contains("\"phone_id\":\"phone-abc\"", json);
        Assert.Contains("\"candidate_profile_id\":\"caller-uuid-002\"", json);
        Assert.Contains("\"kind\":\"work\"", json);
        Assert.Contains("\"display_name\":\"Acme\"", json);
    }

    // -----------------------------------------------------------------
    // ProfileCreateResponse — POST response (201 + 200 already_exists)
    // -----------------------------------------------------------------

    [Fact]
    public void ProfileCreateResponse_DeserializesNewlyQueuedShape()
    {
        // HTTP 201 case: new request queued, caller polls result_url.
        const string pythonWire = """
        {
          "request_id": "req-789",
          "candidate_profile_id": "caller-uuid-001",
          "expires_at_unix": 1715000600,
          "result_url": "/v0.4/profile/result/req-789"
        }
        """;

        var resp = JsonSerializer.Deserialize<ProfileCreateResponse>(pythonWire);
        Assert.NotNull(resp);
        Assert.Equal("req-789", resp!.RequestId);
        Assert.Equal("caller-uuid-001", resp.CandidateProfileId);
        Assert.Equal(1715000600L, resp.ExpiresAtUnix);
        Assert.Equal("/v0.4/profile/result/req-789", resp.ResultUrl);
        // Idempotency-hit fields are null in the queued case.
        Assert.Null(resp.Status);
        Assert.Null(resp.ProfileId);
        Assert.Null(resp.Reason);
    }

    [Fact]
    public void ProfileCreateResponse_DeserializesAlreadyExistsShape()
    {
        // HTTP 200 case: idempotency-key hit — same candidate_profile_id
        // already has a persisted Profile; bootloader returns the
        // existing id without re-prompting the operator.
        const string pythonWire = """
        {
          "status": "already_exists",
          "profile_id": "caller-uuid-001",
          "candidate_profile_id": "caller-uuid-001",
          "reason": "candidate_profile_id was already used; profile exists"
        }
        """;

        var resp = JsonSerializer.Deserialize<ProfileCreateResponse>(pythonWire);
        Assert.NotNull(resp);
        Assert.Equal(ProfileCreateResultStatus.AlreadyExists, resp!.Status);
        Assert.Equal("caller-uuid-001", resp.ProfileId);
        Assert.Equal("caller-uuid-001", resp.CandidateProfileId);
        Assert.NotNull(resp.Reason);
        // Queue-time fields are null in the already-exists case.
        Assert.Null(resp.RequestId);
        Assert.Null(resp.ExpiresAtUnix);
        Assert.Null(resp.ResultUrl);
    }

    // -----------------------------------------------------------------
    // ProfileCreateResult — GET poll response
    // -----------------------------------------------------------------

    [Fact]
    public void ProfileCreateResult_DeserializesApprovedShape()
    {
        const string pythonWire = """
        {
          "status": "approved",
          "profile_id": "caller-uuid-001"
        }
        """;

        var result = JsonSerializer.Deserialize<ProfileCreateResult>(pythonWire);
        Assert.NotNull(result);
        Assert.Equal(ProfileCreateResultStatus.Approved, result!.Status);
        Assert.Equal("caller-uuid-001", result.ProfileId);
        Assert.Null(result.Reason);
    }

    [Fact]
    public void ProfileCreateResult_DeserializesDeniedShape()
    {
        const string pythonWire = """
        {
          "status": "denied",
          "reason": "Operator rejected the proposed kind"
        }
        """;

        var result = JsonSerializer.Deserialize<ProfileCreateResult>(pythonWire);
        Assert.NotNull(result);
        Assert.Equal(ProfileCreateResultStatus.Denied, result!.Status);
        Assert.Null(result.ProfileId);
        Assert.Equal("Operator rejected the proposed kind", result.Reason);
    }

    [Fact]
    public void ProfileCreateResult_DeserializesSignatureErrorShape()
    {
        const string pythonWire = """
        {
          "status": "signature_error",
          "reason": "master attestation did not recover to the configured operator pubkey"
        }
        """;

        var result = JsonSerializer.Deserialize<ProfileCreateResult>(pythonWire);
        Assert.NotNull(result);
        Assert.Equal(ProfileCreateResultStatus.SignatureError, result!.Status);
        Assert.Null(result.ProfileId);
        Assert.NotNull(result.Reason);
        Assert.Contains("did not recover", result.Reason!);
    }

    [Fact]
    public void ProfileCreateResult_DeserializesPersistErrorAsSignatureErrorWithPrefix()
    {
        // Milan commitment D was deferred — disk-write failures
        // surface as signature_error with "persist_error: " reason
        // prefix rather than a separate status enum value. Callers
        // distinguish via reason-grep.
        const string pythonWire = """
        {
          "status": "signature_error",
          "reason": "persist_error: OSError: [Errno 13] Permission denied"
        }
        """;

        var result = JsonSerializer.Deserialize<ProfileCreateResult>(pythonWire);
        Assert.NotNull(result);
        Assert.Equal(ProfileCreateResultStatus.SignatureError, result!.Status);
        Assert.NotNull(result.Reason);
        Assert.StartsWith("persist_error:", result.Reason);
    }

    [Fact]
    public void ProfileCreateResult_DeserializesPendingShape()
    {
        const string pythonWire = """
        {
          "status": "pending"
        }
        """;

        var result = JsonSerializer.Deserialize<ProfileCreateResult>(pythonWire);
        Assert.NotNull(result);
        Assert.Equal(ProfileCreateResultStatus.Pending, result!.Status);
        Assert.Null(result.ProfileId);
        Assert.Null(result.Reason);
    }

    // -----------------------------------------------------------------
    // RespondRequest — cap_signature_b64u reuse for profile_create
    // -----------------------------------------------------------------

    [Fact]
    public void RespondRequest_ProfileCreateApprovalUsesCapSignatureB64uField()
    {
        // Phase 2.0.B SPEC: profile_create approval uses the SAME
        // cap_signature_b64u field as capability_request (the
        // signing-input wire shape is identical between the two
        // flows — phone-side respond logic doesn't fork). Pin this
        // contract so a future refactor doesn't accidentally add a
        // profile_create-specific signature field.
        var resp = new RespondRequest(
            PhoneId: "phone-abc",
            Decision: "approved",
            SignatureB64u: "ed25519-envelope-sig",
            CapSignatureB64u: "secp256k1-master-attestation-64-bytes-b64url");

        var json = JsonSerializer.Serialize(resp);
        Assert.Contains("\"phone_id\":\"phone-abc\"", json);
        Assert.Contains("\"decision\":\"approved\"", json);
        Assert.Contains("\"signature_b64u\":\"ed25519-envelope-sig\"", json);
        Assert.Contains("\"cap_signature_b64u\":\"secp256k1-master-attestation-64-bytes-b64url\"", json);
    }

    // -----------------------------------------------------------------
    // CapabilityClaims parent_profile — v2.0 forward-compat slot
    // -----------------------------------------------------------------

    [Fact]
    public void CapabilityClaims_ParentProfile_DefaultsToNull()
    {
        // v1.x claims never set parent_profile. Default-null ensures
        // existing JWS-signing code paths produce byte-identical
        // signing inputs without changing per Hard Rule #1.
        var claims = new CapabilityClaims(
            Iss: "phone:operator:enclave",
            Sub: "agent:cli",
            Aud: new[] { "recto" },
            Iat: 1715000000L,
            Nbf: 1715000000L,
            Exp: 1715086400L,
            Jti: "cap-001",
            Cap: new CapabilityClause(
                Tier: 0,
                RegistryVersion: "2026-05-05",
                Groups: new[] { "darwin:doc-edits" },
                Scope: new CapabilityScope(System.Array.Empty<string>(), System.Array.Empty<string>(), System.Array.Empty<string>()),
                AllowActions: System.Array.Empty<string>(),
                DenyActions: System.Array.Empty<string>(),
                Limits: CapabilityLimits.Empty),
            Purpose: "test");

        Assert.Null(claims.ParentProfile);
    }

    [Fact]
    public void CapabilityClaims_ParentProfile_RoundTripsWhenSet()
    {
        // v2.0+ claims set parent_profile to the BIP-32-derived
        // child profile's id. Pin that the field round-trips
        // through JsonSerializer.
        var claims = new CapabilityClaims(
            Iss: "phone:operator:enclave",
            Sub: "agent:cli",
            Aud: new[] { "recto" },
            Iat: 1715000000L,
            Nbf: 1715000000L,
            Exp: 1715086400L,
            Jti: "cap-002",
            Cap: new CapabilityClause(
                Tier: 0,
                RegistryVersion: "2026-05-05",
                Groups: new[] { "darwin:doc-edits" },
                Scope: new CapabilityScope(System.Array.Empty<string>(), System.Array.Empty<string>(), System.Array.Empty<string>()),
                AllowActions: System.Array.Empty<string>(),
                DenyActions: System.Array.Empty<string>(),
                Limits: CapabilityLimits.Empty),
            Purpose: "v2.0 test",
            ParentProfile: "work-profile-uuid");

        Assert.Equal("work-profile-uuid", claims.ParentProfile);
    }
}
