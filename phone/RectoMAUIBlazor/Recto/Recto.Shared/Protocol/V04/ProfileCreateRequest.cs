using System.Text.Json.Serialization;

namespace Recto.Shared.Protocol.V04;

/// <summary>
/// Wire shape for <c>POST /v0.4/profile/create</c> (Phase 2.0.B
/// multi-profile identity integration).
///
/// <para>
/// Submitted by external callers (CLI's <c>recto profile create</c>,
/// SCIM provisioning glue, future automation) to mint a new child
/// Profile under the operator's master. The bootloader requires
/// agent-token authentication via the <c>X-Recto-Agent-Id</c> and
/// <c>X-Recto-Agent-Token</c> HTTP headers (same posture as
/// <c>POST /v0.4/capability/request</c>).
/// </para>
///
/// <para>
/// On success, the bootloader returns a
/// <see cref="ProfileCreateResponse"/> with the queued request_id and
/// a result_url the caller polls until the operator approves on the
/// phone. The phone signs a secp256k1 master-attestation over the
/// canonical-JSON encoding of the candidate fields; the bootloader
/// verifies the attestation recovers to the operator pubkey, atomic-
/// writes the new Profile via
/// <c>recto.profile.manage.create_child_profile</c>, and stashes a
/// <see cref="ProfileCreateResult"/> for the caller's poll. See
/// <see cref="PendingRequestKind.ProfileCreate"/> for the full flow.
/// </para>
///
/// <para>
/// Idempotency-key contract (Milan Jovanović commitment A):
/// <see cref="CandidateProfileId"/> is CALLER-AUTHORED (UUID4
/// generated at intent-formation time, stashed locally, submitted
/// with the request). The bootloader uses it end-to-end:
/// </para>
/// <list type="bullet">
/// <item>Idempotency precheck against existing Profile rows on disk
/// at POST time. Match → HTTP 200 with status="already_exists";
/// operator phone is NOT re-prompted.</item>
/// <item>Canonical Profile.profile_id at persist time. The new row
/// stored in master_identity.json carries CandidateProfileId as its
/// canonical identifier — distinct from a bootloader-assigned UUID.</item>
/// <item>Lookup key for downstream consumers binding off-platform
/// state to the profile (a consumer's user-record public-key column
/// per architectural commitment #11; future capability JWS
/// <c>parent_profile</c> references; etc.).</item>
/// </list>
/// <para>
/// Callers MUST generate a fresh UUID per distinct intent. Reusing a
/// CandidateProfileId for a different (kind, display_name) pair
/// triggers a collision-rejection at the manage.py layer (the
/// idempotency contract assumes the key uniquely identifies an
/// intent; reuse breaks that contract for the downstream binding
/// consumers above).
/// </para>
/// </summary>
public sealed record ProfileCreateRequest(
    [property: JsonPropertyName("phone_id")] string PhoneId,
    [property: JsonPropertyName("candidate_profile_id")] string CandidateProfileId,
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("display_name")] string DisplayName,
    [property: JsonPropertyName("theme_hint")] string? ThemeHint = null,
    [property: JsonPropertyName("scim_provider")] string? ScimProvider = null,
    [property: JsonPropertyName("ttl_seconds")] int? TtlSeconds = null,
    [property: JsonPropertyName("operation_description")] string? OperationDescription = null,
    [property: JsonPropertyName("service")] string? Service = null,
    [property: JsonPropertyName("secret")] string? Secret = null);
