using System.Text.Json.Serialization;

namespace Recto.Shared.Protocol.V04;

/// <summary>
/// Wire shape for the bootloader's two possible responses to
/// <c>POST /v0.4/profile/create</c> (Phase 2.0.B).
///
/// <para>
/// Two cases discriminated by <see cref="Status"/>:
/// </para>
///
/// <para>
/// <strong>New request queued (HTTP 201):</strong> bootloader queued
/// a <see cref="PendingRequestKind.ProfileCreate"/> PendingRequest on
/// the operator's phone. Caller polls <see cref="ResultUrl"/> until
/// the operator approves. <see cref="Status"/> is null in this case
/// (the field is only populated for the idempotent-hit case below);
/// callers should check whether <see cref="RequestId"/> is non-null
/// to distinguish.
/// </para>
///
/// <para>
/// <strong>Idempotent hit on existing profile (HTTP 200):</strong>
/// <see cref="CandidateProfileId"/> already corresponds to a persisted
/// Profile on disk; bootloader returns the existing profile_id without
/// re-prompting the operator. <see cref="Status"/> = "already_exists",
/// <see cref="ProfileId"/> = the existing Profile's id (which equals
/// <see cref="CandidateProfileId"/>), <see cref="Reason"/> carries
/// human-readable diagnostic. <see cref="RequestId"/> and
/// <see cref="ResultUrl"/> are null — no polling needed.
/// </para>
///
/// <para>
/// This shape unifies the 201-created and 200-already-exists cases so
/// callers can deserialize once and branch on the discriminator. Per
/// Milan Jovanović's idempotency-key commitment (A) the caller's
/// natural recovery path on uncertainty ("did my submit land?") is
/// to re-submit with the same <see cref="ProfileCreateRequest.CandidateProfileId"/>
/// and inspect this response — guaranteed safe by construction.
/// </para>
/// </summary>
public sealed record ProfileCreateResponse(
    [property: JsonPropertyName("candidate_profile_id")] string CandidateProfileId,
    [property: JsonPropertyName("request_id")] string? RequestId = null,
    [property: JsonPropertyName("expires_at_unix")] long? ExpiresAtUnix = null,
    [property: JsonPropertyName("result_url")] string? ResultUrl = null,
    [property: JsonPropertyName("status")] string? Status = null,
    [property: JsonPropertyName("profile_id")] string? ProfileId = null,
    [property: JsonPropertyName("reason")] string? Reason = null);

/// <summary>
/// Wire shape for the bootloader's response to
/// <c>GET /v0.4/profile/result/{request_id}</c> (Phase 2.0.B).
///
/// <para>
/// Single-use fetch: the result is removed from the bootloader's
/// in-memory store on read. Caller is responsible for caching the
/// <see cref="ProfileId"/> locally if it needs to reference it after
/// the poll. Note: the Profile row itself persists in
/// master_identity.json and remains discoverable via
/// <c>recto profile list</c> even after this result is consumed —
/// the in-memory result is a derived projection of the on-disk
/// source-of-truth (Milan commitment B).
/// </para>
///
/// <para>
/// Auth: same <c>X-Recto-Agent-Id</c> + <c>X-Recto-Agent-Token</c>
/// headers as the POST endpoint, AND the bootloader pins the
/// request to <c>cap_agent_id</c> at queue time so only the agent
/// that submitted the request can fetch its result. Other agents
/// (with valid auth) get HTTP 404 request_not_found — defense
/// against cross-agent result inspection.
/// </para>
///
/// <para>
/// <see cref="Status"/> values per <see cref="ProfileCreateResultStatus"/>:
/// </para>
/// <list type="bullet">
/// <item><c>approved</c>: operator approved; new profile persisted in
/// master_identity.json. <see cref="ProfileId"/> populated.</item>
/// <item><c>denied</c>: operator declined at the phone.
/// <see cref="Reason"/> carries the operator's note.</item>
/// <item><c>signature_error</c>: phone returned an attestation that
/// didn't verify against the operator pubkey OR the disk write failed.
/// <see cref="Reason"/> carries the diagnostic. If the reason string
/// starts with <c>"persist_error: "</c>, the attestation verified
/// fine but the bootloader couldn't write to master_identity.json
/// (filesystem error / permission denied / disk full). Recovery for
/// persist_error is to fix the host's disk state and retry-with-
/// same-CandidateProfileId; recovery for plain signature_error is to
/// re-prompt the operator on a working phone.</item>
/// <item><c>pending</c>: still waiting for operator action.</item>
/// </list>
///
/// <para>
/// HTTP 404 with <c>error: "request_not_found"</c> is also possible
/// — fires when the request_id has expired (TTL elapsed) OR the
/// fetching agent doesn't own the request. Recovery: re-submit with
/// the same <see cref="ProfileCreateRequest.CandidateProfileId"/> —
/// idempotency-key contract guarantees safe retry.
/// </para>
/// </summary>
public sealed record ProfileCreateResult(
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("profile_id")] string? ProfileId = null,
    [property: JsonPropertyName("reason")] string? Reason = null);

/// <summary>
/// Canonical status values for <see cref="ProfileCreateResult.Status"/>
/// and <see cref="ProfileCreateResponse.Status"/>. Constant strings
/// (NOT an enum) so additive expansion stays backward-compatible per
/// Hard Rule #1.
/// </summary>
public static class ProfileCreateResultStatus
{
    /// <summary>Operator approved on the phone; new Profile persisted
    /// in master_identity.json. <see cref="ProfileCreateResult.ProfileId"/>
    /// carries the new id (equal to the caller's CandidateProfileId
    /// per Milan A).</summary>
    public const string Approved = "approved";

    /// <summary>Operator declined on the phone.
    /// <see cref="ProfileCreateResult.Reason"/> carries the operator's
    /// note.</summary>
    public const string Denied = "denied";

    /// <summary>Phone returned an attestation that didn't verify
    /// against the operator pubkey OR the bootloader's atomic write
    /// to master_identity.json failed.
    /// <see cref="ProfileCreateResult.Reason"/> carries the diagnostic
    /// — check for the <c>"persist_error: "</c> prefix to distinguish
    /// "phone signed wrong" (operator re-prompt) from "disk write
    /// failed" (fix disk + retry-with-same-key).</summary>
    public const string SignatureError = "signature_error";

    /// <summary>Still waiting for the operator to approve or deny on
    /// the phone. Caller polls again after a backoff.</summary>
    public const string Pending = "pending";

    /// <summary>POST-time idempotency hit: a Profile with the
    /// submitted CandidateProfileId already exists on disk. Returned
    /// in the POST response (HTTP 200), NOT the result poll. Operator
    /// phone was NOT re-prompted.</summary>
    public const string AlreadyExists = "already_exists";
}
