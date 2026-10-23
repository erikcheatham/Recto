using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Recto.Shared.Protocol.V04;

/// <summary>
/// Per-phone audit-log response from <c>GET /v0.4/manage/audit?phone_id=...</c>.
/// Returns the most-recent <c>limit</c> events for the calling phone (default 50).
/// Events are ordered newest-first.
/// </summary>
public sealed record AuditLogResponse(
    [property: JsonPropertyName("events")] IReadOnlyList<AuditEvent> Events);

/// <summary>
/// One row in the per-phone audit log. Captures every approve / deny /
/// sign / TOTP / JWT / WebAuthn / push-rotation event the bootloader has
/// processed for this phone, with enough context to surface meaningful
/// history in the phone-side UI without leaking sensitive payload bytes.
/// </summary>
public sealed record AuditEvent(
    [property: JsonPropertyName("event_id")] string EventId,
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("decision")] string? Decision,
    [property: JsonPropertyName("verified")] bool? Verified,
    [property: JsonPropertyName("service")] string? Service,
    [property: JsonPropertyName("secret")] string? Secret,
    [property: JsonPropertyName("payload_hash_b64u")] string? PayloadHashB64u,
    [property: JsonPropertyName("totp_alias")] string? TotpAlias,
    [property: JsonPropertyName("webauthn_rp_id")] string? WebAuthnRpId,
    [property: JsonPropertyName("recorded_at_unix")] long RecordedAtUnix,
    [property: JsonPropertyName("detail")] string? Detail);

public static class AuditEventKind
{
    /// <summary>A sign / TOTP / JWT / WebAuthn approval was recorded.</summary>
    public const string Approval = "approval";

    /// <summary>The operator denied a pending request.</summary>
    public const string Denial = "denial";

    /// <summary>The phone re-paired (replacing an existing entry).</summary>
    public const string Repair = "repair";

    /// <summary>The phone rotated its push token.</summary>
    public const string PushTokenRotation = "push_token_rotation";

    /// <summary>This phone revoked another phone's registration.</summary>
    public const string PhoneRevoked = "phone_revoked";
}
