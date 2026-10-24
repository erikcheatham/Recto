using System.Text.Json.Serialization;

namespace Recto.Shared.Protocol.V04;

/// <summary>
/// Bootloader acknowledgment of a successful revocation. The
/// <see cref="TargetPhoneId"/> echoes back which phone was removed.
/// Pending requests targeting the revoked phone are dropped at the same
/// moment; in-flight requests already-fetched-but-not-responded fail when
/// the surviving phone tries to respond (404 unknown request_id).
/// </summary>
public sealed record RevokeResponse(
    [property: JsonPropertyName("revoked")] bool Revoked,
    [property: JsonPropertyName("target_phone_id")] string TargetPhoneId);
