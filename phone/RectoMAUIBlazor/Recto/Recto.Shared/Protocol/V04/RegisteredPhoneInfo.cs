using System.Text.Json.Serialization;

namespace Recto.Shared.Protocol.V04;

/// <summary>
/// One entry in the bootloader's roster of registered phones for an
/// operator. Returned by <c>GET /v0.4/manage/phones?phone_id=...</c>;
/// the calling phone uses this to render its "Registered phones"
/// section so the operator can see what other phones share the
/// bootloader and revoke any that have been lost.
/// </summary>
public sealed record RegisteredPhoneInfo(
    [property: JsonPropertyName("phone_id")] string PhoneId,
    [property: JsonPropertyName("device_label")] string DeviceLabel,
    [property: JsonPropertyName("algorithm")] string Algorithm,
    [property: JsonPropertyName("paired_at")] string PairedAt);
