using System.Text.Json.Serialization;

namespace Recto.Shared.Protocol.V04;

/// <summary>
/// Phone -&gt; bootloader push-token rotation body. POSTed to
/// <c>POST /v0.4/manage/push_token</c>. The phone calls this whenever it
/// detects its FCM / APNs token has changed (FCM rotates per Google
/// guidance; APNs tokens can change after restoration from backup or
/// uninstall+reinstall).
/// </summary>
public sealed record PushTokenUpdateRequest(
    [property: JsonPropertyName("phone_id")] string PhoneId,
    [property: JsonPropertyName("push_token")] string PushToken,
    [property: JsonPropertyName("push_platform")] string PushPlatform);

public sealed record PushTokenUpdateResponse(
    [property: JsonPropertyName("updated")] bool Updated,
    [property: JsonPropertyName("phone_id")] string PhoneId);
