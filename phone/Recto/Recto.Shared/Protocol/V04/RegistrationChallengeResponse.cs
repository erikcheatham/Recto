using System.Text.Json.Serialization;

namespace Recto.Shared.Protocol.V04;

/// <summary>
/// Bootloader response to <c>GET /v0.4/registration_challenge</c>.
/// </summary>
public sealed record RegistrationChallengeResponse(
    [property: JsonPropertyName("challenge_b64u")] string ChallengeB64u,
    [property: JsonPropertyName("expires_at_unix")] long ExpiresAtUnix);
