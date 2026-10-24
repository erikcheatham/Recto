using System.Text.Json.Serialization;

namespace Recto.Shared.Protocol.V04;

/// <summary>
/// Response shape for <c>GET /v0.4/registration_challenge</c> — the ONE
/// challenge mint the bootloader serves; revocation consumes it like the
/// registration flow does. (This type's doc once named a
/// <c>manage/revoke_challenge</c> endpoint that never existed server-side —
/// defect #4 of the dead revoke lane, found 2026-08-23.) The phone signs the
/// ASCII bytes of <c>{challenge_b64u}:{target_phone_id}</c> and includes the
/// signature in the subsequent <c>POST /v0.4/manage/phones/revoke</c> body.
/// Single-use, short TTL.
/// </summary>
public sealed record RevokeChallengeResponse(
    [property: JsonPropertyName("challenge_b64u")] string ChallengeB64u,
    [property: JsonPropertyName("expires_at_unix")] long ExpiresAtUnix);
