using System.Text.Json.Serialization;

namespace Recto.Shared.Protocol.V04;

/// <summary>
/// Phone -&gt; bootloader revocation request. POSTed to
/// <c>/v0.4/manage/phones/revoke</c>. The surviving phone signs the ASCII
/// bytes of <c>{challenge_b64u}:{target_phone_id}</c> with its enclave key —
/// the colon binding is the anti-replay property: a captured signature for
/// one target cannot be reused against a different target because the
/// payload bytes differ. The bootloader verifies against the revoker's
/// registered public key, then removes <see cref="TargetPhoneId"/> from its
/// registered-phones roster.
/// <para>
/// FIELD NAMES AND ROUTE ARE PINNED BY RevokeContractTests. This type
/// shipped once with its own private contract (route
/// <c>/v0.4/manage/revoke</c>, field <c>revoking_phone_id</c>, bare-challenge
/// signature) against a server that spoke another
/// (<c>/v0.4/manage/phones/revoke</c>, <c>revoker_phone_id</c>, colon-bound
/// signature) — three disagreements, zero errors surfaced, a lane dead on
/// arrival. Found 2026-08-23 when a revoke silently changed nothing.
/// </para>
/// <para>
/// In v0.4.0 a phone can revoke any other phone registered with the same
/// bootloader (single-operator assumption). v0.6+ multi-user models tighten
/// the authorization rules.
/// </para>
/// </summary>
public sealed record RevokeRequest(
    [property: JsonPropertyName("revoker_phone_id")] string RevokerPhoneId,
    [property: JsonPropertyName("target_phone_id")] string TargetPhoneId,
    [property: JsonPropertyName("challenge_b64u")] string ChallengeB64u,
    [property: JsonPropertyName("signature_b64u")] string SignatureB64u);
