using System.Text.Json.Serialization;

namespace Recto.Shared.Protocol.V04;

/// <summary>
/// Consumer-supplied display identity of the ACTOR a
/// <c>capability_request</c> was made for — the agent or persona whose
/// name and face the operator recognises — as distinct from the app
/// that delivered it (<see cref="AppContext"/>). Mirror of
/// <c>recto.bootloader.state.ActorContext</c> in Python
/// (wire: <c>context.actor_context</c>, emitted only when the consumer
/// sent an <c>actor</c> object with the request).
///
/// <para>
/// <see cref="AppContext"/> is registered once per consumer and answers
/// "which app is asking". A platform that hosts many agents on one
/// registration cannot say WHICH of its agents is acting: the signed
/// subject carries the agent's id (<c>agent:&lt;id&gt;@user:&lt;id&gt;</c>),
/// which nobody recognises at a glance. This rides per request so the
/// card can put a name and a face beside that id.
/// </para>
///
/// <para>
/// TRANSPORT, NEVER A CLAIM. It is not in the bytes the phone signs, so
/// the render arm treats it as display context only, and shows it only
/// after <see cref="Recto.Shared.Capability.ActorContextCheck"/> finds
/// <see cref="ActorId"/> equal to the signed subject's acting-agent
/// half: a face may decorate the identity the signature names, never
/// stand in for it. A mismatch renders as a warning the stylesheet
/// cannot hide (sign-what-you-see).
/// </para>
/// </summary>
public sealed record ActorContext(
    [property: JsonPropertyName("actor_id")] string ActorId,
    [property: JsonPropertyName("actor_name")] string ActorName,
    [property: JsonPropertyName("actor_icon_url")] string? ActorIconUrl = null);
