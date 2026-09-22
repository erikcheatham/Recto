using System;
using Recto.Shared.Protocol.V04;

namespace Recto.Shared.Capability;

/// <summary>
/// The one rule that lets an UNSIGNED actor (name + face) appear beside
/// a SIGNED subject on a capability card (2026-09-22): the actor's id
/// must equal the signed subject's acting-agent half, character for
/// character. Then the name and the face are shown as display context —
/// still transport, still labelled as such. Otherwise the card shows a
/// warning naming both ids and renders the signed subject alone; it
/// never picks one side silently, and never lets the delivering app's
/// choice of face override what the signature says.
///
/// <para>Lives beside <see cref="CapabilityAuditView"/> (not in the page)
/// so the verdict is unit-tested without a render harness; Home.razor
/// consumes it thin.</para>
/// </summary>
public static class ActorContextCheck
{
    public sealed record Verdict(bool Show, string? Name, string? IconUrl, string? Warning)
    {
        public static readonly Verdict None = new(false, null, null, null);
    }

    /// <param name="signedActingAgent">The acting-agent half of the signed
    /// <c>sub</c> as <see cref="CapabilityAuditView.ParseSub"/> returns it
    /// (e.g. <c>agent:&lt;id&gt;</c>).</param>
    /// <param name="actor">The unsigned actor the wire carried, or null.</param>
    public static Verdict Of(string signedActingAgent, ActorContext? actor)
    {
        if (actor is null) return Verdict.None;
        if (string.IsNullOrWhiteSpace(actor.ActorId) || string.IsNullOrWhiteSpace(actor.ActorName))
        {
            return new Verdict(false, null, null,
                "The delivering app named an actor without an id or a name; the signed subject stands alone.");
        }
        if (!string.Equals(actor.ActorId, signedActingAgent, StringComparison.Ordinal))
        {
            return new Verdict(false, null, null,
                $"The delivering app names actor {actor.ActorId} but the signed subject is {signedActingAgent}; " +
                "the face and name are withheld — approve only what the signature names.");
        }
        var icon = actor.ActorIconUrl;
        if (icon is not null &&
            !(icon.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ||
              icon.StartsWith("http://", StringComparison.OrdinalIgnoreCase)))
        {
            icon = null;   // a non-http scheme is not an image the card fetches; the monogram stands in
        }
        return new Verdict(true, actor.ActorName.Trim(), icon, null);
    }
}
