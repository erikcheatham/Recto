using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Recto.Shared.Protocol.V04;

/// <summary>
/// Capability JWT claims per the v0.4 protocol RFC and the v0.5+ universal-vault
/// extension. The same shape covers both bootloader-internal cached sessions
/// (<see cref="Bearer"/> = <c>"bootloader"</c>) and external-agent capabilities
/// (<see cref="Bearer"/> = <c>"agent:&lt;agent-id&gt;"</c>) &mdash; the bootloader
/// verifies signatures identically; only the dispatch (cache vs forward to
/// agent) differs.
/// <para>
/// Phone signs these claims with its enclave key. Wire form is a standard
/// JWT: <c>base64url(header).base64url(claims).base64url(signature)</c>,
/// where the algorithm in the header is <c>EdDSA</c> for Ed25519 phones and
/// <c>ES256</c> (raw R||S, NOT DER, per RFC 7518) for ECDSA P-256 phones.
/// </para>
/// </summary>
public sealed record CapabilityJwtClaims(
    [property: JsonPropertyName("iss")] string Iss,
    [property: JsonPropertyName("sub")] string Sub,
    [property: JsonPropertyName("aud")] string Aud,
    [property: JsonPropertyName("exp")] long Exp,
    [property: JsonPropertyName("iat")] long Iat,
    [property: JsonPropertyName("jti")] string Jti,
    [property: JsonPropertyName("recto:scope")] IReadOnlyList<string> Scope,
    [property: JsonPropertyName("recto:max_uses")] int MaxUses,
    [property: JsonPropertyName("recto:bearer")] string Bearer);

public static class CapabilityBearer
{
    /// <summary>The bootloader caches the JWT internally as a latency optimization.</summary>
    public const string Bootloader = "bootloader";

    /// <summary>Format prefix for external-agent bearers: <c>"agent:&lt;agent-id&gt;"</c>.</summary>
    public const string AgentPrefix = "agent:";
}
