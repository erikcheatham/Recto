using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Recto.Shared.Protocol.V04;

/// <summary>
/// Bootloader response to <c>GET /v0.4/pending?phone_id=...</c> &mdash;
/// the list of sign requests waiting for operator approval on this phone.
/// Empty list when nothing is pending; the phone polls or wakes from
/// push.
/// </summary>
public sealed record PendingRequestsResponse(
    [property: JsonPropertyName("requests")] IReadOnlyList<PendingRequest> Requests,
    // 2026-09-16 SERVER-SIGNED CARDS: an ES256K JWS by the bootloader's pair key
    // whose cap.scope.payload_sha256 is the SHA-256 of the exact `requests` text
    // on the wire, sub = phone:<this phone>. Null from bootloaders that hold no
    // key. A paired phone that pinned the key renders NO card without it (see
    // Services.BootloaderAttestation.VerifyPendingEnvelope).
    [property: JsonPropertyName("pending_jws")] string? PendingJws = null)
{
    /// <summary>
    /// The `requests` element exactly as received (JsonElement.GetRawText()),
    /// set by the client after parsing; never serialized. This is what the
    /// envelope's digest is over -- re-encoding the typed records would not
    /// reproduce the server's bytes.
    /// </summary>
    [JsonIgnore]
    public string? RequestsRawJson { get; init; }
}
