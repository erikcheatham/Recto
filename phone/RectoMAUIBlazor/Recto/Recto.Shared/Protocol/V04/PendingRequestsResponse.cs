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
    [property: JsonPropertyName("requests")] IReadOnlyList<PendingRequest> Requests);
