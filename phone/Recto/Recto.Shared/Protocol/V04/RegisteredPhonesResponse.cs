using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Recto.Shared.Protocol.V04;

/// <summary>
/// Response shape for <c>GET /v0.4/manage/phones?phone_id=&lt;self&gt;</c>.
/// Lists every phone OTHER than the requesting phone that's registered
/// for the same bootloader (the requester already knows about itself).
/// </summary>
public sealed record RegisteredPhonesResponse(
    [property: JsonPropertyName("phones")] IReadOnlyList<RegisteredPhoneInfo> Phones);
