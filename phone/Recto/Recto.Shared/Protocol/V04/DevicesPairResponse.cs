using System.Text.Json;
using System.Text.Json.Serialization;

namespace Recto.Shared.Protocol.V04;

/// <summary>
/// Wire shape returned by <c>POST /v0.4/devices/pair</c>.
///
/// <para>
/// The bootloader relays the consumer's response verbatim — the relay
/// pattern means <see cref="Status"/> mirrors the consumer's HTTP
/// status code (200 on successful pairing, 4xx on consumer-side
/// rejection) and <see cref="Body"/> carries whatever JSON object the
/// consumer returned. The phone surfaces the consumer's diagnostic
/// reasons directly (e.g. <c>pubkey_already_bound</c>,
/// <c>capability_invalid</c>, <c>pairing_code_expired</c>) rather than
/// the bootloader re-interpreting them.
/// </para>
///
/// <para>
/// The bootloader's actual wire field names are
/// <c>consumer_status</c> + <c>consumer_body</c> (the
/// <see cref="JsonPropertyName"/> attributes below map them to the
/// shorter C# property names). The disambiguating prefix emphasises
/// "FROM THE CONSUMER, not the bootloader itself" — the bootloader's
/// own outer HTTP status mirrors the consumer's status so a caller
/// switching on <see cref="System.Net.Http.HttpResponseMessage.StatusCode"/>
/// at the HTTP layer sees the same value. (The bootloader's docstring
/// said <c>{status, body}</c>; that was wrong vs the actual emit at
/// <c>recto/bootloader/server.py</c> around line 2402 — banked as a
/// follow-up polish to the bootloader docstring.)
/// </para>
///
/// <para>
/// Bootloader-side errors (consumer unreachable, consumer returned
/// non-JSON, etc.) come back as the bootloader's own HTTP error
/// response with a body matching the standard <c>{"error": "..."}</c>
/// shape — handled by <see cref="Services.BootloaderClient"/>'s
/// generic <c>SendAsync&lt;T&gt;</c> machinery before this DTO ever
/// gets parsed. Successful return from PairDeviceAsync = bootloader
/// reached the consumer AND parsed a JSON body back; the consumer's
/// status code is what determines pairing success.
/// </para>
/// </summary>
public sealed record DevicesPairResponse(
    [property: JsonPropertyName("consumer_status")] int Status,
    [property: JsonPropertyName("consumer_body")] JsonElement? Body);
