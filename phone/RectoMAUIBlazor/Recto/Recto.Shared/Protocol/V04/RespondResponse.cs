using System.Text.Json.Serialization;

namespace Recto.Shared.Protocol.V04;

/// <summary>
/// Bootloader acknowledgment of a phone's response. Just confirms the
/// response was recorded; the actual signature flows back to the
/// supervised child via the launcher's local-socket sign-helper, not
/// through the phone-facing HTTPS surface.
/// </summary>
public sealed record RespondResponse(
    [property: JsonPropertyName("recorded")] bool Recorded);
