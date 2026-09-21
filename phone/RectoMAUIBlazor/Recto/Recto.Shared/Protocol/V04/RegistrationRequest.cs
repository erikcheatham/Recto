using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Recto.Shared.Protocol.V04;

/// <summary>
/// Phone -&gt; bootloader registration body. Sent to <c>POST /v0.4/register</c>.
/// </summary>
public sealed record RegistrationRequest(
    [property: JsonPropertyName("phone_id")] string PhoneId,
    [property: JsonPropertyName("device_label")] string DeviceLabel,
    [property: JsonPropertyName("public_key_b64u")] string PublicKeyB64u,
    [property: JsonPropertyName("supported_algorithms")] IReadOnlyList<string> SupportedAlgorithms,
    [property: JsonPropertyName("v0_4_protocol")] int V04Protocol,
    [property: JsonPropertyName("registration_proof")] RegistrationProof RegistrationProof,
    // Optional push-notification token for sub-second wakeup on incoming
    // pending requests. Absent / null means the bootloader falls back to
    // the 3s poll cycle (Windows / Mac Catalyst dev hosts and any phone
    // where push registration failed). Token rotation post-pairing flows
    // through POST /v0.4/manage/push_token.
    [property: JsonPropertyName("push_token")] string? PushToken = null,
    [property: JsonPropertyName("push_platform")] string? PushPlatform = null);

/// <summary>
/// Proof that the phone holds the private key matching <c>public_key_b64u</c> &mdash;
/// it signed the bootloader's one-time challenge.
/// </summary>
public sealed record RegistrationProof(
    [property: JsonPropertyName("challenge")] string Challenge,
    [property: JsonPropertyName("signature_b64u")] string SignatureB64u);
