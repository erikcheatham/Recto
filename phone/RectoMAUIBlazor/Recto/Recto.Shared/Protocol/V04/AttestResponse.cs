using System.Text.Json.Serialization;

namespace Recto.Shared.Protocol.V04;

/// <summary>
/// Bootloader response to <c>GET /v0.4/attest?nonce=</c> (2026-09-16): the
/// server proves it holds the signing key the phone pinned at pairing, over
/// a nonce the phone chose. <see cref="Services.BootloaderAttestation"/>
/// verifies it. This is what the phone trusts instead of a TLS leaf pin.
/// </summary>
public sealed record AttestResponse(
    [property: JsonPropertyName("bootloader_id")] string BootloaderId,
    [property: JsonPropertyName("nonce")] string Nonce,
    [property: JsonPropertyName("attest_jws")] string AttestJws,
    [property: JsonPropertyName("devices_pair_pubkey")] string? DevicesPairPubkeyHex = null);
