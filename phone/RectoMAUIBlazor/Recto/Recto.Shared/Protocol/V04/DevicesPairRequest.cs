using System.Text.Json.Serialization;

namespace Recto.Shared.Protocol.V04;

/// <summary>
/// Wire shape for <c>POST /v0.4/devices/pair</c>: the pairing record the
/// phone signed and the grant that names it. The bootloader verifies the
/// grant against <see cref="DevicesPairRecord.PhonePubkey"/>, checks that
/// <c>cap.scope.payload_sha256</c> equals the record's fingerprint, spends
/// the grant, and relays to the consumer. No auth on the request: the grant
/// is the auth.
///
/// <para>The grant's <c>aud</c> lists both the bootloader id and the
/// consumer's audience; <c>allow_actions</c> is <c>["devices:pair"]</c>;
/// <c>cap.scope.pairing_code</c> may accompany the fingerprint as the
/// human alias.</para>
/// </summary>
public sealed record DevicesPairRequest(
    [property: JsonPropertyName("consumer_base_url")] string ConsumerBaseUrl,
    [property: JsonPropertyName("record")] DevicesPairRecord Record,
    [property: JsonPropertyName("user_jws")] string UserJws);

/// <summary>The pairing record: the canonical tuple every party fingerprints
/// (sorted keys, no whitespace). <see cref="PhonePubkey"/> is 128 lowercase
/// hex (X||Y); <see cref="NotAfter"/> is unix seconds.</summary>
public sealed record DevicesPairRecord(
    [property: JsonPropertyName("bootloader_id")] string BootloaderId,
    [property: JsonPropertyName("user_id")] string UserId,
    [property: JsonPropertyName("phone_pubkey")] string PhonePubkey,
    [property: JsonPropertyName("code")] string Code,
    [property: JsonPropertyName("not_after")] long NotAfter)
{
    /// <summary>Canonical bytes and their SHA-256 hex — the value signed as
    /// <c>cap.scope.payload_sha256</c>.</summary>
    public string Fingerprint()
    {
        var dict = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["bootloader_id"] = BootloaderId,
            ["code"] = Code,
            ["not_after"] = NotAfter,
            ["phone_pubkey"] = PhonePubkey,
            ["user_id"] = UserId,
        };
        var bytes = Recto.Shared.Capability.CanonicalJson.Encode(dict);
        return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)).ToLowerInvariant();
    }
}
