using System.Text.Json.Serialization;

namespace Recto.Shared.Protocol.V04;

/// <summary>
/// Wire shape for <c>POST /v0.4/devices/unpair</c> (Phase H per-service
/// unpair — the cryptographic teardown completing the local-only removal
/// Build 6 shipped). Sister of <see cref="DevicesPairRequest"/>: same
/// thin-relay body triple, same self-attested verification model. The
/// bootloader looks up the consumer's webhook token, POSTs to
/// <c>{ConsumerBaseUrl}/api/v1/devices/pairing/revoke</c> with
/// <c>{masterPubkeyHex, capabilityJws}</c>, and returns the consumer's
/// response verbatim. The consumer recovers the signature against the
/// master pubkey currently bound on the user row (commitment #11,
/// one-pubkey-one-user) and NULLs the binding on a match.
///
/// <para>
/// JWS payload shape the phone signs (identical to the pair JWS except
/// the action + no <c>pairing_code</c>):
/// </para>
/// <code>
/// {
///   "iss": "phone:user:&lt;phone_id&gt;",
///   "sub": "user:&lt;master-pubkey-prefix&gt;",
///   "aud": ["&lt;consumer-aud&gt;"],
///   "iat": &lt;now&gt;, "nbf": &lt;now&gt;, "exp": &lt;now + 300&gt;,
///   "jti": "recto-unpair-&lt;guid&gt;",
///   "cap": {
///     "tier": 0, "registry_version": "&lt;manifest-version&gt;",
///     "groups": [],
///     "scope": { "env": [], "services": [], "repos": [] },
///     "allow_actions": ["devices:pairing_revoke"],
///     "deny_actions": [],
///     "limits": { "per_hour": {}, "per_day": {}, "per_session": {} }
///   },
///   "purpose": "Unbind master pubkey from &lt;consumer&gt;"
/// }
/// </code>
/// Signed with the same secp256k1 master key at <c>m/44'/60'/0'/0/0</c>.
/// </summary>
public sealed record DevicesUnpairRequest(
    [property: JsonPropertyName("consumer_base_url")] string ConsumerBaseUrl,
    [property: JsonPropertyName("user_pubkey_hex")] string UserPubkeyHex,
    [property: JsonPropertyName("user_jws")] string UserJws);

/// <summary>
/// Bootloader relay response for <c>POST /v0.4/devices/unpair</c>. The
/// bootloader relays the consumer's HTTP status + parsed JSON body
/// verbatim (sister of <see cref="DevicesPairResponse"/>).
/// </summary>
public sealed record DevicesUnpairResponse(
    [property: JsonPropertyName("consumer_status")] int Status,
    [property: JsonPropertyName("consumer_body")] System.Text.Json.JsonElement? Body);
