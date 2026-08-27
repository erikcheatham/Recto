using System.Text.Json.Serialization;

namespace Recto.Shared.Protocol.V04;

/// <summary>
/// Wire shape for <c>POST /v0.4/devices/pair</c> (Phase H end-user
/// device pairing — phone-side surface).
///
/// <para>
/// Submitted by Recto Phone's "Pair a service" UI when an end-user types
/// the 8-char pairing code a downstream consumer minted
/// for them. Different from <see cref="ProfileCreateRequest"/> in two
/// load-bearing ways:
/// </para>
///
/// <list type="bullet">
/// <item>The bootloader does NOT authenticate the incoming request via
/// the agent-token headers used by <c>POST /v0.4/capability/request</c>
/// or <c>POST /v0.4/profile/create</c>. The phone-supplied JWS IS the
/// authentication primitive — the consumer-side verifier recovers the
/// signature against the caller-supplied <see cref="UserPubkeyHex"/>
/// (self-attested model, sister of WebAuthn's "the device proves it
/// holds the key it claims" but without a pre-shared registry).</item>
/// <item>The bootloader is a THIN RELAY — it looks up the consumer's
/// webhook token in its registered-consumers table, POSTs to
/// <c>{ConsumerBaseUrl}/api/v1/devices/pairing/complete</c> with the
/// looked-up <c>X-Openclaw-Token</c> header, and returns the consumer's
/// response verbatim (status + body). No claim parsing happens
/// bootloader-side; the consumer is the authoritative verifier.</item>
/// </list>
///
/// <para>
/// JWS payload shape the phone signs (canonical-JSON of the dict
/// before base64url-encoding):
/// </para>
/// <code>
/// {
///   "iss": "phone:user:&lt;phone_id&gt;",
///   "sub": "user:&lt;master-pubkey-prefix&gt;",
///   "aud": ["&lt;consumer-aud&gt;"],     // the consumer's audience identifier
///   "iat": &lt;now-unix-seconds&gt;,
///   "nbf": &lt;now-unix-seconds&gt;,
///   "exp": &lt;now + 300&gt;,             // 5-min window
///   "jti": "recto-pair-&lt;guid&gt;",
///   "cap": {
///     "tier": 0,
///     "registry_version": "&lt;manifest-version&gt;",
///     "groups": [],
///     "scope": {
///       "env": [], "services": [], "repos": [],
///       "pairing_code": "&lt;8-char-typed-code&gt;"
///     },
///     "allow_actions": ["devices:pair"],
///     "deny_actions": [],
///     "limits": { "per_hour": {}, "per_day": {}, "per_session": {} }
///   },
///   "purpose": "Bind master pubkey to &lt;consumer&gt; via pairing code"
/// }
/// </code>
///
/// <para>
/// Signed with the operator's secp256k1 master key at the canonical ETH
/// derivation path (<c>m/44'/60'/0'/0/0</c>) — same identity primitive
/// the existing capability_request flow uses. One BIP-39 mnemonic, one
/// secp256k1 key, two surfaces (capability JWS + devices:pair JWS).
/// </para>
/// </summary>
public sealed record DevicesPairRequest(
    [property: JsonPropertyName("consumer_base_url")] string ConsumerBaseUrl,
    [property: JsonPropertyName("pairing_code")] string PairingCode,
    [property: JsonPropertyName("user_pubkey_hex")] string UserPubkeyHex,
    [property: JsonPropertyName("user_jws")] string UserJws);
