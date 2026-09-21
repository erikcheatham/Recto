using System.Text.Json.Serialization;

namespace Recto.Shared.Protocol.V04;

/// <summary>
/// Phone -&gt; bootloader response to a pending request. POSTed to
/// <c>/v0.4/respond/{request_id}</c>. The shape is a flat union of all
/// kind-specific result fields:
/// <list type="bullet">
/// <item><c>single_sign</c> approval populates <see cref="SignatureB64u"/>.</item>
/// <item><c>totp_provision</c> approval has no extra fields (just <see cref="Decision"/>).</item>
/// <item><c>totp_generate</c> approval populates <see cref="TotpCode"/>.</item>
/// <item><c>session_issuance</c> approval populates <see cref="SessionJwt"/>.</item>
/// <item><c>webauthn_assert</c> approval populates <see cref="WebAuthnClientDataB64u"/>,
/// <see cref="WebAuthnAuthenticatorDataB64u"/>, and reuses <see cref="SignatureB64u"/>
/// for the assertion signature over <c>authenticatorData || sha256(clientDataJSON)</c>.</item>
/// <item><c>eth_sign</c> approval populates <see cref="EthSignatureRsv"/> with
/// the 65-byte r||s||v secp256k1 signature as a hex string with <c>0x</c>
/// prefix. The phone is also expected to populate <see cref="SignatureB64u"/>
/// with its registration-key signature over the request body so the
/// bootloader can verify the response came from the paired phone (same
/// guarantee single_sign provides).</item>
/// <item><c>btc_sign</c> approval populates
/// <see cref="BtcSignatureBase64"/> with the 65-byte BIP-137 compact
/// signature (header || r || s) base64-encoded (88 chars typical).
/// Header byte encodes recovery id + intended address kind per BIP-137
/// §"Header byte values". As with eth_sign, <see cref="SignatureB64u"/>
/// is also populated with the phone's registration-key Ed25519
/// envelope so the bootloader proves response provenance.</item>
/// <item><c>ed_sign</c> approval populates
/// <see cref="EdSignatureBase64"/> with the 64-byte raw ed25519
/// chain signature base64-encoded AND <see cref="EdPubkeyHex"/> with
/// the 32-byte ed25519 public key as 64 hex chars (with optional 0x
/// prefix). The pubkey is required because XRP addresses are
/// HASH160s of the pubkey — verifiers can't recover pubkey from an
/// XRP classic address; SOL and XLM addresses ARE invertible but
/// carry the pubkey explicitly for protocol uniformity. As with
/// eth_sign / btc_sign, <see cref="SignatureB64u"/> is also populated
/// with the phone's registration-key Ed25519 envelope.</item>
/// </list>
/// Denial of any kind populates <see cref="Reason"/> instead.
/// </summary>
public sealed record RespondRequest(
    [property: JsonPropertyName("phone_id")] string PhoneId,
    [property: JsonPropertyName("decision")] string Decision,
    [property: JsonPropertyName("signature_b64u")] string? SignatureB64u = null,
    [property: JsonPropertyName("totp_code")] string? TotpCode = null,
    [property: JsonPropertyName("session_jwt")] string? SessionJwt = null,
    [property: JsonPropertyName("reason")] string? Reason = null,
    [property: JsonPropertyName("webauthn_client_data_b64u")] string? WebAuthnClientDataB64u = null,
    [property: JsonPropertyName("webauthn_authenticator_data_b64u")] string? WebAuthnAuthenticatorDataB64u = null,
    [property: JsonPropertyName("eth_signature_rsv")] string? EthSignatureRsv = null,
    [property: JsonPropertyName("btc_signature_base64")] string? BtcSignatureBase64 = null,
    [property: JsonPropertyName("ed_signature_base64")] string? EdSignatureBase64 = null,
    [property: JsonPropertyName("ed_pubkey_hex")] string? EdPubkeyHex = null,
    // Wave 9: TRON 65-byte r||s||v secp256k1 signature, hex-encoded
    // with optional 0x prefix (130 hex chars after prefix). Set only
    // when responding to a tron_sign approval; null otherwise. Same
    // shape as EthSignatureRsv since both chains share the secp256k1
    // + low-s + canonical-v pipeline. Bootloader structure-checks
    // (130 hex chars, valid hex) and forwards opaque to the
    // consumer; signer-address recovery happens consumer-side via
    // recto.tron.recover_address.
    [property: JsonPropertyName("tron_signature_rsv")] string? TronSignatureRsv = null,
    // Phase 5 Wave B: capability_request 64-byte raw r||s secp256k1
    // signature, base64url-encoded WITHOUT padding. Set only when
    // responding to a capability_request approval; null otherwise.
    // NOTE the shape difference vs EthSignatureRsv / TronSignatureRsv
    // (those are 65-byte r||s||v hex strings): JWS ES256K (RFC 8812)
    // uses the 64-byte raw r||s form, no recovery byte — the
    // verifier knows the signer's pubkey upfront so it doesn't need
    // a recovery hint, and base64url is the JWS-spec encoding. The
    // bootloader assembles the final 3-part JWS by concatenating
    // <c>{cap_header_b64}.{cap_payload_b64}.{cap_signature_b64u}</c>
    // and stashes it as a CapabilityResult for the requesting agent
    // to fetch.
    [property: JsonPropertyName("cap_signature_b64u")] string? CapSignatureB64u = null,
    // Phase 2.0.C wave C.1: profile_create derived child pubkey, hex-
    // encoded (128 chars, accepts optional 0x / 0x04 prefix; bootloader
    // strips before validation). REQUIRED on every profile_create
    // approval — the phone derives this from the master mnemonic at
    // the candidate's BIP-32 path and signs over the FULL canonical
    // JSON (queue-time candidate fields + this pubkey). Bootloader
    // rejects with `protocol_violation` if absent on a profile_create
    // approval. Null for every other PendingRequest kind. Sister
    // field to CapSignatureB64u above — both populated together when
    // approving a profile_create request. See recto/profile/SPEC.md
    // Phase 2.0.C wave C.1 for the wire-shape rationale.
    [property: JsonPropertyName("child_pubkey_hex")] string? ChildPubkeyHex = null);

public static class RespondDecision
{
    public const string Approved = "approved";
    public const string Denied = "denied";
}
