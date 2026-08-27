using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Recto.Shared.Protocol.V04;

/// <summary>
/// Per-request context the operator visually confirms before approving.
/// The shape is a flat union: each <see cref="PendingRequest.Kind"/>
/// populates the fields relevant to it and leaves the others null.
/// <para>
/// Common fields (all kinds): <see cref="ChildPid"/>, <see cref="ChildArgv0"/>,
/// <see cref="RequestedAtUnix"/>, <see cref="OperationDescription"/>.
/// </para>
/// <para>
/// <c>single_sign</c> populates <see cref="PayloadHashB64u"/>.
/// </para>
/// <para>
/// <c>totp_provision</c> populates <see cref="TotpAlias"/>,
/// <see cref="TotpSecretB32"/>, and the optional algorithm parameters
/// (<see cref="TotpPeriodSeconds"/>, <see cref="TotpDigits"/>,
/// <see cref="TotpAlgorithm"/>).
/// </para>
/// <para>
/// <c>totp_generate</c> populates <see cref="TotpAlias"/> only; the phone
/// looks up the previously-provisioned secret by alias.
/// </para>
/// <para>
/// <c>session_issuance</c> populates <see cref="SessionBearer"/>,
/// <see cref="SessionScope"/>, <see cref="SessionLifetimeSeconds"/>,
/// <see cref="SessionMaxUses"/>, <see cref="SessionBootloaderId"/>. The
/// phone signs a JWT carrying these as claims and returns it via the
/// <c>session_jwt</c> field on <see cref="RespondRequest"/>.
/// </para>
/// <para>
/// <c>webauthn_assert</c> populates <see cref="WebAuthnRpId"/>,
/// <see cref="WebAuthnOrigin"/>, <see cref="WebAuthnChallengeB64u"/>, and
/// <see cref="WebAuthnUserHandleB64u"/> (optional). Phone constructs a
/// WebAuthn-shaped clientDataJSON + authenticatorData and signs them; the
/// assertion is returned via <see cref="RespondRequest.WebAuthnClientDataB64u"/>,
/// <see cref="RespondRequest.WebAuthnAuthenticatorDataB64u"/>, and the
/// existing <see cref="RespondRequest.SignatureB64u"/> field.
/// </para>
/// <para>
/// <c>eth_sign</c> populates <see cref="EthChainId"/>,
/// <see cref="EthMessageKind"/>, <see cref="EthAddress"/>,
/// <see cref="EthDerivationPath"/>, plus exactly one of
/// <see cref="EthMessageText"/> (for <c>personal_sign</c>),
/// <see cref="EthTypedDataJson"/> (for <c>typed_data</c>), or
/// <see cref="EthTransactionJson"/> (for <c>transaction</c>; reserved for
/// a follow-up). The phone derives the secp256k1 private key from its
/// BIP39 mnemonic via <see cref="EthDerivationPath"/>, computes the
/// EIP-191 / EIP-712 / RLP hash, signs, and returns the result as a
/// 65-byte r||s||v hex string in
/// <see cref="RespondRequest.EthSignatureRsv"/>.
/// </para>
/// <para>
/// <c>btc_sign</c> populates <see cref="BtcNetwork"/>,
/// <see cref="BtcMessageKind"/>, <see cref="BtcAddress"/>,
/// <see cref="BtcDerivationPath"/>, plus exactly one of
/// <see cref="BtcMessageText"/> (for <c>message_signing</c>) or
/// <see cref="BtcPsbtBase64"/> (for <c>psbt</c>; reserved). The phone
/// derives the secp256k1 private key from the SAME BIP-39 mnemonic
/// the eth_sign credential uses (different BIP-44 path tree), computes
/// the BIP-137 hash for <c>message_signing</c> or the relevant PSBT
/// per-input hashes, signs, and returns the 65-byte BIP-137 compact
/// signature base64-encoded in
/// <see cref="RespondRequest.BtcSignatureBase64"/>.
/// </para>
/// </summary>
public sealed record PendingRequestContext(
    [property: JsonPropertyName("child_pid")] int ChildPid,
    [property: JsonPropertyName("child_argv0")] string ChildArgv0,
    [property: JsonPropertyName("requested_at_unix")] long RequestedAtUnix,
    [property: JsonPropertyName("operation_description")] string OperationDescription,
    [property: JsonPropertyName("payload_hash_b64u")] string? PayloadHashB64u = null,
    [property: JsonPropertyName("totp_alias")] string? TotpAlias = null,
    [property: JsonPropertyName("totp_secret_b32")] string? TotpSecretB32 = null,
    [property: JsonPropertyName("totp_period_seconds")] int? TotpPeriodSeconds = null,
    [property: JsonPropertyName("totp_digits")] int? TotpDigits = null,
    [property: JsonPropertyName("totp_algorithm")] string? TotpAlgorithm = null,
    [property: JsonPropertyName("session_bearer")] string? SessionBearer = null,
    [property: JsonPropertyName("session_scope")] IReadOnlyList<string>? SessionScope = null,
    [property: JsonPropertyName("session_lifetime_seconds")] int? SessionLifetimeSeconds = null,
    [property: JsonPropertyName("session_max_uses")] int? SessionMaxUses = null,
    [property: JsonPropertyName("session_bootloader_id")] string? SessionBootloaderId = null,
    [property: JsonPropertyName("webauthn_rp_id")] string? WebAuthnRpId = null,
    [property: JsonPropertyName("webauthn_origin")] string? WebAuthnOrigin = null,
    [property: JsonPropertyName("webauthn_challenge_b64u")] string? WebAuthnChallengeB64u = null,
    [property: JsonPropertyName("webauthn_user_handle_b64u")] string? WebAuthnUserHandleB64u = null,
    // PKCS#11 / PGP (v0.5+): purpose tag (e.g. "ssh-login", "code-signing",
    // "git-commit", "mail-decrypt") drives the operator-UI copy so the human
    // sees what the request is for, not just opaque payload bytes. The
    // pkcs11_consumer_label / pgp_key_label fields surface which downstream
    // consumer the bootloader is sourcing the request from (SSH agent name,
    // GPG keyring entry, etc.) for additional operator context.
    [property: JsonPropertyName("purpose")] string? Purpose = null,
    [property: JsonPropertyName("pkcs11_consumer_label")] string? Pkcs11ConsumerLabel = null,
    [property: JsonPropertyName("pgp_key_label")] string? PgpKeyLabel = null,
    [property: JsonPropertyName("pgp_operation")] string? PgpOperation = null,
    // eth_sign (v0.5+): chain id (1=mainnet, 8453=Base, 11155111=Sepolia, ...),
    // message-kind discriminator (personal_sign / typed_data / transaction),
    // expected signer address (lowercase hex with 0x prefix), BIP32/BIP44
    // derivation path the phone should resolve the signing key from
    // (default "m/44'/60'/0'/0/0"), and exactly one of the three message-
    // body fields. The address field is set by the launcher / consumer at
    // request-creation time so the phone can refuse a request whose
    // derivation path produces a different address (defense against the
    // launcher accidentally crossing wires between two registered ETH
    // addresses on the same phone).
    [property: JsonPropertyName("eth_chain_id")] long? EthChainId = null,
    [property: JsonPropertyName("eth_message_kind")] string? EthMessageKind = null,
    [property: JsonPropertyName("eth_address")] string? EthAddress = null,
    [property: JsonPropertyName("eth_derivation_path")] string? EthDerivationPath = null,
    [property: JsonPropertyName("eth_message_text")] string? EthMessageText = null,
    [property: JsonPropertyName("eth_typed_data_json")] string? EthTypedDataJson = null,
    [property: JsonPropertyName("eth_transaction_json")] string? EthTransactionJson = null,
    // btc_sign (v0.5+): Bitcoin network discriminator
    // (mainnet / testnet / signet / regtest), message-kind discriminator
    // (message_signing / psbt), expected signer address (lowercase
    // bech32 for P2WPKH or Base58Check for legacy / nested-SegWit),
    // BIP32/BIP44 derivation path the phone resolves the signing key
    // from (default `m/84'/0'/0'/0/0` native SegWit), and exactly one
    // of the two message-body fields. The address field is set by the
    // launcher / consumer at request-creation time so the phone can
    // refuse a request whose derivation path produces a different
    // address. SAME mnemonic as eth_sign — different BIP-44 tree.
    [property: JsonPropertyName("btc_network")] string? BtcNetwork = null,
    [property: JsonPropertyName("btc_message_kind")] string? BtcMessageKind = null,
    [property: JsonPropertyName("btc_address")] string? BtcAddress = null,
    [property: JsonPropertyName("btc_derivation_path")] string? BtcDerivationPath = null,
    [property: JsonPropertyName("btc_message_text")] string? BtcMessageText = null,
    [property: JsonPropertyName("btc_psbt_base64")] string? BtcPsbtBase64 = null,
    // Wave-7: Bitcoin-family coin discriminator. Same `btc_sign`
    // credential kind covers BTC + LTC + DOGE + BCH; this field
    // selects which. Absent / null defaults to "btc" for backward
    // compat with v0.5 launchers that pre-date the multi-coin
    // extension. See BtcCoin enum class for valid values.
    [property: JsonPropertyName("btc_coin")] string? BtcCoin = null,
    // Wave-8: Ed25519-chain context (SOL / XLM / XRP). Same `ed_sign`
    // credential kind covers all three; the ed_chain discriminator
    // selects which. ed_message_kind is `message_signing` (the only
    // wired modality today) or `transaction` (reserved). ed_address
    // is the chain-encoded address the operator pre-approved; the
    // phone displays it on the approval card so the human can
    // visually confirm the signing key matches. ed_derivation_path
    // defaults to the chain-canonical SLIP-0010 path when absent.
    // Exactly one of (ed_message_text, ed_payload_hex) must be
    // populated to match ed_message_kind. SAME mnemonic as eth_sign
    // and btc_sign — different SLIP-0010 path tree per chain. Sign
    // side derives via SLIP-0010 ed25519 (NOT BIP-32 secp256k1),
    // hashes the message with the chain-specific preamble, and
    // returns a raw 64-byte ed25519 signature plus the 32-byte
    // public key (XRP needs the explicit pubkey because addresses
    // are HASH160s and don't carry it; SOL and XLM carry it for
    // protocol uniformity).
    [property: JsonPropertyName("ed_chain")] string? EdChain = null,
    [property: JsonPropertyName("ed_message_kind")] string? EdMessageKind = null,
    [property: JsonPropertyName("ed_address")] string? EdAddress = null,
    [property: JsonPropertyName("ed_derivation_path")] string? EdDerivationPath = null,
    [property: JsonPropertyName("ed_message_text")] string? EdMessageText = null,
    [property: JsonPropertyName("ed_payload_hex")] string? EdPayloadHex = null,
    // Wave 9: TRON-specific context. Six optional fields populated
    // only when kind == "tron_sign". Same secp256k1 + Keccak-256
    // primitive as eth_sign; net-new is the TIP-191 preamble +
    // base58check address + SLIP-0044 coin-type 195 BIP-32 path.
    // Address is 34-char T-prefixed base58check (mainnet version
    // byte 0x41; Shasta + Nile testnets share the same byte).
    // tron_message_text is the raw string the operator approves
    // signing; the phone TIP-191-hashes + signs at request time.
    [property: JsonPropertyName("tron_network")] string? TronNetwork = null,
    [property: JsonPropertyName("tron_message_kind")] string? TronMessageKind = null,
    [property: JsonPropertyName("tron_address")] string? TronAddress = null,
    [property: JsonPropertyName("tron_derivation_path")] string? TronDerivationPath = null,
    [property: JsonPropertyName("tron_message_text")] string? TronMessageText = null,
    [property: JsonPropertyName("tron_payload_hex")] string? TronPayloadHex = null,
    // Phase 5 Wave B: capability_request context. Three optional fields
    // populated only when kind == "capability_request". The two
    // <c>cap_*_b64</c> fields are the canonical-JSON-encoded JWS header
    // and payload segments — the phone's signing input is
    // <c>SHA-256(f"{CapHeaderB64}.{CapPayloadB64}".encode("ascii"))</c>
    // which matches <c>CapabilityJws.BuildSigningInput</c>'s output
    // exactly. The phone-side render arm decodes <see cref="CapPayloadB64"/>
    // via <c>CapabilityJws.PayloadToClaims</c> to reconstruct the
    // typed <c>CapabilityClaims</c> for the structured-list approval
    // UI. <see cref="CapAgentId"/> carries the requesting agent's
    // logical identifier (the <c>X-Recto-Agent-Id</c> header value
    // from the queue request) so the operator UI can label which
    // principal is asking. Bootloader binds the envelope hash to the
    // signing-input digest at queue time so the operator's biometric
    // consent on the Ed25519 envelope binds 1:1 to the JWS they sign.
    [property: JsonPropertyName("cap_header_b64")] string? CapHeaderB64 = null,
    [property: JsonPropertyName("cap_payload_b64")] string? CapPayloadB64 = null,
    [property: JsonPropertyName("cap_agent_id")] string? CapAgentId = null,
    // Phase 2.0.B integration: profile_create context. All optional
    // with default null. The candidate fields describe the proposed
    // new child profile under the operator's master; phone responds
    // by signing an attestation over the canonical-JSON encoding of
    // these fields (stashed in <see cref="CapPayloadB64"/> at queue
    // time — same field as capability_request because the signing-
    // input wire shape is identical between the two flows). The
    // signature is returned via <see cref="RespondRequest.CapSignatureB64u"/>
    // — same field as capability_request approval. Bootloader-side
    // dispatch via <see cref="PendingRequest.Kind"/> selects which
    // verifier path runs (recover-to-operator-pubkey-and-mint-JWS
    // for capability_request vs recover-to-operator-pubkey-and-
    // persist-Profile for profile_create).
    //
    // <para><c>candidate_profile_id</c> is the load-bearing idempotency
    // key. CALLER-AUTHORED at submit time (NOT bootloader-assigned at
    // queue time) so that retry-with-same-key against an already-
    // persisted profile is safe by construction. The bootloader's POST
    // endpoint runs an idempotency precheck before queueing: if a
    // Profile with this id already exists on disk, it returns
    // status="already_exists" synchronously without re-prompting the
    // phone.</para>
    [property: JsonPropertyName("candidate_profile_id")] string? CandidateProfileId = null,
    [property: JsonPropertyName("candidate_kind")] string? CandidateKind = null,
    [property: JsonPropertyName("candidate_display_name")] string? CandidateDisplayName = null,
    [property: JsonPropertyName("candidate_derivation_purpose")] long? CandidateDerivationPurpose = null,
    [property: JsonPropertyName("candidate_derivation_coin_type")] int? CandidateDerivationCoinType = null,
    [property: JsonPropertyName("candidate_derivation_index")] int? CandidateDerivationIndex = null,
    [property: JsonPropertyName("candidate_theme_hint")] string? CandidateThemeHint = null,
    [property: JsonPropertyName("candidate_scim_provider")] string? CandidateScimProvider = null,
    // Phase 2.0.C wave C.5: profile_add_device context fields. Phone-
    // rendered approval card displays AddevProfileId (target profile)
    // + AddevNewPhoneId (the device being authorized to act on the
    // profile's behalf) + optional AddevNewPhoneLabel (operator-
    // supplied friendly name like "Pixel 10 Pro Fold"). Signing input
    // (the canonical-JSON encoding of profile_id + new_phone_id +
    // added_at_unix + request_id + master_pubkey_hex) lives in
    // CapPayloadB64; phone signs SHA-256 of those exact bytes with the
    // operator master key. No phone-supplied field needs injection at
    // respond time (unlike profile_create's ChildPubkeyHex).
    [property: JsonPropertyName("addev_profile_id")] string? AddevProfileId = null,
    [property: JsonPropertyName("addev_new_phone_id")] string? AddevNewPhoneId = null,
    [property: JsonPropertyName("addev_new_phone_label")] string? AddevNewPhoneLabel = null,
    // Phase 2.0.C wave C.6: profile_revoke_device context fields.
    // Phone-rendered approval card displays RevdevProfileId (target
    // profile) + RevdevPhoneIdToRevoke (device being removed from
    // device_ids) + optional RevdevRevokerLabel (operator-supplied
    // friendly label for the master device that's signing the
    // revocation, for situational awareness on the approval card).
    // Signing input (canonical-JSON encoding of profile_id +
    // phone_id_to_revoke + revoked_at_unix + request_id +
    // master_pubkey_hex) lives in CapPayloadB64; phone signs SHA-256
    // of those exact bytes with the operator master key. Same shape
    // as profile_add_device's wire — no phone-supplied field at
    // respond time.
    [property: JsonPropertyName("revdev_profile_id")] string? RevdevProfileId = null,
    [property: JsonPropertyName("revdev_phone_id_to_revoke")] string? RevdevPhoneIdToRevoke = null,
    [property: JsonPropertyName("revdev_revoker_label")] string? RevdevRevokerLabel = null,
    // Phase 5 Wave C part 3: AppContext for the phone's approval render.
    // Generic top-level field (NOT capability-specific) so every
    // phone-rendered request kind can carry an app identity. Bootloader
    // injects from `BootloaderConfig.principal_apps` at queue time.
    // Null when no matching registration exists; the phone shows an
    // "Unknown app" warning banner in that case so unregistered agents
    // are visible rather than silently approved.
    //
    // Recto is public-OSS, designed to be used alongside any
    // application. Each consumer registers its AppContext once at
    // deploy time; the bootloader injects matching context into every
    // PendingRequest from that consumer. See
    // <see cref="Recto.Shared.Protocol.V04.AppContext"/> for the
    // canonical wire shape.
    [property: JsonPropertyName("app_context")] AppContext? AppContext = null);

public static class PgpOperation
{
    public const string Sign = "sign";
    public const string Decrypt = "decrypt";
}

public static class Pkcs11Purpose
{
    public const string SshLogin = "ssh-login";
    public const string CodeSigning = "code-signing";
    public const string CertificateRequest = "certificate-request";
}
