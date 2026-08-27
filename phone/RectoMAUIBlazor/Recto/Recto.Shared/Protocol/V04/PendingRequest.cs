using System.Text.Json.Serialization;

namespace Recto.Shared.Protocol.V04;

/// <summary>
/// One pending request the bootloader is waiting on the operator to
/// approve. The <see cref="Kind"/> field discriminates what the
/// request is for; different kinds populate different optional fields
/// on <see cref="PendingRequestContext"/>.
/// </summary>
public sealed record PendingRequest(
    [property: JsonPropertyName("request_id")] string RequestId,
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("service")] string Service,
    [property: JsonPropertyName("secret")] string Secret,
    [property: JsonPropertyName("context")] PendingRequestContext Context);

public static class PendingRequestKind
{
    /// <summary>v0.4 default: phone signs a payload hash with the enclave keypair.</summary>
    public const string SingleSign = "single_sign";

    /// <summary>v0.5: phone imports a TOTP shared secret into local SecureStorage.</summary>
    public const string TotpProvision = "totp_provision";

    /// <summary>v0.5: phone generates a current TOTP code from a previously-provisioned secret.</summary>
    public const string TotpGenerate = "totp_generate";

    /// <summary>v0.5+ (future): bootloader requests an operator-signed JWT capability for itself or an agent.</summary>
    public const string SessionIssuance = "session_issuance";

    /// <summary>
    /// v0.5+: phone produces a WebAuthn-compatible assertion (FIDO2 / RFC 8809)
    /// for a browser-side passkey login. The bootloader stands in as the
    /// authenticator from the relying-party web app's perspective; the phone
    /// produces the actual cryptographic material (clientDataJSON +
    /// authenticatorData + signature). Foundation for the Keycloak-replacement
    /// integration where Recto-equipped users can sign in to web apps via
    /// their phone instead of password + TOTP.
    /// </summary>
    public const string WebAuthnAssert = "webauthn_assert";

    /// <summary>
    /// v0.5+: phone signs an arbitrary payload with its enclave key for
    /// PKCS#11-compatible consumers (SSH agents, OpenSSL-backed code
    /// signers, hardware-token-emulating PKCS#11 modules). Wire-shape is
    /// identical to single_sign but the <c>purpose</c> field on
    /// <see cref="PendingRequestContext"/> distinguishes the use-case so
    /// the operator's UI shows "SSH login to host.example.com" rather than
    /// just "Sign data". Foundation for v0.5+'s real PKCS#11 module on
    /// the bootloader; today the wire format + UI lands.
    /// </summary>
    public const string Pkcs11Sign = "pkcs11_sign";

    /// <summary>
    /// v0.5+: phone signs or decrypts on behalf of a phone-resident PGP
    /// key for git commit signing, encrypted-mail decryption, etc. The
    /// bootloader exposes the phone-resident PGP key via a local
    /// gpg-agent socket; each cryptographic operation flows through this
    /// kind for biometric authorization. Today: protocol DTOs + UI seam;
    /// real gpg-agent socket integration is v0.5+.
    /// </summary>
    public const string PgpSign = "pgp_sign";

    /// <summary>
    /// v0.5+: phone signs an Ethereum-shaped payload with a phone-resident
    /// secp256k1 private key derived from a BIP39 mnemonic. Three message
    /// shapes are supported via <see cref="EthMessageKind"/> in the
    /// per-request context:
    /// <list type="bullet">
    /// <item><c>personal_sign</c> — EIP-191 prefixed message hash. Phone
    /// computes <c>keccak256("\x19Ethereum Signed Message:\n" + len(msg) + msg)</c>
    /// and signs the hash; result is a 65-byte r||s||v signature.</item>
    /// <item><c>typed_data</c> — EIP-712 structured-data hash. Phone computes
    /// the typed-data hash from the JSON spec in
    /// <see cref="PendingRequestContext.EthTypedDataJson"/> and signs it; same
    /// 65-byte r||s||v output shape.</item>
    /// <item><c>transaction</c> — RLP-encoded Ethereum transaction signing
    /// (EIP-1559 / 2930 / legacy). Deferred to a follow-up; protocol space
    /// reserved here so consumers can plan against the field set.</item>
    /// </list>
    /// The operator approves a single signing operation per request. Agent
    /// signing for higher-frequency consumers (e.g. an automation script
    /// invoking ETH actions on behalf of the operator) flows through
    /// <see cref="SessionIssuance"/> capability JWTs whose <c>scope</c>
    /// claims encode a per-operation cap (target contract, method selector,
    /// value cap, gas cap, expiry) — not via direct phone-side approval per
    /// invocation.
    /// </summary>
    public const string EthSign = "eth_sign";

    /// <summary>
    /// v0.5+: phone signs a Bitcoin-shaped payload with a phone-resident
    /// secp256k1 private key derived from the SAME BIP-39 mnemonic the
    /// eth_sign credential uses (different BIP-44 path tree —
    /// <c>m/84'/0'/0'/0/N</c> for native-SegWit P2WPKH default,
    /// <c>m/49'/0'</c> for nested SegWit, <c>m/44'/0'</c> for legacy
    /// P2PKH). Two message shapes are supported via
    /// <see cref="BtcMessageKind"/>:
    /// <list type="bullet">
    /// <item><c>message_signing</c> — BIP-137 compact-signature
    /// signed-message verb. Phone computes
    /// <c>double_sha256("\x18Bitcoin Signed Message:\n" + varint(len(msg)) + msg)</c>,
    /// signs it, and returns a 65-byte base64-encoded compact
    /// signature whose header byte encodes the address kind +
    /// recovery id per BIP-137.</item>
    /// <item><c>psbt</c> — BIP-174 partially-signed Bitcoin transaction.
    /// Reserved for a follow-up. Phone receives a base64-encoded PSBT,
    /// signs the inputs it controls, returns the partially-signed PSBT.</item>
    /// </list>
    /// Same operator-approval ceremony as eth_sign — biometric gate per
    /// signing operation, capability-JWT delegation for agent flows
    /// (target output, value cap, fee cap, expiry).
    /// </summary>
    public const string BtcSign = "btc_sign";

    /// <summary>
    /// v0.6+: phone signs an ed25519-chain payload (Solana, Stellar, or
    /// XRP-ed25519) with a phone-resident ed25519 private key derived
    /// from the SAME BIP-39 mnemonic the eth_sign / btc_sign credentials
    /// use, via SLIP-0010 (NOT BIP-32 — secp256k1 vs ed25519 are
    /// different curves). Three chain trees, all hardened-only paths
    /// because SLIP-0010 ed25519 doesn't support non-hardened derivation:
    /// <list type="bullet">
    /// <item>SOL: <c>m/44'/501'/N'/0'</c> → <c>base58(pubkey32)</c>
    /// addresses (no checksum, Bitcoin alphabet — Phantom / Solflare
    /// convention).</item>
    /// <item>XLM: <c>m/44'/148'/N'</c> → StrKey <c>G…</c> addresses
    /// (RFC-4648 base32 with version byte 0x30 + CRC16-XMODEM checksum,
    /// SEP-0023 / SEP-0005).</item>
    /// <item>XRP-ed25519: <c>m/44'/144'/0'/0'/N'</c> → classic
    /// <c>r…</c> addresses (Ripple-flavored Base58Check + 0xED ed25519
    /// prefix on pubkey pre-image).</item>
    /// </list>
    /// Chain selected via <see cref="PendingRequestContext.EdChain"/>;
    /// message-kind selected via
    /// <see cref="PendingRequestContext.EdMessageKind"/> (currently
    /// only <c>message_signing</c>; <c>transaction</c> is reserved
    /// for a follow-up wave). Approval response carries both the
    /// 64-byte raw ed25519 signature in
    /// <see cref="RespondRequest.EdSignatureBase64"/> AND the 32-byte
    /// ed25519 public key in <see cref="RespondRequest.EdPubkeyHex"/>
    /// because XRP addresses are HASH160s and can't recover the pubkey
    /// (SOL and XLM addresses ARE invertible but carry the pubkey
    /// explicitly for protocol uniformity across the three chains).
    /// </summary>
    public const string EdSign = "ed_sign";

    /// <summary>
    /// Wave 9: TRON signing. The phone holds a secp256k1 BIP-32 tree
    /// at <c>m/44'/195'/0'/0/N</c> (SLIP-0044 coin-type 195) derived
    /// from the SAME BIP-39 mnemonic as <see cref="EthSign"/> /
    /// <see cref="BtcSign"/> / <see cref="EdSign"/>. The phone signs
    /// the TIP-191 hash (structurally identical to EIP-191 with the
    /// preamble swapped to <c>"TRON Signed Message:\n"</c>) and
    /// returns a 65-byte <c>r||s||v</c> hex signature in
    /// <see cref="RespondRequest.TronSignatureRsv"/>. Address is
    /// base58check with version byte 0x41 (T-prefixed, 34 chars).
    /// Operator approval surface in Home.razor displays the network
    /// + derived address + message text.
    /// </summary>
    public const string TronSign = "tron_sign";

    /// <summary>
    /// Phase 5 Wave B: capability-JWT routing. An external agent
    /// (e.g. MyService-side Darwin chatbot) POSTs a proposed
    /// <see cref="Recto.Shared.Capability.CapabilityClaims"/> to
    /// <c>POST /v0.4/capability/request</c>; the bootloader canonical-
    /// JSON-encodes the claims into JWS header_b64 + payload_b64
    /// segments and queues a PendingRequest of this kind. The phone
    /// derives the operator's secp256k1 key from the SAME BIP-39
    /// mnemonic the eth_sign credential uses (same operator identity
    /// for both surfaces) at the default ETH path
    /// (<c>m/44'/60'/0'/0/0</c>), computes
    /// <c>SHA-256(f"{cap_header_b64}.{cap_payload_b64}".encode("ascii"))</c>,
    /// signs the digest, and returns the 64-byte raw <c>r||s</c>
    /// (no <c>v</c> byte — JWS doesn't use recovery) base64url-encoded
    /// in <see cref="RespondRequest.CapSignatureB64u"/>. The bootloader
    /// assembles the final 3-part JWS via
    /// <c>recto.capability.jwt.assemble_jws</c> and stashes it as a
    /// CapabilityResult for the requesting agent to fetch via
    /// <c>GET /v0.4/capability/result/{request_id}</c>.
    /// <para>
    /// As with eth_sign / btc_sign / ed_sign / tron_sign, the phone's
    /// registration-key Ed25519 envelope rides on
    /// <see cref="RespondRequest.SignatureB64u"/> to prove paired-phone
    /// identity. The bootloader binds the envelope hash to the JWS
    /// signing input by setting <c>payload_hash_b64u =
    /// base64url(SHA-256(signing_input))</c> at queue time, so the
    /// operator's biometric consent on the envelope binds 1:1 to the
    /// JWS they sign.
    /// </para>
    /// <para>
    /// Sits in the Identity &amp; Access UI section (NOT Crypto Tokens)
    /// because the approval is a permission grant, not on-chain
    /// movement of value — closer in shape to <see cref="SessionIssuance"/>
    /// or <see cref="WebAuthnAssert"/> than to <see cref="EthSign"/>.
    /// </para>
    /// </summary>
    public const string CapabilityRequest = "capability_request";

    /// <summary>
    /// Phase 2.0.B integration: multi-profile identity creation. A
    /// caller (CLI, SCIM glue, automation) POSTs a candidate Profile
    /// shape (kind / display_name / theme_hint / scim_provider) plus a
    /// <c>candidate_profile_id</c> (caller-authored UUID4 — the
    /// idempotency key) to <c>POST /v0.4/profile/create</c>; the
    /// bootloader resolves the BIP-32 derivation slot, canonical-JSON-
    /// encodes the candidate fields, and queues a PendingRequest of
    /// this kind on the operator's phone. The phone derives the
    /// operator's secp256k1 master key from the SAME BIP-39 mnemonic
    /// the eth_sign / capability_request credentials use, computes
    /// <c>SHA-256(canonical_json(candidate_fields))</c> from
    /// <see cref="PendingRequestContext.CapPayloadB64"/>, signs the
    /// digest, and returns the 64-byte raw <c>r||s</c> base64url-encoded
    /// in <see cref="RespondRequest.CapSignatureB64u"/> (SAME field as
    /// <see cref="CapabilityRequest"/> — phone-side respond logic
    /// doesn't fork). The bootloader verifies the master attestation
    /// recovers to the operator pubkey, then atomic-writes the new
    /// Profile via <c>recto.profile.manage.create_child_profile</c>
    /// using the caller's <c>candidate_profile_id</c> as the canonical
    /// Profile id, and stashes a ProfileCreateResult for the caller
    /// to fetch via <c>GET /v0.4/profile/result/{request_id}</c>.
    /// <para>
    /// Phone-side approval card surfaces: candidate kind (personal:child
    /// / work / school / contractor / custom), display_name, BIP-32
    /// derivation path (purpose / coin_type / index), theme hint, SCIM
    /// provider (if managed), and the operator-supplied
    /// <c>operation_description</c>. The candidate_profile_id and
    /// master_pubkey_hex are part of the signing input but not
    /// front-and-center on the UI — the operator's consent is on the
    /// PROFILE SHAPE, not on the opaque UUID.
    /// </para>
    /// <para>
    /// Partial-failure contract (Milan Jovanović's "use case is a unit
    /// of intent, not a unit of atomicity"):
    /// </para>
    /// <list type="bullet">
    /// <item><c>candidate_profile_id</c> is the load-bearing idempotency
    /// key. Caller-authored at submit time and used end-to-end. A
    /// retry-with-same-key against an already-persisted profile returns
    /// HTTP 200 with status="already_exists" and the existing
    /// profile_id, WITHOUT re-prompting the operator.</item>
    /// <item>Persist-last ordering in the bootloader: verify attestation,
    /// atomic-write to master_identity.json, then store the in-memory
    /// result. The disk state is source-of-truth; the result-store is a
    /// derived projection that can fail without losing the operation.</item>
    /// <item>Status enum stays at five values (approved / denied /
    /// signature_error / pending / already_exists). Disk-write failures
    /// surface as signature_error with reason prefix
    /// <c>"persist_error: &lt;diag&gt;"</c> so callers can distinguish
    /// "phone signed wrong" from "disk write failed" via reason-grep
    /// without forking the enum.</item>
    /// </list>
    /// <para>
    /// Sits in the Identity &amp; Access UI section alongside
    /// <see cref="CapabilityRequest"/>. The approval creates a new
    /// IDENTITY under the operator's master — every future capability
    /// JWS bearing <c>parent_profile=&lt;new profile_id&gt;</c> recovers
    /// to a key derived under this profile's BIP-32 subtree, NOT the
    /// master root key directly.
    /// </para>
    /// </summary>
    public const string ProfileCreate = "profile_create";

    /// <summary>
    /// Phase 2.0.C wave C.5: phone-rendered approval card for appending
    /// a paired device to an existing profile's <c>device_ids</c> tuple.
    /// The master phone (the device holding the operator's BIP-39
    /// mnemonic) signs a master-attestation over the canonical-JSON
    /// encoding of (profile_id, new_phone_id, added_at_unix,
    /// request_id, master_pubkey_hex); bootloader verifies the
    /// attestation against the operator pubkey loaded via
    /// <c>vault_root.json</c> and atomic-writes the appended phone_id
    /// to master_identity.json via
    /// <c>recto.profile.manage.profile_add_device</c>.
    /// <para>
    /// Wire shape simpler than <see cref="ProfileCreate"/> because no
    /// phone-supplied field needs injection at respond time: the full
    /// canonical-JSON signing input is known at queue time and stashed
    /// in <c>cap_payload_b64</c>; the phone signs SHA-256 of those
    /// exact bytes; bootloader verifies against the same SHA-256 at
    /// respond time. No <c>child_pubkey_hex</c>-equivalent field
    /// needed.
    /// </para>
    /// <para>
    /// Idempotency on (profile_id, new_phone_id): re-adding an
    /// already-member phone_id returns HTTP 200 with status=
    /// "already_member" at endpoint pre-flight, no phone prompt fires.
    /// Privilege graph integrity (per Hard Rule #9): the master OR an
    /// already-paired device on the profile signs the attestation;
    /// the new device CANNOT add itself (the new device isn't yet in
    /// device_ids so it has no signing authority over the profile).
    /// v0.5 ships master-only signing; K-of-N quorum across paired
    /// devices is C.6 work.
    /// </para>
    /// <para>
    /// Sits in the Identity &amp; Access UI section alongside
    /// <see cref="ProfileCreate"/> + <see cref="CapabilityRequest"/>.
    /// </para>
    /// </summary>
    public const string ProfileAddDevice = "profile_add_device";

    /// <summary>
    /// Phase 2.0.C wave C.6: phone-rendered approval card for
    /// removing a paired device from an existing profile's
    /// <c>device_ids</c> tuple. The master phone signs a master-
    /// attestation over the canonical-JSON encoding of (profile_id,
    /// phone_id_to_revoke, revoked_at_unix, request_id,
    /// master_pubkey_hex); bootloader verifies + calls
    /// <c>recto.profile.manage.profile_revoke_device</c> to
    /// atomic-write the phone_id removal to
    /// master_identity.json.
    /// <para>
    /// At v1 (this wave): only K=1 master-only signing is wired
    /// end-to-end. Profiles with <c>revoke_quorum_k &gt;= 2</c> are
    /// rejected at the endpoint pre-flight with a
    /// <c>quorum_not_yet_implemented</c> error. K-of-N
    /// signature aggregation is banked for v1.1 alongside the
    /// schema bump that adds secp256k1 pubkeys to non-master phone
    /// registrations (today phones only carry Ed25519 / p256
    /// paired-phone keys, which can't produce secp256k1 master
    /// attestations).
    /// </para>
    /// <para>
    /// Endpoint pre-flight checks include the load-bearing
    /// last-device guard: the profile must have at least 2 devices
    /// in <c>device_ids</c> for any revoke to succeed (revoking the
    /// only paired device would make the profile unreachable).
    /// </para>
    /// <para>
    /// Idempotency contract: if <c>phone_id_to_revoke</c> isn't in
    /// the profile's <c>device_ids</c> tuple at request time, the
    /// endpoint returns HTTP 200 with status=already_not_member
    /// WITHOUT queueing a phone prompt. Sister of
    /// <see cref="ProfileAddDevice"/>'s already_member pattern.
    /// </para>
    /// <para>
    /// Sits in the Identity &amp; Access UI section alongside
    /// <see cref="ProfileCreate"/> + <see cref="ProfileAddDevice"/>
    /// + <see cref="CapabilityRequest"/>.
    /// </para>
    /// </summary>
    public const string ProfileRevokeDevice = "profile_revoke_device";
}

/// <summary>
/// Canonical profile-kind identifiers for
/// <see cref="PendingRequestKind.ProfileCreate"/>. Operators MAY use
/// custom strings (e.g. <c>"personal:throwaway"</c>,
/// <c>"work:contractor"</c>); the v2.0 runtime ships native UI / SCIM
/// federation support for the five canonical kinds below. Custom kinds
/// fall back to a generic phone render and operator-defined
/// deny-action sets.
/// <para>
/// Constant strings (NOT enums) for the same reason capability action
/// keys are strings: new profile types register via manifest / config
/// without enum drift across Recto + consumers + phone-side. Mirrors
/// <c>recto/profile/types.py</c>'s <c>PROFILE_KIND_*</c> constants
/// 1:1.
/// </para>
/// </summary>
public static class ProfileKind
{
    /// <summary>The master profile — root of the hierarchy. Exactly
    /// ONE per master enclave key. Cannot be created via
    /// <see cref="PendingRequestKind.ProfileCreate"/>; the master is
    /// established via <c>recto vault bootstrap</c> at operator-side
    /// install time.</summary>
    public const string PersonalMaster = "personal:master";

    /// <summary>A second personal-tier profile under the same master.
    /// Use cases: public-persona vs private-identity, on-chain
    /// pseudonymity, throwaway profiles. Same trust posture as master;
    /// inherits the master's phone-enclave as root of trust.</summary>
    public const string PersonalChild = "personal:child";

    /// <summary>Employer-bound profile. Provisioned via SCIM or manual
    /// import from Azure AD / Okta / Google Workspace. On employment
    /// termination, SCIM provider revokes the profile; operator's
    /// master is unaffected.</summary>
    public const string Work = "work";

    /// <summary>Educational-institution-bound profile. Provisioned via
    /// the school's SSO or manual federation handshake. Same SCIM-style
    /// scope restrictions as work profiles.</summary>
    public const string School = "school";

    /// <summary>Project-bound profile, like work but per-engagement
    /// rather than per-employer. Multiple contractor profiles can
    /// coexist (one per client). Operator is the SCIM admin (no
    /// external provider).</summary>
    public const string Contractor = "contractor";
}

/// <summary>
/// Discriminator for the three shapes <see cref="PendingRequestKind.EthSign"/>
/// can carry.
/// </summary>
public static class EthMessageKind
{
    /// <summary>EIP-191 prefixed message hash.</summary>
    public const string PersonalSign = "personal_sign";

    /// <summary>EIP-712 structured-data hash.</summary>
    public const string TypedData = "typed_data";

    /// <summary>RLP-encoded transaction signing (EIP-1559 / 2930 / legacy).</summary>
    public const string Transaction = "transaction";
}

/// <summary>
/// Discriminator for the two shapes <see cref="PendingRequestKind.BtcSign"/>
/// can carry.
/// </summary>
public static class BtcMessageKind
{
    /// <summary>BIP-137 compact-signature signed-message verb.</summary>
    public const string MessageSigning = "message_signing";

    /// <summary>BIP-174 partially-signed Bitcoin transaction. Reserved.</summary>
    public const string Psbt = "psbt";
}

/// <summary>
/// Bitcoin network discriminator carried on
/// <see cref="PendingRequestContext.BtcNetwork"/>. Same address bytes
/// derive different bech32 / Base58Check strings depending on the
/// network HRP / version byte, so the phone needs to know which to
/// produce when displaying the expected signing address to the
/// operator.
/// </summary>
public static class BtcNetwork
{
    /// <summary>Bitcoin mainnet — <c>bc1q...</c> P2WPKH addresses, <c>1...</c> legacy.</summary>
    public const string Mainnet = "mainnet";

    /// <summary>Testnet (testnet3) — <c>tb1q...</c> P2WPKH, <c>m...</c>/<c>n...</c> legacy.</summary>
    public const string Testnet = "testnet";

    /// <summary>Signet — shares testnet's HRP / version bytes.</summary>
    public const string Signet = "signet";

    /// <summary>Regtest — local-dev chain with hrp <c>bcrt</c>.</summary>
    public const string Regtest = "regtest";
}

/// <summary>
/// Bitcoin-family coin discriminator carried on
/// <see cref="PendingRequestContext.BtcCoin"/>. The crypto primitives
/// (secp256k1, double-SHA-256, BIP-137, HASH160) are identical across
/// the family; the per-coin differences are the signed-message
/// preamble string, the address-format version bytes / bech32 HRP,
/// and the BIP-44 coin type. All four coins share the
/// <c>btc_sign</c> credential kind, distinguished by this value.
///
/// <para>Defaulting absent / null to <see cref="Bitcoin"/> preserves
/// backward compatibility with v0.5 launchers that pre-date the
/// multi-coin extension.</para>
/// </summary>
public static class BtcCoin
{
    /// <summary>Bitcoin (BTC) — default. <c>m/84'/0'/0'/0/N</c> native
    /// SegWit P2WPKH (<c>bc1q...</c>). Preamble:
    /// <c>"Bitcoin Signed Message:\n"</c>.</summary>
    public const string Bitcoin = "btc";

    /// <summary>Litecoin (LTC) — <c>m/84'/2'/0'/0/N</c> native SegWit
    /// P2WPKH (<c>ltc1q...</c>) with HRP <c>ltc</c>; legacy P2PKH
    /// version byte 0x30 (<c>L...</c>). Preamble:
    /// <c>"Litecoin Signed Message:\n"</c>.</summary>
    public const string Litecoin = "ltc";

    /// <summary>Dogecoin (DOGE) — <c>m/44'/3'/0'/0/N</c> legacy P2PKH
    /// only (<c>D...</c> address starting with version byte 0x1E).
    /// DOGE never adopted native SegWit. Preamble:
    /// <c>"Dogecoin Signed Message:\n"</c>.</summary>
    public const string Dogecoin = "doge";

    /// <summary>Bitcoin Cash (BCH) — <c>m/44'/145'/0'/0/N</c> legacy
    /// P2PKH (<c>1...</c>, same version byte as BTC's legacy). BCH
    /// retained Bitcoin's signed-message preamble post-fork; only
    /// the BIP-44 coin type and forward CashAddr surface differ
    /// (CashAddr deferred — legacy P2PKH still verifies on every
    /// BCH wallet). Preamble:
    /// <c>"Bitcoin Signed Message:\n"</c>.</summary>
    public const string BitcoinCash = "bch";
}

/// <summary>
/// Discriminator for the two shapes <see cref="PendingRequestKind.EdSign"/>
/// can carry.
/// </summary>
public static class EdMessageKind
{
    /// <summary>Recto-convention chain-specific signed-message: SHA-256
    /// of <c>chain-preamble || message_bytes</c>. Today's only wired
    /// modality.</summary>
    public const string MessageSigning = "message_signing";

    /// <summary>Chain-specific transaction-blob hashing (Solana tx hash,
    /// Stellar envelope hash with network passphrase, XRP sha512-half
    /// with TX_PREFIX). Reserved for a follow-up wave.</summary>
    public const string Transaction = "transaction";
}

/// <summary>
/// Ed25519-chain discriminator carried on
/// <see cref="PendingRequestContext.EdChain"/>. The crypto primitive
/// (raw 64-byte ed25519 signature over a 32-byte chain-specific
/// message hash) is identical across the family; per-chain
/// differences are the SLIP-0010 derivation path, the address
/// encoding, and the message preamble. All three chains share the
/// <c>ed_sign</c> credential kind, distinguished by this value.
/// </summary>
public static class EdChain
{
    /// <summary>Solana (SOL) — <c>m/44'/501'/N'/0'</c> SLIP-0010
    /// hardened path; <c>base58(pubkey32)</c> addresses (no checksum,
    /// Bitcoin alphabet — Phantom / Solflare convention). Preamble:
    /// <c>"Solana signed message:\n"</c>.</summary>
    public const string Solana = "sol";

    /// <summary>Stellar (XLM) — <c>m/44'/148'/N'</c> SLIP-0010 hardened
    /// path (SEP-0005); StrKey <c>G…</c> base32 addresses with version
    /// byte 0x30 + CRC16-XMODEM checksum. Preamble:
    /// <c>"Stellar signed message:\n"</c>.</summary>
    public const string Stellar = "xlm";

    /// <summary>XRP (ed25519) — <c>m/44'/144'/0'/0'/N'</c> SLIP-0010
    /// hardened path (Xumm / XRPL ed25519 convention); classic <c>r…</c>
    /// Base58Check addresses (Ripple alphabet) with version byte 0x00,
    /// AccountID = HASH160(0xED || pubkey32). Preamble:
    /// <c>"XRP signed message:\n"</c>.</summary>
    public const string Ripple = "xrp";
}

/// <summary>
/// Discriminator for the two shapes <see cref="PendingRequestKind.TronSign"/>
/// can carry. Wave 9.
/// </summary>
public static class TronMessageKind
{
    /// <summary>TIP-191 prefixed message hash. Today's only wired modality.</summary>
    public const string MessageSigning = "message_signing";

    /// <summary>TRON protobuf-serialized Transaction signing. Reserved
    /// for a follow-up wave when the protobuf parser ships.</summary>
    public const string Transaction = "transaction";
}

/// <summary>
/// TRON network discriminator carried on
/// <see cref="PendingRequestContext.TronNetwork"/>. All three TRON
/// networks share the same address-version byte (0x41) and the same
/// signed-message preamble, so the network distinction lives at the
/// RPC + explorer layer, not the signature layer. We surface it here
/// so the operator UI can label which environment is being signed
/// against ("mainnet" vs "shasta" vs "nile").
/// </summary>
public static class TronNetwork
{
    /// <summary>TRON mainnet.</summary>
    public const string Mainnet = "mainnet";

    /// <summary>Shasta testnet.</summary>
    public const string Shasta = "shasta";

    /// <summary>Nile testnet.</summary>
    public const string Nile = "nile";
}
