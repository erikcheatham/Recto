using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Recto.Shared.Protocol.V04;

/// <summary>
/// Bootloader response to <c>POST /v0.4/register</c> &mdash; pairing confirmation
/// plus the list of secrets the operator has authorized this phone to gate.
/// </summary>
public sealed record RegistrationResponse(
    [property: JsonPropertyName("registered")] bool Registered,
    [property: JsonPropertyName("phone_id")] string PhoneId,
    [property: JsonPropertyName("bootloader_id")] string BootloaderId,
    [property: JsonPropertyName("managed_secrets")] IReadOnlyList<ManagedSecretInfo> ManagedSecrets,
    // Build 12 (2026-07-11, wave-C consumer): the bootloader's advertised
    // failover URL list, primary first. Emitted only when the deployment
    // configures `public_urls` (load-balanced production); omitted by
    // single-instance bootloaders -> null here, and the phone keeps the
    // single paired URL it already has.
    [property: JsonPropertyName("bootloader_urls")] IReadOnlyList<string>? BootloaderUrls = null,
    // GATE 5b phone-recomputation half: the derivation inputs that produced
    // BootloaderId, emitted by bootloaders whose id is DERIVED (rb1-...).
    // Additive like BootloaderUrls: older bootloaders omit it -> null. An
    // rb1- id arriving WITHOUT this field is refused at pairing (the id
    // claims to be recomputable and denies the phone the inputs), see
    // Services/BootloaderIdentity.Check.
    [property: JsonPropertyName("bootloader_identity")] BootloaderIdentityInfo? Identity = null,
    // 2026-09-16 (additive): the bootloader's own secp256k1 signing pubkey
    // (128 hex, uncompressed X||Y). The phone pins THIS instead of the TLS
    // leaf: a certificate change is answered by GET /v0.4/attest, signed by
    // this key. Null from bootloaders that hold no signing key.
    [property: JsonPropertyName("devices_pair_pubkey")] string? DevicesPairPubkeyHex = null,
    // 2026-09-21 (rule 14.2): the poll key this bootloader RECORDED -- echoed
    // back so the phone signs reads only with a key the registry will verify.
    // The pairing flow refuses a response whose echo is not the key it sent.
    [property: JsonPropertyName("poll_public_key_b64u")] string? PollPublicKeyB64u = null,
    // 2026-09-21 (hard rule 14.4): the slot this registration holds, and -- on
    // a displacement -- the phone_ref that left it.
    [property: JsonPropertyName("slot")] string? Slot = null,
    [property: JsonPropertyName("displaced_phone_ref")] string? DisplacedPhoneRef = null,
    // THE REPLACEMENT QUESTION: a 409 slot_occupied parses into this same
    // record with Registered=false, Error="slot_occupied" and the occupant the
    // operator is asked about. BootloaderClient passes that one 409 through.
    [property: JsonPropertyName("error")] string? Error = null,
    [property: JsonPropertyName("occupant")] SlotOccupant? Occupant = null);

/// <summary>The phone holding a slot the incoming phone asked for (hard rule 14.4).</summary>
public sealed record SlotOccupant(
    [property: JsonPropertyName("phone_ref")] string PhoneRef,
    [property: JsonPropertyName("device_label")] string DeviceLabel,
    [property: JsonPropertyName("last_seen_unix")] long LastSeenUnix,
    [property: JsonPropertyName("registered_at_unix")] long RegisteredAtUnix);

/// <summary>
/// The key set a derived bootloader id is computed from. Public keys only —
/// the phone recomputes the id from these and refuses a mismatch.
/// </summary>
public sealed record BootloaderIdentityInfo(
    [property: JsonPropertyName("derivation")] string Derivation,
    [property: JsonPropertyName("operator_pubkey_b64u")] string OperatorPubkeyB64u,
    [property: JsonPropertyName("member_pubkeys_b64u")] IReadOnlyList<string> MemberPubkeysB64u);

/// <summary>
/// A secret this phone GATES, by name: which service, which secret name, which
/// algorithm. The value never crosses this wire (recurve 2026-09-25 renamed the
/// field from <c>secret</c> so the shape says so; the bootloader emits an empty
/// list until the launcher side wires services to phones).
/// </summary>
public sealed record ManagedSecretInfo(
    [property: JsonPropertyName("service")] string Service,
    [property: JsonPropertyName("secret_name")] string SecretName,
    [property: JsonPropertyName("algorithm")] string Algorithm);
