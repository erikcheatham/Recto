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
    [property: JsonPropertyName("bootloader_identity")] BootloaderIdentityInfo? Identity = null);

/// <summary>
/// The key set a derived bootloader id is computed from. Public keys only —
/// the phone recomputes the id from these and refuses a mismatch.
/// </summary>
public sealed record BootloaderIdentityInfo(
    [property: JsonPropertyName("derivation")] string Derivation,
    [property: JsonPropertyName("operator_pubkey_b64u")] string OperatorPubkeyB64u,
    [property: JsonPropertyName("member_pubkeys_b64u")] IReadOnlyList<string> MemberPubkeysB64u);

public sealed record ManagedSecretInfo(
    [property: JsonPropertyName("service")] string Service,
    [property: JsonPropertyName("secret")] string Secret,
    [property: JsonPropertyName("algorithm")] string Algorithm);
