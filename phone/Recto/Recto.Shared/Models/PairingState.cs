using System;
using System.Collections.Generic;

namespace Recto.Shared.Models;

/// <summary>
/// Per-bootloader pairing record persisted across app launches.
/// One pairing per phone in v0.4; multi-bootloader federation is v0.6+.
/// </summary>
/// <param name="PhoneId">Persistent phone identifier (uuid4) the bootloader knows us by.</param>
/// <param name="BootloaderId">The bootloader's id (uuid4) returned during pairing.</param>
/// <param name="BootloaderUrl">HTTPS URL the phone reaches the bootloader at.</param>
/// <param name="ManagedSecrets">Secrets the bootloader said this phone gates.</param>
/// <param name="PairedAt">UTC timestamp of pairing.</param>
/// <param name="BootloaderSpkiPin">
/// Round-6 cert-pinning addition. The SPKI hash (SHA-256 of
/// <c>SubjectPublicKeyInfo</c>, base64url-encoded) of the bootloader's TLS
/// cert as observed during pairing. Subsequent connections MUST present a
/// cert with the same SPKI; mismatch fails validation regardless of
/// system-trust outcome (which is what makes self-signed LAN bootloaders
/// viable post-pairing). Null on pairings made before round 6 landed; the
/// pairing flow falls back to system-trust-only validation in that case.
/// </param>
public sealed record PairingState(
    string PhoneId,
    string BootloaderId,
    string BootloaderUrl,
    IReadOnlyList<ManagedSecretRef> ManagedSecrets,
    DateTimeOffset PairedAt,
    string? BootloaderSpkiPin = null,
    // Build 12 (2026-07-11) multi-URL failover: the bootloader's advertised
    // failover list captured at pairing time (primary first, sanitized —
    // the paired BootloaderUrl is always candidate #0 even if the list
    // omits it). Null on single-instance pairings AND on every pairing
    // persisted before Build 12 (optional param keeps old JSON loading).
    // Failover is SESSION-scoped: connection errors rotate an in-memory
    // index through these; the persisted primary is retried first on the
    // next cold start.
    IReadOnlyList<string>? BootloaderUrls = null,
    // 2026-09-16: the bootloader's signing pubkey captured at pairing (from
    // RegistrationResponse.DevicesPairPubkeyHex). The server identity the
    // phone trusts ABOVE TLS: when the certificate chain drifts, the phone
    // asks /v0.4/attest and accepts only a signature by this key. Null on
    // pairings made before this build and on unsigned bootloaders -- those
    // cannot be re-verified after a certificate change and must re-pair once.
    string? BootloaderPairPubkeyHex = null,
    // 2026-09-21 (hard rule 14.2): the poll key this bootloader
    // recorded at registration (RegistrationResponse.PollPublicKeyB64u); the
    // phone's reads are signed by the key under PollSigning.PollKeyAlias.
    // Nullable only so a demo-mode pairing (no bootloader) constructs; a real
    // pairing is refused without it.
    string? PollPublicKeyB64u = null);

/// <summary>A NAME the phone gates (service + secret name + algorithm) - never a value.</summary>
public sealed record ManagedSecretRef(string Service, string SecretName, string Algorithm);
