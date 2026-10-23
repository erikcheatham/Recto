using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Recto.Shared.Services;

/// <summary>
/// TLS certificate pinning. Stores per-host SPKI hashes; the
/// <see cref="HttpClient"/> handler's
/// <c>ServerCertificateCustomValidationCallback</c> consults this service
/// to decide whether a connection's cert is acceptable.
/// <para>
/// Trust-on-first-use model: the first connection (typically the pairing
/// flow) records the observed pin via <see cref="GetObservedPin"/>; the
/// caller then promotes it to a permanent pin via <see cref="SetPin"/>
/// after successful pairing. Subsequent connections to the same host
/// must present a cert with the matching SPKI hash.
/// </para>
/// </summary>
public interface IPinningService
{
    /// <summary>
    /// Records what the validation callback observed. Called by the handler
    /// for every connection regardless of pin state.
    /// </summary>
    void RecordObserved(string host, string spkiPinB64u);

    /// <summary>
    /// Returns the most recently observed SPKI pin for <paramref name="host"/>,
    /// or null if no connection has been seen yet. Used by the pairing flow
    /// to capture the bootloader's pin after the first connection.
    /// </summary>
    string? GetObservedPin(string host);

    /// <summary>
    /// Sets the verification pin for <paramref name="host"/>. Subsequent
    /// connections to that host MUST present a cert with this SPKI hash;
    /// any mismatch fails validation regardless of system-trust outcome.
    /// </summary>
    void SetPin(string host, string spkiPinB64u);

    /// <summary>
    /// Returns the verification pin for <paramref name="host"/>, or null
    /// if none has been set. When null, validation falls back to the
    /// system trust store.
    /// </summary>
    string? GetPin(string host);

    /// <summary>
    /// Removes the pin for <paramref name="host"/>. Subsequent connections
    /// fall back to system trust. Call on unpair.
    /// </summary>
    void ClearPin(string host);

    /// <summary>
    /// True when the most recently observed SPKI for <paramref name="host"/>
    /// differs from its pin: the certificate in front of the bootloader
    /// changed since pairing. Not a failure by itself (2026-09-16) &mdash;
    /// the caller answers it with <c>GET /v0.4/attest</c> and re-pins on a
    /// verified signature.
    /// </summary>
    bool HasDrifted(string host);

    /// <summary>
    /// Validation entry point called by the HttpClient handler. Returns
    /// true if the connection should be accepted.
    /// <para>
    /// 2026-09-16 semantics (the Cloudflare reissue): a connection is
    /// accepted when the system trust store accepts the chain OR the cert
    /// matches the pin. The pin is an ANCHOR for self-signed LAN
    /// bootloaders, never a lock on a CA-issued leaf &mdash; a leaf is the
    /// CA's lease, and locking it bricked every paired phone on the first
    /// reissue. Server identity is proven above TLS by the bootloader's own
    /// signing key (<see cref="BootloaderAttestation"/>).
    /// </para>
    /// </summary>
    bool Validate(string host, string actualSpki, bool systemTrustOk);

    /// <summary>
    /// Opens the pre-pairing TOFU window for ONE host: while open, a
    /// certificate that is neither pinned nor system-trusted is accepted for
    /// that host only. Recurve 2026-09-25 (fail-open-pinning): the window used
    /// to be implied by "no pin yet" and so stood open for every host, forever.
    /// </summary>
    void BeginPairing(string host);

    /// <summary>Closes the TOFU window. Called from the pairing flow's finally.</summary>
    void EndPairing();
}

/// <summary>
/// Helpers shared by the pinning service and the HttpClient handler.
/// </summary>
public static class CertPinHelpers
{
    /// <summary>
    /// Computes the SPKI pin (SHA-256 of <c>SubjectPublicKeyInfo</c>,
    /// base64url-encoded, no padding) for <paramref name="cert"/>. This
    /// is the canonical "pin" form used by HPKP, Chrome's pinset, etc.
    /// </summary>
    public static string ComputeSpkiPin(X509Certificate2 cert)
    {
        var spki = cert.PublicKey.ExportSubjectPublicKeyInfo();
        var hash = SHA256.HashData(spki);
        var b64 = System.Convert.ToBase64String(hash);
        return b64.TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}
