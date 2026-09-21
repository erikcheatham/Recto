using System.Threading;
using System.Threading.Tasks;

namespace Recto.Shared.Services;

// ---------------------------------------------------------------------------
// IBiometricsAvailability — pre-flight check for Face ID / Touch ID / Android
// biometric availability BEFORE keygen.
// ---------------------------------------------------------------------------
//
// Banked Build 5 (2026-06-02) to fix Apple App Store rejection of 1.0.1 (4).
// The Secure Enclave keygen path requires biometric enrollment (the
// BiometryCurrentSet ACL flag); without it, keygen fails with OSStatus
// -25293 errSecAuthFailed mid-flow, surfacing a scary raw OSStatus error
// to the user.
//
// The architecturally cleaner fix is to detect availability BEFORE the user
// taps Pair, so we can show a clear "Enable Face ID in Settings" prose
// banner instead of dumping an OSStatus dump after a failed keygen attempt.
//
// Platform mapping:
//   - iOS:     LAContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)
//              + LAError.code (-7 biometryNotEnrolled, -6 biometryNotAvailable,
//              -5 passcodeNotSet, etc.)
//   - Android: BiometricManager.canAuthenticate(BIOMETRIC_STRONG)
//              + BIOMETRIC_ERROR_NONE_ENROLLED / BIOMETRIC_ERROR_NO_HARDWARE
//              / BIOMETRIC_ERROR_HW_UNAVAILABLE
//   - Windows/MacCatalyst: always returns Available (no real biometric
//              integration; software fallback in MauiProgram.cs handles it)
//
// Architectural commitment baked in: Recto Hard Rule #9 (phone enclave as
// root of trust) is preserved — we don't fall back to a non-biometric
// keygen path when biometric is unavailable. Demo mode is the canonical
// exception (no real authority at stake), and it short-circuits the
// biometric requirement at Home.razor's IsDemoPairAttempt branch.

/// <summary>
/// Categorical status of the device's biometric authentication subsystem.
/// </summary>
public enum BiometricsStatus
{
    /// <summary>Biometric enrolled and ready to use. Pairing can proceed.</summary>
    Available,

    /// <summary>Hardware is capable but no biometric is enrolled (no Face ID
    /// face / no fingerprint registered). User must enroll in OS Settings.</summary>
    NoneEnrolled,

    /// <summary>No device passcode / screen lock is set. iOS Secure Enclave
    /// + Android StrongBox both require a device passcode as a prerequisite
    /// for biometric-gated key generation.</summary>
    NoPasscode,

    /// <summary>Biometric hardware is not present on this device (e.g. older
    /// iPad without Face ID, Android device with no fingerprint sensor).
    /// Recto cannot run on this device.</summary>
    NoHardware,

    /// <summary>Biometric hardware is temporarily unavailable (lockout after
    /// too many failed attempts, hardware busy, etc.). User can retry.</summary>
    HardwareUnavailable,

    /// <summary>Cannot determine availability (API call failed, unexpected
    /// state). Pair button should remain enabled; we'll let the keygen path
    /// surface whatever the actual problem is.</summary>
    Unknown,
}

/// <summary>
/// Cross-platform pre-flight check for biometric authentication availability.
/// Implementations should be cheap (microseconds, no UI prompts) so call
/// sites can invoke on every render of the Pair card.
/// </summary>
public interface IBiometricsAvailability
{
    /// <summary>
    /// Check the current biometric availability state. Returns the
    /// categorical status; callers consult <see cref="GetUserMessage"/>
    /// for a user-readable action string when status != Available.
    /// </summary>
    Task<BiometricsStatus> CheckAsync(CancellationToken ct);

    /// <summary>
    /// Translate a status to a user-readable action message. Returns null
    /// for <see cref="BiometricsStatus.Available"/> (no action needed) and
    /// <see cref="BiometricsStatus.Unknown"/> (silent fall-through so
    /// keygen surfaces the actual error).
    /// </summary>
    static string? GetUserMessage(BiometricsStatus status) => status switch
    {
        BiometricsStatus.Available => null,
        BiometricsStatus.NoneEnrolled =>
            "Enroll Face ID, Touch ID, or a fingerprint in your device " +
            "Settings before pairing. Recto uses your biometric to protect " +
            "every signing operation.",
        BiometricsStatus.NoPasscode =>
            "Set a device passcode in your device Settings before pairing. " +
            "Recto requires a passcode + biometric to protect your keys.",
        BiometricsStatus.NoHardware =>
            "This device doesn't have biometric hardware. Recto requires " +
            "Face ID, Touch ID, or a fingerprint sensor to protect your keys.",
        BiometricsStatus.HardwareUnavailable =>
            "Biometric authentication is temporarily unavailable. Unlock your " +
            "device, then tap Pair again.",
        BiometricsStatus.Unknown => null,
        _ => null,
    };
}
