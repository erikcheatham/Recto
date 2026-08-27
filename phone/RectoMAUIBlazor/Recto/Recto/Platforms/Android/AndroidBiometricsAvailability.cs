using System;
using System.Threading;
using System.Threading.Tasks;
using Android.App;
using AndroidX.Biometric;
using Recto.Shared.Services;

namespace Recto.Platforms.AndroidImpl;

// ---------------------------------------------------------------------------
// AndroidBiometricsAvailability — pre-flight biometric check via
// AndroidX BiometricManager.canAuthenticate.
// ---------------------------------------------------------------------------
//
// Sister of IosBiometricsAvailability for Android. Uses AndroidX's
// BiometricManager (the canonical Jetpack API; not the deprecated
// FingerprintManager) to detect biometric availability without prompting.
//
// We probe with BIOMETRIC_STRONG (Class 3) because AndroidStrongBoxKeyService
// requires it — the StrongBox / TEE-backed key generation in our enclave
// service uses .setUserAuthenticationRequired(true) which Android maps to
// BIOMETRIC_STRONG availability.
//
// BiometricManager.canAuthenticate return codes (per Android docs):
//   BIOMETRIC_SUCCESS                              → Available
//   BIOMETRIC_ERROR_NONE_ENROLLED                  → NoneEnrolled
//   BIOMETRIC_ERROR_NO_HARDWARE                    → NoHardware
//   BIOMETRIC_ERROR_HW_UNAVAILABLE                 → HardwareUnavailable
//   BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED       → HardwareUnavailable
//   BIOMETRIC_ERROR_UNSUPPORTED                    → NoHardware
//   BIOMETRIC_STATUS_UNKNOWN                       → Unknown
//
// Note on the Recto IM-banked gotcha: AndroidStrongBoxKeyService requires
// a secure lockscreen credential. If the device has no PIN / pattern /
// password set, keygen fails with "Secure lock screen must be enabled".
// BiometricManager doesn't have a distinct code for that — BIOMETRIC_ERROR_
// NONE_ENROLLED covers both "no biometric enrolled" and "no lockscreen
// configured." Our EnclaveErrors.Translate maps both to the appropriate
// Android Settings guidance.

public sealed class AndroidBiometricsAvailability : IBiometricsAvailability
{
    public Task<BiometricsStatus> CheckAsync(CancellationToken ct)
    {
        try
        {
            var context = Android.App.Application.Context;
            if (context is null)
            {
                return Task.FromResult(BiometricsStatus.Unknown);
            }

            var manager = BiometricManager.From(context);
            var canAuth = manager.CanAuthenticate(BiometricManager.Authenticators.BiometricStrong);

            return Task.FromResult(canAuth switch
            {
                BiometricManager.BiometricSuccess => BiometricsStatus.Available,
                BiometricManager.BiometricErrorNoneEnrolled => BiometricsStatus.NoneEnrolled,
                BiometricManager.BiometricErrorNoHardware => BiometricsStatus.NoHardware,
                BiometricManager.BiometricErrorHwUnavailable => BiometricsStatus.HardwareUnavailable,
                BiometricManager.BiometricErrorSecurityUpdateRequired => BiometricsStatus.HardwareUnavailable,
                _ => BiometricsStatus.Unknown,
            });
        }
        catch (Exception)
        {
            // BiometricManager interop can throw on older Android versions
            // or weird device states. Fall through to Unknown — keygen will
            // surface whatever the actual issue is via EnclaveErrors.Translate.
            return Task.FromResult(BiometricsStatus.Unknown);
        }
    }
}
