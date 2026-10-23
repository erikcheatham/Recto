using System;
using System.Threading;
using System.Threading.Tasks;
using LocalAuthentication;
using Recto.Shared.Services;

namespace Recto.Platforms.iOSImpl;

// ---------------------------------------------------------------------------
// IosBiometricsAvailability — pre-flight biometric check via LAContext.
// ---------------------------------------------------------------------------
//
// Wraps Apple's LocalAuthentication framework's canEvaluatePolicy method to
// answer "is biometric enrolled + ready to use?" WITHOUT triggering a real
// authentication prompt. This is the canonical Apple-blessed way to detect
// availability before invoking a biometric-gated operation.
//
// Banked Build 5 (2026-06-02) to close the Apple App Store rejection gap.
// Build 4 hit OSStatus -25293 during the SecKey keygen call when the
// reviewer's device didn't have biometric enrolled; Build 5 detects this
// state ahead of time and shows actionable guidance instead.
//
// LAError code mapping (per Apple docs):
//   -7: biometryNotEnrolled       → BiometricsStatus.NoneEnrolled
//   -6: biometryNotAvailable      → BiometricsStatus.NoHardware
//   -5: passcodeNotSet            → BiometricsStatus.NoPasscode
//   -8: biometryLockout           → BiometricsStatus.HardwareUnavailable
//   -9: notInteractive            → BiometricsStatus.Unknown (rare)
//   any other → BiometricsStatus.Unknown (fall through)
//
// Simulator behavior (since 2026-08-05, software-key branch removed):
//   - LAContext reports the simulator's "Face ID enrolled" toggle state
//     honestly; there is no special-case early return. Keygen on
//     simulator fails at the Secure Enclave layer by design, so this
//     check reporting real state is the correct, truthful behavior.

public sealed class IosBiometricsAvailability : IBiometricsAvailability
{
    public Task<BiometricsStatus> CheckAsync(CancellationToken ct)
    {
        try
        {
            using var context = new LAContext();
            // .deviceOwnerAuthenticationWithBiometrics: requires biometric.
            // Does NOT fall back to passcode automatically. This matches
            // what IosSecureEnclaveKeyService demands (BiometryCurrentSet
            // ACL flag requires biometric, not passcode).
            var canEvaluate = context.CanEvaluatePolicy(
                LAPolicy.DeviceOwnerAuthenticationWithBiometrics,
                out var error);

            if (canEvaluate)
            {
                return Task.FromResult(BiometricsStatus.Available);
            }

            if (error is null)
            {
                return Task.FromResult(BiometricsStatus.Unknown);
            }

            // Map LAError code. We use the integer code rather than the
            // LAStatus enum because the enum values aren't reliably exposed
            // in older MAUI iOS bindings; the integer codes are stable.
            var code = (int)error.Code;
            return code switch
            {
                -7 => Task.FromResult(BiometricsStatus.NoneEnrolled),   // biometryNotEnrolled
                -6 => Task.FromResult(BiometricsStatus.NoHardware),     // biometryNotAvailable
                -5 => Task.FromResult(BiometricsStatus.NoPasscode),     // passcodeNotSet
                -8 => Task.FromResult(BiometricsStatus.HardwareUnavailable), // biometryLockout
                _  => Task.FromResult(BiometricsStatus.Unknown),
            };
        }
        catch (Exception)
        {
            // LocalAuthentication interop can throw on devices in weird
            // states. Fall through to Unknown — keygen will surface
            // whatever the actual issue is via EnclaveErrors.Translate.
            return Task.FromResult(BiometricsStatus.Unknown);
        }
    }
}
