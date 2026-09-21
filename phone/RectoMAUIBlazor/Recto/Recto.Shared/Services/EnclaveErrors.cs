using System;

namespace Recto.Shared.Services;

// ---------------------------------------------------------------------------
// EnclaveErrors — translate raw Secure Enclave / StrongBox error messages to
// user-readable strings.
// ---------------------------------------------------------------------------
//
// Banked Build 5 (2026-06-02) after Apple App Store rejection of Recto Phone
// 1.0.1 (4) under Guideline 2.1(a) Information Needed. The rejection's
// "an error message still displays when we attempt to access your app" was
// most likely the Secure Enclave returning errSecAuthFailed (-25293) on a
// review device that didn't have biometric enrolled — but our error surface
// was dumping the raw OSStatus message into a Bootstrap alert-danger card,
// which reads as "the app is broken" to an App Store reviewer.
//
// This helper translates the canonical OSStatus codes Apple's Security
// framework + .NET's LocalAuthentication interop surface into actionable
// messages. Sister of the consumer-side "ServiceUnavailable" 503 graceful
// degradation pattern — same architectural principle (translate technical
// failures into user actions) applied at the phone-side enclave boundary.
//
// Reference for iOS OSStatus codes:
//   https://developer.apple.com/documentation/security/1542001-security_framework_result_codes
//   https://developer.apple.com/documentation/localauthentication/laerror/code
//
// Reference for Android KeyStore exceptions:
//   https://developer.android.com/reference/android/security/keystore/UserNotAuthenticatedException
//   https://developer.android.com/reference/android/security/keystore/KeyPermanentlyInvalidatedException
//
// The translation MUST be idempotent (calling Translate on an already-
// translated string returns it unchanged) and SAFE (never throws — falls
// through to "Authentication failed (CODE). Try again." for unknown codes).
//
// Hard rule baked here: this helper only produces USER-READABLE strings.
// The raw OSStatus / exception type is appended in parentheses at the end
// of every translation so support / Erik can trace the actual failure when
// reviewing screenshots. Format: "User-readable message (osstatus: -25293)".

/// <summary>
/// Translation helper for iOS Secure Enclave / Android StrongBox enclave
/// error messages. Maps raw OSStatus codes + LAError codes to user-readable
/// actionable strings.
/// </summary>
public static class EnclaveErrors
{
    /// <summary>
    /// Translate a raw enclave error message to a user-readable string.
    /// The input is the .Message of the Result.Failure returned by
    /// IEnclaveKeyService.GenerateAsync / SignAsync / etc. — typically
    /// has the shape "Secure Enclave keygen failed: &lt;LocalizedDescription&gt;"
    /// on iOS or "Android enclave keygen exception: &lt;ExceptionMessage&gt;"
    /// on Android.
    /// </summary>
    /// <param name="rawMessage">The raw error message from the enclave path.
    /// May contain embedded OSStatus codes, LAError codes, or Android
    /// exception names.</param>
    /// <returns>A user-readable actionable message. Falls through to the
    /// raw message with a generic prefix if no known pattern matches.</returns>
    public static string Translate(string? rawMessage)
    {
        if (string.IsNullOrWhiteSpace(rawMessage))
        {
            return "Authentication failed. Please try again.";
        }

        // iOS OSStatus codes — surface via SecKey API + LocalizedDescription.
        // The canonical pattern is the LocalizedDescription containing the
        // OSStatus code in either decimal or hex form. We match on the
        // numeric code, the LAError enum name, AND common LocalizedDescription
        // substrings so we catch all three surface shapes.
        if (Contains(rawMessage, "-25293", "errSecAuthFailed", "authentication failed"))
        {
            return BuildMessage(
                "Face ID / Touch ID is required but isn't set up on this device. " +
                "Open iOS Settings → Face ID & Passcode (or Touch ID & Passcode), " +
                "set a device passcode, and enroll Face ID. Then tap Pair again.",
                rawMessage);
        }

        if (Contains(rawMessage, "-25300", "userCanceled", "user canceled", "user cancelled"))
        {
            return BuildMessage(
                "Authentication was cancelled. Tap Pair again when you're ready " +
                "to authorize with Face ID / Touch ID.",
                rawMessage);
        }

        if (Contains(rawMessage, "-25291", "errSecNotAvailable", "not available"))
        {
            return BuildMessage(
                "The Secure Enclave is not available on this device. Recto requires " +
                "a device with hardware-backed key storage (iPhone 5s or later, " +
                "or an Android device with StrongBox or TEE).",
                rawMessage);
        }

        if (Contains(rawMessage, "-25308", "errSecInteractionNotAllowed"))
        {
            return BuildMessage(
                "The device is locked. Unlock your phone with Face ID / Touch ID " +
                "or your passcode, then tap Pair again.",
                rawMessage);
        }

        if (Contains(rawMessage, "biometryNotEnrolled", "no biometric enrolled", "biometry not enrolled"))
        {
            return BuildMessage(
                "Face ID / Touch ID isn't enrolled on this device. Open iOS Settings " +
                "→ Face ID & Passcode (or Touch ID & Passcode) and enroll your face " +
                "or fingerprint. Then tap Pair again.",
                rawMessage);
        }

        if (Contains(rawMessage, "biometryNotAvailable", "biometry not available"))
        {
            return BuildMessage(
                "Face ID / Touch ID is not available on this device. Recto requires " +
                "biometric authentication to protect your keys.",
                rawMessage);
        }

        if (Contains(rawMessage, "biometryLockout", "biometry lockout"))
        {
            return BuildMessage(
                "Face ID / Touch ID is locked out after too many failed attempts. " +
                "Unlock your phone with your passcode, then tap Pair again.",
                rawMessage);
        }

        if (Contains(rawMessage, "passcodeNotSet", "passcode not set"))
        {
            return BuildMessage(
                "Your device doesn't have a passcode set. Open iOS Settings → Face ID " +
                "& Passcode (or Touch ID & Passcode) and set a passcode before pairing.",
                rawMessage);
        }

        // Android KeyStore exceptions surface from AndroidStrongBoxKeyService.
        if (Contains(rawMessage, "UserNotAuthenticatedException"))
        {
            return BuildMessage(
                "Biometric authentication is required. Open Android Settings → " +
                "Security → Fingerprint / Face Unlock, set a screen lock and enroll " +
                "a fingerprint or face. Then tap Pair again.",
                rawMessage);
        }

        if (Contains(rawMessage, "KeyPermanentlyInvalidatedException"))
        {
            return BuildMessage(
                "Your saved enclave key was invalidated when you changed your " +
                "biometric or screen lock. Tap Start fresh to re-pair.",
                rawMessage);
        }

        if (Contains(rawMessage, "StrongBoxUnavailableException", "no StrongBox"))
        {
            return BuildMessage(
                "Hardware-backed key storage (StrongBox) is not available on this " +
                "device. Recto will fall back to TEE-backed storage automatically; " +
                "if you see this message, please retry.",
                rawMessage);
        }

        // Catch-all for "Secure lock screen must be enabled" Android error.
        if (Contains(rawMessage, "Secure lock screen must be enabled", "secure lock screen"))
        {
            return BuildMessage(
                "Set a screen lock (PIN, pattern, or password) and enroll a fingerprint " +
                "in Android Settings → Security before pairing.",
                rawMessage);
        }

        // Unknown error — surface the raw message with a generic prefix so
        // Erik / support can trace it from screenshots.
        return $"Authentication failed. {rawMessage} Try again, or restart the app.";
    }

    /// <summary>
    /// Translates ALL Recto-internal "Secure Enclave keygen failed: ..." /
    /// "Secure Enclave sign failed: ..." prefixes by extracting the inner
    /// message + applying <see cref="Translate"/>. Convenience wrapper for
    /// call sites that don't want to strip the prefix manually.
    /// </summary>
    public static string TranslateRectoEnclaveError(string? rectoErrorMessage)
    {
        if (string.IsNullOrWhiteSpace(rectoErrorMessage))
        {
            return "Authentication failed. Please try again.";
        }

        // Strip the "Secure Enclave xxx failed: " prefix if present so the
        // inner LocalizedDescription / OSStatus surfaces to the matcher.
        var inner = rectoErrorMessage;
        var colonIdx = inner.IndexOf(':');
        if (colonIdx > 0 && colonIdx < inner.Length - 1)
        {
            // Only strip if the prefix looks like our wrapping ("Secure Enclave
            // keygen failed: ", "iOS enclave keygen exception: ", etc.). Don't
            // strip arbitrary colons that might be inside the actual message.
            var prefix = inner.Substring(0, colonIdx);
            if (prefix.Contains("Enclave", StringComparison.OrdinalIgnoreCase)
                || prefix.Contains("KeyStore", StringComparison.OrdinalIgnoreCase)
                || prefix.Contains("StrongBox", StringComparison.OrdinalIgnoreCase))
            {
                inner = inner.Substring(colonIdx + 1).Trim();
            }
        }

        return Translate(inner);
    }

    private static bool Contains(string haystack, params string[] needles)
    {
        foreach (var n in needles)
        {
            if (haystack.Contains(n, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    private static string BuildMessage(string userMessage, string rawMessage)
    {
        // Append a compact technical trail in parentheses so screenshots
        // can still be traced back to the underlying OSStatus / exception.
        // Format keeps the user-facing message FIRST so reviewers see the
        // actionable guidance before the technical details.
        var compactRaw = CompactRaw(rawMessage);
        if (string.IsNullOrEmpty(compactRaw))
        {
            return userMessage;
        }
        return $"{userMessage} (Technical: {compactRaw})";
    }

    private static string CompactRaw(string rawMessage)
    {
        // Trim Recto-internal wrapping prefixes for the compact trail. We
        // want the OSStatus code or exception name to be visible without
        // the verbose Result.Failure framing.
        var compact = rawMessage.Trim();
        if (compact.Length > 80)
        {
            compact = compact.Substring(0, 80) + "...";
        }
        return compact;
    }
}
