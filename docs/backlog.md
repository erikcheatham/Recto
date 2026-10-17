# Recto backlog

Ideas and owed work, newest first. A stacked item is not a commitment; it moves to a release when it is picked.
(`docs/_config.yml` is an allowlist, so this file is not published to the Pages site.)

## Next phone app updates — Google Play quality requirements (stacked 2026-10-17)

Source: Google Play's 2026-08-26 announcement and its help-center answer 17492799. Play enforces the memory and DEX thresholds
from **February 2027** and Zero-Tap Sign-In from **April 2027**. An app that misses them may lose visibility and publishing
capability on Play.

1. **DEX optimization (at least 25% coverage across optimization, shrinking and obfuscation).**
   - `Recto.csproj` does not set `AndroidLinkTool`. Confirm against a built Release AAB whether R8 is shrinking the Java/DEX
     side; the expectation is that it is not.
   - Set `<AndroidLinkTool>r8</AndroidLinkTool>` for Release Android builds, with keep rules for Firebase Messaging, ML Kit
     barcode scanning and the CameraX bindings.
   - Upload the bundle to an internal track, then read Play Console's new DEX optimization insights for it.
   - Re-run the camera and QR, push wake and StrongBox signing paths on a device: R8 failures show up at runtime, not at build.
2. **Dynamic memory (anonymous RSS + swap) and bitmap memory.**
   - Read the new metrics for `app.recto.phone` in Android vitals, by RAM bucket and app state.
   - The Blazor Hybrid WebView is the likely largest share.
   - Bitmaps must not stay held while the app is in the background or cached: check the QR camera preview, icons and any
     decoded images, and release them on pause.
   - Change something only if a threshold is near; the measurement comes first.
3. **Zero-Tap Sign-In (the Android Restore Credentials API).**
   - The requirement covers apps that support user sign-in. Recto has no account sign-in, and its signing keys are generated in
     StrongBox and are non-exportable by design, so a new phone pairs again. Confirm against the help-center wording that Recto
     is out of scope, and record the answer here.
   - Related, and worth fixing either way: `AndroidManifest.xml` sets `android:allowBackup="true"`. A device-to-device restore
     can bring back pairing records whose keystore aliases do not exist on the new phone. Test the restore, and either exclude
     the pairing store from backup (`dataExtractionRules` / `fullBackupContent`) or make the app treat a record without its key
     as unpaired, with a clear prompt to pair again.

## Lessons from WhatsApp's passkey rollout (stacked 2026-10-17)

Source: the Android Developers blog, 2026-08-27, "How WhatsApp Upgraded to Secure, Seamless Sign-In for 1 Billion Users with
Passkeys"; the Credential Manager passkey guide; Google's server-registration guide.

**How passkeys work, in brief.** A passkey is a key pair. The private half stays with the user's credential provider (Google
Password Manager, iCloud Keychain), unlocked by the screen lock or biometrics. The server keeps only the public key. The server
runs two WebAuthn ceremonies, each split into Begin and Finish:
- **Registration.** *Begin*: look up the user's existing credentials, reuse or mint a user handle, generate the creation
  options and a challenge, list the user's existing credential IDs as `excludeCredentials` (so a device does not enroll
  twice), and store the challenge with a short TTL. *Finish*: load the challenge (it must exist and be unexpired), verify the
  attestation, index credential_id → account, then append the credential (evicting the oldest past a cap) or replace it.
- **Authentication.** *Begin*: list the user's valid credentials, generate request options and a challenge, and store it with a
  short TTL. *Finish*: verify the assertion against the challenge and credentials. Require user verification, refresh the
  stored credential when the library says it needs an update (for example the sign counter), and mark it used.
- WhatsApp's server does the cryptography in a library (Rust `webauthn-rs`) and keeps its own code to orchestration, storage,
  eligibility, rate limits and lifecycle.

**What Recto can take from it.** Recto's pairing and signing are the same shape (a phone-held key, a server-issued challenge, a
verified signature), so most of their lessons transfer:
1. **An error taxonomy.** Sort every KeyStore, BiometricPrompt and Credential Manager exception into *recoverable* (retry,
   prompt again, wait for connectivity) or *terminal* (fall back, or re-pair), each with one defined path, so a failed flow never
   leaves the user stuck. `Recto.csproj` already notes a KeyStore-exception → message mapping; extend it to that two-way split.
2. **An eligibility funnel before pairing.** Check, up front: a screen lock is set, StrongBox and biometrics are present, Play
   Services is current enough for FCM, and the OS version. Turn an ineligible device away with a reason before the flow starts,
   not halfway through it. `AndroidBiometricsAvailability.cs` is the start of this.
3. **Challenge hygiene.** Every challenge is single use, short TTL, and bound to the account and the ceremony. Check the
   bootloader's pairing and signing endpoints hold all three. (The connections/act grant is already single use.)
4. **Several devices per paired service.** A bounded list of phone keys per tenant account, oldest evicted past a cap, so a
   second phone or a replacement phone is just another key, plus lifecycle states and background cleanup for keys unused for a
   long time. Too aggressive forces needless re-pairing; too lenient lets stale keys pile up.
5. **A new phone generates a new key.** WhatsApp dropped the QR + Bluetooth cross-device flow as unreliable and confusing, and
   has users make a fresh passkey on the new platform instead. That is already Recto's model (a key never leaves its phone); it
   argues against ever building key sync or export.
6. **Test across OS versions and OEMs.** WhatsApp hit device-specific exceptions on Android 13 and 14. Keep a device matrix
   (Android 13, 14, 15+, Pixel and Samsung at least) for the signing path, and watch error telemetry after each OS update.
7. **Idea: Recto as a credential provider.** Android 14+ lets an app register as a Credential Manager *provider*. A Recto
   phone could hold passkeys for the services it already signs for, under the same StrongBox + biometric gate. This is a large
   piece of work; stacked as an idea, not planned.
8. **Not Recto, but related:** AllThruit's own web sign-in could offer passkeys, with the Recto pairing as the
   high-assurance step for sensitive actions (WhatsApp is moving the same way, using passkeys to re-authenticate in-app for
   sensitive actions).
