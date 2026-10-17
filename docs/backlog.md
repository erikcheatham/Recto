# Recto backlog

Ideas and owed work, newest first. A stacked item is not a commitment; it moves to a release when it is picked.
(`docs/_config.yml` is an allowlist, so this file is not published to the Pages site.)

## Encryption at rest for the bootloader's file-backed vaults (stacked 2026-10-17)

In the container topology (`RECTO_USER_VAULT_SECRET_DIR` and the connections secret dir set), `FileBackedSecretSource` writes
each value as a plaintext JSON file in the bootloader's data volume. That holds for both the connections (application) vault
and the user vault. DPAPI-machine applies only to the foreground Windows-host topology.
- **Today's posture (owner, 2026-10-17):** it stands. The values live in one place, the volume is in no backup lane, and
  anyone who can read the volume already owns the host.
- **Owed before the volume ever joins a backup or snapshot lane:** values encrypted at rest. For example, an envelope key held
  outside the volume (the host's secret store, or a TPM-sealed key), so a copied volume carries only ciphertext.
- **Applies to both vaults.**
- **Related, ruled the same day:** each vault has its own agent token. The user vault is mapped to its own agent identity
  alone, and that identity is in no connections ACL.

## Next phone app updates — Google Play quality requirements (stacked 2026-10-17)

Source: Google Play's 2026-08-26 announcement and its help-center answer 17492799. Play enforces the memory and DEX thresholds
from **February 2027** and Zero-Tap Sign-In from **April 2027**. An app that misses them may lose visibility and publishing
capability on Play.

1. **DEX optimization (at least 25% coverage across optimization, shrinking and obfuscation).**
   - `Recto.csproj` does not set `AndroidLinkTool`. Confirm against a built Release AAB whether R8 is shrinking the Java/DEX
     side; the expectation is that it is not.
   - Set `<AndroidLinkTool>r8</AndroidLinkTool>` for Release Android builds, with keep rules for Firebase Messaging, ML Kit
     barcode scanning and the CameraX bindings. **Carried by the R-series step 3 release (2026-10-17):** r8 is set and
     `Platforms/Android/proguard.cfg` keeps Firebase Messaging and AndroidX Biometric. ML Kit and CameraX are not
     referenced by `Recto.csproj` (commented out), so they get rules when they come back. The device re-test and the Play
     Console read below are still owed.
   - Upload the bundle to an internal track, then read Play Console's new DEX optimization insights for it.
   - Re-run the camera and QR, push wake and StrongBox signing paths on a device: R8 failures show up at runtime, not at build.
2. **Dynamic memory (anonymous RSS + swap) and bitmap memory.**
   - Read the new metrics for `app.recto.phone` in Android vitals, by RAM bucket and app state.
   - The Blazor Hybrid WebView is the likely largest share.
   - Bitmaps must not stay held while the app is in the background or cached: check the QR camera preview, icons and any
     decoded images, and release them on pause.
   - Change something only if a threshold is near; the measurement comes first.
3. **Zero-Tap Sign-In (the Android Restore Credentials API).**
   - **Out of scope (checked 2026-10-17):** the requirement applies to "apps that support sign-in"; the help-center answer
     (17492799) says apps without user accounts are not affected. Recto has no account sign-in, and its keys are generated in
     StrongBox and are non-exportable by design, so a new phone pairs again. Restoring pairing state through the Restore
     Credentials API would also defeat the one-device binding, so Recto should never adopt it.
   - Related, and worth fixing either way: `AndroidManifest.xml` sets `android:allowBackup="true"`. A device-to-device restore
     can bring back pairing records whose keystore aliases do not exist on the new phone. Test the restore, and either exclude
     the pairing store from backup (`dataExtractionRules` / `fullBackupContent`) or make the app treat a record without its key
     as unpaired, with a clear prompt to pair again. **Carried by the R-series step 3 release (2026-10-17):**
     `allowBackup="false"`, with `data_extraction_rules.xml` (API 31+, cloud backup and device transfer) and
     `backup_rules.xml` (API 24-30) excluding every domain. The restore test on a device is still owed.

## Passkeys on both platforms versus Recto's own keys (researched 2026-10-17)

**The standard is common; the ecosystems are not.**
- One WebAuthn server can verify passkeys from both platforms. WebAuthn Level 3 became a W3C Recommendation on 2026-08-25. Its
  backup-eligible / backup-state flags tell a server whether a credential is synced or single-device.
- Below that, each platform keeps its own silo:
  - **Android:** Credential Manager (Jetpack; androidx.credentials 1.6.0). On Android 9–13 it needs Google Play Services;
    Android 14+ uses whatever providers the user installs.
  - **iOS:** AuthenticationServices. Passkeys sync through the iCloud Keychain or an iOS 17+ provider extension. The app needs an
    Associated Domains `webcredentials` entry, whose association file Apple fetches through its own CDN.
  - **Moving passkeys between providers:** the FIDO Credential Exchange Format is a Proposed Standard, and the transfer protocol
    is still a draft. Apple ships export/import in iOS 26; per Bitwarden, Android shipped it in July 2026 through Play Services
    on Android 14+.
- **Attestation:** synced consumer passkeys carry none in practice (`fmt: none`), so nothing proves where the key lives.
  Neither platform gives consumers a device-bound passkey; only enterprise-managed devices or security keys do.

**Recto's raw StrongBox / Secure Enclave key is the better fit for a governance channel, so it stays.**
- It is generated in hardware, non-exportable, and lives on exactly one device behind a biometric gate.
- Android key attestation can prove StrongBox and non-exportability.
- It needs no Play Services, no iCloud, no provider, no hosted domain and no vendor CDN in the trust path.
- Recovery is re-pairing, which is what a governance channel should require.
- A passkey would trade all of that for sync, which is a feature for account sign-in and a defect for Recto.

**Reference only, not planned:**
- If a paired service ever demands proof of app integrity, iOS App Attest is available. It is a second key that Apple's servers
  certify, and it is lost on reinstall or migration, so it adds an Apple dependency. Adopt only on a concrete demand.
- .NET MAUI can reach both stacks: the `Xamarin.AndroidX.Credentials` bindings, and AuthenticationServices in `Microsoft.iOS`.
  Neither is needed for Recto.
- Apple has announced no counterpart to Play's 2027 memory, DEX or sign-in-restore rules. That rests on not finding one, so
  re-check at each iOS release.

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
7. **RULED OUT (owner, 2026-10-17): Recto as a credential provider.** Android 14+ lets an app register as a Credential
   Manager provider, but Recto stays governance-only: a proxy communication channel guaranteed by biometrics, nothing else. It is
   its own app for that reason; holding passkeys or other credentials would make it no longer a governance-only app. Recto
   also does not lean on either store's ecosystem (it is distributed through both, and built so that it does not depend on
   either), so platform credential APIs are weighed for what they cost in independence, not only for what they add.
8. **Not Recto, but related:** AllThruit's own web sign-in could offer passkeys, with the Recto pairing as the
   high-assurance step for sensitive actions (WhatsApp is moving the same way, using passkeys to re-authenticate in-app for
   sensitive actions).
