---
layout: default
title: Support — Recto Agentic
permalink: /support/
---

# Support — Recto Agentic

For bug reports, questions, and feature requests:
[https://github.com/erikcheatham/Recto/issues](https://github.com/erikcheatham/Recto/issues)

---

## Frequently asked questions

### I installed Recto but I have nothing to pair it with. What do I do?

Recto Agentic is the operator-side authenticator for any service that integrates with the Recto substrate. If you don't yet use a service that integrates with Recto, the app waits idle. As services adopt Recto, your existing app installation can pair with them.

### My Face ID / Touch ID is failing during signing approval.

Recto uses your device's Secure Enclave (iOS) or StrongBox keystore (Android) to gate signing. The biometric prompt is from the operating system, not from Recto directly. If the biometric prompt is failing, the issue is typically:

- Your device's biometric template needs to be re-enrolled in Settings.
- Your device's passcode is not set (Secure Enclave requires a passcode to release biometric-gated keys).
- Hardware fault (rare).

Restart the app and try again. If the issue persists, [open an issue](https://github.com/erikcheatham/Recto/issues) with your device model and iOS / Android version.

### Signing requests aren't arriving on my Android device.

Android's Doze mode aggressively suspends background apps. To ensure timely delivery:

- Disable battery optimization for Recto Agentic in **Android Settings → Apps → Recto Agentic → Battery → Unrestricted**.
- Keep the app open in the foreground when you expect imminent signing requests.

For iOS, Apple Push Notification service delivers signing requests even when the app is fully backgrounded.

### I lost my phone. How do I revoke my paired services?

Each paired service maintains its own list of paired devices and can revoke yours from its bootloader. Contact the service you paired with (your platform operator, your homelab admin) and ask them to revoke the device. Recto Agentic has no central revocation service of its own.

### Can I move my pairings to a new phone?

No. Each pairing's private key is generated on the device and bound to its Secure Enclave / StrongBox. The key cannot be exported, so a new phone must be paired with each service individually.

### Is Recto Agentic open source?

Yes. The full source code is published at [github.com/erikcheatham/Recto](https://github.com/erikcheatham/Recto) under the Apache 2.0 license.

### How does Recto differ from Google Authenticator / Authy?

Google Authenticator and Authy generate time-based one-time passwords (TOTP / RFC 6238) for two-factor authentication. Recto performs cryptographic signing operations — the service sends a structured request, Recto signs it with a device-bound private key, and the signed response goes back. Use cases extend beyond 2FA: capability-bounded agent control, deployment approvals, credential release — anything that benefits from "operator phone approves with cryptographic evidence" as the trust primitive.

---

For developers integrating with Recto: [open an issue](https://github.com/erikcheatham/Recto/issues).
