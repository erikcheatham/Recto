---
layout: default
title: Recto Agentic
permalink: /
---

# Recto Agentic

**The phone signing vault for agents — your phone as the root of trust for cryptographic signing.**

Multi-tenant authenticator app — like Authy for OTP, but for cryptographic
signing operations. One Recto Agentic install on your device, paired with as
many services as you use, each authorizing its own actions through your
operator approval.

---

## Get the app

[<img src="/Recto/assets/badge-app-store.svg" alt="Download Recto Agentic on the App Store" height="54">](https://apps.apple.com/us/app/recto-agentic/id6771544174)&nbsp;
[<img src="/Recto/assets/badge-google-play.svg" alt="Get Recto Agentic on Google Play" height="54">](https://play.google.com/store/apps/details?id=app.recto.phone)

- **iOS / iPadOS** — [Apple App Store](https://apps.apple.com/us/app/recto-agentic/id6771544174)
- **Android** — [Google Play](https://play.google.com/store/apps/details?id=app.recto.phone)

---

## How it works

Recto Agentic is the operator-side authenticator for any service that
integrates with the **Recto substrate**. When a paired service needs you
to authorize a sensitive operation — approve a deployment, release a
stored credential, authorize a configuration change — its bootloader
sends Recto a structured request, you read what's being asked, and you
approve via Face ID / Touch ID / fingerprint.

The private key gating the signature lives in your device's Secure
Enclave (iOS) or StrongBox keystore (Android) and never leaves your
device.

---

## Security posture

- Private keys never leave the Secure Enclave / StrongBox
- Biometric is hardware-bound and never leaves your device
- Zero analytics, advertising, or third-party data-collection SDKs
- Open-source under Apache 2.0 — auditable end-to-end
- Cross-device verification of trust artifacts via QR codes
- Pairing is local-network or HTTPS only — no central Recto cloud

---

## Pages

- [Privacy Policy](/Recto/privacy/) — what data the app does and doesn't handle
- [Support](/Recto/support/) — FAQ and issue-reporting

---

## For developers

**Recto Agentic** is the mobile app. **Recto** is the codebase it pairs
with — a public OSS project (Apache 2.0) implementing
operator-phone-as-root-of-trust authorization.

Integration documentation is available to integrators on request —
[open an issue](https://github.com/erikcheatham/Recto/issues) or contact
Recto LLC.

---

## Contact

For privacy questions or app support: [open an issue](https://github.com/erikcheatham/Recto/issues) on the GitHub repository.

---

*Recto Agentic — transitioning to Recto LLC (in formation).*
