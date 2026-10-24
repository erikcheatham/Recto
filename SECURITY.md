# Recto — Security Policy

**Report a vulnerability privately, never in a public issue.** Use GitHub's
private reporting: open this repository's **Security** tab and choose **Report a
vulnerability**. Only Recto's maintainers can see the report.

Recto is maintained by **Recto LLC**.

## What to include

- **Which part:** `recto-core`, the bootloader, or the phone app (Android or
  iOS).
- **Which version:** the release or commit you tested.
- **How to reproduce it:** the steps, what happened, and what you expected.

A report does not need a working exploit. Test against a deployment you run
yourself, never against someone else's.

## What happens next

- **An acknowledgement within 7 days.**
- **An assessment you see before anything is published:** a fix, or the reason
  the behaviour is intended. Some behaviour is a deliberate decision listed in
  [docs/hard-rules.md](docs/hard-rules.md); a report that meets one is answered
  by its rule.
- **Coordinated disclosure:** the advisory is published when the fix ships, and
  it credits you unless you ask otherwise.

## Supported versions

Fixes land on `main` and in the next release of `recto-core` and the phone app.
Earlier releases are not patched.

## Scope

The code in this repository. An operator's own deployment of it — the host,
the configuration, the users — is that operator's to secure, and reports about
it go to them.
