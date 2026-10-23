"""Recto v0.4 bootloader -- the bridge between Recto's launcher and a
phone-resident Ed25519 vault.

The bootloader is a long-lived Python process spawned by the launcher
when any service.yaml has `spec.secrets[].source == "enclave"`. It runs
an HTTPS server the phone app polls; holds public keys, session JWTs,
and pending sign requests in `~/.recto/bootloader/`; and forwards sign
calls from the launcher's local sign-helper socket to the phone over
HTTPS.

Wire-protocol contract: see `docs/v0.4-protocol.md`. Both the phone app
and this package implement that contract verbatim.

Submodules:

- `state`   -- persistence contract (StateStoreBase) + the file-backed
  default store (phones, sessions, pending requests).
- `state_postgres` -- PostgresStateStore, the production multi-instance
  backend (`pip install recto[postgres]`; see
  docs/production-scale-brief.md).
- `sessions` -- JWT EdDSA encode/verify helpers + session cache.
- `server` -- HTTPS server + endpoint handlers.
- `push`   -- push-notification helpers (APNs / FCM stubs).

This package depends on the [v0_4] optional extra (`pip install
recto[v0_4]`) -- specifically `cryptography` and `pyjwt[crypto]`. Imports
are lazy at the submodule level so importing `recto.bootloader` itself
does not pull those deps; the imports happen when an endpoint actually
needs to verify a signature.
"""

from __future__ import annotations

__all__ = [
    "BootloaderError",
    "RegistrationExpiredError",
    "UnknownPhoneError",
    "PendingRequestNotFoundError",
]


class BootloaderError(Exception):
    """Base class for bootloader-side errors."""


class RegistrationExpiredError(BootloaderError):
    """A pairing-code or registration challenge has expired."""


class UnknownPhoneError(BootloaderError):
    """A request references a phone_id that's not registered with this
    bootloader. Usually means the phone re-paired and the old
    registration was implicitly superseded."""


class PendingRequestNotFoundError(BootloaderError):
    """A POST /v0.4/respond/<id> references a request_id that doesn't
    exist (already responded, expired, or never created)."""
