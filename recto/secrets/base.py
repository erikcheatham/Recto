"""Plugin boundary for secret-source backends.

The architectural decision that lets v0.4 hardware-enclave backends slot in
without rewriting v0.1: SecretSource.fetch returns a SecretMaterial, which
is a sealed sum type (DirectSecret | SigningCapability). v0.1 backends
return DirectSecret; v0.4 hardware-enclave backends return SigningCapability.
The launcher consumes both shapes via separate code paths.

Hard rules for backend implementors:

1. Never log a secret value.
2. Never serialize a SecretMaterial to disk.
3. SecretMaterial.__repr__ MUST return "<redacted>" — see DirectSecret /
   SigningCapability dataclasses below for the canonical impl.
4. Raise SecretNotFoundError (NOT a generic exception) when the named
   secret does not exist in your backend.
5. Raise SecretSourceError for any other backend failure (network down,
   auth failed, malformed config, etc.). Don't leak underlying provider
   error details into the message — keep the message generic and put
   provider-specific debug info in __cause__.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


class SecretSourceError(Exception):
    """Generic backend failure. Network down, auth failed, malformed config,
    etc. Do not include secret values in the message; provider-specific debug
    info goes in __cause__."""


class SecretNotFoundError(SecretSourceError):
    """The named secret does not exist in the backend.

    Distinct from SecretSourceError so callers can decide whether 'missing'
    is fatal (required: true in service.yaml) or fine (required: false).
    """


@dataclass(frozen=True, slots=True)
class DirectSecret:
    """Secret value materialized as a string.

    Returned by v0.1 + v0.3 backends (Credential Manager, env passthrough,
    AWS Secrets Manager, HashiCorp Vault, etc.). The launcher injects
    `value` as an environment variable on the supervised child process.

    DO NOT add __repr__ / __str__ / __format__ overrides that expose
    `value`. The frozen dataclass default __repr__ is overridden below
    to return "<redacted>" for safety.
    """

    value: str

    def __repr__(self) -> str:
        return "<DirectSecret redacted>"

    def __str__(self) -> str:
        return "<DirectSecret redacted>"


@dataclass(frozen=True, slots=True)
class SigningCapability:
    """Secret never leaves its enclave; instead expose a sign-callable.

    Returned by v0.4 hardware-enclave backends. The launcher does NOT
    inject a value as env var; instead it offers a local-socket sign-
    helper to the supervised child process. Child apps that opt in call
    `sign(message)` and use the signature for downstream operations
    (signing API requests, decrypting tokens, etc.).

    `algorithm` matches the over-the-wire signature scheme name. Today:
    "ed25519", "ecdsa-p256". Post-quantum: "dilithium3", "falcon-512",
    "sphincsplus-sha2-128s" once hardware support catches up.
    """

    sign: Callable[[bytes], bytes]
    public_key: bytes
    algorithm: str

    def __repr__(self) -> str:
        return f"<SigningCapability algorithm={self.algorithm!r} redacted>"

    def __str__(self) -> str:
        return f"<SigningCapability algorithm={self.algorithm!r} redacted>"


SecretMaterial = DirectSecret | SigningCapability


class SecretSource(ABC):
    """Pluggable backend for materializing a named secret.

    Subclass and implement `fetch`. Optionally implement init/teardown
    if your backend needs to open / close a network connection or session.
    Optionally implement supports_rotation + rotate if your backend
    supports changing a secret's value programmatically.

    Concrete subclasses must override `name` to a unique short identifier
    used in service.yaml `source:` selectors (e.g. "credman", "vault",
    "aws-secrets-manager").
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Backend selector used in service.yaml. Lowercase, hyphenated."""

    @abstractmethod
    def fetch(self, secret_name: str, config: dict[str, Any]) -> SecretMaterial:
        """Return the named secret as a SecretMaterial.

        Raises:
            SecretNotFoundError: secret_name does not exist in this backend.
            SecretSourceError: any other backend failure.
        """

    def supports_lifecycle(self) -> bool:
        """True if this backend needs init() / teardown() bracketing.

        Default: False. Stateless backends (env, credman) return False.
        Network-backed backends (vault, hardware-enclave) return True
        and implement init/teardown to open/close the session.
        """
        return False

    def init(self) -> None:
        """One-time setup. Called before first fetch() if supports_lifecycle()."""

    def teardown(self) -> None:
        """One-time cleanup. Called on launcher shutdown if supports_lifecycle()."""

    def supports_rotation(self) -> bool:
        """True if rotate() is supported (the source can change a secret's value)."""
        return False

    def rotate(self, secret_name: str, new_value: str) -> None:
        """Replace the named secret's value. Default: not supported."""
        raise NotImplementedError(
            f"{type(self).__name__} does not support rotation"
        )
