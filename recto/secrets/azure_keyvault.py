"""Azure Key Vault secret-source backend -- production cloud vault.

The first cloud SecretSource, per the production-scale plan
(docs/production-scale-brief.md, layer 2): a load-balanced multi-instance
bootloader deployment can't use ``dpapi-machine`` (Windows machine-bound
by definition -- the encrypted blobs can't roam across instances), so
production instances resolve platform secrets from ONE shared Azure Key
Vault instead. Install with ``pip install recto[azure]``.

Authentication is ``DefaultAzureCredential`` -- on Azure app-tier hosts
that resolves to the instance's **Managed Identity** (zero credentials
anywhere in Recto config: the identity IS the instance); on an
operator's workstation it falls back to environment / Azure CLI login.
Grant the identity the "Key Vault Secrets User" role (read) plus
"Key Vault Secrets Officer" if the deployment uses the connections
write-path.

One vault is the intended shape (NOT one per service or per user):
Recto's architecture keeps private keys phone-side, so the server-side
secret set is small and platform-scoped -- operator trust-root config,
agent tokens, consumer webhook tokens, provider connection keys.
Per-user material (pubkeys, pairings) is NOT secret and belongs in the
state backend, never in Key Vault.

Naming convention
-----------------

Key Vault secret names allow only ``[0-9a-zA-Z-]`` (1..127 chars), while
Recto secret names use ``_`` and ``.`` freely (``KEYCLOAK_WEB_SECRET``,
``conn.cloudflare``). This backend maps deterministically:

- lowercase everything,
- every character outside ``[a-z0-9]`` becomes ``-`` (1:1, no collapsing),
- the service scope is prefixed with a double-hyphen separator:
  ``{service}--{secret-name}``.

Example: service ``MyService`` + secret ``conn.cloudflare`` is stored as
``myservice--conn-cloudflare``. The mapping is lossy in theory
(``a_b`` and ``a.b`` normalize identically) -- avoid secret names that
differ only in punctuation; the docstring convention across Recto's
built-in names already satisfies this.

Semantics parity with the other writable backends
-------------------------------------------------

- ``fetch`` raises ``SecretNotFoundError`` on a missing secret and
  ``SecretSourceError`` (generic message, provider detail in
  ``__cause__``) on auth/network failures -- base.py hard rules.
- ``write`` upserts (Key Vault versions the secret automatically); an
  optional comment lands as a ``recto-comment`` tag, never in the value.
- ``delete`` is idempotent (missing secret is a no-op, matching the
  file-backed store). Key Vault soft-delete applies per vault policy --
  this backend intentionally does NOT purge; recovery/purge is an
  operator ceremony in the Azure portal or CLI.

Values are fetched live per call -- no caching layer here (callers like
the connections substrate own their own caching; secret material is
consumed immediately per base.py hard rule #2).
"""

from __future__ import annotations

import os
from typing import Any

from recto.secrets.base import (
    DirectSecret,
    SecretMaterial,
    SecretNotFoundError,
    SecretSource,
    SecretSourceError,
)

#: Environment variable the registry factory reads for the vault URL
#: (e.g. ``https://my-vault.vault.azure.net/``). Constructor callers can
#: pass ``vault_url`` explicitly instead.
VAULT_URL_ENV = "RECTO_AZURE_KEYVAULT_URL"

_NAME_ALPHABET = set("abcdefghijklmnopqrstuvwxyz0123456789")
_KV_MAX_NAME_LEN = 127


def normalize_kv_name(service: str, secret_name: str) -> str:
    """Map a (service, secret_name) pair to a Key Vault secret name.

    Deterministic, documented in the module docstring. Raises
    SecretSourceError when the inputs are empty or the result exceeds
    Key Vault's 127-char limit.
    """
    if not service or not secret_name:
        raise SecretSourceError(
            "azure-keyvault: service and secret name must be non-empty"
        )

    def _norm(part: str) -> str:
        return "".join(
            c if c in _NAME_ALPHABET else "-" for c in part.lower()
        )

    result = f"{_norm(service)}--{_norm(secret_name)}"
    if len(result) > _KV_MAX_NAME_LEN:
        raise SecretSourceError(
            f"azure-keyvault: normalized secret name exceeds Key Vault's "
            f"{_KV_MAX_NAME_LEN}-char limit ({len(result)} chars); shorten "
            f"the service or secret name"
        )
    return result


def _import_azure() -> tuple[Any, Any, Any, Any]:
    """Lazy-import the Azure SDK; clean error when the extra is missing."""
    try:
        from azure.core.exceptions import (
            ClientAuthenticationError,
            ResourceNotFoundError,
        )
        from azure.identity import DefaultAzureCredential
        from azure.keyvault.secrets import SecretClient
    except ImportError as exc:
        raise ImportError(
            "AzureKeyVaultSource requires the optional azure extra: "
            "pip install recto[azure]"
        ) from exc
    return (
        SecretClient,
        DefaultAzureCredential,
        ResourceNotFoundError,
        ClientAuthenticationError,
    )


class AzureKeyVaultSource(SecretSource):
    """SecretSource + connections write-path on one Azure Key Vault.

    Satisfies the ``WritableSecretSource`` protocol
    (recto.connections.manage): ``fetch`` / ``write`` / ``delete``.

    Args:
        service: the consuming service's name (``metadata.name`` in
            service.yaml); scopes every secret name -- one vault serves
            many services without collisions, mirroring how
            ``dpapi-machine`` scopes by per-service subfolder.
        vault_url: the vault URL; falls back to the
            ``RECTO_AZURE_KEYVAULT_URL`` environment variable.
        credential: optional pre-built Azure credential (tests /
            non-default auth chains); defaults to
            ``DefaultAzureCredential``.
        secret_client: optional pre-built client (the test-injection
            seam); when supplied, ``vault_url`` / ``credential`` are
            ignored.
    """

    def __init__(
        self,
        service: str,
        *,
        vault_url: str | None = None,
        credential: Any = None,
        secret_client: Any = None,
    ):
        if not service:
            raise SecretSourceError(
                "azure-keyvault: service name must be non-empty"
            )
        self._service = service

        if secret_client is not None:
            self._client = secret_client
            # Exception types are still needed for error mapping even
            # with an injected client; fall back to duck-typed names if
            # the SDK genuinely isn't installed (pure-fake test rigs).
            try:
                (_, _, self._not_found_exc, self._auth_exc) = _import_azure()
            except ImportError:
                self._not_found_exc = LookupError
                self._auth_exc = PermissionError
            return

        (
            secret_client_cls,
            default_credential_cls,
            self._not_found_exc,
            self._auth_exc,
        ) = _import_azure()

        url = vault_url or os.environ.get(VAULT_URL_ENV)
        if not url:
            raise SecretSourceError(
                "azure-keyvault: no vault URL configured -- pass vault_url "
                f"or set the {VAULT_URL_ENV} environment variable "
                "(e.g. https://my-vault.vault.azure.net/)"
            )
        cred = credential if credential is not None else default_credential_cls()
        self._client = secret_client_cls(vault_url=url, credential=cred)

    # ------------------------------------------------------------------
    # SecretSource
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "azure-keyvault"

    @property
    def service(self) -> str:
        return self._service

    def fetch(
        self, secret_name: str, config: dict[str, Any]
    ) -> SecretMaterial:
        kv_name = normalize_kv_name(self._service, secret_name)
        try:
            secret = self._client.get_secret(kv_name)
        except self._not_found_exc as exc:
            raise SecretNotFoundError(
                f"azure-keyvault secret {secret_name!r} "
                f"(vault name {kv_name!r}) not found for service "
                f"{self._service!r}"
            ) from exc
        except self._auth_exc as exc:
            raise SecretSourceError(
                "azure-keyvault: authentication failed -- check the "
                "instance's Managed Identity / credential chain and its "
                "Key Vault role assignment"
            ) from exc
        except Exception as exc:  # noqa: BLE001 - map per base.py rule 5
            raise SecretSourceError(
                f"azure-keyvault: fetch failed for {secret_name!r}"
            ) from exc
        value = getattr(secret, "value", None)
        if value is None:
            raise SecretSourceError(
                f"azure-keyvault: secret {secret_name!r} has no value"
            )
        return DirectSecret(value=value)

    # ------------------------------------------------------------------
    # WritableSecretSource protocol (connections write-path)
    # ------------------------------------------------------------------

    def write(self, secret_name: str, value: str, comment: str = "") -> None:
        if value is None or value == "":
            raise SecretSourceError(
                "azure-keyvault: refusing to write an empty secret value"
            )
        kv_name = normalize_kv_name(self._service, secret_name)
        tags = {"recto-comment": comment} if comment else None
        try:
            self._client.set_secret(kv_name, value, tags=tags)
        except self._auth_exc as exc:
            raise SecretSourceError(
                "azure-keyvault: write denied -- the identity needs the "
                "Key Vault Secrets Officer role for the connections "
                "write-path"
            ) from exc
        except Exception as exc:  # noqa: BLE001
            raise SecretSourceError(
                f"azure-keyvault: write failed for {secret_name!r}"
            ) from exc

    def delete(self, secret_name: str) -> None:
        """Idempotent delete (missing secret is a no-op, matching the
        file-backed store). Soft-delete retention applies per vault
        policy; this backend never purges."""
        kv_name = normalize_kv_name(self._service, secret_name)
        try:
            poller = self._client.begin_delete_secret(kv_name)
            # Don't block on purge; waiting for the delete operation to
            # be accepted keeps subsequent write() of the same name from
            # racing a half-deleted secret.
            wait = getattr(poller, "wait", None)
            if callable(wait):
                wait()
        except self._not_found_exc:
            return  # idempotent
        except Exception as exc:  # noqa: BLE001
            raise SecretSourceError(
                f"azure-keyvault: delete failed for {secret_name!r}"
            ) from exc
