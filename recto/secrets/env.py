"""Plain environment-variable passthrough backend.

The simplest possible SecretSource: reads from os.environ. Useful for:

- Local dev where the secret is already exported in the developer's shell.
- CI / containerized environments where secrets arrive via env vars from
  some upstream secret store (Kubernetes Secret, GitHub Actions secret,
  Docker Compose .env, etc.) and Recto's job is just to forward them.
- Testing — the canonical test fixture for SecretSource consumers.

The `config` argument supports two optional keys:

    {"env_var": "OVERRIDE_NAME"}   -- read from this env var instead of
                                      using secret_name as the key.
    {"required": true|false}        -- if true, missing env vars raise
                                       SecretNotFoundError; if false,
                                       missing env vars return DirectSecret("")

If neither is set, default behavior is: read from os.environ[secret_name]
and raise SecretNotFoundError if missing.

This backend does NOT support rotation (env vars are read-only from the
process's perspective).
"""

from __future__ import annotations

import os
from typing import Any

from recto.secrets.base import (
    DirectSecret,
    SecretMaterial,
    SecretNotFoundError,
    SecretSource,
)


class EnvSource(SecretSource):
    """Read secrets from the current process's environment variables."""

    @property
    def name(self) -> str:
        return "env"

    def fetch(self, secret_name: str, config: dict[str, Any]) -> SecretMaterial:
        env_var = config.get("env_var", secret_name)
        required = config.get("required", True)
        value = os.environ.get(env_var)
        if value is None:
            if required:
                raise SecretNotFoundError(
                    f"environment variable {env_var!r} is not set"
                )
            return DirectSecret(value="")
        return DirectSecret(value=value)
