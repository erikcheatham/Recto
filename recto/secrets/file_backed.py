"""File-backed secret store for non-Windows / containerized deployments.

DpapiMachineSource binds secret values to Windows DPAPI, which cannot
decrypt inside a Linux container. The dockerized bootloader topology
(host-side launcher decrypts agent tokens into env vars, container never
touches DPAPI) works for the *tokens* that arrive at spawn time — but the
Connections substrate reads/writes per-connection secret VALUES at runtime
through `recto.connections.manage`, whose `connections_secret_source_factory`
defaults to DpapiMachineSource. Inside a Linux container that default has no
DPAPI, so the first `set_connection` / `get_connection_secret` 500s.

This backend is the container-viable substitute: it stores each secret as a
small JSON file under a per-service directory inside a host-private location
(in practice the bootloader-data named volume, which survives image rebuilds
and is root-owned, not baked into any image, not network-reachable). The
threat model matches how the bootloader already treats its state dir
(phones.json / sessions.json live in the clear in the same volume) — anyone
who can read the volume already owns the host.

Storage layout::

    <base_dir>/<service>/<secret_name>.json
      -> {"value": "...", "comment": "...", "updated_at_unix": 1750000000}

Hard rules from `recto.secrets.base` honored here:

1. The secret value never appears in a log line or a `__repr__`.
2. We serialize the raw `value` string (NOT a SecretMaterial dataclass).
3. Missing secret -> SecretNotFoundError (distinct from generic failure).
4. Files are written atomically (temp + os.replace) with 0o600 perms on
   POSIX so a partial write never yields a torn read.

`fetch` / `write` / `delete` satisfy the `WritableSecretSource` Protocol the
Connections substrate is typed against (wider than the SecretSource ABC's
fetch-only mandate). A factory closure `(service) -> FileBackedSecretSource`
is what `create_server(connections_secret_source_factory=...)` wants.
"""

from __future__ import annotations

import json
import os
import stat
import tempfile
import time
from pathlib import Path
from typing import Any

from recto.secrets.base import (
    DirectSecret,
    SecretMaterial,
    SecretNotFoundError,
    SecretSource,
    SecretSourceError,
)


def _safe_component(name: str, *, label: str) -> str:
    """Reject path-traversal / separator characters in a service or secret
    name so a hostile or malformed key can never escape the base dir."""
    if not name:
        raise SecretSourceError(f"file-backed secret store: empty {label}")
    if name in (".", ".."):
        raise SecretSourceError(f"file-backed secret store: invalid {label} {name!r}")
    if "/" in name or "\\" in name or "\x00" in name or os.sep in name:
        raise SecretSourceError(
            f"file-backed secret store: {label} {name!r} contains a path separator"
        )
    if (altsep := os.altsep) and altsep in name:
        raise SecretSourceError(
            f"file-backed secret store: {label} {name!r} contains a path separator"
        )
    return name


class FileBackedSecretSource(SecretSource):
    """Per-service secret backend that persists values as JSON files on disk.

    Construct one per consuming service: ``FileBackedSecretSource("MyService",
    base_dir=Path("/var/lib/recto/bootloader/connections-secrets"))``. The
    Connections substrate's `SecretSourceFactory` is then just
    ``lambda service: FileBackedSecretSource(service, base_dir=...)``.
    """

    def __init__(self, service: str, base_dir: str | os.PathLike[str]) -> None:
        self._service = _safe_component(service, label="service")
        self._dir = Path(base_dir) / self._service

    @property
    def name(self) -> str:
        return "file-backed"

    # -- read --------------------------------------------------------------

    def fetch(self, secret_name: str, config: dict[str, Any]) -> SecretMaterial:
        path = self._path_for(secret_name)
        required = config.get("required", True) if config else True
        try:
            raw = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            if required:
                raise SecretNotFoundError(
                    f"file-backed secret {secret_name!r} not found for "
                    f"service {self._service!r}"
                ) from None
            return DirectSecret(value="")
        except OSError as exc:
            raise SecretSourceError(
                f"file-backed secret store: read failed for {secret_name!r}"
            ) from exc
        try:
            payload = json.loads(raw)
            value = payload["value"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise SecretSourceError(
                f"file-backed secret store: corrupt blob for {secret_name!r}"
            ) from exc
        if not isinstance(value, str):
            raise SecretSourceError(
                f"file-backed secret store: non-string value for {secret_name!r}"
            )
        return DirectSecret(value=value)

    # -- write -------------------------------------------------------------

    def write(self, secret_name: str, value: str, comment: str = "") -> None:
        if not isinstance(value, str):
            raise SecretSourceError(
                "file-backed secret store: value must be a string"
            )
        path = self._path_for(secret_name)
        self._dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self._dir, stat.S_IRWXU)  # 0o700
        except OSError:
            pass  # best-effort on filesystems without POSIX perms (e.g. some bind mounts)
        payload = json.dumps(
            {"value": value, "comment": comment, "updated_at_unix": int(time.time())},
            separators=(",", ":"),
        )
        # Atomic replace: write a sibling temp file, fchmod, fsync, rename.
        fd, tmp = tempfile.mkstemp(dir=str(self._dir), prefix=".", suffix=".tmp")
        try:
            try:
                os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
            except (OSError, AttributeError):
                pass
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
        except OSError as exc:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise SecretSourceError(
                f"file-backed secret store: write failed for {secret_name!r}"
            ) from exc

    # -- delete ------------------------------------------------------------

    def delete(self, secret_name: str) -> None:
        path = self._path_for(secret_name)
        try:
            path.unlink()
        except FileNotFoundError:
            return  # idempotent — deleting a missing secret is a no-op
        except OSError as exc:
            raise SecretSourceError(
                f"file-backed secret store: delete failed for {secret_name!r}"
            ) from exc

    # -- internals ---------------------------------------------------------

    def _path_for(self, secret_name: str) -> Path:
        safe = _safe_component(secret_name, label="secret name")
        return self._dir / f"{safe}.json"
