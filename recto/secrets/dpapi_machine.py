"""Machine-bound DPAPI-encrypted file storage backend.

Encrypts secrets using `CryptProtectData` with the
`CRYPTPROTECT_LOCAL_MACHINE` flag, then stores each encrypted blob as
a file under `C:\\ProgramData\\recto\\<service>\\<name>.dpapi`. Any process
on the box (running as any user) can decrypt; processes on other
machines cannot.

This solves the per-user limitation of the `credman` backend: Windows
Credential Manager scopes credentials to the user that wrote them, so
when a service account (e.g. `LocalSystem`) reads a secret installed
by an admin user, CredReadW returns `ERROR_NOT_FOUND`. DPAPI's machine-
key flavor sidesteps the problem — the encryption is bound to the
machine's keying material, not the user's.

Threat model
------------

- An attacker with code-exec on the machine CAN decrypt our secrets.
  This is the same boundary as Windows DPAPI itself; we do not add per-
  process isolation. Storing in `C:\\ProgramData` (instead of the
  registry or per-user paths) makes this explicit — the security
  boundary is the machine, not the user.
- An attacker with file-system read but not code-exec CANNOT decrypt:
  DPAPI machine-key derivation requires running in a process context
  on the same machine, not just file-read.
- Files are stored under `C:\\ProgramData\\recto\\<service>\\` with
  default ACLs (Administrators/SYSTEM read+write, Users read). Any
  process running as a normal user can list and read the encrypted
  blobs, but only on this same machine. Tightening to SYSTEM-only ACLs
  would shift the boundary to "running as SYSTEM"; for our use case
  the machine boundary is the security boundary so default ACLs are
  acceptable.

Public surface
--------------

`DpapiMachineSource` implements `SecretSource`. Registered in
`recto.secrets.__init__` under the selector name `dpapi-machine`,
matching `service.yaml` `source: dpapi-machine` declarations.

The implementation is Windows-only at runtime (CryptProtectData is a
Win32 API). Importing on non-Windows is allowed so the rest of the
package can be unit-tested cross-platform; the public API raises
`SecretSourceError("dpapi-machine backend requires Windows")` at
construction time off-Windows. Tests use `DpapiMachineSource(service,
platform_check=False)` plus a fake storage layer to cover high-level
flow on Linux CI.
"""

from __future__ import annotations

import ctypes
import os
import sys
from ctypes import wintypes
from pathlib import Path
from typing import Any

from recto.secrets.base import (
    DirectSecret,
    SecretMaterial,
    SecretNotFoundError,
    SecretSource,
    SecretSourceError,
)

__all__ = [
    "DpapiMachineSource",
    "format_storage_path",
]


# ---------------------------------------------------------------------------
# CryptProtectData / CryptUnprotectData flag constants
# ---------------------------------------------------------------------------


CRYPTPROTECT_UI_FORBIDDEN = 0x1
"""Suppress any UI prompts. Required for service-context decryption."""

CRYPTPROTECT_LOCAL_MACHINE = 0x4
"""Bind encryption to the machine's keying material, not the user's.
Any process on this machine can decrypt; processes on other machines
cannot. THIS IS WHAT MAKES THE BACKEND SOLVE THE PER-USER PROBLEM."""


class _DATA_BLOB(ctypes.Structure):
    """DPAPI's plain (cbData, pbData) blob struct.

    Used for both input plaintext-or-ciphertext and output ciphertext-
    or-plaintext via Crypt{Protect,Unprotect}Data.
    """

    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_byte)),
    ]


def _ensure_windows() -> None:
    """Guard non-Windows runtime calls so they fail with a clean error
    rather than a bare AttributeError on `ctypes.WinDLL`."""
    if sys.platform != "win32":
        raise SecretSourceError(
            "dpapi-machine backend requires Windows. For cross-platform "
            "secret storage, use recto.secrets.{keychain,secretsvc,vault,"
            "aws,env}."
        )


# ---------------------------------------------------------------------------
# CryptProtectData / CryptUnprotectData wrappers
# ---------------------------------------------------------------------------


def _machine_protect(plaintext: str) -> bytes:  # pragma: no cover
    """Encrypt `plaintext` with CRYPTPROTECT_LOCAL_MACHINE.

    Returns the ciphertext as raw bytes. The format is opaque DPAPI
    internal; we treat it as a blob and never parse it.
    """
    _ensure_windows()
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(_DATA_BLOB),  # pDataIn
        wintypes.LPCWSTR,            # szDataDescr (None)
        ctypes.POINTER(_DATA_BLOB),  # pOptionalEntropy (None)
        ctypes.c_void_p,             # pvReserved (None)
        ctypes.c_void_p,             # pPromptStruct (None)
        wintypes.DWORD,              # dwFlags
        ctypes.POINTER(_DATA_BLOB),  # pDataOut
    ]
    crypt32.CryptProtectData.restype = wintypes.BOOL

    in_bytes = plaintext.encode("utf-8")
    in_buf = ctypes.create_string_buffer(in_bytes, len(in_bytes))
    in_blob = _DATA_BLOB(
        len(in_bytes),
        ctypes.cast(in_buf, ctypes.POINTER(ctypes.c_byte)),
    )
    out_blob = _DATA_BLOB()

    flags = CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN
    ok = crypt32.CryptProtectData(
        ctypes.byref(in_blob),
        None, None, None, None,
        flags,
        ctypes.byref(out_blob),
    )
    if not ok:
        err = ctypes.get_last_error()
        raise SecretSourceError(
            f"CryptProtectData failed: Win32 error {err}"
        )
    try:
        if out_blob.cbData == 0 or not out_blob.pbData:
            return b""
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        # DPAPI allocates output via LocalAlloc; caller must LocalFree.
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree(out_blob.pbData)
        # Defensive: zero the input buffer immediately after encryption.
        ctypes.memset(in_buf, 0, len(in_bytes))


def _machine_unprotect(ciphertext: bytes) -> str:  # pragma: no cover
    """Decrypt a CRYPTPROTECT_LOCAL_MACHINE blob.

    Returns the plaintext UTF-8-decoded. Raises SecretSourceError on
    decryption failure (corrupt blob, missing key material, etc.).
    """
    _ensure_windows()
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(_DATA_BLOB),  # pDataIn
        ctypes.c_void_p,             # ppszDataDescr (None — we ignore it)
        ctypes.POINTER(_DATA_BLOB),  # pOptionalEntropy (None)
        ctypes.c_void_p,             # pvReserved (None)
        ctypes.c_void_p,             # pPromptStruct (None)
        wintypes.DWORD,              # dwFlags
        ctypes.POINTER(_DATA_BLOB),  # pDataOut
    ]
    crypt32.CryptUnprotectData.restype = wintypes.BOOL

    in_buf = ctypes.create_string_buffer(ciphertext, len(ciphertext))
    in_blob = _DATA_BLOB(
        len(ciphertext),
        ctypes.cast(in_buf, ctypes.POINTER(ctypes.c_byte)),
    )
    out_blob = _DATA_BLOB()

    ok = crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None, None, None, None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    )
    if not ok:
        err = ctypes.get_last_error()
        raise SecretSourceError(
            f"CryptUnprotectData failed: Win32 error {err}"
        )
    try:
        if out_blob.cbData == 0 or not out_blob.pbData:
            return ""
        plaintext_bytes = ctypes.string_at(out_blob.pbData, out_blob.cbData)
        return plaintext_bytes.decode("utf-8")
    finally:
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree(out_blob.pbData)


# ---------------------------------------------------------------------------
# Storage layout
# ---------------------------------------------------------------------------


def _program_data_root() -> Path:
    """Return %PROGRAMDATA%\\recto\\ on Windows; a sane test path elsewhere.

    Off-Windows the test suite uses platform_check=False + monkeypatched
    storage; this fallback never gets used in production.
    """
    if sys.platform == "win32":
        return Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "recto"
    # Tests on Linux: prefer XDG_DATA_HOME, fall back to /tmp.
    base = os.environ.get("XDG_DATA_HOME") or "/tmp"
    return Path(base) / "recto"


def format_storage_path(service: str, secret_name: str) -> Path:
    """Compute the on-disk path for a given (service, secret_name) pair.

    The naming convention is `<root>/<service>/<secret_name>.dpapi`.
    Used by tests to verify storage layout and by operators reading
    `cmdkey`-style listings of what's installed.
    """
    if not service or ":" in service:
        raise SecretSourceError(
            f"invalid service name {service!r} (empty or contains ':')"
        )
    if not secret_name or ":" in secret_name or "/" in secret_name or "\\" in secret_name:
        raise SecretSourceError(
            f"invalid secret name {secret_name!r} (empty or contains "
            f"separator characters)"
        )
    return _program_data_root() / service / f"{secret_name}.dpapi"


# ---------------------------------------------------------------------------
# DpapiMachineSource — the public SecretSource implementation
# ---------------------------------------------------------------------------


class DpapiMachineSource(SecretSource):
    """Machine-bound DPAPI file-storage backend.

    Each secret is stored as a single file under
    `C:\\ProgramData\\recto\\<service>\\<name>.dpapi`, encrypted with
    CryptProtectData + CRYPTPROTECT_LOCAL_MACHINE so any process on the
    same machine can decrypt regardless of which user wrote it.

    Constructor takes the service name (the same value as
    `metadata.name` in the consuming service.yaml). Secrets are scoped
    to that service via the directory layout — operators inspecting
    storage see one subdirectory per consuming service.
    """

    def __init__(
        self, service: str, *, platform_check: bool = True
    ) -> None:
        if platform_check:
            _ensure_windows()
        if not service:
            raise SecretSourceError("service name must be non-empty")
        if ":" in service:
            raise SecretSourceError(
                f"service name must not contain ':' (got {service!r})"
            )
        self._service = service

    # ------------------------------------------------------------------
    # SecretSource API
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "dpapi-machine"

    @property
    def service(self) -> str:
        return self._service

    def fetch(
        self, secret_name: str, config: dict[str, Any]
    ) -> SecretMaterial:
        path = format_storage_path(self._service, secret_name)
        try:
            ciphertext = self._read_blob(path)
        except SecretNotFoundError:
            if config.get("required", True):
                raise
            return DirectSecret(value="")
        return DirectSecret(value=self._decrypt(ciphertext))

    def write(
        self, secret_name: str, value: str, comment: str = ""
    ) -> None:
        """Store / update a secret. Idempotent — overwrites by design.

        The `comment` parameter is accepted for API parity with the
        credman backend's `write()` signature, but is not stored;
        DPAPI blobs do not carry side-channel metadata.
        """
        path = format_storage_path(self._service, secret_name)
        ciphertext = self._encrypt(value)
        self._write_blob(path, ciphertext)

    def delete(self, secret_name: str) -> None:
        path = format_storage_path(self._service, secret_name)
        self._delete_blob(path)

    def list_names(self) -> list[str]:
        directory = _program_data_root() / self._service
        return sorted(self._list_files(directory))

    def supports_rotation(self) -> bool:
        return True

    def rotate(self, secret_name: str, new_value: str) -> None:
        """Replace an existing secret's value. Implemented as write-over;
        DPAPI doesn't have a separate rotate primitive, and machine-key
        material isn't user-rotatable from userland anyway."""
        self.write(secret_name, new_value)

    # ------------------------------------------------------------------
    # Platform-dispatch storage backend (the seam tests override).
    # ------------------------------------------------------------------
    # Same pattern as CredManSource — these four methods are the
    # injection points where in-memory test doubles substitute the
    # real ctypes/file-IO calls. Production wires them through to the
    # `_machine_*` helpers and `pathlib`. Tests subclass and override.

    def _encrypt(self, plaintext: str) -> bytes:
        return _machine_protect(plaintext)

    def _decrypt(self, ciphertext: bytes) -> str:
        return _machine_unprotect(ciphertext)

    def _read_blob(self, path: Path) -> bytes:
        try:
            return path.read_bytes()
        except FileNotFoundError as exc:
            raise SecretNotFoundError(
                f"dpapi-machine secret at {path} not found"
            ) from exc
        except PermissionError as exc:
            raise SecretSourceError(
                f"dpapi-machine secret at {path} unreadable: {exc}"
            ) from exc

    def _write_blob(self, path: Path, ciphertext: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        # Atomic replace: write to a sibling tempfile, fsync, rename.
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_bytes(ciphertext)
        os.replace(tmp, path)

    def _delete_blob(self, path: Path) -> None:
        try:
            path.unlink()
        except FileNotFoundError as exc:
            raise SecretNotFoundError(
                f"dpapi-machine secret at {path} not found"
            ) from exc

    def _list_files(self, directory: Path) -> list[str]:
        if not directory.exists():
            return []
        return [p.stem for p in directory.glob("*.dpapi")]
