"""Windows Credential Manager backend.

Stores secrets via the Win32 Credential Manager API (advapi32.CredReadW /
CredWriteW / CredDeleteW / CredEnumerateW). On disk, Credential Manager
encrypts secrets via DPAPI scoped to the credential's persist flag —
CRED_PERSIST_LOCAL_MACHINE means SYSTEM and any account that runs the
service can read them, but other users on the same box cannot.

Target name convention:
    recto:{service_name}:{secret_name}
Example:
    recto:myservice:MY_API_KEY

The 'recto:' prefix lets `recto credman list <service>` filter to just
our entries and prevents accidental collision with other apps' Cred
Manager usage.

Platform: Windows only. Importing this module on non-Windows is allowed
(so platform-detection code can do `from .credman import CredManSource`
without crashing), but instantiating CredManSource without
platform_check=False raises SecretSourceError("CredMan backend requires
Windows"). The actual ctypes calls are wrapped in `_ensure_windows()`
which raises the same error type — that's deliberate so callers can
`except SecretSourceError` once and catch both instantiation-time
and call-time failures.

Testing: subclass CredManSource and override the four `_*_blob` /
`_list_targets` methods to back them with an in-memory dict. See
tests/test_secrets_credman.py for the canonical pattern.
"""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes
from typing import Any

from recto.secrets.base import (
    DirectSecret,
    SecretMaterial,
    SecretNotFoundError,
    SecretSource,
    SecretSourceError,
)

# Win32 constants from wincred.h
CRED_TYPE_GENERIC = 1
CRED_PERSIST_LOCAL_MACHINE = 2

# Win32 error codes
_ERROR_NOT_FOUND = 1168
_ERROR_NO_SUCH_LOGON_SESSION = 1312

_TARGET_PREFIX = "recto:"


# ---------------------------------------------------------------------------
# Target-name (de)formatting
# ---------------------------------------------------------------------------


def format_target(service: str, secret: str) -> str:
    """Build the Cred Manager target name for a Recto secret.

    Example:
        format_target('myservice', 'MY_API_KEY') -> 'recto:myservice:MY_API_KEY'

    Raises SecretSourceError if either name contains ':' (the separator).
    """
    if ":" in service or ":" in secret:
        raise SecretSourceError(
            f"service and secret names must not contain ':' "
            f"(got service={service!r} secret={secret!r})"
        )
    if not service or not secret:
        raise SecretSourceError("service and secret names must be non-empty")
    return f"{_TARGET_PREFIX}{service}:{secret}"


def parse_target(target: str) -> tuple[str, str] | None:
    """Reverse of format_target. Returns (service, secret) or None if
    target is not a Recto-formatted entry."""
    if not target.startswith(_TARGET_PREFIX):
        return None
    rest = target[len(_TARGET_PREFIX) :]
    if ":" not in rest:
        return None
    service, _, secret = rest.partition(":")
    if not service or not secret:
        return None
    return service, secret


# ---------------------------------------------------------------------------
# Windows ctypes layer (wrapped so the module imports on non-Windows)
# ---------------------------------------------------------------------------


class _FILETIME(ctypes.Structure):
    _fields_ = [
        ("dwLowDateTime", wintypes.DWORD),
        ("dwHighDateTime", wintypes.DWORD),
    ]


class _CREDENTIAL_ATTRIBUTEW(ctypes.Structure):
    _fields_ = [
        ("Keyword", wintypes.LPWSTR),
        ("Flags", wintypes.DWORD),
        ("ValueSize", wintypes.DWORD),
        ("Value", ctypes.POINTER(ctypes.c_byte)),
    ]


class _CREDENTIALW(ctypes.Structure):
    _fields_ = [
        ("Flags", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("TargetName", wintypes.LPWSTR),
        ("Comment", wintypes.LPWSTR),
        ("LastWritten", _FILETIME),
        ("CredentialBlobSize", wintypes.DWORD),
        ("CredentialBlob", ctypes.POINTER(ctypes.c_byte)),
        ("Persist", wintypes.DWORD),
        ("AttributeCount", wintypes.DWORD),
        ("Attributes", ctypes.POINTER(_CREDENTIAL_ATTRIBUTEW)),
        ("TargetAlias", wintypes.LPWSTR),
        ("UserName", wintypes.LPWSTR),
    ]


def _ensure_windows() -> None:
    """Guard for the Win32 ctypes calls. Raises SecretSourceError on non-Windows.

    Defense in depth: CredManSource.__init__ already rejects non-Windows
    by default, so we only get here if a caller bypassed the guard via
    platform_check=False but then forgot to override the _* methods. Per
    Darwin's 2026-04-25 IM-update suggestion: a clean SecretSourceError
    surfaces better than the bare AttributeError that would result from
    `ctypes.windll` not existing on Linux/macOS.
    """
    if sys.platform != "win32":
        raise SecretSourceError(
            "CredMan backend requires Windows. For cross-platform secret "
            "storage, use recto.secrets.{keychain,secretsvc,vault,aws,env}."
        )


def _win_read_blob(target: str) -> str:  # pragma: no cover
    """Read a credential's blob value, decoded as UTF-16-LE.

    Raises:
        SecretNotFoundError: ERROR_NOT_FOUND from CredReadW (1168).
        SecretSourceError: any other Win32 error.

    Marked `# pragma: no cover`: this is Windows-only ctypes binding.
    The cross-platform Linux suite covers CredManSource via the
    FakeCredManSource subclass that overrides the four `_*_blob`
    methods. Real Win32 behavior is exercised by Darwin's smoke run.
    """
    _ensure_windows()
    # use_last_error=True makes ctypes save the GetLastError value into a
    # per-thread slot that ctypes.get_last_error() can read. Without it,
    # get_last_error() always returns 0 because the cross-FFI error tracking
    # isn't wired up. The plain `ctypes.windll.advapi32` accessor does NOT
    # enable this flag, so callers got "Win32 error 0" for every actual
    # failure (5a, surfaced 2026-04-26 round 6 — bombed first-consumer migration on
    # CRED_PERSIST_LOCAL_MACHINE per-user invisibility, masked underneath
    # by this plumbing bug).
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi32.CredReadW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.POINTER(_CREDENTIALW)),
    ]
    advapi32.CredReadW.restype = wintypes.BOOL

    p_cred = ctypes.POINTER(_CREDENTIALW)()
    if not advapi32.CredReadW(target, CRED_TYPE_GENERIC, 0, ctypes.byref(p_cred)):
        err = ctypes.get_last_error()
        if err == _ERROR_NOT_FOUND:
            raise SecretNotFoundError(f"credential {target!r} not found")
        raise SecretSourceError(
            f"CredReadW failed for {target!r}: Win32 error {err}"
        )
    try:
        size = p_cred.contents.CredentialBlobSize
        blob_ptr = p_cred.contents.CredentialBlob
        if size == 0 or not blob_ptr:
            return ""
        raw = ctypes.string_at(blob_ptr, size)
        return raw.decode("utf-16-le")
    finally:
        advapi32.CredFree.argtypes = [ctypes.c_void_p]
        advapi32.CredFree(p_cred)


def _win_write_blob(target: str, value: str, comment: str = "") -> None:  # pragma: no cover
    """Store / update a credential. CredWriteW is upsert by default."""
    _ensure_windows()
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)  # see note in _win_read_blob
    advapi32.CredWriteW.argtypes = [ctypes.POINTER(_CREDENTIALW), wintypes.DWORD]
    advapi32.CredWriteW.restype = wintypes.BOOL

    blob = value.encode("utf-16-le")
    # ctypes.create_string_buffer's stored bytes survive as long as the buffer
    # object does; we keep `blob_buf` alive until after CredWriteW returns.
    blob_buf = ctypes.create_string_buffer(blob, len(blob)) if blob else None

    cred = _CREDENTIALW()
    cred.Flags = 0
    cred.Type = CRED_TYPE_GENERIC
    cred.TargetName = target
    cred.Comment = comment or None
    cred.CredentialBlobSize = len(blob)
    cred.CredentialBlob = (
        ctypes.cast(blob_buf, ctypes.POINTER(ctypes.c_byte)) if blob_buf else None
    )
    cred.Persist = CRED_PERSIST_LOCAL_MACHINE
    cred.AttributeCount = 0
    cred.Attributes = None
    cred.TargetAlias = None
    cred.UserName = None  # Generic-type creds don't require a username.

    if not advapi32.CredWriteW(ctypes.byref(cred), 0):
        err = ctypes.get_last_error()
        raise SecretSourceError(
            f"CredWriteW failed for {target!r}: Win32 error {err}"
        )
    # Defensive: clear our local copy of the blob bytes immediately.
    # (Won't help with ctypes' internal buffers but reduces the window.)
    if blob_buf is not None:
        ctypes.memset(blob_buf, 0, len(blob))


def _win_delete_blob(target: str) -> None:  # pragma: no cover
    """Remove a credential by target name."""
    _ensure_windows()
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)  # see note in _win_read_blob
    advapi32.CredDeleteW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    advapi32.CredDeleteW.restype = wintypes.BOOL

    if not advapi32.CredDeleteW(target, CRED_TYPE_GENERIC, 0):
        err = ctypes.get_last_error()
        if err == _ERROR_NOT_FOUND:
            raise SecretNotFoundError(f"credential {target!r} not found")
        raise SecretSourceError(
            f"CredDeleteW failed for {target!r}: Win32 error {err}"
        )


def _win_list_targets(filter_pattern: str) -> list[str]:  # pragma: no cover
    """List target names matching the wildcard pattern. Pass '*' to list all."""
    _ensure_windows()
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)  # see note in _win_read_blob
    advapi32.CredEnumerateW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(ctypes.POINTER(ctypes.POINTER(_CREDENTIALW))),
    ]
    advapi32.CredEnumerateW.restype = wintypes.BOOL

    count = wintypes.DWORD(0)
    p_creds = ctypes.POINTER(ctypes.POINTER(_CREDENTIALW))()
    if not advapi32.CredEnumerateW(
        filter_pattern, 0, ctypes.byref(count), ctypes.byref(p_creds)
    ):
        err = ctypes.get_last_error()
        if err == _ERROR_NOT_FOUND:
            return []
        raise SecretSourceError(f"CredEnumerateW failed: Win32 error {err}")
    try:
        targets: list[str] = []
        for i in range(count.value):
            cred = p_creds[i].contents
            if cred.TargetName:
                targets.append(cred.TargetName)
        return targets
    finally:
        advapi32.CredFree.argtypes = [ctypes.c_void_p]
        advapi32.CredFree(p_creds)


# ---------------------------------------------------------------------------
# High-level CredManSource — implements SecretSource for service consumers
# ---------------------------------------------------------------------------


class CredManSource(SecretSource):
    """Windows Credential Manager backend.

    Constructor takes the service name (the same value as metadata.name in
    the consuming service.yaml). All secrets fetched, stored, deleted, or
    listed via this source are scoped to that service via the
    'recto:{service}:{secret}' target-name convention.

    Args:
        service: Logical service name. Must not contain ':'.
        platform_check: When True (default), raise SecretSourceError on
            non-Windows platforms. Tests pass platform_check=False and
            override the four _* methods to back them with an in-memory
            dict; see tests/test_secrets_credman.py.
    """

    def __init__(self, service: str, *, platform_check: bool = True):
        if platform_check and sys.platform != "win32":
            raise SecretSourceError(
                "CredMan backend requires Windows. For cross-platform secret "
                "storage, use recto.secrets.{keychain,secretsvc,vault,aws,env}."
            )
        if not service:
            raise SecretSourceError("CredManSource requires a non-empty service name")
        if ":" in service:
            raise SecretSourceError(
                f"service name must not contain ':' (got {service!r})"
            )
        self._service = service

    @property
    def name(self) -> str:
        return "credman"

    @property
    def service(self) -> str:
        return self._service

    def fetch(self, secret_name: str, config: dict[str, Any]) -> SecretMaterial:
        target = format_target(self._service, secret_name)
        try:
            value = self._read_blob(target)
        except SecretNotFoundError:
            if config.get("required", True):
                raise
            return DirectSecret(value="")
        return DirectSecret(value=value)

    def write(self, secret_name: str, value: str, comment: str = "") -> None:
        """Store / update a secret.

        Used by `recto credman set <service>/<name>` to install a new
        secret value, and by the migrate-from-nssm command to import
        each AppEnvironmentExtra entry from an existing NSSM service.

        Idempotent — calling write() on an existing target replaces the
        value (Credential Manager's CredWriteW is upsert).
        """
        target = format_target(self._service, secret_name)
        self._write_blob(target, value, comment=comment)

    def delete(self, secret_name: str) -> None:
        """Remove a secret.

        Raises SecretNotFoundError if the secret doesn't exist.
        """
        target = format_target(self._service, secret_name)
        self._delete_blob(target)

    def list_names(self) -> list[str]:
        """List secret names stored for this service.

        Returns logical names (e.g. ['MY_API_KEY', 'WEBHOOK_TOKEN']),
        sorted alphabetically. Used by `recto credman list <service>`.
        """
        prefix = f"{_TARGET_PREFIX}{self._service}:"
        targets = self._list_targets(prefix + "*")
        names: list[str] = []
        for t in targets:
            parsed = parse_target(t)
            if parsed and parsed[0] == self._service:
                names.append(parsed[1])
        return sorted(names)

    def supports_rotation(self) -> bool:
        return True

    # ------------------------------------------------------------------
    # Platform-dispatch storage backend (the seam tests override).
    # ------------------------------------------------------------------
    # The four methods below dispatch the actual storage I/O to the
    # platform-specific helper functions at module scope. They exist as
    # methods (rather than direct module-function calls in fetch/write/
    # delete/list_names above) because:
    #   1. Test doubles can override them per-instance without
    #      monkeypatching module globals (the FakeCredManSource pattern
    #      tests/test_secrets_credman.py uses).
    #   2. v0.3 will plug macOS Keychain (_mac_*) and Linux Secret
    #      Service (_lin_*) backends in via the same seam — the
    #      dispatch lookup belongs here, not at every call site.
    #
    # On Windows, all four delegate to `_win_*` module functions which
    # bind to advapi32.dll's Cred* APIs via ctypes. On non-Windows the
    # constructor's _ensure_windows() guard already raised
    # SecretSourceError before any operation reaches these methods, so
    # the Windows assumption is safe in production.

    def _read_blob(self, target: str) -> str:
        return _win_read_blob(target)

    def _write_blob(self, target: str, value: str, comment: str = "") -> None:
        _win_write_blob(target, value, comment=comment)

    def _delete_blob(self, target: str) -> None:
        _win_delete_blob(target)

    def _list_targets(self, filter_pattern: str) -> list[str]:
        return _win_list_targets(filter_pattern)

    def rotate(self, secret_name: str, new_value: str) -> None:
        """Replace an existing secret's value.

        Equivalent to write() with the same target name; Credential
        Manager's CredWriteW handles update-or-insert transparently.
        """
        self.write(secret_name, new_value)

    # ------------------------------------------------------------------
    # Lower-level 