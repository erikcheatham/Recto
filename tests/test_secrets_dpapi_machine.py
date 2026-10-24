"""Tests for the dpapi-machine secret source backend.

Linux-runnable tests subclass DpapiMachineSource and override the
`_encrypt` / `_decrypt` / `_read_blob` / `_write_blob` / `_delete_blob`
/ `_list_files` methods to back them with an in-memory dict, mirroring
the FakeCredManSource pattern from tests/test_secrets_credman.py.

Windows-only `TestWindowsLiveDpapi` exercises the actual
CryptProtectData / CryptUnprotectData ctypes path against the live
crypt32.dll, end-to-end via temp directories.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest

from recto.secrets.base import (
    DirectSecret,
    SecretNotFoundError,
    SecretSourceError,
)
from recto.secrets.dpapi_machine import (
    DpapiMachineSource,
    format_storage_path,
)


# ---------------------------------------------------------------------------
# In-memory test double
# ---------------------------------------------------------------------------


class _FakeMachineStore:
    """Stand-in for the host's filesystem + DPAPI primitives."""

    def __init__(self) -> None:
        # Maps Path -> ciphertext bytes. We keep ciphertext as bytes to
        # match the real implementation's interface; encryption is a
        # no-op string<->bytes round-trip via UTF-8 encode/decode.
        self.files: dict[Path, bytes] = {}

    def encrypt(self, plaintext: str) -> bytes:
        # Identity encryption — UTF-8 round-trip. Keeps tests honest
        # about the bytes/str boundary without bringing in real DPAPI.
        return plaintext.encode("utf-8")

    def decrypt(self, ciphertext: bytes) -> str:
        return ciphertext.decode("utf-8")

    def read(self, path: Path) -> bytes:
        if path not in self.files:
            raise SecretNotFoundError(f"fake store: {path} not found")
        return self.files[path]

    def write(self, path: Path, ciphertext: bytes) -> None:
        self.files[path] = ciphertext

    def delete(self, path: Path) -> None:
        if path not in self.files:
            raise SecretNotFoundError(f"fake store: {path} not found")
        del self.files[path]

    def list_files(self, directory: Path) -> list[str]:
        # Return filenames whose parent is `directory` and which end in
        # `.dpapi`, stem-only.
        return [
            p.stem
            for p in self.files
            if p.parent == directory and p.suffix == ".dpapi"
        ]


class FakeDpapiMachineSource(DpapiMachineSource):
    """DpapiMachineSource backed by an in-memory dict, runnable on Linux."""

    def __init__(
        self, service: str, store: _FakeMachineStore | None = None
    ) -> None:
        super().__init__(service, platform_check=False)
        self._store = store if store is not None else _FakeMachineStore()

    def _encrypt(self, plaintext: str) -> bytes:
        return self._store.encrypt(plaintext)

    def _decrypt(self, ciphertext: bytes) -> str:
        return self._store.decrypt(ciphertext)

    def _read_blob(self, path: Path) -> bytes:
        return self._store.read(path)

    def _write_blob(self, path: Path, ciphertext: bytes) -> None:
        self._store.write(path, ciphertext)

    def _delete_blob(self, path: Path) -> None:
        self._store.delete(path)

    def _list_files(self, directory: Path) -> list[str]:
        return self._store.list_files(directory)


# ---------------------------------------------------------------------------
# format_storage_path
# ---------------------------------------------------------------------------


class TestFormatStoragePath:
    def test_basic_layout(self) -> None:
        path = format_storage_path("MyService", "MY_PUSH_TOKEN")
        # Last two parts are always service / <name>.dpapi regardless of
        # the platform-specific root.
        assert path.parent.name == "MyService"
        assert path.name == "MY_PUSH_TOKEN.dpapi"

    def test_rejects_empty_service(self) -> None:
        with pytest.raises(SecretSourceError):
            format_storage_path("", "K")

    def test_rejects_colon_in_service(self) -> None:
        with pytest.raises(SecretSourceError):
            format_storage_path("ver:so", "K")

    def test_rejects_empty_secret(self) -> None:
        with pytest.raises(SecretSourceError):
            format_storage_path("MyService", "")

    def test_rejects_path_separator_in_secret(self) -> None:
        for bad in ("a/b", "a\\b", "a:b"):
            with pytest.raises(SecretSourceError):
                format_storage_path("MyService", bad)


# ---------------------------------------------------------------------------
# DpapiMachineSource constructor + platform check
# ---------------------------------------------------------------------------


class TestConstructor:
    @pytest.mark.skipif(sys.platform == "win32", reason="Linux/macOS only")
    def test_raises_on_non_windows_by_default(self) -> None:
        with pytest.raises(SecretSourceError) as exc_info:
            DpapiMachineSource("myservice")
        assert "Windows" in str(exc_info.value)

    def test_test_mode_works_on_any_platform(self) -> None:
        src = DpapiMachineSource("myservice", platform_check=False)
        assert src.name == "dpapi-machine"
        assert src.service == "myservice"

    def test_rejects_empty_service(self) -> None:
        with pytest.raises(SecretSourceError):
            DpapiMachineSource("", platform_check=False)

    def test_rejects_colon_in_service(self) -> None:
        with pytest.raises(SecretSourceError):
            DpapiMachineSource("ver:so", platform_check=False)

    def test_class_has_storage_seam_methods(self) -> None:
        """Same structural regression test as CredManSource — the seam
        methods MUST exist on the class so test doubles can override.
        Catches the missing-wrapper-class regression that bombed the
        first-consumer migration round 5 if it ever recurs in this backend."""
        for method_name in (
            "_encrypt",
            "_decrypt",
            "_read_blob",
            "_write_blob",
            "_delete_blob",
            "_list_files",
        ):
            assert hasattr(DpapiMachineSource, method_name), (
                f"DpapiMachineSource is missing {method_name!r} — "
                f"required for test-double overrides and v0.3 platform "
                f"variants."
            )


# ---------------------------------------------------------------------------
# fetch / write / delete / list_names lifecycle
# ---------------------------------------------------------------------------


class TestLifecycle:
    def test_write_then_fetch(self) -> None:
        src = FakeDpapiMachineSource("myservice")
        src.write("MY_API_KEY", "secret-v1")
        result = src.fetch("MY_API_KEY", {})
        assert isinstance(result, DirectSecret)
        assert result.value == "secret-v1"

    def test_fetch_missing_required_raises(self) -> None:
        src = FakeDpapiMachineSource("myservice")
        with pytest.raises(SecretNotFoundError):
            src.fetch("MISSING", {})

    def test_fetch_missing_optional_returns_empty(self) -> None:
        src = FakeDpapiMachineSource("myservice")
        result = src.fetch("MISSING", {"required": False})
        assert result.value == ""

    def test_write_upserts_existing(self) -> None:
        src = FakeDpapiMachineSource("myservice")
        src.write("K", "v1")
        src.write("K", "v2")
        assert src.fetch("K", {}).value == "v2"

    def test_write_with_comment_accepted_but_ignored(self) -> None:
        # The migrate-from-nssm path passes comment="Migrated from NSSM:..."
        # to write(); the backend accepts but doesn't store it (DPAPI
        # blobs don't carry side-channel metadata). Just verify no raise.
        src = FakeDpapiMachineSource("myservice")
        src.write("K", "v", comment="Migrated from NSSM:myservice")
        assert src.fetch("K", {}).value == "v"

    def test_delete_removes(self) -> None:
        src = FakeDpapiMachineSource("myservice")
        src.write("K", "v")
        src.delete("K")
        with pytest.raises(SecretNotFoundError):
            src.fetch("K", {})

    def test_delete_missing_raises(self) -> None:
        src = FakeDpapiMachineSource("myservice")
        with pytest.raises(SecretNotFoundError):
            src.delete("MISSING")

    def test_list_names_filters_per_service(self) -> None:
        store = _FakeMachineStore()
        a = FakeDpapiMachineSource("svc_a", store)
        b = FakeDpapiMachineSource("svc_b", store)
        a.write("A1", "v")
        a.write("A2", "v")
        b.write("B1", "v")
        assert a.list_names() == ["A1", "A2"]
        assert b.list_names() == ["B1"]

    def test_list_names_empty(self) -> None:
        assert FakeDpapiMachineSource("myservice").list_names() == []

    def test_list_names_returns_sorted(self) -> None:
        src = FakeDpapiMachineSource("myservice")
        for n in ["zed", "Alpha", "mid"]:
            src.write(n, "v")
        names = src.list_names()
        assert names == sorted(names)

    def test_supports_rotation_true(self) -> None:
        assert FakeDpapiMachineSource("myservice").supports_rotation() is True

    def test_rotate_replaces_value(self) -> None:
        src = FakeDpapiMachineSource("myservice")
        src.write("K", "v1")
        src.rotate("K", "v2")
        assert src.fetch("K", {}).value == "v2"


# ---------------------------------------------------------------------------
# fetch never logs the secret value
# ---------------------------------------------------------------------------


class TestNoSecretLeakage:
    def test_fetch_does_not_log_value(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        src = FakeDpapiMachineSource("myservice")
        src.write("K", "very-secret-value")
        src.fetch("K", {})
        captured = capsys.readouterr()
        assert "very-secret-value" not in captured.out
        assert "very-secret-value" not in captured.err


# ---------------------------------------------------------------------------
# Backend registration in recto.secrets.__init__
# ---------------------------------------------------------------------------


class TestBackendRegistration:
    def test_registered_under_dpapi_machine_selector(self) -> None:
        from recto.secrets import registered_sources

        assert "dpapi-machine" in registered_sources()

    def test_resolve_returns_dpapi_machine_source(self) -> None:
        # On Linux the resolve() call instantiates DpapiMachineSource which
        # would normally raise SecretSourceError from _ensure_windows. So
        # we verify by name-only via registered_sources, plus by
        # constructing manually with platform_check=False.
        from recto.secrets import registered_sources

        assert "dpapi-machine" in registered_sources()
        src = DpapiMachineSource("myservice", platform_check=False)
        assert src.name == "dpapi-machine"


# ---------------------------------------------------------------------------
# Windows-only live integration test (against real CryptProtectData)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    sys.platform != "win32", reason="Live DPAPI only on Windows"
)
class TestWindowsLiveDpapi:
    """End-to-end smoke against the actual CryptProtectData /
    CryptUnprotectData ctypes path. Uses a temp PROGRAMDATA root so it
    doesn't touch operator-installed secrets."""

    def _make_src_in_tmp(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> tuple[DpapiMachineSource, Path]:
        """Construct a real DpapiMachineSource pointed at a tempdir for
        storage. Encryption still uses real CryptProtectData; only the
        on-disk root is isolated."""
        tmp = Path(tempfile.mkdtemp(prefix="recto_dpapi_test_"))
        monkeypatch.setenv("PROGRAMDATA", str(tmp))
        src = DpapiMachineSource("test_dpapi_live")
        return src, tmp

    def test_round_trip(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        src, tmp = self._make_src_in_tmp(monkeypatch)
        try:
            src.write("RoundTripKey", "live-value-1")
            assert src.list_names() == ["RoundTripKey"]
            assert src.fetch("RoundTripKey", {}).value == "live-value-1"
            src.rotate("RoundTripKey", "live-value-2")
            assert src.fetch("RoundTripKey", {}).value == "live-value-2"
            src.delete("RoundTripKey")
            assert src.list_names() == []
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_unicode_value_round_trips(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        src, tmp = self._make_src_in_tmp(monkeypatch)
        try:
            value = "Hello — 世界 ñ ç"
            src.write("UnicodeKey", value)
            assert src.fetch("UnicodeKey", {}).value == value
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_ciphertext_is_not_plaintext_on_disk(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Smoke: confirm the on-disk file does NOT contain the plaintext
        # in the clear. Catches the case where the encrypt/decrypt
        # round-trip is a no-op for some reason.
        src, tmp = self._make_src_in_tmp(monkeypatch)
        try:
            plaintext = "this-string-must-not-appear-on-disk"
            src.write("Smoke", plaintext)
            on_disk_path = tmp / "recto" / "test_dpapi_live" / "Smoke.dpapi"
            assert on_disk_path.exists()
            on_disk_bytes = on_disk_path.read_bytes()
            assert plaintext.encode("utf-8") not in on_disk_bytes
            assert plaintext.encode("utf-16-le") not in on_disk_bytes
            # And of course we can still decrypt back:
            assert src.fetch("Smoke", {}).value == plaintext
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)
