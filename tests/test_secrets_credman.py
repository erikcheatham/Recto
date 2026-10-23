"""Tests for the Windows Credential Manager backend.

Most tests subclass CredManSource and override the four `_*_blob` /
`_list_targets` methods to back them with an in-memory dict. This lets
us cover the high-level CredManSource logic on any platform; the actual
ctypes->advapi32 plumbing is verified at first-deploy on a real Windows
host (and in v0.2 via a Windows GitHub Actions runner).
"""

from __future__ import annotations

import sys

import pytest

from recto.secrets.base import (
    DirectSecret,
    SecretNotFoundError,
    SecretSourceError,
)
from recto.secrets.credman import (
    CredManSource,
    format_target,
    parse_target,
)

# ---------------------------------------------------------------------------
# In-memory CredManSource subclass used by every test below
# ---------------------------------------------------------------------------


class _FakeStore:
    """Stand-in for the host's Credential Manager storage."""

    def __init__(self) -> None:
        self.data: dict[str, str] = {}

    def read(self, target: str) -> str:
        if target not in self.data:
            raise SecretNotFoundError(f"credential {target!r} not found")
        return self.data[target]

    def write(self, target: str, value: str, comment: str = "") -> None:
        self.data[target] = value

    def delete(self, target: str) -> None:
        if target not in self.data:
            raise SecretNotFoundError(f"credential {target!r} not found")
        del self.data[target]

    def list(self, pattern: str) -> list[str]:
        # Pattern is 'recto:<service>:*' — strip trailing '*' and prefix-match.
        if pattern.endswith("*"):
            prefix = pattern[:-1]
            return [k for k in self.data if k.startswith(prefix)]
        return [k for k in self.data if k == pattern]


class FakeCredManSource(CredManSource):
    """CredManSource backed by an in-memory dict for testability on Linux."""

    def __init__(self, service: str, store: _FakeStore | None = None):
        super().__init__(service, platform_check=False)
        self._store = store if store is not None else _FakeStore()

    def _read_blob(self, target: str) -> str:
        return self._store.read(target)

    def _write_blob(self, target: str, value: str, comment: str = "") -> None:
        self._store.write(target, value, comment)

    def _delete_blob(self, target: str) -> None:
        self._store.delete(target)

    def _list_targets(self, filter_pattern: str) -> list[str]:
        return self._store.list(filter_pattern)


# ---------------------------------------------------------------------------
# Target-name formatting helpers
# ---------------------------------------------------------------------------


class TestFormatTarget:
    def test_basic(self) -> None:
        assert format_target("myservice", "MY_API_KEY") == "recto:myservice:MY_API_KEY"

    def test_rejects_colon_in_service(self) -> None:
        with pytest.raises(SecretSourceError):
            format_target("ver:so", "K")

    def test_rejects_colon_in_secret(self) -> None:
        with pytest.raises(SecretSourceError):
            format_target("myservice", "K:1")

    def test_rejects_empty_service(self) -> None:
        with pytest.raises(SecretSourceError):
            format_target("", "K")

    def test_rejects_empty_secret(self) -> None:
        with pytest.raises(SecretSourceError):
            format_target("myservice", "")


class TestParseTarget:
    def test_round_trip(self) -> None:
        t = format_target("myservice", "MY_API_KEY")
        parsed = parse_target(t)
        assert parsed == ("myservice", "MY_API_KEY")

    def test_non_recto_returns_none(self) -> None:
        # Other apps' Cred Manager entries shouldn't be parsed as ours.
        assert parse_target("Microsoft_OC1:bar") is None
        assert parse_target("git:https://github.com") is None

    def test_malformed_recto_target_returns_none(self) -> None:
        # Has the prefix but no ':' separator after it.
        assert parse_target("recto:no_secret_separator") is None
        # Has the prefix and separator but empty parts.
        assert parse_target("recto::secret") is None
        assert parse_target("recto:service:") is None


# ---------------------------------------------------------------------------
# CredManSource constructor + platform check
# ---------------------------------------------------------------------------


class TestConstructor:
    @pytest.mark.skipif(sys.platform == "win32", reason="Linux/macOS only")
    def test_raises_on_non_windows_by_default(self) -> None:
        # Per Darwin's 2026-04-25 IM-update suggestion: should raise
        # SecretSourceError (the canonical secret-backend error type),
        # not NotImplementedError or a bare AttributeError. This lets
        # the launcher's `except SecretSourceError` path catch it
        # uniformly with other backend failures.
        with pytest.raises(SecretSourceError) as exc_info:
            CredManSource("myservice")
        assert "Windows" in str(exc_info.value)

    @pytest.mark.skipif(sys.platform == "win32", reason="Linux/macOS only")
    def test_ensure_windows_helper_raises_secret_source_error(self) -> None:
        # The internal _ensure_windows() guard should also raise
        # SecretSourceError — defense in depth for the platform_check=False
        # path where a caller bypasses the constructor guard but a real
        # _win_* function still gets reached.
        from recto.secrets.credman import _ensure_windows

        with pytest.raises(SecretSourceError) as exc_info:
            _ensure_windows()
        assert "Windows" in str(exc_info.value)

    def test_test_mode_works_on_any_platform(self) -> None:
        src = CredManSource("myservice", platform_check=False)
        assert src.name == "credman"
        assert src.service == "myservice"

    def test_rejects_empty_service(self) -> None:
        with pytest.raises(SecretSourceError):
            CredManSource("", platform_check=False)

    def test_rejects_colon_in_service(self) -> None:
        with pytest.raises(SecretSourceError):
            CredManSource("ver:so", platform_check=False)

    def test_class_has_storage_wrapper_methods(self) -> None:
        """Structural regression test for the 2026-04-26 missing-wrapper
        bug. The four `_*_blob` / `_list_targets` methods MUST exist on
        the class itself (not only on FakeCredManSource subclasses), so
        a plain CredManSource instance can dispatch to the platform
        backend. Linux-runnable; catches the regression without needing
        a live Windows host."""
        for method_name in (
            "_read_blob",
            "_write_blob",
            "_delete_blob",
            "_list_targets",
        ):
            assert hasattr(CredManSource, method_name), (
                f"CredManSource is missing {method_name!r} — required for "
                f"platform-dispatch to _win_*/_mac_*/_lin_* backends. "
                f"See CHANGELOG [Unreleased] / Fixed for the 2026-04-26 "
                f"regression that motivated this test."
            )


# ---------------------------------------------------------------------------
# fetch() behavior
# ---------------------------------------------------------------------------


class TestFetch:
    def test_fetch_returns_direct_secret(self) -> None:
        store = _FakeStore()
        store.write("recto:myservice:MY_API_KEY", "secret-value")
        src = FakeCredManSource("myservice", store)
        result = src.fetch("MY_API_KEY", {})
        assert isinstance(result, DirectSecret)
        assert result.value == "secret-value"

    def test_fetch_missing_required_raises(self) -> None:
        src = FakeCredManSource("myservice")
        with pytest.raises(SecretNotFoundError):
            src.fetch("MISSING", {})

    def test_fetch_missing_optional_returns_empty(self) -> None:
        src = FakeCredManSource("myservice")
        result = src.fetch("MISSING", {"required": False})
        assert isinstance(result, DirectSecret)
        assert result.value == ""

    def test_fetch_does_not_log_value(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        store = _FakeStore()
        store.write("recto:myservice:K", "very-secret-value")
        src = FakeCredManSource("myservice", store)
        src.fetch("K", {})
        captured = capsys.readouterr()
        assert "very-secret-value" not in captured.out
        assert "very-secret-value" not in captured.err


# ---------------------------------------------------------------------------
# write() / delete() / rotate()
# ---------------------------------------------------------------------------


class TestWrite:
    def test_write_stores_value(self) -> None:
        store = _FakeStore()
        src = FakeCredManSource("myservice", store)
        src.write("MY_API_KEY", "v1")
        assert store.data["recto:myservice:MY_API_KEY"] == "v1"

    def test_write_upserts_existing(self) -> None:
        store = _FakeStore()
        store.write("recto:myservice:MY_API_KEY", "old")
        src = FakeCredManSource("myservice", store)
        src.write("MY_API_KEY", "new")
        assert store.data["recto:myservice:MY_API_KEY"] == "new"

    def test_write_then_fetch_round_trip(self) -> None:
        src = FakeCredManSource("myservice")
        src.write("MY_API_KEY", "abc123")
        result = src.fetch("MY_API_KEY", {})
        assert isinstance(result, DirectSecret)
        assert result.value == "abc123"


class TestDelete:
    def test_delete_removes(self) -> None:
        store = _FakeStore()
        store.write("recto:myservice:MY_API_KEY", "v")
        src = FakeCredManSource("myservice", store)
        src.delete("MY_API_KEY")
        assert "recto:myservice:MY_API_KEY" not in store.data

    def test_delete_missing_raises(self) -> None:
        src = FakeCredManSource("myservice")
        with pytest.raises(SecretNotFoundError):
            src.delete("MISSING")


class TestRotate:
    def test_supports_rotation(self) -> None:
        assert FakeCredManSource("myservice").supports_rotation() is True

    def test_rotate_replaces_value(self) -> None:
        src = FakeCredManSource("myservice")
        src.write("MY_API_KEY", "v1")
        src.rotate("MY_API_KEY", "v2")
        assert src.fetch("MY_API_KEY", {}).value == "v2"  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# list_names() — service-scoped enumeration
# ---------------------------------------------------------------------------


class TestListNames:
    def test_empty_store(self) -> None:
        assert FakeCredManSource("myservice").list_names() == []

    def test_lists_only_this_service(self) -> None:
        store = _FakeStore()
        # Three different services in the same store.
        store.write("recto:myservice:MY_API_KEY", "v")
        store.write("recto:myservice:WEBHOOK_TOKEN", "v")
        store.write("recto:otherservice:ANTHROPIC_KEY", "v")
        store.write("recto:third:UNRELATED", "v")
        # Plus a non-Recto entry to make sure we filter.
        store.write("Microsoft_OC1:foo", "v")

        svc = FakeCredManSource("myservice", store)
        assert svc.list_names() == ["MY_API_KEY", "WEBHOOK_TOKEN"]

        other = FakeCredManSource("otherservice", store)
        assert other.list_names() == ["ANTHROPIC_KEY"]

        unknown = FakeCredManSource("nonexistent", store)
        assert unknown.list_names() == []

    def test_returns_sorted(self) -> None:
        store = _FakeStore()
        # Insert in random order; list_names should sort.
        for name in ["ZED", "alpha", "MID"]:
            store.write(f"recto:myservice:{name}", "v")
        names = FakeCredManSource("myservice", store).list_names()
        assert names == sorted(names)


# ---------------------------------------------------------------------------
# Integration smoke test
# ---------------------------------------------------------------------------


class TestEndToEnd:
    def test_full_lifecycle(self) -> None:
        """Mirrors a canonical secret-install flow:
        write -> list -> fetch -> rotate -> delete."""
        src = FakeCredManSource("myservice")

        # No secrets installed yet.
        assert src.list_names() == []

        # Install two secrets.
        src.write("MY_API_KEY", "v1")
        src.write("WEBHOOK_TOKEN", "tok-1")

        # Both visible under this service, sorted.
        assert src.list_names() == ["MY_API_KEY", "WEBHOOK_TOKEN"]

        # Fetch returns them.
        assert src.fetch("MY_API_KEY", {}).value == "v1"
        assert src.fetch("WEBHOOK_TOKEN", {}).value == "tok-1"

        # Rotate one. supports_rotation() is True; rotate replaces in place.
        src.rotate("MY_API_KEY", "v2")
        assert src.fetch("MY_API_KEY", {}).value == "v2"
        assert src.list_names() == ["MY_API_KEY", "WEBHOOK_TOKEN"]

        # Delete one. The other survives.
        src.delete("WEBHOOK_TOKEN")
        assert src.list_names() == ["MY_API_KEY"]
        with pytest.raises(SecretNotFoundError):
            src.fetch("WEBHOOK_TOKEN", {})

        # Delete the last one.
        src.delete("MY_API_KEY")
        assert src.list_names() == []


# ---------------------------------------------------------------------------
# Windows-only live integration test (against real Credential Manager)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform != "win32", reason="Live CredMan only on Windows")
class TestWindowsLiveCredMan:
    """End-to-end smoke against the actual `_win_*` ctypes path.

    The Linux suite covers CredManSource via FakeCredManSource, which
    overrides the four `_*_blob` / `_list_targets` methods on the
    instance. That's enough to test the high-level flow logic but it
    DOES NOT exercise the four wrapper methods on the class itself —
    which means a missing wrapper (the kind of bug that bombed the
    first-consumer migration round 5 on 2026-04-26) goes undetected because no test
    ever calls a real CredManSource against a live store.

    This class fills that gap: writes, fetches, lists, rotates, and
    deletes a real Credential Manager entry under a UUID-scoped service
    name (`recto:test-suite-{uuid}:RoundTripKey`) so it can't collide
    with anything operator-installed. Cleanup happens unconditionally
    in the test body's `try/finally` so a failed assertion mid-test
    still leaves CredMan clean.
    """

    def _make_src(self) -> tuple[CredManSource, str]:
        """Create a real CredManSource with a unique service name."""
        import uuid

        # Underscores everywhere — no colons (would be rejected by
        # format_target's validation). A short UUID slice keeps the
        # target name human-readable in `cmdkey /list` output.
        unique_service = f"test_suite_{uuid.uuid4().hex[:8]}"
        return CredManSource(unique_service), unique_service

    def test_round_trip_against_live_credman(self) -> None:
        src, service_name = self._make_src()
        try:
            # Pre-condition: service is empty.
            assert src.list_names() == []

            # Write -> list -> fetch.
            src.write("RoundTripKey", "live-value-1", comment="test_round_trip")
            assert src.list_names() == ["RoundTripKey"]
            fetched = src.fetch("RoundTripKey", {})
            assert isinstance(fetched, DirectSecret)
            assert fetched.value == "live-value-1"

            # Rotate.
            src.rotate("RoundTripKey", "live-value-2")
            assert src.fetch("RoundTripKey", {}).value == "live-value-2"

            # Delete -> verify gone.
            src.delete("RoundTripKey")
            assert src.list_names() == []
            with pytest.raises(SecretNotFoundError):
                src.fetch("RoundTripKey", {})
        finally:
            # Idempotent cleanup: silence SecretNotFoundError so we don't
            # mask the real test failure with a teardown failure.
            try:
                src.delete("RoundTripKey")
            except SecretNotFoundError:
                pass

    def test_unicode_value_round_trips(self) -> None:
        # CredMan stores values as wide-strings (UTF-16-LE); the wrappers
        # encode and decode correctly across the ctypes boundary.
        src, _ = self._make_src()
        try:
            src.write("UnicodeKey", "Hello — 世界 ñ ç")
            assert src.fetch("UnicodeKey", {}).value == "Hello — 世界 ñ ç"
        finally:
            try:
                src.delete("UnicodeKey")
            except SecretNotFoundError:
                pass

    def test_write_with_comment_round_trips(self) -> None:
        # The migrate-from-nssm path writes with a Migrated from NSSM:<svc>
        # comment. We don't expose the comment via fetch(), but the write
        # call shouldn't raise on it.
        src, _ = self._make_src()
        try:
            src.write("CommentedKey", "v", comment="Migrated from NSSM:test")
            assert src.fetch("CommentedKey", {}).value == "v"
        finally:
            try:
                src.delete("CommentedKey")
            except SecretNotFoundError:
                pass

    def test_fetch_missing_raises(self) -> None:
        src, _ = self._make_src()
        # The unique service hasn't had anything written; fetch must raise.
        with pytest.raises(SecretNotFoundError):
            src.fetch("NeverExisted", {})

    def test_list_filters_to_this_service(self) -> None:
        # Two unique CredManSource instances on the same machine; each
        # should only see its own secrets even though both walk the same
        # CredEnumerateW result list.
        src_a, _ = self._make_src()
        src_b, _ = self._make_src()
        try:
            src_a.write("OnlyInA", "a-val")
            src_b.write("OnlyInB", "b-val")
            assert src_a.list_names() == ["OnlyInA"]
            assert src_b.list_names() == ["OnlyInB"]
        finally:
            for src, name in [(src_a, "OnlyInA"), (src_b, "OnlyInB")]:
                try:
                    src.delete(name)
                except SecretNotFoundError:
                    pass