"""Tests for the env-passthrough SecretSource backend."""

from __future__ import annotations

import pytest

from recto.secrets.base import DirectSecret, SecretNotFoundError
from recto.secrets.env import EnvSource


class TestEnvSourceName:
    def test_name_is_env(self) -> None:
        assert EnvSource().name == "env"


class TestEnvSourceFetch:
    def test_fetch_reads_from_environ(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TEST_RECTO_SECRET", "hello")
        result = EnvSource().fetch("TEST_RECTO_SECRET", {})
        assert isinstance(result, DirectSecret)
        assert result.value == "hello"

    def test_fetch_missing_raises_when_required(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("TEST_RECTO_MISSING", raising=False)
        with pytest.raises(SecretNotFoundError):
            EnvSource().fetch("TEST_RECTO_MISSING", {})

    def test_fetch_missing_returns_empty_when_not_required(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("TEST_RECTO_MISSING", raising=False)
        result = EnvSource().fetch("TEST_RECTO_MISSING", {"required": False})
        assert isinstance(result, DirectSecret)
        assert result.value == ""

    def test_fetch_with_env_var_override(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Logical secret name "MY_KEY" but actually read from "ACTUAL_VAR".
        monkeypatch.setenv("ACTUAL_VAR", "actual-value")
        result = EnvSource().fetch(
            "MY_KEY", {"env_var": "ACTUAL_VAR"}
        )
        assert isinstance(result, DirectSecret)
        assert result.value == "actual-value"

    def test_fetch_does_not_log_value(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        # Sanity: no print/log calls in the fetch path that would leak the secret.
        monkeypatch.setenv("TEST_RECTO_SECRET", "very-secret-value")
        EnvSource().fetch("TEST_RECTO_SECRET", {})
        captured = capsys.readouterr()
        assert "very-secret-value" not in captured.out
        assert "very-secret-value" not in captured.err


class TestEnvSourceLifecycle:
    def test_no_lifecycle_needed(self) -> None:
        # env-passthrough is stateless; should report so.
        assert EnvSource().supports_lifecycle() is False

    def test_no_rotation_supported(self) -> None:
        # env vars are read-only from the process; rotation isn't meaningful.
        assert EnvSource().supports_rotation() is False
