"""Pytest fixtures shared across the Recto test suite."""

from __future__ import annotations

from collections.abc import Iterator

import pytest


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[pytest.MonkeyPatch]:
    """Yield a monkeypatch instance with no Recto-prefixed env vars set.

    Useful for tests that want a deterministic env-var landscape; tests can
    add their own with monkeypatch.setenv(...) and they auto-clean at
    fixture teardown.
    """
    for var in list(__import__("os").environ.keys()):
        if var.startswith(("RECTO_", "TEST_RECTO_")):
            monkeypatch.delenv(var, raising=False)
    yield monkeypatch
