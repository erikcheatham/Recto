"""Pytest fixtures shared across the Recto test suite, and the shard selection CI uses."""

from __future__ import annotations

import os
from collections.abc import Iterator, Sequence
from typing import TypeVar

import pytest

T = TypeVar("T")


def select_shard(items: Sequence[T], spec: str) -> tuple[list[T], list[T]]:
    """Split ``items`` into (kept, deselected) for the shard ``spec``, "<index>/<total>" with index from 1.

    Items are dealt out in turn (position modulo total), so every module spreads across every shard and the
    shards of one total partition the suite. A spec that is not two integers with 1 <= index <= total raises
    ValueError, so a typo never runs an empty or partial suite quietly.
    """
    parts = spec.split("/")
    if len(parts) != 2 or not all(p.strip().isdigit() for p in parts):
        raise ValueError(f"shard spec {spec!r} is not <index>/<total>")
    index, total = int(parts[0]), int(parts[1])
    if not 1 <= index <= total:
        raise ValueError(f"shard spec {spec!r} needs 1 <= index <= total")
    kept = [item for position, item in enumerate(items) if position % total == index - 1]
    deselected = [item for position, item in enumerate(items) if position % total != index - 1]
    return kept, deselected


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """With RECTO_TEST_SHARD set (e.g. "2/4"), run only that shard of the collected tests."""
    spec = os.environ.get("RECTO_TEST_SHARD", "").strip()
    if not spec:
        return
    try:
        kept, deselected = select_shard(items, spec)
    except ValueError as exc:
        raise pytest.UsageError(f"RECTO_TEST_SHARD: {exc}") from exc
    if deselected:
        config.hook.pytest_deselected(items=deselected)
    items[:] = kept


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
