"""Tests for recto.joblimit -- plan + JobLimit lifecycle.

Strategy:
- ``plan_for`` is pure; tests assert directly on the returned dataclass.
- ``JobLimit`` tests subclass and override the four ``_create_job_object``
  / ``_apply_limits`` / ``_assign_process`` / ``_close_handle`` methods to
  back them with an in-memory fake recorder. Same pattern as
  ``CredManSource`` / ``FakeCredManSource`` in tests/test_secrets_credman.py.
- The ``_ensure_windows`` guard is exercised on Linux/macOS via the
  module-level helper directly.
"""

from __future__ import annotations

import sys

import pytest

from recto.config import ResourceLimitsSpec
from recto.joblimit import (
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    JobLimit,
    JoblimitError,
    plan_for,
)


# ---------------------------------------------------------------------------
# In-memory test double
# ---------------------------------------------------------------------------


class FakeJobLimit(JobLimit):
    """JobLimit that records every Win32 call without touching ctypes."""

    def __init__(self, spec: ResourceLimitsSpec) -> None:
        self.create_calls = 0
        self.apply_calls = 0
        self.assign_calls: list[tuple[int, int]] = []  # (handle, pid)
        self.close_calls: list[int] = []  # handles closed
        self._next_handle = 100
        super().__init__(spec)

    def _create_job_object(self) -> int:
        self.create_calls += 1
        h = self._next_handle
        self._next_handle += 1
        return h

    def _apply_limits(self) -> None:
        self.apply_calls += 1

    def _assign_process(self, handle: int, pid: int) -> None:
        self.assign_calls.append((handle, pid))

    def _close_handle(self, handle: int) -> None:
        self.close_calls.append(handle)


# ---------------------------------------------------------------------------
# plan_for
# ---------------------------------------------------------------------------


class TestPlanFor:
    def test_no_limits_has_any_limit_false(self) -> None:
        plan = plan_for(ResourceLimitsSpec())
        assert plan.has_any_limit is False
        assert plan.limit_flags == 0
        assert plan.cpu_rate_enabled is False

    def test_memory_limit_sets_flag_and_bytes(self) -> None:
        plan = plan_for(ResourceLimitsSpec(memory_mb=512))
        assert plan.has_any_limit is True
        # 512 MB -> 536_870_912 bytes
        assert plan.process_memory_bytes == 512 * 1024 * 1024
        assert plan.limit_flags & JOB_OBJECT_LIMIT_PROCESS_MEMORY
        # Always-on flag is included whenever ANY limit is requested.
        assert plan.limit_flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        # Other limits stay off.
        assert not (plan.limit_flags & JOB_OBJECT_LIMIT_ACTIVE_PROCESS)
        assert plan.cpu_rate_enabled is False

    def test_process_count_sets_active_process_limit(self) -> None:
        plan = plan_for(ResourceLimitsSpec(process_count=32))
        assert plan.has_any_limit is True
        assert plan.active_process_count == 32
        assert plan.limit_flags & JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        assert plan.limit_flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        assert not (plan.limit_flags & JOB_OBJECT_LIMIT_PROCESS_MEMORY)

    def test_cpu_percent_sets_cpu_rate(self) -> None:
        plan = plan_for(ResourceLimitsSpec(cpu_percent=50))
        assert plan.has_any_limit is True
        assert plan.cpu_rate_enabled is True
        # CpuRate is in 1/100ths of a percent: 50% -> 5000.
        assert plan.cpu_rate == 5000
        # ENABLE | HARD_CAP = 0x1 | 0x4 = 5
        assert plan.cpu_rate_control_flags == 0x1 | 0x4
        # Memory and process-count limits stay off.
        assert not (plan.limit_flags & JOB_OBJECT_LIMIT_PROCESS_MEMORY)
        assert not (plan.limit_flags & JOB_OBJECT_LIMIT_ACTIVE_PROCESS)
        # KILL_ON_JOB_CLOSE still rides along even when only cpu_percent
        # is set.
        assert plan.limit_flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE

    def test_all_three_limits_combine_correctly(self) -> None:
        plan = plan_for(
            ResourceLimitsSpec(memory_mb=256, cpu_percent=25, process_count=16)
        )
        assert plan.has_any_limit is True
        assert plan.limit_flags & JOB_OBJECT_LIMIT_PROCESS_MEMORY
        assert plan.limit_flags & JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        assert plan.limit_flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        assert plan.process_memory_bytes == 256 * 1024 * 1024
        assert plan.active_process_count == 16
        assert plan.cpu_rate == 2500
        assert plan.cpu_rate_enabled is True

    def test_one_percent_cpu_is_minimum_resolution(self) -> None:
        plan = plan_for(ResourceLimitsSpec(cpu_percent=1))
        assert plan.cpu_rate == 100  # 1% -> 100/10000

    def test_hundred_percent_cpu_is_maximum(self) -> None:
        plan = plan_for(ResourceLimitsSpec(cpu_percent=100))
        assert plan.cpu_rate == 10_000


# ---------------------------------------------------------------------------
# JobLimit lifecycle (with the in-memory fake)
# ---------------------------------------------------------------------------


class TestJobLimitNoOp:
    """When the spec has no limits, JobLimit is an inert shell."""

    def test_no_limits_skips_create(self) -> None:
        # FakeJobLimit normally records create_calls; with no limits,
        # _create_job_object should NEVER be called.
        jl = FakeJobLimit(ResourceLimitsSpec())
        assert jl.create_calls == 0
        assert jl.apply_calls == 0
        assert jl.handle is None

    def test_no_limits_attach_is_noop(self) -> None:
        jl = FakeJobLimit(ResourceLimitsSpec())
        jl.attach(12345)
        # No assign call recorded.
        assert jl.assign_calls == []

    def test_no_limits_close_is_noop(self) -> None:
        jl = FakeJobLimit(ResourceLimitsSpec())
        jl.close()
        assert jl.close_calls == []

    def test_double_close_is_idempotent(self) -> None:
        jl = FakeJobLimit(ResourceLimitsSpec(memory_mb=128))
        jl.close()
        jl.close()
        # First close ran; second close is no-op (handle already None).
        assert len(jl.close_calls) == 1


class TestJobLimitWithLimits:
    def test_constructor_creates_and_applies(self) -> None:
        jl = FakeJobLimit(ResourceLimitsSpec(memory_mb=128))
        assert jl.create_calls == 1
        assert jl.apply_calls == 1
        assert jl.handle == 100  # FakeJobLimit's first allocated handle

    def test_attach_records_pid(self) -> None:
        jl = FakeJobLimit(ResourceLimitsSpec(memory_mb=128))
        jl.attach(54321)
        assert jl.assign_calls == [(100, 54321)]

    def test_attach_multiple_pids(self) -> None:
        # Real-world: a process tree where the root spawns helpers; all
        # should land in the same job. The launcher only attaches the
        # root pid (children inherit), but JobLimit doesn't enforce a
        # 1-pid limit, so multiple attaches are fine.
        jl = FakeJobLimit(ResourceLimitsSpec(memory_mb=128))
        jl.attach(1000)
        jl.attach(1001)
        assert jl.assign_calls == [(100, 1000), (100, 1001)]

    def test_close_releases_handle(self) -> None:
        jl = FakeJobLimit(ResourceLimitsSpec(memory_mb=128))
        jl.close()
        assert jl.close_calls == [100]
        assert jl.handle is None

    def test_attach_after_close_is_noop(self) -> None:
        # close() drops the handle; subsequent attach should silently
        # do nothing rather than raise. (Defensive -- the launcher
        # doesn't do this, but if some future caller does, a noop is
        # safer than a confusing AttributeError.)
        jl = FakeJobLimit(ResourceLimitsSpec(memory_mb=128))
        jl.close()
        jl.attach(99999)
        # Only the original close call should be recorded; no assign.
        assert jl.assign_calls == []

    def test_context_manager_closes_on_exit(self) -> None:
        with FakeJobLimit(ResourceLimitsSpec(memory_mb=128)) as jl:
            jl.attach(1234)
            assert jl.handle == 100
        # After exit, close has been called.
        assert jl.close_calls == [100]
        assert jl.handle is None


# ---------------------------------------------------------------------------
# Platform guard
# ---------------------------------------------------------------------------


class TestPlatformGuard:
    @pytest.mark.skipif(sys.platform == "win32", reason="Linux/macOS only")
    def test_real_create_raises_on_non_windows(self) -> None:
        # Constructing a JobLimit (NOT FakeJobLimit) on Linux with limits
        # set should fail at _create_job_object via _ensure_windows.
        with pytest.raises(JoblimitError) as exc:
            JobLimit(ResourceLimitsSpec(memory_mb=128))
        assert "Windows" in str(exc.value)

    @pytest.mark.skipif(sys.platform == "win32", reason="Linux/macOS only")
    def test_no_limits_does_not_raise_on_non_windows(self) -> None:
        # The "common case" (no limits) must not raise on any platform.
        # Win32 calls are only invoked when has_any_limit is True.
        jl = JobLimit(ResourceLimitsSpec())
        jl.attach(12345)  # no-op
        jl.close()        # no-op
        assert jl.handle is None

    @pytest.mark.skipif(sys.platform == "win32", reason="Linux/macOS only")
    def test_ensure_windows_helper_raises_joblimit_error(self) -> None:
        from recto.joblimit import _ensure_windows

        with pytest.raises(JoblimitError) as exc:
            _ensure_windows()
        assert "Windows" in str(exc.value)
