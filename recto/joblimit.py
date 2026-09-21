"""Win32 Job Object resource limits for the supervised child.

The launcher wraps each spawned child in a Job Object so the YAML's
``spec.resource_limits`` is ENFORCED at the kernel level rather than
trusted to the child's own self-discipline. Today (v0.2) this covers:

- ``memory_mb`` -> per-process committed memory cap. Exceed it, the
  process is killed by the OS.
- ``cpu_percent`` -> hard CPU rate cap. The job's processes can only
  consume up to N% of total CPU across all cores (Windows scales
  internally via ``CpuRate`` set in 1/100ths of a percent).
- ``process_count`` -> active-process count cap. Forking past the limit
  fails with ERROR_NOT_ENOUGH_QUOTA.

Plus an unconditional ``KILL_ON_JOB_CLOSE`` so that if the launcher
itself dies (orphaned, panicked, etc.), every process the job is
holding dies with it. NSSM already does process-tree cleanup on most
shutdowns, but the Job Object is the kernel-level guarantee that
nothing leaks even if the launcher's own teardown path is skipped.

Cross-platform behavior
-----------------------

This module imports cleanly on non-Windows hosts so the rest of the
package can be unit-tested cross-platform. The actual ctypes calls
are gated by ``_ensure_windows()``, which raises ``JoblimitError``
on Linux/macOS. (Same pattern as ``recto.secrets.credman``.)

If a service.yaml with no resource_limits is loaded, ``JobLimit``
constructs but skips the Win32 path entirely - ``attach()`` and
``close()`` become no-ops. So the launcher can always create a
``JobLimit(spec.resource_limits)`` regardless of platform; only
services that actually request limits hit the Windows requirement.

Design
------

Two-layer construction so tests on non-Windows can verify limit
calculation without a ctypes mock:

- ``plan_for(spec) -> _JobLimitPlan`` is pure: given a
  ``ResourceLimitsSpec``, return what flags + values the Win32 calls
  WOULD set. Tests assert on this dataclass directly.

- ``JobLimit._create_job_object()`` /  ``_apply_limits()`` /
  ``_assign_process()`` / ``_close_handle()`` are the four ctypes-
  touching internals. Tests subclass JobLimit and override these to
  back them with an in-memory fake (mirrors the
  ``CredManSource._*_blob`` test pattern).
"""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes
from dataclasses import dataclass

from recto.config import ResourceLimitsSpec

__all__ = [
    "JOB_OBJECT_LIMIT_ACTIVE_PROCESS",
    "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE",
    "JOB_OBJECT_LIMIT_PROCESS_MEMORY",
    "JobLimit",
    "JoblimitError",
    "plan_for",
]


# ---------------------------------------------------------------------------
# Win32 constants (from WinNT.h / WinBase.h)
# ---------------------------------------------------------------------------

JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008

JOB_OBJECT_CPU_RATE_CONTROL_ENABLE = 0x1
JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP = 0x4

# JOBOBJECTINFOCLASS values
_JobObjectExtendedLimitInformation = 9
_JobObjectCpuRateControlInformation = 15


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class JoblimitError(Exception):
    """Job Object setup or attach failure."""


# ---------------------------------------------------------------------------
# Pure planning layer (no ctypes)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _JobLimitPlan:
    """What the Win32 calls SHOULD do for a given ResourceLimitsSpec.

    Pure data. Tests assert on this dataclass directly without needing
    to fake out ctypes. Production code feeds this into the actual
    SetInformationJobObject calls.
    """

    has_any_limit: bool
    limit_flags: int  # bitmask of JOB_OBJECT_LIMIT_*
    process_memory_bytes: int  # 0 if memory_mb is None
    active_process_count: int  # 0 if process_count is None
    cpu_rate_enabled: bool
    cpu_rate: int  # 1/100ths of a percent; 0 if cpu_percent is None
    cpu_rate_control_flags: int  # 0 if cpu_percent is None


def plan_for(spec: ResourceLimitsSpec) -> _JobLimitPlan:
    """Translate a ResourceLimitsSpec into Win32-shaped limit values.

    The KILL_ON_JOB_CLOSE flag is always set when ANY limit is requested
    -- it's the kernel-level guarantee that the supervised child dies
    with the launcher. (Without any limits, no Job Object is created at
    all and the flag is moot.)
    """
    has_memory = spec.memory_mb is not None
    has_count = spec.process_count is not None
    has_cpu = spec.cpu_percent is not None
    has_any = has_memory or has_count or has_cpu

    limit_flags = 0
    if has_any:
        limit_flags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if has_memory:
        limit_flags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY
    if has_count:
        limit_flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS

    cpu_rate_flags = 0
    if has_cpu:
        cpu_rate_flags = (
            JOB_OBJECT_CPU_RATE_CONTROL_ENABLE
            | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP
        )

    return _JobLimitPlan(
        has_any_limit=has_any,
        limit_flags=limit_flags,
        # MB -> bytes. Stored as 0 if memory_mb is None; the limit_flags
        # bit decides whether to consult this field.
        process_memory_bytes=(spec.memory_mb or 0) * 1024 * 1024,
        active_process_count=spec.process_count or 0,
        cpu_rate_enabled=has_cpu,
        # CpuRate is 1/100ths of a percent (so 50% -> 5000).
        cpu_rate=(spec.cpu_percent or 0) * 100,
        cpu_rate_control_flags=cpu_rate_flags,
    )


# ---------------------------------------------------------------------------
# Win32 ctypes structures (declared at module level so they import on
# non-Windows; only the ctypes calls themselves are Windows-gated)
# ---------------------------------------------------------------------------


class _IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    ]


class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", _IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class _JOBOBJECT_CPU_RATE_CONTROL_INFORMATION(ctypes.Structure):
    # Union in the SDK; we only use the CpuRate (hard-cap) variant.
    _fields_ = [
        ("ControlFlags", wintypes.DWORD),
        ("CpuRate", wintypes.DWORD),
    ]


# ---------------------------------------------------------------------------
# Windows-only guard
# ---------------------------------------------------------------------------


def _ensure_windows() -> None:
    """Raise JoblimitError if not on Windows.

    Defense in depth: ``JobLimit`` only invokes Win32 calls when at
    least one limit is set, and only after construction succeeds, but
    the helper makes the platform error consistent and explicit.
    """
    if sys.platform != "win32":
        raise JoblimitError(
            "Job Object limits require Windows. resource_limits is a "
            "Windows-only feature in v0.2; cross-platform support tracks "
            "alongside the v0.3 keychain/secretsvc backends."
        )


# ---------------------------------------------------------------------------
# JobLimit
# ---------------------------------------------------------------------------


class JobLimit:
    """Win32 Job Object wrapper enforcing a ResourceLimitsSpec.

    Lifecycle:
        jl = JobLimit(config.spec.resource_limits)
        proc = subprocess.Popen(...)
        jl.attach(proc.pid)
        try:
            ...
        finally:
            jl.close()  # KILL_ON_JOB_CLOSE fires here if proc still alive

    No-op when ``spec`` has no fields set: ``attach()`` and ``close()``
    return without touching Win32, so the launcher can always construct
    a JobLimit regardless of whether the YAML requested any limits.

    Subclass + override ``_create_job_object`` / ``_apply_limits`` /
    ``_assign_process`` / ``_close_handle`` for in-memory testing on
    non-Windows hosts. See tests/test_joblimit.py for the canonical
    pattern.
    """

    def __init__(self, spec: ResourceLimitsSpec):
        self.spec = spec
        self.plan = plan_for(spec)
        self._handle: int | None = None
        if self.plan.has_any_limit:
            self._handle = self._create_job_object()
            self._apply_limits()

    @property
    def handle(self) -> int | None:
        """Raw Win32 HANDLE, or None if no limits were requested."""
        return self._handle

    def attach(self, pid: int) -> None:
        """Add the named PID to this Job Object.

        No-op when no limits were requested. Raises JoblimitError on
        Win32 failure. The PID typically comes from
        ``subprocess.Popen.pid`` immediately after spawn.
        """
        if self._handle is None:
            return
        self._assign_process(self._handle, pid)

    def close(self) -> None:
        """Release the Job Object handle.

        KILL_ON_JOB_CLOSE means any still-running process in the job
        gets terminated when this fires. Idempotent -- calling close
        twice (e.g. once explicitly, once via __del__) is a no-op on
        the second call.
        """
        if self._handle is None:
            return
        try:
            self._close_handle(self._handle)
        finally:
            # Drop the reference even if close raised, so a subsequent
            # close() call doesn't attempt a double-free.
            self._handle = None

    def __enter__(self) -> "JobLimit":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Win32 layer -- subclass and override these in cross-platform tests.
    # The four `_*` methods below are marked `# pragma: no cover`: they
    # only execute on Windows, where Recto is actually deployed. The
    # cross-platform Linux test suite covers the higher-level logic via
    # the FakeJobLimit subclass pattern (see tests/test_joblimit.py),
    # and Darwin's full-Windows smoke run exercises the real ctypes
    # path. Pragma is honest, not coverage gaming.
    # ------------------------------------------------------------------

    def _create_job_object(self) -> int:  # pragma: no cover
        _ensure_windows()
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        kernel32.CreateJobObjectW.argtypes = [
            ctypes.c_void_p,  # LPSECURITY_ATTRIBUTES (None)
            wintypes.LPCWSTR,  # name (None == anonymous)
        ]
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        handle = kernel32.CreateJobObjectW(None, None)
        if not handle:
            err = ctypes.get_last_error()
            raise JoblimitError(f"CreateJobObjectW failed: Win32 error {err}")
        return int(handle)

    def _apply_limits(self) -> None:  # pragma: no cover
        """Push the planned limits into the job object via SetInformationJobObject."""
        _ensure_windows()
        if self._handle is None:
            return
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        kernel32.SetInformationJobObject.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,  # JOBOBJECTINFOCLASS
            ctypes.c_void_p,  # struct ptr
            wintypes.DWORD,  # struct size
        ]
        kernel32.SetInformationJobObject.restype = wintypes.BOOL

        # Extended-limit info: covers LimitFlags, ProcessMemoryLimit,
        # ActiveProcessLimit. Always set if any limit is requested
        # (KILL_ON_JOB_CLOSE flag rides along).
        ext = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        ext.BasicLimitInformation.LimitFlags = self.plan.limit_flags
        ext.BasicLimitInformation.ActiveProcessLimit = self.plan.active_process_count
        ext.ProcessMemoryLimit = self.plan.process_memory_bytes
        if not kernel32.SetInformationJobObject(
            self._handle,
            _JobObjectExtendedLimitInformation,
            ctypes.byref(ext),
            ctypes.sizeof(ext),
        ):
            err = ctypes.get_last_error()
            raise JoblimitError(
                f"SetInformationJobObject(ExtendedLimitInformation) failed: "
                f"Win32 error {err}"
            )

        # CPU rate control is a separate JobObjectInfoClass, only set
        # when a cpu_percent was requested.
        if self.plan.cpu_rate_enabled:
            cpu = _JOBOBJECT_CPU_RATE_CONTROL_INFORMATION()
            cpu.ControlFlags = self.plan.cpu_rate_control_flags
            cpu.CpuRate = self.plan.cpu_rate
            if not kernel32.SetInformationJobObject(
                self._handle,
                _JobObjectCpuRateControlInformation,
                ctypes.byref(cpu),
                ctypes.sizeof(cpu),
            ):
                err = ctypes.get_last_error()
                raise JoblimitError(
                    f"SetInformationJobObject(CpuRateControlInformation) "
                    f"failed: Win32 error {err}"
                )

    def _assign_process(self, handle: int, pid: int) -> None:  # pragma: no cover
        _ensure_windows()
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        kernel32.OpenProcess.argtypes = [
            wintypes.DWORD,  # dwDesiredAccess
            wintypes.BOOL,  # bInheritHandle
            wintypes.DWORD,  # dwProcessId
        ]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.AssignProcessToJobObject.argtypes = [
            wintypes.HANDLE,
            wintypes.HANDLE,
        ]
        kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL

        # PROCESS_SET_QUOTA | PROCESS_TERMINATE -- the minimum the API needs
        # to enroll the process and let the job kill it on limit breach.
        access = 0x0100 | 0x0001
        proc_handle = kernel32.OpenProcess(access, False, pid)
        if not proc_handle:
            err = ctypes.get_last_error()
            raise JoblimitError(
                f"OpenProcess({pid}) failed: Win32 error {err}"
            )
        try:
            if not kernel32.AssignProcessToJobObject(handle, proc_handle):
                err = ctypes.get_last_error()
                raise JoblimitError(
                    f"AssignProcessToJobObject(pid={pid}) failed: "
                    f"Win32 error {err}"
                )
        finally:
            kernel32.CloseHandle(proc_handle)

    def _close_handle(self, handle: int) -> None:  # pragma: no cover
        _ensure_windows()
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        if not kernel32.CloseHandle(handle):
            err = ctypes.get_last_error()
            raise JoblimitError(f"CloseHandle failed: Win32 error {err}")
