"""Tests for recto.healthz.

Strategy: drive HealthzProbe.tick() directly with a stub check callable
(or the v0.1-era fetch callable for HTTP-only tests). Avoids real I/O,
real threads, real sleeps -- keeps tests deterministic and fast. The
thread / sleep machinery in _loop() is exercised by a small integration
slice that uses a 1-second interval and stops promptly via stop().

Default check implementations (default_http_check, default_tcp_check,
default_exec_check) get their own integration-style tests at the bottom
of the file: real socket bind for TCP, real subprocess for exec, real
unreachable host for HTTP. These are bounded (sub-second timeouts,
no network egress).
"""

from __future__ import annotations

import sys
from collections.abc import Callable

import pytest

from recto.config import HealthzSpec
from recto.healthz import (
    HealthzProbe,
    default_exec_check,
    default_http_check,
    default_http_fetch,
    default_tcp_check,
)


def make_spec(
    *,
    enabled: bool = True,
    type_: str = "http",
    url: str = "http://localhost:5000/healthz",
    interval_seconds: int = 30,
    timeout_seconds: int = 5,
    failure_threshold: int = 3,
    restart_grace_seconds: int = 10,
) -> HealthzSpec:
    return HealthzSpec(
        enabled=enabled,
        type=type_,
        url=url,
        interval_seconds=interval_seconds,
        timeout_seconds=timeout_seconds,
        failure_threshold=failure_threshold,
        restart_grace_seconds=restart_grace_seconds,
    )


def stub_fetch(*statuses: int) -> Callable[[str, float], int]:
    """Build a fetch callable that returns the given statuses in order.
    After exhausting the sequence, repeats the LAST value (so a long
    test doesn't have to specify forever)."""
    seq = list(statuses)

    def _fetch(_url: str, _timeout: float) -> int:
        if not seq:
            return 0
        return seq.pop(0) if len(seq) > 1 else seq[0]

    return _fetch


# ---------------------------------------------------------------------------
# tick() -- single-iteration probe semantics
# ---------------------------------------------------------------------------


class TestTickHealthy:
    def test_200_counts_as_healthy(self) -> None:
        probe = HealthzProbe(make_spec(), fetch=stub_fetch(200))
        assert probe.tick() is True
        assert probe.consecutive_failures == 0
        assert probe.restart_required.is_set() is False

    def test_201_counts_as_healthy(self) -> None:
        probe = HealthzProbe(make_spec(), fetch=stub_fetch(201))
        assert probe.tick() is True

    def test_301_counts_as_healthy(self) -> None:
        probe = HealthzProbe(make_spec(), fetch=stub_fetch(301))
        assert probe.tick() is True

    def test_399_counts_as_healthy(self) -> None:
        probe = HealthzProbe(make_spec(), fetch=stub_fetch(399))
        assert probe.tick() is True


class TestTickFailing:
    def test_500_counts_as_failure(self) -> None:
        probe = HealthzProbe(make_spec(), fetch=stub_fetch(500))
        assert probe.tick() is False
        assert probe.consecutive_failures == 1

    def test_404_counts_as_failure(self) -> None:
        probe = HealthzProbe(make_spec(), fetch=stub_fetch(404))
        assert probe.tick() is False

    def test_zero_status_counts_as_failure(self) -> None:
        probe = HealthzProbe(make_spec(), fetch=stub_fetch(0))
        assert probe.tick() is False

    def test_fetch_raising_counts_as_failure(self) -> None:
        def boom(_url: str, _timeout: float) -> int:
            raise RuntimeError("connection refused")

        probe = HealthzProbe(make_spec(), fetch=boom)
        assert probe.tick() is False
        assert probe.consecutive_failures == 1


class TestConsecutiveFailureCounting:
    def test_failure_threshold_triggers_restart_required(self) -> None:
        probe = HealthzProbe(
            make_spec(failure_threshold=3),
            fetch=stub_fetch(500),
        )
        probe.tick()
        assert probe.restart_required.is_set() is False
        probe.tick()
        assert probe.restart_required.is_set() is False
        probe.tick()
        assert probe.restart_required.is_set() is True
        assert probe.consecutive_failures == 3

    def test_success_resets_failure_counter(self) -> None:
        statuses = iter([500, 500, 200, 500, 500, 500])

        def _fetch(_url: str, _t: float) -> int:
            return next(statuses)

        probe = HealthzProbe(make_spec(failure_threshold=3), fetch=_fetch)
        probe.tick()
        probe.tick()
        assert probe.consecutive_failures == 2
        probe.tick()
        assert probe.consecutive_failures == 0
        assert probe.restart_required.is_set() is False
        probe.tick()
        probe.tick()
        assert probe.restart_required.is_set() is False
        probe.tick()
        assert probe.restart_required.is_set() is True

    def test_threshold_of_one_trips_immediately(self) -> None:
        probe = HealthzProbe(
            make_spec(failure_threshold=1), fetch=stub_fetch(500)
        )
        probe.tick()
        assert probe.restart_required.is_set() is True


# ---------------------------------------------------------------------------
# start() / stop()
# ---------------------------------------------------------------------------


class TestStartStop:
    def test_start_is_noop_when_disabled(self) -> None:
        probe = HealthzProbe(make_spec(enabled=False))
        probe.start()
        assert probe._thread is None  # noqa: SLF001
        probe.stop()

    def test_start_runs_for_tcp_type(self) -> None:
        spec = HealthzSpec(
            enabled=True,
            type="tcp",
            host="127.0.0.1",
            port=1,
            interval_seconds=1,
            timeout_seconds=1,
            failure_threshold=1_000_000,
            restart_grace_seconds=0,
        )
        probe = HealthzProbe(spec, check=lambda _s: True)
        probe.start()
        probe.stop(timeout=2.0)
        assert probe._thread is not None  # noqa: SLF001
        assert not probe._thread.is_alive()  # noqa: SLF001

    def test_start_runs_for_exec_type(self) -> None:
        spec = HealthzSpec(
            enabled=True,
            type="exec",
            command=("true",),
            interval_seconds=1,
            timeout_seconds=1,
            failure_threshold=1_000_000,
            restart_grace_seconds=0,
        )
        probe = HealthzProbe(spec, check=lambda _s: True)
        probe.start()
        probe.stop(timeout=2.0)
        assert probe._thread is not None  # noqa: SLF001
        assert not probe._thread.is_alive()  # noqa: SLF001

    def test_stop_is_idempotent(self) -> None:
        probe = HealthzProbe(make_spec(enabled=False))
        probe.stop()
        probe.stop()
        probe.stop()


# ---------------------------------------------------------------------------
# _loop() -- integration-style: real thread, fast tick interval
# ---------------------------------------------------------------------------


class TestLoopIntegration:
    def test_loop_stops_promptly_on_stop_signal(self) -> None:
        spec = HealthzSpec(
            enabled=True,
            type="http",
            url="http://localhost/x",
            interval_seconds=1,
            timeout_seconds=1,
            failure_threshold=1_000_000,
            restart_grace_seconds=0,
        )
        probe = HealthzProbe(spec, fetch=stub_fetch(200))
        probe.start()
        import time
        time.sleep(0.05)
        probe.stop(timeout=2.0)
        assert probe._thread is not None  # noqa: SLF001
        assert not probe._thread.is_alive()  # noqa: SLF001

    def test_loop_signals_restart_required_on_persistent_failures(self) -> None:
        spec = HealthzSpec(
            enabled=True,
            type="http",
            url="http://localhost/x",
            interval_seconds=1,
            timeout_seconds=1,
            failure_threshold=2,
            restart_grace_seconds=0,
        )
        probe = HealthzProbe(spec, fetch=stub_fetch(500))
        probe.start()
        signaled = probe.restart_required.wait(timeout=2.0)
        probe.stop(timeout=2.0)
        assert signaled is True


# ---------------------------------------------------------------------------
# default_http_fetch
# ---------------------------------------------------------------------------


class TestDefaultHttpFetch:
    def test_returns_0_on_unreachable_host(self) -> None:
        rc = default_http_fetch("http://192.0.2.1:1/", timeout_seconds=0.1)
        assert rc == 0

    def test_returns_0_on_invalid_url_scheme(self) -> None:
        rc = default_http_fetch("not-a-real-url", timeout_seconds=0.1)
        assert rc == 0


# ---------------------------------------------------------------------------
# TCP probe
# ---------------------------------------------------------------------------


def make_tcp_spec(
    *,
    enabled: bool = True,
    host: str = "127.0.0.1",
    port: int = 12345,
    interval_seconds: int = 30,
    timeout_seconds: int = 5,
    failure_threshold: int = 3,
    restart_grace_seconds: int = 0,
) -> HealthzSpec:
    return HealthzSpec(
        enabled=enabled,
        type="tcp",
        host=host,
        port=port,
        interval_seconds=interval_seconds,
        timeout_seconds=timeout_seconds,
        failure_threshold=failure_threshold,
        restart_grace_seconds=restart_grace_seconds,
    )


class TestTcpProbeDispatch:
    def test_check_invoked_with_full_spec(self) -> None:
        seen: dict[str, object] = {}

        def check(spec: HealthzSpec) -> bool:
            seen["host"] = spec.host
            seen["port"] = spec.port
            seen["timeout"] = spec.timeout_seconds
            return True

        probe = HealthzProbe(make_tcp_spec(host="example", port=8080), check=check)
        assert probe.tick() is True
        assert seen["host"] == "example"
        assert seen["port"] == 8080
        assert seen["timeout"] == 5

    def test_failed_check_increments_counter(self) -> None:
        probe = HealthzProbe(
            make_tcp_spec(failure_threshold=2), check=lambda _s: False
        )
        probe.tick()
        assert probe.consecutive_failures == 1
        probe.tick()
        assert probe.restart_required.is_set() is True

    def test_default_check_for_tcp_is_default_tcp_check(self) -> None:
        probe = HealthzProbe(make_tcp_spec())
        assert probe._check is default_tcp_check  # noqa: SLF001


class TestDefaultTcpCheck:
    def test_listening_socket_is_healthy(self) -> None:
        import socket

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            spec = make_tcp_spec(host="127.0.0.1", port=port, timeout_seconds=1)
            assert default_tcp_check(spec) is True
        finally:
            srv.close()

    def test_refused_connection_is_unhealthy(self) -> None:
        spec = make_tcp_spec(host="192.0.2.1", port=1, timeout_seconds=0.1)
        assert default_tcp_check(spec) is False

    def test_invalid_host_is_unhealthy(self) -> None:
        spec = make_tcp_spec(
            host="this-host-should-not-resolve.invalid",
            port=8080,
            timeout_seconds=0.5,
        )
        assert default_tcp_check(spec) is False


# ---------------------------------------------------------------------------
# Exec probe
# ---------------------------------------------------------------------------


def make_exec_spec(
    *,
    enabled: bool = True,
    command: tuple[str, ...] = ("echo", "ok"),
    expected_exit_code: int = 0,
    interval_seconds: int = 30,
    timeout_seconds: int = 5,
    failure_threshold: int = 3,
    restart_grace_seconds: int = 0,
) -> HealthzSpec:
    return HealthzSpec(
        enabled=enabled,
        type="exec",
        command=command,
        expected_exit_code=expected_exit_code,
        interval_seconds=interval_seconds,
        timeout_seconds=timeout_seconds,
        failure_threshold=failure_threshold,
        restart_grace_seconds=restart_grace_seconds,
    )


class TestExecProbeDispatch:
    def test_check_invoked_with_full_spec(self) -> None:
        seen: dict[str, object] = {}

        def check(spec: HealthzSpec) -> bool:
            seen["command"] = spec.command
            seen["expected_exit_code"] = spec.expected_exit_code
            return True

        probe = HealthzProbe(
            make_exec_spec(command=("my-check", "--mode=quick"), expected_exit_code=0),
            check=check,
        )
        assert probe.tick() is True
        assert seen["command"] == ("my-check", "--mode=quick")
        assert seen["expected_exit_code"] == 0

    def test_default_check_for_exec_is_default_exec_check(self) -> None:
        probe = HealthzProbe(make_exec_spec())
        assert probe._check is default_exec_check  # noqa: SLF001


class TestDefaultExecCheck:
    """Use sys.executable so these tests work cross-platform without
    assuming /bin/sh, true(1), or a specific Python interpreter on PATH."""

    def test_zero_exit_is_healthy(self) -> None:
        spec = make_exec_spec(
            command=(sys.executable, "-c", "import sys; sys.exit(0)"),
            timeout_seconds=10,
        )
        assert default_exec_check(spec) is True

    def test_nonzero_exit_is_unhealthy(self) -> None:
        spec = make_exec_spec(
            command=(sys.executable, "-c", "import sys; sys.exit(2)"),
            timeout_seconds=10,
        )
        assert default_exec_check(spec) is False

    def test_custom_expected_exit_code_passes(self) -> None:
        spec = make_exec_spec(
            command=(sys.executable, "-c", "import sys; sys.exit(7)"),
            expected_exit_code=7,
            timeout_seconds=10,
        )
        assert default_exec_check(spec) is True

    def test_custom_expected_exit_code_fails_when_mismatched(self) -> None:
        spec = make_exec_spec(
            command=(sys.executable, "-c", "import sys; sys.exit(0)"),
            expected_exit_code=7,
            timeout_seconds=10,
        )
        assert default_exec_check(spec) is False

    def test_command_not_found_is_unhealthy(self) -> None:
        spec = make_exec_spec(
            command=("definitely-not-a-real-binary-xyz-recto-test",),
            timeout_seconds=2,
        )
        assert default_exec_check(spec) is False

    def test_timeout_is_unhealthy(self) -> None:
        spec = make_exec_spec(
            command=(sys.executable, "-c", "import time; time.sleep(10)"),
            timeout_seconds=0.2,
        )
        assert default_exec_check(spec) is False

    def test_empty_command_is_unhealthy(self) -> None:
        spec = HealthzSpec(enabled=False, type="exec")
        assert default_exec_check(spec) is False


# ---------------------------------------------------------------------------
# default_http_check
# ---------------------------------------------------------------------------


class TestDefaultHttpCheck:
    def test_returns_false_for_unreachable(self) -> None:
        spec = HealthzSpec(
            enabled=True,
            type="http",
            url="http://192.0.2.1:1/",
            timeout_seconds=1,
        )
        assert default_http_check(spec) is False


# ---------------------------------------------------------------------------
# Backward-compat fetch= seam
# ---------------------------------------------------------------------------


class TestLegacyFetchSeam:
    def test_fetch_still_drives_http_health(self) -> None:
        probe = HealthzProbe(make_spec(), fetch=stub_fetch(200))
        assert probe.tick() is True

    def test_fetch_and_check_both_provided_raises(self) -> None:
        with pytest.raises(TypeError):
            HealthzProbe(
                make_spec(),
                fetch=stub_fetch(200),
                check=lambda _s: True,
            )
