"""Liveness probes for the supervised child process.

Why we have this even though NSSM restarts crashed processes
------------------------------------------------------------

NSSM's `AppExit` and `AppRestartDelay` settings cover process EXIT --
when the child crashes outright. They do not cover a child that has
silently deadlocked: imports complete, the HTTP server is bound, but
some background thread holding the request-handling lock has wedged.
The process is "Running" from the OS perspective forever. Recto's
healthz probe is the second line of defense: by polling some external
indicator of liveness, we detect deadlocks the OS can't see.

Probe types (v0.2)
------------------

Three default check implementations, dispatched by `spec.healthz.type`:

- ``http``: GET ``url`` with ``timeout_seconds``; 2xx/3xx is healthy,
  anything else (including network errors and timeouts) is a failure.
  No body inspection -- apps that want richer health semantics return
  a 5xx when degraded and a 2xx when ready.
- ``tcp``: open a TCP connection to ``host:port`` with
  ``timeout_seconds``; success is healthy. Lighter-weight than HTTP
  for services that don't expose a `/healthz` endpoint but DO listen
  on a port.
- ``exec``: run ``command`` (list of args) with ``timeout_seconds``;
  exit code matching ``expected_exit_code`` (default 0) is healthy.
  Useful for services with a bespoke health check (database connection
  test, custom CLI tool, etc.).

Adding a new probe type is a one-line registration in
`_default_check_for_spec`; the loop / threading / restart-signaling
machinery is type-agnostic.

Design
------

`HealthzProbe` owns a daemon thread. After ``restart_grace_seconds``
of quiet (give the child time to bind its socket / become reachable),
it ticks every ``interval_seconds`` with a ``timeout_seconds`` budget
per check. After ``failure_threshold`` CONSECUTIVE failures, it sets
``restart_required``. The launcher's run-loop reads that event and
treats it as a synthetic non-zero exit, restarting the child via the
same restart-policy machinery used for exit-code-driven restarts.
"""

from __future__ import annotations

import socket
import subprocess
import threading
import urllib.error
import urllib.request
from collections.abc import Callable

from recto.config import HealthzSpec

__all__ = [
    "HealthzProbe",
    "ProbeCheck",
    "HttpFetch",
    "default_http_fetch",
    "default_http_check",
    "default_tcp_check",
    "default_exec_check",
]


ProbeCheck = Callable[[HealthzSpec], bool]
"""(spec) -> True if healthy, False if unhealthy. Default implementations
swallow their own exceptions and return False; HealthzProbe.tick() also
catches as defense in depth."""


HttpFetch = Callable[[str, float], int]
"""(url, timeout_seconds) -> HTTP status code. Returns 0 on any failure
(network error, timeout, malformed response, etc.). Legacy v0.1 test
seam -- pass via ``HealthzProbe(fetch=...)`` to override the HTTP probe.
For non-HTTP probe types or new tests, prefer the more general
``check=`` parameter."""


def default_http_fetch(url: str, timeout_seconds: float) -> int:
    """Default HTTP probe fetcher backed by stdlib urllib.

    Returns the HTTP status code on a successful round-trip; returns 0
    on any failure (TCP refused, DNS fail, timeout, redirect-loop, etc.).
    """
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            return int(resp.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return 0


def default_http_check(spec: HealthzSpec) -> bool:
    """HTTP probe default. 2xx/3xx is healthy."""
    status = default_http_fetch(spec.url, float(spec.timeout_seconds))
    return 200 <= status < 400


def default_tcp_check(spec: HealthzSpec) -> bool:
    """TCP probe default. A successful connect is healthy."""
    try:
        with socket.create_connection(
            (spec.host, spec.port),
            timeout=float(spec.timeout_seconds),
        ):
            return True
    except OSError:
        return False


def default_exec_check(spec: HealthzSpec) -> bool:
    """Exec probe default. ``command`` exiting with ``expected_exit_code``
    is healthy.
    """
    if not spec.command:
        return False
    try:
        result = subprocess.run(
            list(spec.command),
            timeout=float(spec.timeout_seconds),
            capture_output=True,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == spec.expected_exit_code


def _default_check_for_spec(spec: HealthzSpec) -> ProbeCheck:
    """Pick a default check implementation based on ``spec.type``."""
    if spec.type == "http":
        return default_http_check
    if spec.type == "tcp":
        return default_tcp_check
    if spec.type == "exec":
        return default_exec_check
    raise NotImplementedError(
        f"healthz type {spec.type!r} has no default check implementation; "
        f"valid types are http, tcp, exec."
    )


class HealthzProbe:
    """Threaded liveness probe.

    Lifecycle:
        probe = HealthzProbe(config.spec.healthz)
        probe.start()
        if probe.restart_required.is_set():
            ...
        probe.stop()

    Backward compat: the v0.1 ``fetch=`` kwarg (HTTP-only,
    ``(url, timeout) -> status_code``) still works and is wrapped into
    a check internally. Pass either ``check=`` or ``fetch=``, not both.
    """

    def __init__(
        self,
        spec: HealthzSpec,
        *,
        fetch: HttpFetch | None = None,
        check: ProbeCheck | None = None,
    ):
        self.spec = spec
        if fetch is not None and check is not None:
            raise TypeError(
                "HealthzProbe: pass either fetch= or check=, not both"
            )
        if check is not None:
            self._check: ProbeCheck = check
        elif fetch is not None:
            self._check = lambda s, _f=fetch: 200 <= _f(s.url, float(s.timeout_seconds)) < 400
        else:
            self._check = _default_check_for_spec(spec)
        self.restart_required = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._consecutive_failures = 0

    @property
    def consecutive_failures(self) -> int:
        return self._consecutive_failures

    def tick(self) -> bool:
        """Run one probe iteration synchronously."""
        try:
            healthy = bool(self._check(self.spec))
        except Exception:  # noqa: BLE001
            healthy = False

        if healthy:
            self._consecutive_failures = 0
        else:
            self._consecutive_failures += 1
            if self._consecutive_failures >= self.spec.failure_threshold:
                self.restart_required.set()
        return healthy

    def start(self) -> None:
        """Spawn the background probe loop. No-op if disabled."""
        if not self.spec.enabled:
            return
        if self.spec.type not in ("http", "tcp", "exec"):
            raise NotImplementedError(
                f"healthz type {self.spec.type!r} is not supported; "
                f"valid types are http, tcp, exec."
            )
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="recto.healthz"
        )
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        """Signal the loop to stop and join the thread. Idempotent."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    def _loop(self) -> None:
        if self._stop.wait(timeout=float(self.spec.restart_grace_seconds)):
            return
        while not self._stop.is_set():
            self.tick()
            if self.restart_required.is_set():
                return
            if self._stop.wait(timeout=float(self.spec.interval_seconds)):
                return
