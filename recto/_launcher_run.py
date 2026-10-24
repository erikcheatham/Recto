"""Restart-loop entry point split out of recto.launcher.

Lives in its own module to keep recto/launcher.py under the
cross-mount Write-tool truncation threshold encountered during v0.1
work. Re-exported as `recto.launcher.run` at the bottom of
recto/launcher.py.
"""

from __future__ import annotations

import subprocess
import time
from collections.abc import Callable, Mapping

from recto.adminui import AdminUIServer, EventBuffer
from recto.config import ServiceConfig
from recto.healthz import HealthzProbe
from recto.joblimit import JobLimit
from recto.restart import MaxAttemptsReachedError, next_delay, should_restart
from recto.secrets import SecretSource
from recto.telemetry import TelemetryClient

__all__ = ["run"]


def run(
    config: ServiceConfig,
    *,
    sources: Mapping[str, SecretSource] | None = None,
    popen: Callable[..., "subprocess.Popen"] = subprocess.Popen,
    base_env: Mapping[str, str] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    probe_factory: Callable[..., HealthzProbe] = HealthzProbe,
    poll_interval_seconds: float = 0.5,
    terminate_grace_seconds: float = 5.0,
    dispatcher_factory: Callable[..., object] | None = None,
    joblimit_factory: Callable[..., JobLimit] = JobLimit,
    telemetry_factory: Callable[..., TelemetryClient] = TelemetryClient,
    buffer_factory: Callable[[], EventBuffer] = EventBuffer,
    adminui_factory: Callable[..., AdminUIServer] = AdminUIServer,
) -> int:
    """Run the supervised child with the configured restart policy.

    Compared to launch():
    - launch() is one-shot (single spawn, single bracket).
    - run() brackets init/teardown ONCE around the whole loop and
      re-spawns per restart policy. Long-lived backends (Vault session,
      hardware-enclave handle) stay open across restarts. The
      TelemetryClient also lives across the whole loop -- one OTel
      span covers every restart attempt. Likewise the EventBuffer +
      AdminUIServer cover the whole loop, so /api/events shows the
      full lifecycle history rather than just the latest spawn.

    Returns the LAST child invocation's exit code, whether the policy
    decided "no restart" or max_attempts_reached fired.
    """
    # Local imports avoid the recto.launcher <-> recto._launcher_run
    # circular import at module load time.
    from recto.launcher import (
        _bracket_lifecycle,
        _build_dispatcher,
        _emit_event,
        _spawn_and_wait,
        build_child_env,
        resolve_sources,
    )

    if sources is None:
        sources = resolve_sources(config)

    telemetry = telemetry_factory(config.spec.telemetry)
    telemetry.start_run(
        config.metadata.name,
        attributes={
            "recto.healthz.type": config.spec.healthz.type,
            "recto.restart.policy": config.spec.restart.policy,
        },
    )
    buffer = buffer_factory()
    adminui = adminui_factory(
        config.spec.admin_ui,
        service_name=config.metadata.name,
        buffer=buffer,
        config=config,
    )
    adminui.start()
    last_rc = 0
    try:
        with _bracket_lifecycle(
            config, sources, telemetry=telemetry, buffer=buffer
        ):
            env = build_child_env(config.spec, sources, base_env=base_env)
            dispatcher = _build_dispatcher(config, env, dispatcher_factory)
            attempt = 0
            while True:
                last_rc = _spawn_and_wait(
                    config,
                    env,
                    popen,
                    probe_factory=probe_factory,
                    poll_interval_seconds=poll_interval_seconds,
                    terminate_grace_seconds=terminate_grace_seconds,
                    dispatcher=dispatcher,
                    joblimit_factory=joblimit_factory,
                    telemetry=telemetry,
                    buffer=buffer,
                )
                if not should_restart(last_rc, config.spec.restart):
                    _emit_event(
                        config,
                        "run.final_exit",
                        {"returncode": last_rc, "restart_attempts": attempt},
                        dispatcher=dispatcher,
                        telemetry=telemetry,
                        buffer=buffer,
                    )
                    return last_rc
                attempt += 1
                try:
                    delay = next_delay(attempt, config.spec.restart)
                except MaxAttemptsReachedError:
                    _emit_event(
                        config,
                        "max_attempts_reached",
                        {
                            "max_attempts": config.spec.restart.max_attempts,
                            "last_returncode": last_rc,
                        },
                        dispatcher=dispatcher,
                        telemetry=telemetry,
                        buffer=buffer,
                    )
                    return last_rc
                _emit_event(
                    config,
                    "restart.attempt",
                    {
                        "attempt": attempt,
                        "delay_seconds": delay,
                        "previous_returncode": last_rc,
                        "backoff": config.spec.restart.backoff,
                    },
                    dispatcher=dispatcher,
                    telemetry=telemetry,
                    buffer=buffer,
                )
                sleep(delay)
    finally:
        adminui.stop()
        telemetry.end_run(last_rc)
        telemetry.shutdown()
