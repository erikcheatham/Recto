"""Launcher: read service.yaml, fetch secrets, spawn the child, supervise.

Hosts launch() (one-shot), build_child_env, resolve_sources, plus the
internals shared with run(). `run()` and the longer-form event emitter
live in `recto._launcher_run` to keep this file under the cross-mount
Write-tool truncation threshold encountered during v0.1.

Hard rules in this file:
- Secrets never serialized through _emit_event (caller is responsible).
- SigningCapability raises NotImplementedError pointing at v0.4.
- spec.env entries lose to fetched secrets on env-var collision.
- shell=False everywhere; YAML's exec+args is the canonical command.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

from recto.adminui import AdminUIServer, EventBuffer
from recto.comms import CommsDispatcher
from recto.config import (
    AdminUISpec,
    HealthzSpec,
    ResourceLimitsSpec,
    ServiceConfig,
    ServiceSpec,
    TelemetrySpec,
)
from recto.healthz import HealthzProbe
from recto.joblimit import JobLimit
from recto.secrets import (
    DirectSecret,
    SecretMaterial,
    SecretSource,
    SigningCapability,
    resolve_source,
)
from recto.telemetry import TelemetryClient

__all__ = [
    "AdminUIFactory",
    "BufferFactory",
    "DispatcherFactory",
    "JoblimitFactory",
    "LauncherError",
    "PopenFactory",
    "ProbeFactory",
    "SecretInjectionError",
    "TelemetryFactory",
    "build_child_env",
    "launch",
    "resolve_sources",
    "run",
]


PopenFactory = Callable[..., "subprocess.Popen[Any]"]
ProbeFactory = Callable[[HealthzSpec], HealthzProbe]
DispatcherFactory = Callable[
    [ServiceConfig, Mapping[str, str]], "CommsDispatcher | None"
]
JoblimitFactory = Callable[[ResourceLimitsSpec], JobLimit]
TelemetryFactory = Callable[[TelemetrySpec], TelemetryClient]
"""(spec.telemetry) -> TelemetryClient. Production uses TelemetryClient
directly; tests inject a stub that records start_run / record_event /
end_run calls. No-op when telemetry.enabled=False (the default)."""

BufferFactory = Callable[[], EventBuffer]
"""() -> EventBuffer. Production uses EventBuffer with default capacity;
tests pass a smaller-capacity stub to verify ring behavior."""

AdminUIFactory = Callable[
    [AdminUISpec, str, EventBuffer, ServiceConfig], AdminUIServer
]
"""(spec.admin_ui, service_name, buffer, config) -> AdminUIServer.
Construction does NOT bind; .start() does. Tests inject a stub that
records start/stop without spawning a real HTTP server."""
"""(spec.resource_limits) -> JobLimit. Production uses JobLimit directly;
tests inject a stub that records attach() / close() calls without
touching Win32. Constructed once per spawn (per-spawn lifetime, parallels
HealthzProbe)."""


class LauncherError(Exception):
    """Top-level launcher failure. Subclasses pin down the cause."""


class SecretInjectionError(LauncherError):
    """A secret could not be resolved or injected into the child env.

    Distinct from `SecretNotFoundError` (the source's "I don't have it")
    and `UnknownSecretSourceError` (no backend registered).
    """


def resolve_sources(config: ServiceConfig) -> dict[str, SecretSource]:
    """Build {source_name: SecretSource} for every source referenced.

    Each unique `source:` value is resolved once via the registry so
    one CredManSource handle covers every secret that shares a source.
    """
    needed = {s.source for s in config.spec.secrets}
    return {name: resolve_source(name, config.metadata.name) for name in needed}


def build_child_env(
    spec: ServiceSpec,
    sources: Mapping[str, SecretSource],
    *,
    base_env: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Compose the env-var dict the child inherits.

    Layering (later wins): base_env -> spec.env -> resolved secrets.
    Secrets always override spec.env entries with the same target_env.
    """
    env: dict[str, str] = dict(base_env if base_env is not None else os.environ)
    env.update(spec.env)
    for s in spec.secrets:
        source = sources.get(s.source)
        if source is None:
            raise SecretInjectionError(
                f"secret {s.name!r} declares source {s.source!r} but no "
                f"matching SecretSource was provided to the launcher; "
                f"this is a launcher-internal bug - resolve_sources "
                f"should have populated it"
            )
        fetch_config = dict(s.config)
        fetch_config["required"] = s.required
        material: SecretMaterial = source.fetch(s.name, fetch_config)
        if isinstance(material, SigningCapability):
            raise NotImplementedError(
                f"secret {s.name!r}: source {s.source!r} returned a "
                f"SigningCapability (algorithm={material.algorithm!r}). "
                f"v0.1 launcher only handles DirectSecret. "
                f"SigningCapability support ships in v0.4. See ROADMAP.md."
            )
        if not isinstance(material, DirectSecret):
            raise SecretInjectionError(
                f"secret {s.name!r}: source {s.source!r} returned "
                f"unsupported material type {type(material).__name__}; "
                f"expected DirectSecret"
            )
        env[s.target_env] = material.value
    return env


def launch(
    config: ServiceConfig,
    *,
    sources: Mapping[str, SecretSource] | None = None,
    popen: PopenFactory = subprocess.Popen,
    base_env: Mapping[str, str] | None = None,
    probe_factory: ProbeFactory = HealthzProbe,
    poll_interval_seconds: float = 0.5,
    terminate_grace_seconds: float = 5.0,
    dispatcher_factory: DispatcherFactory | None = None,
    joblimit_factory: JoblimitFactory = JobLimit,
    telemetry_factory: TelemetryFactory = TelemetryClient,
    buffer_factory: BufferFactory = EventBuffer,
    adminui_factory: AdminUIFactory = AdminUIServer,
) -> int:
    """Run the supervised child once. Returns the child's exit code."""
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
    rc = 0
    try:
        with _bracket_lifecycle(
            config, sources, telemetry=telemetry, buffer=buffer
        ):
            env = build_child_env(config.spec, sources, base_env=base_env)
            dispatcher = _build_dispatcher(config, env, dispatcher_factory)
            rc = _spawn_and_wait(
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
            return rc
    finally:
        adminui.stop()
        telemetry.end_run(rc)
        telemetry.shutdown()


# ---------------------------------------------------------------------------
# Internals shared by launch() and run()
# ---------------------------------------------------------------------------


@contextmanager
def _bracket_lifecycle(
    config: ServiceConfig,
    sources: Mapping[str, SecretSource],
    *,
    telemetry: TelemetryClient | None = None,
    buffer: EventBuffer | None = None,
) -> Iterator[None]:
    """init() lifecycle-stateful sources before, teardown() after."""
    initialized: list[SecretSource] = []
    try:
        for src in sources.values():
            if src.supports_lifecycle():
                src.init()
                initialized.append(src)
        yield
    finally:
        for src in initialized:
            try:
                src.teardown()
            except Exception as exc:  # noqa: BLE001
                _emit_event(
                    config,
                    "source.teardown_failed",
                    {"source": src.name, "error": type(exc).__name__},
                    telemetry=telemetry,
                    buffer=buffer,
                )


def _build_dispatcher(
    config: ServiceConfig,
    env: Mapping[str, str],
    dispatcher_factory: DispatcherFactory | None,
) -> CommsDispatcher | None:
    """Construct CommsDispatcher (or accept None opt-out)."""
    if dispatcher_factory is not None:
        return dispatcher_factory(config, env)
    if not config.spec.comms:
        return None

    def _emit_failure(kind: str, ctx: dict[str, Any]) -> None:
        _emit_event(config, kind, ctx, dispatcher=None)

    return CommsDispatcher(config, env=env, emit_failure=_emit_failure)


def _spawn_and_wait(
    config: ServiceConfig,
    env: Mapping[str, str],
    popen: PopenFactory,
    *,
    probe_factory: ProbeFactory = HealthzProbe,
    poll_interval_seconds: float = 0.5,
    terminate_grace_seconds: float = 5.0,
    dispatcher: CommsDispatcher | None = None,
    joblimit_factory: JoblimitFactory = JobLimit,
    telemetry: TelemetryClient | None = None,
    buffer: EventBuffer | None = None,
) -> int:
    """Spawn one child with the given env, wait for exit OR healthz unhealthy.

    Owns the per-spawn HealthzProbe + JobLimit lifetimes. The JobLimit
    is constructed regardless of whether resource_limits is set; it's a
    no-op at the Win32 layer when no limits are requested. SIGTERMs the
    child if the probe trips while still running, with
    terminate_grace_seconds before SIGKILL.
    """
    cmd: list[str] = [config.spec.exec, *config.spec.args]
    cwd: str | None = config.spec.working_dir or None

    _emit_event(
        config,
        "child.spawn",
        {
            "cmd": cmd,
            "cwd": cwd,
            "secrets_injected": [s.target_env for s in config.spec.secrets],
        },
        dispatcher=dispatcher,
        telemetry=telemetry,
        buffer=buffer,
    )

    proc = popen(cmd, env=dict(env), cwd=cwd)

    # JobLimit attach happens AFTER popen but BEFORE the wait loop so
    # the kernel-level enforcement is in place before the child has had
    # time to misbehave. KILL_ON_JOB_CLOSE means handle release in the
    # finally below kills any still-running child.
    #
    # When the spec has no resource_limits set (the common case), the
    # JobLimit is a no-op shell -- handle is None, attach/close return
    # without touching Win32. We skip the proc.pid access in that path
    # so existing tests that pass a StubProc without a .pid attribute
    # keep working unchanged.
    joblimit = joblimit_factory(config.spec.resource_limits)
    if joblimit.handle is not None:
        try:
            joblimit.attach(proc.pid)
        except Exception:  # noqa: BLE001
            joblimit.close()
            raise

    probe: HealthzProbe | None = None
    if config.spec.healthz.enabled:
        probe = probe_factory(config.spec.healthz)
        probe.start()

    healthz_signaled = False
    try:
        rc = _wait_for_exit_or_unhealthy(
            proc,
            probe,
            poll_interval_seconds=poll_interval_seconds,
            terminate_grace_seconds=terminate_grace_seconds,
        )
        if probe is not None and probe.restart_required.is_set():
            healthz_signaled = True
    finally:
        if probe is not None:
            probe.stop()
        # Close the JobLimit AFTER the probe stops so a probe-driven
        # restart still runs through proc.terminate() / proc.wait()
        # naturally. KILL_ON_JOB_CLOSE here is a backstop.
        joblimit.close()

    _emit_event(
        config,
        "child.exit",
        {"returncode": rc, "healthz_signaled": healthz_signaled},
        dispatcher=dispatcher,
        telemetry=telemetry,
        buffer=buffer,
    )
    return rc


def _wait_for_exit_or_unhealthy(
    proc: subprocess.Popen[Any],
    probe: HealthzProbe | None,
    *,
    poll_interval_seconds: float,
    terminate_grace_seconds: float,
) -> int:
    """Block until child exits or probe signals unhealthy."""
    while True:
        rc = proc.poll()
        if rc is not None:
            return int(rc)
        if probe is not None and probe.restart_required.is_set():
            proc.terminate()
            try:
                rc = proc.wait(timeout=terminate_grace_seconds)
            except subprocess.TimeoutExpired:
                proc.kill()
                rc = proc.wait()
            return int(rc)
        time.sleep(poll_interval_seconds)


def _emit_event(
    config: ServiceConfig,
    kind: str,
    ctx: dict[str, Any],
    *,
    dispatcher: CommsDispatcher | None = None,
    telemetry: TelemetryClient | None = None,
    buffer: EventBuffer | None = None,
) -> None:
    """Structured stdout log line + optional webhook + OTel + admin-UI buffer."""
    record = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),  # noqa: UP017
        "service": config.metadata.name,
        "kind": kind,
        "ctx": ctx,
    }
    try:
        line = json.dumps(record, default=str)
    except (TypeError, ValueError) as exc:
        line = json.dumps(
            {
                "ts": record["ts"],
                "service": record["service"],
                "kind": "internal.event_serialize_failed",
                "ctx": {"original_kind": kind, "error": str(exc)},
            }
        )
    print(line, file=sys.stdout, flush=True)
    if dispatcher is not None:
        dispatcher.dispatch(kind, ctx)
    if telemetry is not None:
        telemetry.record_event(kind, ctx)
    if buffer is not None:
        buffer.append(kind, ctx)


# Restart-loop entry point lives in _launcher_run to dodge the
# cross-mount Write-tool truncation. Re-exported under recto.launcher.run
# so callers don't need to know about the split.
from recto._launcher_run import run  # noqa: E402, F401
