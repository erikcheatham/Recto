"""Launcher <-> CommsDispatcher integration tests.

Lives in its own file (rather than as a class in test_launcher.py)
because adding to the latter has tripped over a Cowork-mount cache
lag too many times. The contract under test:

- launch() builds a CommsDispatcher when spec.comms is non-empty,
  unless dispatcher_factory overrides.
- The dispatcher is constructed AFTER source.init() so resolved
  secrets are visible to ${env:VAR} interpolation.
- run() builds the dispatcher ONCE per restart loop (not per spawn).
- The launcher's _emit_event forwards every kind to the dispatcher;
  filtering is the dispatcher's responsibility, not the launcher's.

Stub helpers live here too — duplicating a couple of small classes
from test_launcher.py is cheaper than coupling the two files.
"""

from __future__ import annotations

from typing import Any

import pytest

from recto.config import RestartSpec, ServiceConfig, load_config
from recto.launcher import launch, run
from recto.secrets import DirectSecret, SecretMaterial, SecretNotFoundError, SecretSource


# ---------------------------------------------------------------------------
# Stubs
# ---------------------------------------------------------------------------


class _StubSource(SecretSource):
    """Minimal in-memory SecretSource for these tests."""

    def __init__(
        self,
        materials: dict[str, SecretMaterial] | None = None,
        *,
        source_name: str = "stub",
        supports_lifecycle: bool = False,
    ) -> None:
        self.materials = materials if materials is not None else {}
        self._source_name = source_name
        self._supports_lifecycle = supports_lifecycle
        self.init_call_count = 0
        self.teardown_call_count = 0

    @property
    def name(self) -> str:
        return self._source_name

    def fetch(self, secret_name: str, config: dict[str, Any]) -> SecretMaterial:
        if secret_name not in self.materials:
            if config.get("required", True):
                raise SecretNotFoundError(secret_name)
            return DirectSecret(value="")
        return self.materials[secret_name]

    def supports_lifecycle(self) -> bool:
        return self._supports_lifecycle

    def init(self) -> None:
        self.init_call_count += 1

    def teardown(self) -> None:
        self.teardown_call_count += 1


class _StubProc:
    """subprocess.Popen-shaped stub. Default behavior: child has already
    exited with the configured returncode."""

    def __init__(self, returncode: int = 0) -> None:
        self._returncode = returncode
        self.terminate_call_count = 0
        self.kill_call_count = 0

    def poll(self) -> int:
        return self._returncode

    def wait(self, timeout: float | None = None) -> int:  # noqa: ARG002
        return self._returncode

    def terminate(self) -> None:
        self.terminate_call_count += 1

    def kill(self) -> None:
        self.kill_call_count += 1


def _make_popen_stub(returncode: int = 0) -> Any:
    def fake_popen(
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        **_kw: Any,
    ) -> _StubProc:
        return _StubProc(returncode=returncode)

    return fake_popen


class _SequencedPopen:
    """Pre-canned exit-code sequence for restart-loop tests."""

    def __init__(self, returncodes: list[int]) -> None:
        self.returncodes = list(returncodes)
        self.spawn_count = 0

    def __call__(
        self,
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        **_kw: Any,
    ) -> _StubProc:
        if self.spawn_count >= len(self.returncodes):
            raise AssertionError("_SequencedPopen exhausted")
        rc = self.returncodes[self.spawn_count]
        self.spawn_count += 1
        return _StubProc(returncode=rc)


class _SleepRecorder:
    def __init__(self) -> None:
        self.calls: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


class _StubDispatcher:
    """CommsDispatcher-shaped stub. Records every dispatch(kind, ctx)."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def dispatch(self, kind: str, ctx: dict[str, Any]) -> None:
        self.calls.append((kind, dict(ctx)))


# ---------------------------------------------------------------------------
# Fixtures: configs
# ---------------------------------------------------------------------------


def _make_comms_config(
    *,
    name: str = "myservice",
    secrets: list[dict[str, Any]] | None = None,
    restart: dict[str, Any] | None = None,
) -> ServiceConfig:
    spec: dict[str, Any] = {
        "exec": "python.exe",
        "comms": [
            {
                "type": "webhook",
                "url": "https://hooks.example.com/recto",
                "headers": {"X-Auth": "${env:WEBHOOK_TOKEN}"},
            }
        ],
        "restart": restart if restart is not None else {"notify_on_event": ["*"]},
    }
    if secrets is not None:
        spec["secrets"] = secrets
    return load_config(
        {
            "apiVersion": "recto/v1",
            "kind": "Service",
            "metadata": {"name": name},
            "spec": spec,
        }
    )


def _make_no_comms_config() -> ServiceConfig:
    return load_config(
        {
            "apiVersion": "recto/v1",
            "kind": "Service",
            "metadata": {"name": "noweb"},
            "spec": {"exec": "python.exe"},
        }
    )


# ---------------------------------------------------------------------------
# launch() wiring
# ---------------------------------------------------------------------------


class TestLaunchDispatcherWiring:
    def test_launch_passes_dispatcher_to_emit_events(self) -> None:
        config = _make_comms_config()
        stub = _StubDispatcher()
        launch(
            config,
            sources={},
            popen=_make_popen_stub(returncode=0),
            base_env={},
            dispatcher_factory=lambda _cfg, _env: stub,
        )
        kinds = [k for k, _ in stub.calls]
        assert "child.spawn" in kinds
        assert "child.exit" in kinds

    def test_launch_no_dispatcher_when_factory_returns_none(self) -> None:
        config = _make_comms_config()
        rc = launch(
            config,
            sources={},
            popen=_make_popen_stub(returncode=0),
            base_env={},
            dispatcher_factory=lambda _cfg, _env: None,
        )
        assert rc == 0

    def test_launch_default_factory_skips_dispatcher_when_no_comms(self) -> None:
        # No comms => default factory returns None => no urllib touched.
        config = _make_no_comms_config()
        rc = launch(
            config,
            sources={},
            popen=_make_popen_stub(returncode=0),
            base_env={},
        )
        assert rc == 0

    def test_dispatcher_receives_env_with_resolved_secrets(self) -> None:
        config = _make_comms_config(
            secrets=[
                {
                    "name": "WEBHOOK_TOKEN",
                    "source": "stub",
                    "target_env": "WEBHOOK_TOKEN",
                }
            ],
        )
        sources = {
            "stub": _StubSource(
                {"WEBHOOK_TOKEN": DirectSecret("real-token-from-credman")}
            )
        }
        captured_env: dict[str, str] = {}

        def factory(_cfg: ServiceConfig, env: Any) -> Any:
            captured_env.update(dict(env))
            return _StubDispatcher()

        launch(
            config,
            sources=sources,
            popen=_make_popen_stub(returncode=0),
            base_env={},
            dispatcher_factory=factory,
        )
        assert captured_env["WEBHOOK_TOKEN"] == "real-token-from-credman"


# ---------------------------------------------------------------------------
# run() wiring across the restart loop
# ---------------------------------------------------------------------------


class TestRunDispatcherWiring:
    def test_run_dispatcher_sees_full_event_stream(self) -> None:
        config = _make_comms_config(
            restart={
                "policy": "always",
                "backoff": "constant",
                "initial_delay_seconds": 0,
                "max_delay_seconds": 0,
                "max_attempts": 1,
                "notify_on_event": ["*"],
            },
        )
        stub = _StubDispatcher()
        popen = _SequencedPopen([2, 2])
        run(
            config,
            sources={},
            popen=popen,
            base_env={},
            sleep=_SleepRecorder(),
            dispatcher_factory=lambda _cfg, _env: stub,
        )
        kinds = [k for k, _ in stub.calls]
        assert "child.spawn" in kinds
        assert "child.exit" in kinds
        assert "restart.attempt" in kinds
        assert "max_attempts_reached" in kinds

    def test_run_factory_called_once_for_whole_loop(self) -> None:
        # Long-lived backends shouldn't see their dispatcher rebuilt on
        # every restart attempt.
        stateful = _StubSource(
            materials={"WEBHOOK_TOKEN": DirectSecret("token-v1")},
            source_name="stateful",
            supports_lifecycle=True,
        )
        config = _make_comms_config(
            secrets=[
                {
                    "name": "WEBHOOK_TOKEN",
                    "source": "stateful",
                    "target_env": "WEBHOOK_TOKEN",
                }
            ],
            restart={
                "policy": "always",
                "backoff": "constant",
                "initial_delay_seconds": 0,
                "max_delay_seconds": 0,
                "max_attempts": 2,
                "notify_on_event": ["*"],
            },
        )
        factory_call_count = [0]
        captured_envs: list[dict[str, str]] = []

        def factory(_cfg: ServiceConfig, env: Any) -> Any:
            factory_call_count[0] += 1
            captured_envs.append(dict(env))
            return _StubDispatcher()

        run(
            config,
            sources={"stateful": stateful},
            popen=_SequencedPopen([1, 1, 1]),
            base_env={},
            sleep=_SleepRecorder(),
            dispatcher_factory=factory,
        )
        assert factory_call_count[0] == 1
        assert stateful.init_call_count == 1
        assert stateful.teardown_call_count == 1
        assert captured_envs[0]["WEBHOOK_TOKEN"] == "token-v1"


# ---------------------------------------------------------------------------
# Boundary: dispatcher errors must NOT bubble up
# ---------------------------------------------------------------------------


class TestLauncherDispatcherBoundary:
    def test_raising_dispatcher_propagates_through_emit_event(self) -> None:
        # _emit_event does not currently wrap dispatcher.dispatch in
        # try/except; that's by design — the real CommsDispatcher
        # swallows all errors internally. This test pins the boundary
        # so anyone changing _emit_event's wrap policy notices.
        class RaisingDispatcher:
            def dispatch(self, kind: str, ctx: dict[str, Any]) -> None:
                raise RuntimeError("boom")

        config = _make_comms_config()
        with pytest.raises(RuntimeError, match="boom"):
            launch(
                config,
                sources={},
                popen=_make_popen_stub(returncode=0),
                base_env={},
                dispatcher_factory=lambda _cfg, _env: RaisingDispatcher(),
            )

    def test_real_dispatcher_swallows_dispatch_errors(self) -> None:
        # End-to-end: with the default factory, a webhook that always
        # errors should NOT crash launch(). This goes through the real
        # CommsDispatcher with its built-in soft-failure handling.
        from recto.comms import CommsDispatcher

        config = _make_comms_config()

        def always_failing_urlopen(*_a: Any, **_kw: Any) -> Any:
            import urllib.error

            raise urllib.error.URLError("simulated outage")

        def factory(cfg: ServiceConfig, env: Any) -> CommsDispatcher:
            return CommsDispatcher(
                cfg,
                env=env,
                urlopen=always_failing_urlopen,
                emit_failure=None,  # use stderr-fallback path
            )

        rc = launch(
            config,
            sources={},
            popen=_make_popen_stub(returncode=0),
            base_env={},
            dispatcher_factory=factory,
        )
        assert rc == 0
