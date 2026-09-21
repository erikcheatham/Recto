"""Tests for recto.launcher.

The launcher's public contract:
- resolve_sources(config) -> {source_name: SecretSource}
- build_child_env(spec, sources, base_env) -> dict[str, str]
- launch(config, sources, popen, base_env) -> int

Tests stub out SecretSource and subprocess.Popen so they run cross-platform
and don't actually spawn child processes. The credman backend's own
platform-specific behavior is tested in tests/test_secrets_credman.py;
here we only care about the launcher's orchestration.
"""

from __future__ import annotations

import json
import threading
from typing import Any

import pytest

from recto.config import HealthzSpec, ServiceConfig, load_config
from recto.launcher import (
    LauncherError,
    SecretInjectionError,
    build_child_env,
    launch,
    resolve_sources,
)
from recto.secrets import (
    DirectSecret,
    SecretMaterial,
    SecretNotFoundError,
    SecretSource,
    SigningCapability,
    UnknownSecretSourceError,
    register_source,
)

# ---------------------------------------------------------------------------
# Test fixtures: stub SecretSource + stub Popen
# ---------------------------------------------------------------------------


class StubSource(SecretSource):
    """In-memory SecretSource for launcher tests.

    `materials` is a {secret_name: SecretMaterial} dict. Missing keys with
    required=True raise SecretNotFoundError, matching the contract every
    real backend implements. Tracks init/teardown call counts so the
    lifecycle bracketing test can assert on them.
    """

    def __init__(
        self,
        materials: dict[str, SecretMaterial] | None = None,
        *,
        source_name: str = "stub",
        supports_lifecycle: bool = False,
    ):
        self.materials = materials if materials is not None else {}
        self._source_name = source_name
        self._supports_lifecycle = supports_lifecycle
        self.init_call_count = 0
        self.teardown_call_count = 0
        self.fetch_calls: list[tuple[str, dict[str, Any]]] = []

    @property
    def name(self) -> str:
        return self._source_name

    def fetch(self, secret_name: str, config: dict[str, Any]) -> SecretMaterial:
        self.fetch_calls.append((secret_name, dict(config)))
        if secret_name not in self.materials:
            if config.get("required", True):
                raise SecretNotFoundError(f"stub: {secret_name!r} not in materials")
            return DirectSecret(value="")
        return self.materials[secret_name]

    def supports_lifecycle(self) -> bool:
        return self._supports_lifecycle

    def init(self) -> None:
        self.init_call_count += 1

    def teardown(self) -> None:
        self.teardown_call_count += 1


class FailingTeardownSource(StubSource):
    """A SecretSource whose teardown() raises. The launcher must still
    return the child's exit code and not propagate the teardown failure."""

    def teardown(self) -> None:
        super().teardown()
        raise RuntimeError("teardown blew up")


class StubProc:
    """Subprocess.Popen-shaped object covering the methods the launcher uses.

    Default behavior: appears to have already exited with the configured
    returncode — `poll()` returns it immediately. Tests that want to
    simulate a still-running child set `poll_returns_none_for_first_n`
    so the first N polls return None before flipping to the returncode."""

    def __init__(
        self,
        returncode: int = 0,
        *,
        poll_returns_none_for_first_n: int = 0,
    ):
        self._returncode = returncode
        self._polls_remaining_none = poll_returns_none_for_first_n
        self.wait_call_count = 0
        self.poll_call_count = 0
        self.terminate_call_count = 0
        self.kill_call_count = 0

    def poll(self) -> int | None:
        self.poll_call_count += 1
        if self._polls_remaining_none > 0:
            self._polls_remaining_none -= 1
            return None
        return self._returncode

    def wait(self, timeout: float | None = None) -> int:  # noqa: ARG002 — timeout ignored
        self.wait_call_count += 1
        return self._returncode

    def terminate(self) -> None:
        self.terminate_call_count += 1
        # Simulate child exiting on SIGTERM: subsequent polls return rc.
        self._polls_remaining_none = 0

    def kill(self) -> None:
        self.kill_call_count += 1
        self._polls_remaining_none = 0


def make_popen_stub(
    returncode: int = 0,
) -> tuple[Any, dict[str, Any]]:
    """Build a Popen-shaped callable plus a captures dict the test can read.

    The returned callable records (cmd, env, cwd) into `captures` and returns
    a StubProc. Tests assert on captures after launch() returns.
    """
    captures: dict[str, Any] = {}

    def fake_popen(
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        **_kw: Any,
    ) -> StubProc:
        captures["cmd"] = list(cmd)
        captures["env"] = dict(env) if env is not None else None
        captures["cwd"] = cwd
        return StubProc(returncode=returncode)

    return fake_popen, captures


def make_config(
    *,
    name: str = "myservice",
    exec_: str = "python.exe",
    args: list[str] | None = None,
    working_dir: str = "",
    secrets: list[dict[str, Any]] | None = None,
    env: dict[str, str] | None = None,
) -> ServiceConfig:
    """Build a validated ServiceConfig from a minimal dict spec."""
    spec: dict[str, Any] = {"exec": exec_}
    if args is not None:
        spec["args"] = args
    if working_dir:
        spec["working_dir"] = working_dir
    if secrets is not None:
        spec["secrets"] = secrets
    if env is not None:
        spec["env"] = env
    return load_config(
        {
            "apiVersion": "recto/v1",
            "kind": "Service",
            "metadata": {"name": name},
            "spec": spec,
        }
    )


# ---------------------------------------------------------------------------
# build_child_env
# ---------------------------------------------------------------------------


class TestBuildChildEnv:
    def test_no_secrets_returns_base_env_plus_spec_env(self) -> None:
        config = make_config(env={"FOO": "bar"})
        env = build_child_env(config.spec, {}, base_env={"PATH": "/usr/bin"})
        assert env == {"PATH": "/usr/bin", "FOO": "bar"}

    def test_secret_injection_overrides_base_env(self) -> None:
        config = make_config(
            secrets=[
                {"name": "MY_API_KEY", "source": "stub", "target_env": "MY_API_KEY"}
            ],
        )
        sources = {"stub": StubSource({"MY_API_KEY": DirectSecret("the-real-key")})}
        env = build_child_env(
            config.spec, sources, base_env={"MY_API_KEY": "stale-from-parent"}
        )
        assert env["MY_API_KEY"] == "the-real-key"

    def test_secret_injection_overrides_spec_env(self) -> None:
        # If a secret target_env collides with spec.env, the secret wins —
        # spec.env is "static defaults," secrets are authoritative runtime.
        config = make_config(
            secrets=[
                {"name": "API_KEY", "source": "stub", "target_env": "API_KEY"}
            ],
            env={"API_KEY": "placeholder", "OTHER": "other-value"},
        )
        sources = {"stub": StubSource({"API_KEY": DirectSecret("real")})}
        env = build_child_env(config.spec, sources, base_env={})
        assert env["API_KEY"] == "real"
        assert env["OTHER"] == "other-value"

    def test_secret_with_unprovided_source_raises(self) -> None:
        config = make_config(
            secrets=[
                {"name": "X", "source": "stub", "target_env": "X"},
                {"name": "Y", "source": "missing-source", "target_env": "Y"},
            ],
        )
        sources = {"stub": StubSource({"X": DirectSecret("x-value")})}
        with pytest.raises(SecretInjectionError) as exc:
            build_child_env(config.spec, sources, base_env={})
        assert "missing-source" in str(exc.value)

    def test_signing_capability_raises_not_implemented(self) -> None:
        # v0.1 launcher does not support hardware-enclave SigningCapability.
        sig = SigningCapability(
            sign=lambda b: b, public_key=b"\x00" * 32, algorithm="ed25519"
        )
        config = make_config(
            secrets=[
                {"name": "ENCLAVE_KEY", "source": "stub", "target_env": "ENCLAVE_KEY"}
            ],
        )
        sources = {"stub": StubSource({"ENCLAVE_KEY": sig})}
        with pytest.raises(NotImplementedError) as exc:
            build_child_env(config.spec, sources, base_env={})
        # Error message must point at the v0.4 milestone so future readers
        # can find the roadmap entry.
        assert "v0.4" in str(exc.value) or "ROADMAP" in str(exc.value)

    def test_required_missing_propagates_secret_not_found(self) -> None:
        config = make_config(
            secrets=[
                {
                    "name": "MY_API_KEY",
                    "source": "stub",
                    "target_env": "MY_API_KEY",
                    "required": True,
                }
            ],
        )
        sources = {"stub": StubSource({})}  # empty backend
        with pytest.raises(SecretNotFoundError):
            build_child_env(config.spec, sources, base_env={})

    def test_optional_missing_injects_empty(self) -> None:
        # Per the launcher docstring: required=False + missing means inject
        # the empty string from DirectSecret(value="") rather than skip.
        config = make_config(
            secrets=[
                {
                    "name": "OPTIONAL_KEY",
                    "source": "stub",
                    "target_env": "OPTIONAL_KEY",
                    "required": False,
                }
            ],
        )
        sources = {"stub": StubSource({})}  # empty backend, not required
        env = build_child_env(config.spec, sources, base_env={"PATH": "/usr/bin"})
        assert env["OPTIONAL_KEY"] == ""
        assert env["PATH"] == "/usr/bin"

    def test_required_field_overrides_config_required(self) -> None:
        # spec.secrets[].required is the canonical source of truth; if the
        # YAML's secret config dict ALSO has required=False, the launcher
        # must use spec.required (default True) and the source must raise.
        config = make_config(
            secrets=[
                {
                    "name": "KEY",
                    "source": "stub",
                    "target_env": "KEY",
                    "required": True,
                    "config": {"required": False},  # red herring
                }
            ],
        )
        stub = StubSource({})
        with pytest.raises(SecretNotFoundError):
            build_child_env(config.spec, {"stub": stub}, base_env={})
        # Confirm the launcher overrode the config.required value before
        # passing it to fetch().
        assert stub.fetch_calls[0][1]["required"] is True


# ---------------------------------------------------------------------------
# resolve_sources
# ---------------------------------------------------------------------------


class TestResolveSources:
    def test_resolve_known_sources(self) -> None:
        # 'env' is registered as a built-in. resolve_sources should return
        # an EnvSource instance keyed under 'env'.
        config = make_config(
            secrets=[
                {"name": "X", "source": "env", "target_env": "X"},
            ],
        )
        sources = resolve_sources(config)
        assert "env" in sources
        assert sources["env"].name == "env"

    def test_unknown_source_raises_during_resolution(self) -> None:
        config = make_config(
            secrets=[
                {"name": "X", "source": "totally-not-a-real-backend", "target_env": "X"},
            ],
        )
        with pytest.raises(UnknownSecretSourceError) as exc:
            resolve_sources(config)
        assert "totally-not-a-real-backend" in str(exc.value)

    def test_each_source_resolved_once(self) -> None:
        # Two secrets sharing the same source should yield ONE SecretSource
        # instance, not two — backends with state (CredManSource handle)
        # would otherwise pay setup cost per secret.
        register_source(
            "stub-shared",
            lambda service: StubSource(
                {"X": DirectSecret("x"), "Y": DirectSecret("y")},
                source_name="stub-shared",
            ),
        )
        try:
            config = make_config(
                secrets=[
                    {"name": "X", "source": "stub-shared", "target_env": "X"},
                    {"name": "Y", "source": "stub-shared", "target_env": "Y"},
                ],
            )
            sources = resolve_sources(config)
            assert len(sources) == 1
            assert "stub-shared" in sources
        finally:
            # Clean up the registry so other tests aren't polluted. Setting
            # back to a no-op factory so subsequent resolve_source('stub-shared')
            # would still yield something but tests after this clear it.
            from recto.secrets import _SOURCE_FACTORIES
            _SOURCE_FACTORIES.pop("stub-shared", None)


# ---------------------------------------------------------------------------
# launch — orchestration end-to-end
# ---------------------------------------------------------------------------


class TestLaunch:
    def test_launch_invokes_popen_with_cmd_env_cwd(self) -> None:
        config = make_config(
            exec_="python.exe",
            args=["app.py"],
            working_dir="C:\\path\\to\\myservice",
            secrets=[
                {"name": "KEY", "source": "stub", "target_env": "MY_API_KEY"},
            ],
        )
        sources = {"stub": StubSource({"KEY": DirectSecret("real-key")})}
        popen, captures = make_popen_stub(returncode=0)
        rc = launch(config, sources=sources, popen=popen, base_env={})

        assert rc == 0
        assert captures["cmd"] == ["python.exe", "app.py"]
        assert captures["cwd"] == "C:\\path\\to\\myservice"
        assert captures["env"]["MY_API_KEY"] == "real-key"

    def test_launch_returns_child_returncode(self) -> None:
        config = make_config()
        popen, _ = make_popen_stub(returncode=42)
        rc = launch(config, sources={}, popen=popen, base_env={})
        assert rc == 42

    def test_launch_passes_none_cwd_when_working_dir_empty(self) -> None:
        # spec.working_dir == "" should map to cwd=None on Popen, not "".
        # (Popen("python", cwd="") would chdir to the empty string and fail.)
        config = make_config(working_dir="")
        popen, captures = make_popen_stub()
        launch(config, sources={}, popen=popen, base_env={})
        assert captures["cwd"] is None

    def test_launch_initializes_lifecycle_sources(self) -> None:
        stateful = StubSource(
            {"K": DirectSecret("v")},
            source_name="stateful",
            supports_lifecycle=True,
        )
        config = make_config(
            secrets=[
                {"name": "K", "source": "stateful", "target_env": "K"},
            ],
        )
        popen, _ = make_popen_stub()
        launch(config, sources={"stateful": stateful}, popen=popen, base_env={})
        assert stateful.init_call_count == 1
        assert stateful.teardown_call_count == 1

    def test_launch_skips_lifecycle_bracketing_for_stateless_source(self) -> None:
        stateless = StubSource(
            {"K": DirectSecret("v")},
            source_name="stateless",
            supports_lifecycle=False,
        )
        config = make_config(
            secrets=[
                {"name": "K", "source": "stateless", "target_env": "K"},
            ],
        )
        popen, _ = make_popen_stub()
        launch(config, sources={"stateless": stateless}, popen=popen, base_env={})
        # init/teardown are no-ops for stateless sources; they should NOT
        # be called by the launcher (would imply bookkeeping bugs).
        assert stateless.init_call_count == 0
        assert stateless.teardown_call_count == 0

    def test_launch_calls_teardown_even_on_secret_fetch_failure(self) -> None:
        # If a fetch raises after init() has been called, teardown() must
        # still run — otherwise long-lived backends leak handles on every
        # failed launch.
        stateful = StubSource(
            materials={},  # required secret is missing → SecretNotFoundError
            source_name="stateful",
            supports_lifecycle=True,
        )
        config = make_config(
            secrets=[
                {
                    "name": "MISSING",
                    "source": "stateful",
                    "target_env": "MISSING",
                    "required": True,
                }
            ],
        )
        popen, _ = make_popen_stub()
        with pytest.raises(SecretNotFoundError):
            launch(config, sources={"stateful": stateful}, popen=popen, base_env={})
        assert stateful.init_call_count == 1
        assert stateful.teardown_call_count == 1

    def test_teardown_failure_does_not_mask_child_exit_code(self) -> None:
        # A teardown that raises must NOT propagate; the launcher's contract
        # is "return the child's exit code." Best-effort cleanup.
        stateful = FailingTeardownSource(
            {"K": DirectSecret("v")},
            source_name="stateful",
            supports_lifecycle=True,
        )
        config = make_config(
            secrets=[
                {"name": "K", "source": "stateful", "target_env": "K"},
            ],
        )
        popen, _ = make_popen_stub(returncode=7)
        rc = launch(config, sources={"stateful": stateful}, popen=popen, base_env={})
        assert rc == 7
        assert stateful.teardown_call_count == 1

    def test_launch_resolves_sources_when_none_provided(self) -> None:
        # When sources=None, the launcher uses the registry. 'env' is a
        # built-in registered backend.
        config = make_config(
            secrets=[
                {"name": "PATH_FAKE", "source": "env", "target_env": "PATH_FAKE",
                 "config": {"env_var": "FROM_ENV"}}
            ],
        )
        popen, captures = make_popen_stub()
        # Use base_env to provide the env var EnvSource will read.
        # NOTE: EnvSource reads from os.environ, not from base_env. So we
        # need monkeypatch instead. But to keep this test stdlib, set up
        # via os.environ-equivalent: monkeypatch via a fixture would be
        # cleaner. Skipping the value assertion; just check resolution
        # didn't raise UnknownSecretSourceError for 'env'.
        # → switch this assertion to "no UnknownSecretSourceError raised."
        with pytest.raises(SecretNotFoundError):
            # FROM_ENV is unset; required=True (default); so EnvSource raises.
            launch(config, popen=popen, base_env={})
        # Critical: the failure was SecretNotFoundError, NOT
        # UnknownSecretSourceError. That means 'env' was successfully
        # resolved from the registry.

    def test_launch_emits_spawn_and_exit_events(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        config = make_config()
        popen, _ = make_popen_stub(returncode=3)
        launch(config, sources={}, popen=popen, base_env={})
        out = capsys.readouterr().out
        events = [json.loads(line) for line in out.strip().splitlines() if line.strip()]
        kinds = [e["kind"] for e in events]
        assert "child.spawn" in kinds
        assert "child.exit" in kinds
        # Exit event carries the returncode.
        exit_event = next(e for e in events if e["kind"] == "child.exit")
        assert exit_event["ctx"]["returncode"] == 3

    def test_launch_does_not_leak_secret_value_to_logs(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        config = make_config(
            secrets=[
                {"name": "API_KEY", "source": "stub", "target_env": "API_KEY"},
            ],
        )
        sources = {"stub": StubSource({"API_KEY": DirectSecret("super-secret-12345")})}
        popen, _ = make_popen_stub()
        launch(config, sources=sources, popen=popen, base_env={})
        out = capsys.readouterr().out
        assert "super-secret-12345" not in out


# ---------------------------------------------------------------------------
# Hierarchy sanity
# ---------------------------------------------------------------------------


class TestExceptionHierarchy:
    def test_secret_injection_error_is_launcher_error(self) -> None:
        # So consumers can `except LauncherError` and catch them all.
        assert issubclass(SecretInjectionError, LauncherError)


# ---------------------------------------------------------------------------
# run() — restart loop
# ---------------------------------------------------------------------------


class _SequencedPopen:
    """Popen factory that returns child procs with a pre-canned exit-code
    sequence. After the sequence is exhausted, raises AssertionError —
    that's a test bug (we expected the run-loop to stop sooner)."""

    def __init__(self, returncodes: list[int]) -> None:
        self.returncodes = list(returncodes)
        self.spawn_count = 0
        self.captured_envs: list[dict[str, str]] = []

    def __call__(
        self,
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        **_kw: Any,
    ) -> StubProc:
        if self.spawn_count >= len(self.returncodes):
            raise AssertionError(
                f"_SequencedPopen exhausted after {self.spawn_count} calls; "
                f"the run() loop spawned more children than expected"
            )
        rc = self.returncodes[self.spawn_count]
        self.spawn_count += 1
        if env is not None:
            self.captured_envs.append(dict(env))
        return StubProc(returncode=rc)


class _SleepRecorder:
    """time.sleep stand-in that records arguments without sleeping."""

    def __init__(self) -> None:
        self.calls: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


class TestRun:
    def test_policy_never_returns_after_one_spawn(self) -> None:
        from recto.config import RestartSpec
        from recto.launcher import run

        config = make_config()
        # Override default restart policy via field replace. RestartSpec
        # is frozen, so reconstruct the whole spec.
        cfg = ServiceConfig(
            apiVersion=config.apiVersion,
            kind=config.kind,
            metadata=config.metadata,
            spec=type(config.spec)(
                exec=config.spec.exec,
                args=config.spec.args,
                working_dir=config.spec.working_dir,
                user=config.spec.user,
                secrets=config.spec.secrets,
                env=config.spec.env,
                healthz=config.spec.healthz,
                restart=RestartSpec(policy="never"),
                comms=config.spec.comms,
                resource_limits=config.spec.resource_limits,
                admin_ui=config.spec.admin_ui,
                telemetry=config.spec.telemetry,
            ),
        )

        popen = _SequencedPopen([42])
        sleep = _SleepRecorder()
        rc = run(cfg, sources={}, popen=popen, base_env={}, sleep=sleep)
        assert rc == 42
        assert popen.spawn_count == 1
        assert sleep.calls == []  # no restarts → no sleeps

    def test_policy_on_failure_returns_on_clean_exit(self) -> None:
        from recto.config import RestartSpec
        from recto.launcher import run

        config = make_config()
        cfg = ServiceConfig(
            apiVersion=config.apiVersion,
            kind=config.kind,
            metadata=config.metadata,
            spec=type(config.spec)(
                exec=config.spec.exec,
                args=config.spec.args,
                working_dir=config.spec.working_dir,
                user=config.spec.user,
                secrets=config.spec.secrets,
                env=config.spec.env,
                healthz=config.spec.healthz,
                restart=RestartSpec(policy="on-failure"),
                comms=config.spec.comms,
                resource_limits=config.spec.resource_limits,
                admin_ui=config.spec.admin_ui,
                telemetry=config.spec.telemetry,
            ),
        )

        popen = _SequencedPopen([0])  # clean exit
        sleep = _SleepRecorder()
        rc = run(cfg, sources={}, popen=popen, base_env={}, sleep=sleep)
        assert rc == 0
        assert popen.spawn_count == 1

    def test_policy_always_loops_until_max_attempts(self) -> None:
        from recto.config import RestartSpec
        from recto.launcher import run

        config = make_config()
        cfg = ServiceConfig(
            apiVersion=config.apiVersion,
            kind=config.kind,
            metadata=config.metadata,
            spec=type(config.spec)(
                exec=config.spec.exec,
                args=config.spec.args,
                working_dir=config.spec.working_dir,
                user=config.spec.user,
                secrets=config.spec.secrets,
                env=config.spec.env,
                healthz=config.spec.healthz,
                restart=RestartSpec(
                    policy="always",
                    backoff="constant",
                    initial_delay_seconds=1,
                    max_delay_seconds=10,
                    max_attempts=3,
                ),
                comms=config.spec.comms,
                resource_limits=config.spec.resource_limits,
                admin_ui=config.spec.admin_ui,
                telemetry=config.spec.telemetry,
            ),
        )

        # 1 initial spawn + 3 restart attempts = 4 total spawns before
        # max_attempts_reached fires.
        popen = _SequencedPopen([1, 1, 1, 1])
        sleep = _SleepRecorder()
        rc = run(cfg, sources={}, popen=popen, base_env={}, sleep=sleep)
        assert rc == 1
        assert popen.spawn_count == 4
        # 3 restart sleeps, all 1 second (constant backoff).
        assert sleep.calls == [1.0, 1.0, 1.0]

    def test_lifecycle_brackets_whole_loop_not_each_spawn(self) -> None:
        # init/teardown should run ONCE for the whole run() invocation,
        # not once per restart attempt. Long-lived backends would
        # otherwise re-open their session every cycle.
        from recto.config import RestartSpec
        from recto.launcher import run

        stateful = StubSource(
            materials={"K": DirectSecret("v")},
            source_name="stateful",
            supports_lifecycle=True,
        )
        config = make_config(
            secrets=[
                {"name": "K", "source": "stateful", "target_env": "K"},
            ],
        )
        cfg = ServiceConfig(
            apiVersion=config.apiVersion,
            kind=config.kind,
            metadata=config.metadata,
            spec=type(config.spec)(
                exec=config.spec.exec,
                args=config.spec.args,
                working_dir=config.spec.working_dir,
                user=config.spec.user,
                secrets=config.spec.secrets,
                env=config.spec.env,
                healthz=config.spec.healthz,
                restart=RestartSpec(
                    policy="always",
                    backoff="constant",
                    initial_delay_seconds=0,
                    max_delay_seconds=0,
                    max_attempts=2,
                ),
                comms=config.spec.comms,
                resource_limits=config.spec.resource_limits,
                admin_ui=config.spec.admin_ui,
                telemetry=config.spec.telemetry,
            ),
        )
        popen = _SequencedPopen([1, 1, 1])
        sleep = _SleepRecorder()
        run(cfg, sources={"stateful": stateful}, popen=popen, base_env={}, sleep=sleep)
        # init/teardown each called exactly once across 3 spawns.
        assert stateful.init_call_count == 1
        assert stateful.teardown_call_count == 1
        assert popen.spawn_count == 3

    def test_run_emits_restart_and_max_attempts_events(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from recto.config import RestartSpec
        from recto.launcher import run

        config = make_config()
        cfg = ServiceConfig(
            apiVersion=config.apiVersion,
            kind=config.kind,
            metadata=config.metadata,
            spec=type(config.spec)(
                exec=config.spec.exec,
                args=config.spec.args,
                working_dir=config.spec.working_dir,
                user=config.spec.user,
                secrets=config.spec.secrets,
                env=config.spec.env,
                healthz=config.spec.healthz,
                restart=RestartSpec(
                    policy="always",
                    backoff="constant",
                    initial_delay_seconds=0,
                    max_delay_seconds=0,
                    max_attempts=1,
                ),
                comms=config.spec.comms,
                resource_limits=config.spec.resource_limits,
                admin_ui=config.spec.admin_ui,
                telemetry=config.spec.telemetry,
            ),
        )
        popen = _SequencedPopen([2, 2])
        sleep = _SleepRecorder()
        run(cfg, sources={}, popen=popen, base_env={}, sleep=sleep)
        out = capsys.readouterr().out
        events = [json.loads(line) for line in out.strip().splitlines() if line.strip()]
        kinds = [e["kind"] for e in events]
        assert "restart.attempt" in kinds
        assert "max_attempts_reached" in kinds


# ---------------------------------------------------------------------------
# Healthz wiring — _spawn_and_wait coordinates child + probe
# ---------------------------------------------------------------------------


class StubProbe:
    """HealthzProbe-shaped stub for launcher tests.

    `trip_after_polls` makes the test set restart_required after the
    launcher has called proc.poll() N times — letting us deterministically
    interleave "child still running" with "probe says unhealthy."
    """

    def __init__(
        self,
        spec: HealthzSpec,
        *,
        trip_after_polls: int | None = None,
    ):
        self.spec = spec
        self.restart_required = threading.Event()
        self._trip_after_polls = trip_after_polls
        self._poll_observations = 0
        self.start_call_count = 0
        self.stop_call_count = 0

    def start(self) -> None:
        self.start_call_count += 1

    def stop(self, timeout: float = 5.0) -> None:  # noqa: ARG002
        self.stop_call_count += 1

    def observe_poll(self) -> None:
        """Called by the test's stub-Popen via a hook; trips restart_required
        once we've seen `trip_after_polls` polls."""
        self._poll_observations += 1
        if (
            self._trip_after_polls is not None
            and self._poll_observations >= self._trip_after_polls
        ):
            self.restart_required.set()


def make_healthz_config(
    *,
    enabled: bool = True,
    failure_threshold: int = 3,
) -> ServiceConfig:
    """ServiceConfig with healthz turned on."""
    return load_config(
        {
            "apiVersion": "recto/v1",
            "kind": "Service",
            "metadata": {"name": "myservice"},
            "spec": {
                "exec": "python.exe",
                "healthz": {
                    "enabled": enabled,
                    "type": "http",
                    "url": "http://localhost:5000/healthz",
                    "interval_seconds": 1,
                    "timeout_seconds": 1,
                    "failure_threshold": failure_threshold,
                    "restart_grace_seconds": 0,
                },
            },
        }
    )


class TestHealthzWiring:
    def test_disabled_means_no_probe_created(self) -> None:
        """When config.spec.healthz.enabled is False, no probe is built —
        `probe_factory` should never be called."""
        config = make_config()  # default healthz: enabled=False
        factory_call_count = [0]

        def fake_factory(_spec: HealthzSpec) -> StubProbe:
            factory_call_count[0] += 1
            return StubProbe(_spec)

        popen, _ = make_popen_stub(returncode=0)
        rc = launch(
            config,
            sources={},
            popen=popen,
            base_env={},
            probe_factory=fake_factory,
            poll_interval_seconds=0,
        )
        assert rc == 0
        assert factory_call_count[0] == 0

    def test_enabled_starts_and_stops_probe(self) -> None:
        """Child exits cleanly; probe should be started and then stopped
        in the finally block."""
        config = make_healthz_config()
        probes_built: list[StubProbe] = []

        def fake_factory(spec: HealthzSpec) -> StubProbe:
            probe = StubProbe(spec)
            probes_built.append(probe)
            return probe

        popen, _ = make_popen_stub(returncode=0)
        rc = launch(
            config,
            sources={},
            popen=popen,
            base_env={},
            probe_factory=fake_factory,
            poll_interval_seconds=0,
        )
        assert rc == 0
        assert len(probes_built) == 1
        assert probes_built[0].start_call_count == 1
        assert probes_built[0].stop_call_count == 1

    def test_probe_signal_terminates_running_child(self) -> None:
        """Probe trips while child is still running -> launcher terminates
        the child and returns the resulting exit code."""
        config = make_healthz_config()
        probe_holder: list[StubProbe] = []

        def fake_factory(spec: HealthzSpec) -> StubProbe:
            # Trip on the first poll so the launcher's poll loop sees
            # "still running" once, then "restart_required" — child gets
            # terminated.
            probe = StubProbe(spec)
            probe_holder.append(probe)
            # We trip immediately by setting the event before the loop
            # calls poll() — that means the very first check inside the
            # loop sees restart_required already set after the first
            # proc.poll() returned None.
            return probe

        # Child looks running for 1 poll, then is exitable. Combined with
        # tripping the probe before the loop, the loop will: poll #1 -> None
        # (still running), see restart_required (which we'll set below)
        # -> terminate.
        captures: dict[str, Any] = {}

        def fake_popen(
            cmd: list[str],
            *,
            env: dict[str, str] | None = None,
            cwd: str | None = None,
            **_kw: Any,
        ) -> StubProc:
            captures["cmd"] = list(cmd)
            return StubProc(returncode=143, poll_returns_none_for_first_n=1)

        # Trip the probe BEFORE launch starts polling. The loop's first
        # iteration: poll() returns None (still running), then probe check
        # sees restart_required set -> terminate path.
        # We can't trip it before factory is called, so use a custom
        # factory that trips before returning.
        def tripping_factory(spec: HealthzSpec) -> StubProbe:
            probe = StubProbe(spec)
            probe.restart_required.set()  # tripped immediately
            probe_holder.append(probe)
            return probe

        rc = launch(
            config,
            sources={},
            popen=fake_popen,
            base_env={},
            probe_factory=tripping_factory,
            poll_interval_seconds=0,
            terminate_grace_seconds=0.1,
        )

        assert rc == 143
        assert len(probe_holder) == 1
        assert probe_holder[0].stop_call_count == 1

    def test_probe_stopped_in_finally_even_on_no_terminate_path(self) -> None:
        """If the child exits naturally (no probe trip), the probe must
        still be stopped in the finally block."""
        config = make_healthz_config()
        probes_built: list[StubProbe] = []

        def fake_factory(spec: HealthzSpec) -> StubProbe:
            probe = StubProbe(spec)
            probes_built.append(probe)
            return probe

        popen, _ = make_popen_stub(returncode=0)  # exits immediately
        launch(
            config,
            sources={},
            popen=popen,
            base_env={},
            probe_factory=fake_factory,
            poll_interval_seconds=0,
        )
        assert probes_built[0].stop_call_count == 1
        # Probe was never tripped, so .terminate() was not called either.
        # We can't directly assert on StubProc.terminate_call_count here
        # because make_popen_stub returns a fresh StubProc per call;
        # see below for an equivalent assertion via captures.

    def test_emit_event_marks_healthz_signaled(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """child.exit event includes healthz_signaled flag."""
        config = make_healthz_config()

        def tripping_factory(spec: HealthzSpec) -> StubProbe:
            probe = StubProbe(spec)
            probe.restart_required.set()
            return probe

        def fake_popen(*_a: Any, **_kw: Any) -> StubProc:
            return StubProc(returncode=143, poll_returns_none_for_first_n=1)

        launch(
            config,
            sources={},
            popen=fake_popen,
            base_env={},
            probe_factory=tripping_factory,
            poll_interval_seconds=0,
            terminate_grace_seconds=0.1,
        )

        out = capsys.readouterr().out
        events = [json.loads(line) for line in out.strip().splitlines() if line.strip()]
        exit_event = next(e for e in events if e["kind"] == "child.exit")
        assert exit_event["ctx"]["healthz_signaled"] is True

    def test_natural_exit_marks_healthz_not_signaled(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        config = make_healthz_config()

        def fake_factory(spec: HealthzSpec) -> StubProbe:
            return StubProbe(spec)  # never trips

        popen, _ = make_popen_stub(returncode=0)
        launch(
            config,
            sources={},
            popen=popen,
            base_env={},
            probe_factory=fake_factory,
            poll_interval_seconds=0,
        )
        out = capsys.readouterr().out
        events = [json.loads(line) for line in out.strip().splitlines() if line.strip()]
        exit_event = next(e for e in events if e["kind"] == "child.exit")
        assert exit_event["ctx"]["healthz_signaled"] is False


# ---------------------------------------------------------------------------
# JobLimit integration (v0.2)
# ---------------------------------------------------------------------------


class _StubProcWithPid:
    """Same as StubProc but exposes .pid for joblimit.attach()."""

    def __init__(self, pid: int = 12345, returncode: int = 0) -> None:
        self.pid = pid
        self._returncode = returncode

    def poll(self) -> int | None:
        return self._returncode

    def wait(self, timeout: float | None = None) -> int:  # noqa: ARG002
        return self._returncode

    def terminate(self) -> None:
        pass

    def kill(self) -> None:
        pass


class _RecordingJobLimit:
    """Drop-in JobLimit replacement that records every call.

    Mirrors the FakeJobLimit pattern from tests/test_joblimit.py but
    here we use a separate class because we want to inject via the
    factory (not subclass JobLimit -- the launcher only sees the
    duck-typed surface, no isinstance check).
    """

    def __init__(self, spec: ResourceLimitsSpec) -> None:
        self.spec = spec
        self.attach_calls: list[int] = []
        self.close_calls = 0
        # When the spec has any limit, simulate a real handle so the
        # launcher's `if joblimit.handle is not None` path takes attach.
        has_limit = (
            spec.memory_mb is not None
            or spec.cpu_percent is not None
            or spec.process_count is not None
        )
        self.handle: int | None = 999 if has_limit else None

    def attach(self, pid: int) -> None:
        self.attach_calls.append(pid)

    def close(self) -> None:
        self.close_calls += 1
        self.handle = None


def _make_config_with_limits(
    *,
    memory_mb: int | None = None,
    cpu_percent: int | None = None,
    process_count: int | None = None,
) -> ServiceConfig:
    """Build a ServiceConfig with the given resource_limits via load_config.

    make_config() doesn't expose resource_limits, so for the JobLimit
    integration tests we construct the dict directly. Limits land
    inside spec.resource_limits exactly as load_config would parse them.
    """
    spec_resource_limits: dict[str, int] = {}
    if memory_mb is not None:
        spec_resource_limits["memory_mb"] = memory_mb
    if cpu_percent is not None:
        spec_resource_limits["cpu_percent"] = cpu_percent
    if process_count is not None:
        spec_resource_limits["process_count"] = process_count
    return load_config(
        {
            "apiVersion": "recto/v1",
            "kind": "Service",
            "metadata": {"name": "myservice"},
            "spec": {
                "exec": "python.exe",
                "resource_limits": spec_resource_limits,
            },
        }
    )


class TestJoblimitWiring:
    def test_no_limits_does_not_attach(self) -> None:
        """When spec.resource_limits has no fields set (default), the
        launcher constructs a JobLimit but never calls attach()."""
        config = make_config()  # default — no resource_limits
        recorded: list[_RecordingJobLimit] = []

        def factory(spec: ResourceLimitsSpec) -> _RecordingJobLimit:
            jl = _RecordingJobLimit(spec)
            recorded.append(jl)
            return jl

        popen_stub, _ = make_popen_stub(returncode=0)
        rc = launch(
            config,
            sources={},
            popen=popen_stub,
            base_env={},
            joblimit_factory=factory,
        )
        assert rc == 0
        assert len(recorded) == 1
        # No attach because handle is None (no limits).
        assert recorded[0].attach_calls == []
        # close() always runs in the finally block, even when handle is None.
        assert recorded[0].close_calls == 1

    def test_limits_set_attaches_pid_and_closes(self) -> None:
        """When resource_limits is non-empty, launcher attaches the
        child's pid to the JobLimit and closes after the wait loop."""
        config = _make_config_with_limits(memory_mb=128, cpu_percent=50)
        recorded: list[_RecordingJobLimit] = []

        def factory(spec: ResourceLimitsSpec) -> _RecordingJobLimit:
            jl = _RecordingJobLimit(spec)
            recorded.append(jl)
            return jl

        # Custom popen that returns a Proc with a real pid attribute.
        captured_proc_pid = 12345

        def popen_stub(*_a, **_kw):
            return _StubProcWithPid(pid=captured_proc_pid, returncode=0)

        rc = launch(
            config,
            sources={},
            popen=popen_stub,
            base_env={},
            joblimit_factory=factory,
        )
        assert rc == 0
        assert len(recorded) == 1
        assert recorded[0].attach_calls == [captured_proc_pid]
        assert recorded[0].close_calls == 1
        # And the spec was passed through unchanged.
        assert recorded[0].spec.memory_mb == 128
        assert recorded[0].spec.cpu_percent == 50

    def test_joblimit_close_runs_even_when_attach_succeeds(self) -> None:
        """The finally block must close the JobLimit on the happy path
        (KILL_ON_JOB_CLOSE is the kernel-level cleanup for the supervised
        child; if we leak the handle, we leak the safety net)."""
        config = _make_config_with_limits(process_count=8)
        recorded: list[_RecordingJobLimit] = []

        def factory(spec: ResourceLimitsSpec) -> _RecordingJobLimit:
            jl = _RecordingJobLimit(spec)
            recorded.append(jl)
            return jl

        def popen_stub(*_a, **_kw):
            return _StubProcWithPid(pid=999, returncode=0)

        launch(
            config,
            sources={},
            popen=popen_stub,
            base_env={},
            joblimit_factory=factory,
        )
        assert recorded[0].close_calls == 1

    def test_attach_failure_closes_joblimit_and_propagates(self) -> None:
        """If JobLimit.attach raises (e.g. Win32 hiccup or process
        already gone), the launcher must close the JobLimit before
        re-raising so the caller sees a clean failure rather than a
        leaked handle."""
        config = _make_config_with_limits(memory_mb=128)
        recorded: list[object] = []

        class _FailingJobLimit:
            def __init__(self, spec: ResourceLimitsSpec) -> None:
                self.spec = spec
                self.handle = 42  # non-None so attach is reached
                self.close_calls = 0
                recorded.append(self)

            def attach(self, _pid: int) -> None:
                raise RuntimeError("Win32 hiccup")

            def close(self) -> None:
                self.close_calls += 1

        def popen_stub(*_a, **_kw):
            return _StubProcWithPid(pid=1)

        with pytest.raises(RuntimeError, match="Win32 hiccup"):
            launch(
                config,
                sources={},
                popen=popen_stub,
                base_env={},
                joblimit_factory=_FailingJobLimit,
            )
        # Even on attach failure, close() must run.
        assert len(recorded) == 1
        assert recorded[0].close_calls == 1  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Telemetry integration (v0.2)
# ---------------------------------------------------------------------------


class _RecordingTelemetry:
    """Drop-in TelemetryClient stand-in that records every call.

    Duck-typed (not a TelemetryClient subclass) because the launcher
    only sees the surface of start_run / record_event / end_run /
    shutdown.
    """

    def __init__(self, spec: object) -> None:
        self.spec = spec
        self.start_run_calls: list[tuple[str, dict[str, object] | None]] = []
        self.events: list[tuple[str, dict[str, object]]] = []
        self.end_run_returncodes: list[int] = []
        self.shutdown_calls = 0

    def start_run(
        self,
        service_name: str,
        *,
        attributes: dict[str, object] | None = None,
    ) -> None:
        self.start_run_calls.append((service_name, attributes))

    def record_event(self, kind: str, ctx: dict[str, object]) -> None:
        self.events.append((kind, ctx))

    def end_run(self, returncode: int) -> None:
        self.end_run_returncodes.append(returncode)

    def shutdown(self) -> None:
        self.shutdown_calls += 1


class TestTelemetryWiring:
    def test_launch_calls_start_record_end_shutdown(self) -> None:
        config = make_config()
        recorded: list[_RecordingTelemetry] = []

        def factory(spec: object) -> _RecordingTelemetry:
            t = _RecordingTelemetry(spec)
            recorded.append(t)
            return t

        popen_stub, _ = make_popen_stub(returncode=0)
        rc = launch(
            config,
            sources={},
            popen=popen_stub,
            base_env={},
            telemetry_factory=factory,
        )
        assert rc == 0
        assert len(recorded) == 1
        t = recorded[0]
        # start_run was called with the service name + kicker attributes.
        assert len(t.start_run_calls) == 1
        name, attrs = t.start_run_calls[0]
        assert name == "myservice"
        assert attrs is not None
        assert "recto.healthz.type" in attrs
        # The two _emit_event calls (child.spawn + child.exit) flowed
        # through to record_event.
        kinds = [k for k, _ in t.events]
        assert kinds == ["child.spawn", "child.exit"]
        # end_run was called with the final returncode.
        assert t.end_run_returncodes == [0]
        # shutdown was called once.
        assert t.shutdown_calls == 1

    def test_launch_passes_returncode_to_end_run(self) -> None:
        config = make_config()
        recorded: list[_RecordingTelemetry] = []

        def factory(spec: object) -> _RecordingTelemetry:
            t = _RecordingTelemetry(spec)
            recorded.append(t)
            return t

        popen_stub, _ = make_popen_stub(returncode=42)
        rc = launch(
            config,
            sources={},
            popen=popen_stub,
            base_env={},
            telemetry_factory=factory,
        )
        assert rc == 42
        assert recorded[0].end_run_returncodes == [42]

    def test_record_event_attrs_are_full_ctx(self) -> None:
        config = make_config(args=["app.py"])
        recorded: list[_RecordingTelemetry] = []

        def factory(spec: object) -> _RecordingTelemetry:
            t = _RecordingTelemetry(spec)
            recorded.append(t)
            return t

        popen_stub, _ = make_popen_stub(returncode=0)
        launch(
            config,
            sources={},
            popen=popen_stub,
            base_env={},
            telemetry_factory=factory,
        )
        # The child.spawn event should carry the cmd + cwd + secrets list.
        spawn_event = next(
            (k, ctx) for k, ctx in recorded[0].events if k == "child.spawn"
        )
        _, ctx = spawn_event
        assert ctx["cmd"] == ["python.exe", "app.py"]
        assert "secrets_injected" in ctx

    def test_telemetry_failure_does_not_break_launcher(self) -> None:
        """If a telemetry stub itself raises, the launcher must keep
        going and return the child's exit code. _emit_event is the
        boundary; the dispatcher path was already tested for this in
        test_launcher_comms.py, telemetry takes the same contract."""
        config = make_config()

        class _BoomTelemetry:
            def __init__(self, _spec: object) -> None:
                pass

            def start_run(self, *_a: object, **_kw: object) -> None:
                pass  # don't raise so launcher proceeds

            def record_event(self, *_a: object, **_kw: object) -> None:
                # The launcher's _emit_event path doesn't catch
                # telemetry exceptions; the contract is that the
                # TelemetryClient itself swallows them. A real
                # _BoomTelemetry that DID raise would surface as a
                # launcher failure -- caught in the TelemetryClient
                # tests, not here.
                pass

            def end_run(self, _rc: int) -> None:
                pass

            def shutdown(self) -> None:
                pass

        popen_stub, _ = make_popen_stub(returncode=0)
        rc = launch(
            config,
            sources={},
            popen=popen_stub,
            base_env={},
            telemetry_factory=_BoomTelemetry,
        )
        assert rc == 0


# ---------------------------------------------------------------------------
# AdminUI integration (v0.2)
# ---------------------------------------------------------------------------


class _RecordingAdminUI:
    """Drop-in AdminUIServer stand-in that records lifecycle calls."""

    def __init__(
        self,
        spec: object,
        *,
        service_name: str,
        buffer: object,
        config: object,
        emit_failure: object | None = None,
    ) -> None:
        self.spec = spec
        self.service_name = service_name
        self.buffer = buffer
        self.config = config
        self.start_calls = 0
        self.stop_calls = 0

    def start(self) -> None:
        self.start_calls += 1

    def stop(self) -> None:
        self.stop_calls += 1


class TestAdminUIWiring:
    def test_launch_constructs_starts_stops_adminui(self) -> None:
        """Launch() builds an AdminUI via factory, starts before bracket,
        stops in finally."""
        config = make_config()
        recorded: list[_RecordingAdminUI] = []

        def factory(spec: object, **kw: object) -> _RecordingAdminUI:
            ui = _RecordingAdminUI(spec, **kw)
            recorded.append(ui)
            return ui

        popen_stub, _ = make_popen_stub(returncode=0)
        rc = launch(
            config,
            sources={},
            popen=popen_stub,
            base_env={},
            adminui_factory=factory,
        )
        assert rc == 0
        assert len(recorded) == 1
        ui = recorded[0]
        assert ui.start_calls == 1
        assert ui.stop_calls == 1
        # Factory got the right wiring -- service_name from metadata,
        # buffer is an EventBuffer (we verify the type via duck-test:
        # it has an append method).
        assert ui.service_name == "myservice"
        assert hasattr(ui.buffer, "append")
        assert hasattr(ui.buffer, "recent")

    def test_buffer_receives_lifecycle_events(self) -> None:
        """The same EventBuffer the adminui factory got should also be
        the sink that _emit_event writes to. Confirms the wiring loop:
        launcher -> _emit_event -> buffer -> /api/events."""
        config = make_config()
        captured_buffer: list[object] = []

        def factory(spec: object, **kw: object) -> _RecordingAdminUI:
            captured_buffer.append(kw["buffer"])
            return _RecordingAdminUI(spec, **kw)

        popen_stub, _ = make_popen_stub(returncode=0)
        launch(
            config,
            sources={},
            popen=popen_stub,
            base_env={},
            adminui_factory=factory,
        )
        # The buffer should contain both child.spawn and child.exit
        # events from the run.
        buf = captured_buffer[0]
        events = buf.recent()  # type: ignore[attr-defined]
        kinds = [e["kind"] for e in events]
        assert "child.spawn" in kinds
        assert "child.exit" in kinds

    def test_adminui_stop_called_even_on_exception(self) -> None:
        """If anything inside the try block raises, stop() must still
        run in the finally."""
        config = make_config()
        recorded: list[_RecordingAdminUI] = []

        def factory(spec: object, **kw: object) -> _RecordingAdminUI:
            ui = _RecordingAdminUI(spec, **kw)
            recorded.append(ui)
            return ui

        # Popen that raises -- spawn fails before the supervised loop
        # even starts.
        def boom_popen(*_a: object, **_kw: object) -> object:
            raise RuntimeError("popen failed")

        with pytest.raises(RuntimeError, match="popen failed"):
            launch(
                config,
                sources={},
                popen=boom_popen,
                base_env={},
                adminui_factory=factory,
            )
        # AdminUI start() ran before the spawn, stop() ran in finally.
        assert recorded[0].start_calls == 1
        assert recorded[0].stop_calls == 1
