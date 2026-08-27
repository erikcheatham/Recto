"""YAML config loader + schema validator for service.yaml files.

The schema shape is documented in ARCHITECTURE.md. This module is the
canonical Python representation. Loading a service.yaml goes through
load_config(); structural mistakes are caught here, not at first secret
fetch / first child spawn / first webhook dispatch.

Design notes:
- Pure stdlib + PyYAML. No pydantic, no attrs. Consumers don't need
  to absorb heavy deps; Recto stays a single-import-tree package.
- Every spec class is a frozen dataclass with __post_init__ validators
  for value constraints (interval_seconds > 0, etc.). Type errors
  surface as TypeError; semantic errors surface as ConfigValidationError.
- ConfigValidationError carries a path-list so the user sees
  "spec.healthz.interval_seconds: must be > 0, got 0" rather than
  "interval_seconds bad".
- apiVersion is checked early. Only "recto/v1" is accepted; future
  schemas live alongside, never replace.
- Field defaults are explicit and conservative. If the YAML omits a
  field, the resulting dataclass instance is the documented default.

This module does NOT do template interpolation (${env:VAR} substitution
in comms.headers, etc.) -- that's a runtime concern owned by recto.comms
at dispatch time. Config validates structure; runtime substitutes values.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

SUPPORTED_API_VERSIONS = ("recto/v1",)
SUPPORTED_KINDS = ("Service",)


class ConfigValidationError(Exception):
    """One or more structural / semantic problems in a service.yaml."""

    def __init__(self, problems: list[str]):
        self.problems = list(problems)
        super().__init__(self._render())

    def _render(self) -> str:
        if not self.problems:
            return "config validation failed (no specific problems recorded)"
        if len(self.problems) == 1:
            return self.problems[0]
        bullets = "\n".join(f"  - {p}" for p in self.problems)
        return f"config validation failed with {len(self.problems)} problem(s):\n{bullets}"


@dataclass(frozen=True, slots=True)
class SecretSpec:
    """One entry under spec.secrets."""

    name: str
    source: str
    target_env: str
    required: bool = True
    config: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class HealthzSpec:
    """Liveness probe configuration. enabled=False means no probe runs.

    Three probe types ship in v0.2:
    - http: GET url with timeout_seconds; 2xx/3xx is healthy.
    - tcp: open a TCP connection to host:port; success is healthy.
    - exec: run command (list of args); expected_exit_code is healthy.

    Each type uses a different subset of the fields below. Required-field
    validation is type-aware: e.g. url is required for http+enabled,
    host + port are required for tcp+enabled, command is required for
    exec+enabled. Unused fields stay at their defaults and are ignored
    at runtime.
    """

    enabled: bool = False
    type: str = "http"
    url: str = ""
    # tcp-only:
    host: str = ""
    port: int = 0
    # exec-only:
    command: tuple[str, ...] = ()
    expected_exit_code: int = 0
    interval_seconds: int = 30
    timeout_seconds: int = 5
    failure_threshold: int = 3
    restart_grace_seconds: int = 10

    def __post_init__(self) -> None:
        if self.type not in ("http", "tcp", "exec"):
            raise ConfigValidationError(
                [f"spec.healthz.type: must be one of http|tcp|exec, got {self.type!r}"]
            )
        if self.enabled:
            if self.type == "http" and not self.url:
                raise ConfigValidationError(
                    ["spec.healthz: 'url' is required when type=http and enabled=true"]
                )
            if self.type == "tcp":
                if not self.host:
                    raise ConfigValidationError(
                        ["spec.healthz: 'host' is required when type=tcp and enabled=true"]
                    )
                if not (1 <= self.port <= 65535):
                    raise ConfigValidationError(
                        [
                            f"spec.healthz.port: must be 1..65535 when type=tcp and "
                            f"enabled=true, got {self.port}"
                        ]
                    )
            if self.type == "exec" and not self.command:
                raise ConfigValidationError(
                    [
                        "spec.healthz: 'command' is required (non-empty list) "
                        "when type=exec and enabled=true"
                    ]
                )
        if self.interval_seconds <= 0:
            raise ConfigValidationError(
                [f"spec.healthz.interval_seconds: must be > 0, got {self.interval_seconds}"]
            )
        if self.timeout_seconds <= 0:
            raise ConfigValidationError(
                [f"spec.healthz.timeout_seconds: must be > 0, got {self.timeout_seconds}"]
            )
        if self.failure_threshold < 1:
            raise ConfigValidationError(
                [f"spec.healthz.failure_threshold: must be >= 1, got {self.failure_threshold}"]
            )
        if self.restart_grace_seconds < 0:
            raise ConfigValidationError(
                [
                    f"spec.healthz.restart_grace_seconds: must be >= 0, "
                    f"got {self.restart_grace_seconds}"
                ]
            )


@dataclass(frozen=True, slots=True)
class RestartSpec:
    """Restart policy for the supervised child process."""

    policy: str = "always"
    backoff: str = "exponential"
    initial_delay_seconds: int = 1
    max_delay_seconds: int = 60
    max_attempts: int = 10
    notify_on_event: tuple[str, ...] = field(
        default_factory=lambda: ("restart", "health_failure", "max_attempts_reached")
    )

    def __post_init__(self) -> None:
        if self.policy not in ("always", "never", "on-failure"):
            raise ConfigValidationError(
                [f"spec.restart.policy: must be always|never|on-failure, got {self.policy!r}"]
            )
        if self.backoff not in ("exponential", "linear", "constant"):
            raise ConfigValidationError(
                [
                    f"spec.restart.backoff: must be exponential|linear|constant, "
                    f"got {self.backoff!r}"
                ]
            )
        if self.initial_delay_seconds < 0:
            raise ConfigValidationError(
                [
                    f"spec.restart.initial_delay_seconds: must be >= 0, "
                    f"got {self.initial_delay_seconds}"
                ]
            )
        if self.max_delay_seconds < self.initial_delay_seconds:
            raise ConfigValidationError(
                [
                    "spec.restart.max_delay_seconds: must be >= initial_delay_seconds, "
                    f"got max={self.max_delay_seconds} initial={self.initial_delay_seconds}"
                ]
            )
        if self.max_attempts < 0:
            raise ConfigValidationError(
                [f"spec.restart.max_attempts: must be >= 0 (0=unlimited), got {self.max_attempts}"]
            )


@dataclass(frozen=True, slots=True)
class CommsSpec:
    """One webhook destination under spec.comms."""

    type: str = "webhook"
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    template: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.type != "webhook":
            raise ConfigValidationError(
                [f"spec.comms[].type: only 'webhook' is supported in v0.1, got {self.type!r}"]
            )
        if not self.url:
            raise ConfigValidationError(["spec.comms[].url: required"])


@dataclass(frozen=True, slots=True)
class ResourceLimitsSpec:
    """Win32 Job Object resource limits (v0.2 enforces them)."""

    memory_mb: int | None = None
    cpu_percent: int | None = None
    process_count: int | None = None

    def __post_init__(self) -> None:
        if self.memory_mb is not None and self.memory_mb <= 0:
            raise ConfigValidationError(
                [f"spec.resource_limits.memory_mb: must be > 0, got {self.memory_mb}"]
            )
        if self.cpu_percent is not None and not (1 <= self.cpu_percent <= 100):
            raise ConfigValidationError(
                [f"spec.resource_limits.cpu_percent: must be 1..100, got {self.cpu_percent}"]
            )
        if self.process_count is not None and self.process_count < 1:
            raise ConfigValidationError(
                [f"spec.resource_limits.process_count: must be >= 1, got {self.process_count}"]
            )


@dataclass(frozen=True, slots=True)
class AdminUISpec:
    """Web admin UI. Disabled in v0.1; full impl ships in v0.2."""

    enabled: bool = False
    bind: str = "127.0.0.1:5050"
    cf_access_required: bool = True
    expose_via_tunnel: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class TelemetrySpec:
    """OpenTelemetry trace export. Disabled by default; v0.2 wires it up."""

    enabled: bool = False
    otlp_endpoint: str = ""
    service_name: str = ""


@dataclass(frozen=True, slots=True)
class ServiceMeta:
    name: str
    description: str = ""
    # display_name is the short title NSSM shows in the Services snap-in's
    # "Display name" column, as distinct from the longer "Description"
    # column. v0.2.x collapsed both into `description`, which was lossy
    # vs the standard NSSM convention of distinct values. Adding this as
    # an OPTIONAL field per Hard Rule #1 (additive only). When set,
    # reconcile writes it to NSSM `DisplayName`; when empty (default),
    # the v0.2.x fallback applies (description -> DisplayName, or the
    # service name if description is also empty). Existing service.yaml
    # files keep working unchanged.
    display_name: str = ""

    def __post_init__(self) -> None:
        if not self.name:
            raise ConfigValidationError(["metadata.name: required"])
        if not self.name.replace("-", "").replace("_", "").isalnum():
            raise ConfigValidationError(
                [
                    f"metadata.name: must be alphanumeric (with - or _ allowed), "
                    f"got {self.name!r}"
                ]
            )


@dataclass(frozen=True, slots=True)
class ServiceSpec:
    exec: str
    args: tuple[str, ...] = ()
    working_dir: str = ""
    user: str = ""
    secrets: tuple[SecretSpec, ...] = ()
    env: dict[str, str] = field(default_factory=dict)
    healthz: HealthzSpec = field(default_factory=HealthzSpec)
    restart: RestartSpec = field(default_factory=RestartSpec)
    comms: tuple[CommsSpec, ...] = ()
    resource_limits: ResourceLimitsSpec = field(default_factory=ResourceLimitsSpec)
    admin_ui: AdminUISpec = field(default_factory=AdminUISpec)
    telemetry: TelemetrySpec = field(default_factory=TelemetrySpec)

    def __post_init__(self) -> None:
        if not self.exec:
            raise ConfigValidationError(["spec.exec: required"])
        env_targets = [s.target_env for s in self.secrets if s.target_env]
        dupes = {e for e in env_targets if env_targets.count(e) > 1}
        if dupes:
            raise ConfigValidationError(
                [
                    f"spec.secrets: duplicate target_env values: {sorted(dupes)} "
                    f"-- each secret must inject into a distinct env var"
                ]
            )


@dataclass(frozen=True, slots=True)
class ServiceConfig:
    apiVersion: str
    kind: str
    metadata: ServiceMeta
    spec: ServiceSpec

    def __post_init__(self) -> None:
        if self.apiVersion not in SUPPORTED_API_VERSIONS:
            raise ConfigValidationError(
                [
                    f"apiVersion: {self.apiVersion!r} is not supported "
                    f"(expected one of {SUPPORTED_API_VERSIONS})"
                ]
            )
        if self.kind not in SUPPORTED_KINDS:
            raise ConfigValidationError(
                [
                    f"kind: {self.kind!r} is not supported "
                    f"(expected one of {SUPPORTED_KINDS})"
                ]
            )


def _require(d: dict[str, Any], key: str, path: str, problems: list[str]) -> Any:
    if key not in d:
        problems.append(f"{path}.{key}: required")
        return None
    return d[key]


def _build_secret_spec(d: dict[str, Any], path: str, problems: list[str]) -> SecretSpec | None:
    name = _require(d, "name", path, problems)
    source = _require(d, "source", path, problems)
    target_env = _require(d, "target_env", path, problems)
    if name is None or source is None or target_env is None:
        return None
    try:
        return SecretSpec(
            name=str(name),
            source=str(source),
            target_env=str(target_env),
            required=bool(d.get("required", True)),
            config=dict(d.get("config", {})),
        )
    except ConfigValidationError as e:
        problems.extend(f"{path}: {p}" for p in e.problems)
        return None


def _build_comms_spec(d: dict[str, Any], path: str, problems: list[str]) -> CommsSpec | None:
    try:
        return CommsSpec(
            type=str(d.get("type", "webhook")),
            url=str(d.get("url", "")),
            headers={str(k): str(v) for k, v in dict(d.get("headers", {})).items()},
            template=dict(d.get("template", {})),
        )
    except ConfigValidationError as e:
        problems.extend(f"{path}: {p}" for p in e.problems)
        return None


def load_config(source: Path | str | dict[str, Any]) -> ServiceConfig:
    """Load and validate a service.yaml."""
    if isinstance(source, dict):
        data = source
    elif isinstance(source, (str, Path)):
        path = Path(source)
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    else:
        raise ConfigValidationError(
            [
                f"top-level: must be a path or pre-parsed mapping, "
                f"got {type(source).__name__}"
            ]
        )

    if not isinstance(data, dict):
        raise ConfigValidationError(
            [f"top-level: must be a mapping, got {type(data).__name__}"]
        )

    problems: list[str] = []

    api_version = data.get("apiVersion", "")
    kind = data.get("kind", "")
    metadata_raw = data.get("metadata", {})
    spec_raw = data.get("spec", {})

    upfront_problems: list[str] = []
    if api_version not in SUPPORTED_API_VERSIONS:
        upfront_problems.append(
            f"apiVersion: {api_version!r} is not supported "
            f"(expected one of {SUPPORTED_API_VERSIONS})"
        )
    if kind not in SUPPORTED_KINDS:
        upfront_problems.append(
            f"kind: {kind!r} is not supported (expected one of {SUPPORTED_KINDS})"
        )
    problems.extend(upfront_problems)

    if not isinstance(metadata_raw, dict):
        problems.append("metadata: must be a mapping")
        metadata_raw = {}
    if not isinstance(spec_raw, dict):
        problems.append("spec: must be a mapping")
        spec_raw = {}

    metadata: ServiceMeta | None = None
    name = metadata_raw.get("name", "")
    description = metadata_raw.get("description", "")
    display_name = metadata_raw.get("display_name", "")
    try:
        metadata = ServiceMeta(
            name=str(name),
            description=str(description),
            display_name=str(display_name),
        )
    except ConfigValidationError as e:
        problems.extend(e.problems)

    secrets_raw = spec_raw.get("secrets", []) or []
    secrets: list[SecretSpec] = []
    for i, s in enumerate(secrets_raw):
        if not isinstance(s, dict):
            problems.append(f"spec.secrets[{i}]: must be a mapping")
            continue
        ss = _build_secret_spec(s, f"spec.secrets[{i}]", problems)
        if ss is not None:
            secrets.append(ss)

    healthz: HealthzSpec | None = None
    healthz_raw = spec_raw.get("healthz", {}) or {}
    if not isinstance(healthz_raw, dict):
        problems.append("spec.healthz: must be a mapping")
    else:
        try:
            command_raw = healthz_raw.get("command") or ()
            if not isinstance(command_raw, (list, tuple)):
                problems.append(
                    "spec.healthz.command: must be a list of strings"
                )
                command_raw = ()
            healthz = HealthzSpec(
                enabled=bool(healthz_raw.get("enabled", False)),
                type=str(healthz_raw.get("type", "http")),
                url=str(healthz_raw.get("url", "")),
                host=str(healthz_raw.get("host", "")),
                port=int(healthz_raw.get("port", 0)),
                command=tuple(str(c) for c in command_raw),
                expected_exit_code=int(healthz_raw.get("expected_exit_code", 0)),
                interval_seconds=int(healthz_raw.get("interval_seconds", 30)),
                timeout_seconds=int(healthz_raw.get("timeout_seconds", 5)),
                failure_threshold=int(healthz_raw.get("failure_threshold", 3)),
                restart_grace_seconds=int(healthz_raw.get("restart_grace_seconds", 10)),
            )
        except ConfigValidationError as e:
            problems.extend(e.problems)
        except (TypeError, ValueError) as e:
            problems.append(f"spec.healthz: type error -- {e}")

    restart: RestartSpec | None = None
    restart_raw = spec_raw.get("restart", {}) or {}
    if not isinstance(restart_raw, dict):
        problems.append("spec.restart: must be a mapping")
    else:
        try:
            notify_events = restart_raw.get(
                "notify_on_event",
                ("restart", "health_failure", "max_attempts_reached"),
            )
            restart = RestartSpec(
                policy=str(restart_raw.get("policy", "always")),
                backoff=str(restart_raw.get("backoff", "exponential")),
                initial_delay_seconds=int(restart_raw.get("initial_delay_seconds", 1)),
                max_delay_seconds=int(restart_raw.get("max_delay_seconds", 60)),
                max_attempts=int(restart_raw.get("max_attempts", 10)),
                notify_on_event=tuple(str(e) for e in notify_events),
            )
        except ConfigValidationError as e:
            problems.extend(e.problems)
        except (TypeError, ValueError) as e:
            problems.append(f"spec.restart: type error -- {e}")

    comms_raw = spec_raw.get("comms", []) or []
    comms: list[CommsSpec] = []
    for i, c in enumerate(comms_raw):
        if not isinstance(c, dict):
            problems.append(f"spec.comms[{i}]: must be a mapping")
            continue
        cs = _build_comms_spec(c, f"spec.comms[{i}]", problems)
        if cs is not None:
            comms.append(cs)

    rl: ResourceLimitsSpec | None = None
    rl_raw = spec_raw.get("resource_limits", {}) or {}
    if not isinstance(rl_raw, dict):
        problems.append("spec.resource_limits: must be a mapping")
    else:
        try:
            rl = ResourceLimitsSpec(
                memory_mb=rl_raw.get("memory_mb"),
                cpu_percent=rl_raw.get("cpu_percent"),
                process_count=rl_raw.get("process_count"),
            )
        except ConfigValidationError as e:
            problems.extend(e.problems)

    aui = AdminUISpec(
        enabled=bool((spec_raw.get("admin_ui") or {}).get("enabled", False)),
        bind=str((spec_raw.get("admin_ui") or {}).get("bind", "127.0.0.1:5050")),
        cf_access_required=bool(
            (spec_raw.get("admin_ui") or {}).get("cf_access_required", True)
        ),
        expose_via_tunnel=dict(
            (spec_raw.get("admin_ui") or {}).get("expose_via_tunnel", {})
        ),
    )

    tele = TelemetrySpec(
        enabled=bool((spec_raw.get("telemetry") or {}).get("enabled", False)),
        otlp_endpoint=str((spec_raw.get("telemetry") or {}).get("otlp_endpoint", "")),
        service_name=str((spec_raw.get("telemetry") or {}).get("service_name", "")),
    )

    spec: ServiceSpec | None = None
    args = spec_raw.get("args", []) or []
    if not isinstance(args, list):
        problems.append("spec.args: must be a list")
        args = []
    env_raw = spec_raw.get("env", {}) or {}
    if not isinstance(env_raw, dict):
        problems.append("spec.env: must be a mapping")
        env_raw = {}
    if not spec_raw.get("exec"):
        problems.append("spec.exec: required")
    try:
        spec = ServiceSpec(
            exec=str(spec_raw.get("exec", "")) or "<unset>",
            args=tuple(str(a) for a in args),
            working_dir=str(spec_raw.get("working_dir", "")),
            user=str(spec_raw.get("user", "")),
            secrets=tuple(secrets),
            env={str(k): str(v) for k, v in env_raw.items()},
            healthz=healthz if healthz is not None else HealthzSpec(),
            restart=restart if restart is not None else RestartSpec(),
            comms=tuple(comms),
            resource_limits=rl if rl is not None else ResourceLimitsSpec(),
            admin_ui=aui,
            telemetry=tele,
        )
    except ConfigValidationError as e:
        problems.extend(e.problems)

    if metadata is None or spec is None:
        if not problems:
            problems.append("internal: metadata or spec failed silently")
        raise ConfigValidationError(problems)

    safe_api = (
        api_version
        if api_version in SUPPORTED_API_VERSIONS
        else SUPPORTED_API_VERSIONS[0]
    )
    safe_kind = kind if kind in SUPPORTED_KINDS else SUPPORTED_KINDS[0]
    try:
        cfg = ServiceConfig(
            apiVersion=str(safe_api),
            kind=str(safe_kind),
            metadata=metadata,
            spec=spec,
        )
    except ConfigValidationError as e:
        problems.extend(e.problems)
        raise ConfigValidationError(problems) from e

    if problems:
        raise ConfigValidationError(problems)
    return cfg
