"""Tests for recto.config -- YAML loader + schema validator."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from recto.config import (
    ConfigValidationError,
    ServiceConfig,
    load_config,
)

MINIMAL_VALID: dict[str, Any] = {
    "apiVersion": "recto/v1",
    "kind": "Service",
    "metadata": {"name": "myservice"},
    "spec": {"exec": "python.exe"},
}


FULL_VALID: dict[str, Any] = {
    "apiVersion": "recto/v1",
    "kind": "Service",
    "metadata": {
        "name": "myservice",
        "description": "Position-aware planning lens",
    },
    "spec": {
        "exec": "python.exe",
        "args": ["app.py"],
        "working_dir": "C:\\path\\to\\myservice",
        "user": "NT AUTHORITY\\NETWORK SERVICE",
        "secrets": [
            {
                "name": "MY_API_KEY",
                "source": "credman",
                "target_env": "MY_API_KEY",
                "required": True,
            },
            {
                "name": "WEBHOOK_TOKEN",
                "source": "credman",
                "target_env": "WEBHOOK_TOKEN",
            },
        ],
        "env": {"MYTRADINGAPP_TOKEN": "0"},
        "healthz": {
            "enabled": True,
            "type": "http",
            "url": "http://localhost:5000/api/trade/status",
            "interval_seconds": 30,
            "timeout_seconds": 5,
            "failure_threshold": 3,
            "restart_grace_seconds": 10,
        },
        "restart": {
            "policy": "always",
            "backoff": "exponential",
            "initial_delay_seconds": 1,
            "max_delay_seconds": 60,
            "max_attempts": 10,
            "notify_on_event": ["restart", "health_failure", "max_attempts_reached"],
        },
        "comms": [
            {
                "type": "webhook",
                "url": "https://hooks.example.com/recto",
                "headers": {"X-Auth-Token": "${env:WEBHOOK_TOKEN}"},
                "template": {
                    "to": "dev",
                    "from": "darwin",
                    "subject": "[recto/${service.name}] ${event.kind}",
                },
            }
        ],
        "resource_limits": {
            "memory_mb": 512,
            "cpu_percent": 50,
            "process_count": 32,
        },
        "admin_ui": {
            "enabled": True,
            "bind": "127.0.0.1:5050",
            "cf_access_required": True,
        },
        "telemetry": {
            "enabled": False,
            "otlp_endpoint": "http://localhost:4318",
            "service_name": "myservice",
        },
    },
}


class TestApiVersionAndKind:
    def test_minimal_valid_loads(self) -> None:
        c = load_config(MINIMAL_VALID)
        assert isinstance(c, ServiceConfig)
        assert c.apiVersion == "recto/v1"
        assert c.kind == "Service"
        assert c.metadata.name == "myservice"
        assert c.spec.exec == "python.exe"

    def test_unsupported_api_version(self) -> None:
        bad = {**MINIMAL_VALID, "apiVersion": "recto/v999"}
        with pytest.raises(ConfigValidationError) as exc_info:
            load_config(bad)
        assert any("apiVersion" in p for p in exc_info.value.problems)

    def test_unsupported_kind(self) -> None:
        bad = {**MINIMAL_VALID, "kind": "DaemonSet"}
        with pytest.raises(ConfigValidationError) as exc_info:
            load_config(bad)
        assert any("kind" in p for p in exc_info.value.problems)


class TestMetadata:
    def test_missing_name(self) -> None:
        bad = {**MINIMAL_VALID, "metadata": {}}
        with pytest.raises(ConfigValidationError) as exc_info:
            load_config(bad)
        assert any("metadata.name" in p for p in exc_info.value.problems)

    def test_invalid_name_with_special_chars(self) -> None:
        bad = {**MINIMAL_VALID, "metadata": {"name": "ver$o"}}
        with pytest.raises(ConfigValidationError) as exc_info:
            load_config(bad)
        assert any("metadata.name" in p for p in exc_info.value.problems)

    def test_name_with_underscore_and_hyphen_ok(self) -> None:
        ok = {**MINIMAL_VALID, "metadata": {"name": "my-service_web"}}
        c = load_config(ok)
        assert c.metadata.name == "my-service_web"

    def test_display_name_defaults_to_empty_string(self) -> None:
        """Papercut #3 backward-compat: omitting display_name keeps the
        v0.2.0 behavior. ServiceMeta.display_name defaults to ''."""
        c = load_config(MINIMAL_VALID)
        assert c.metadata.display_name == ""

    def test_display_name_optional_field_loads(self) -> None:
        """Papercut #3 additive field: display_name parses cleanly when
        present in metadata."""
        ok = {
            **MINIMAL_VALID,
            "metadata": {
                "name": "myservice",
                "description": "A long description string",
                "display_name": "MyService Short",
            },
        }
        c = load_config(ok)
        assert c.metadata.name == "myservice"
        assert c.metadata.description == "A long description string"
        assert c.metadata.display_name == "MyService Short"

    def test_display_name_coerces_to_string(self) -> None:
        """display_name follows the same str() coercion as description
        so a numeric YAML value (e.g. `display_name: 42`) becomes '42'
        rather than raising."""
        ok = {
            **MINIMAL_VALID,
            "metadata": {"name": "myservice", "display_name": 42},
        }
        c = load_config(ok)
        assert c.metadata.display_name == "42"


class TestSpec:
    def test_missing_exec(self) -> None:
        bad = {**MINIMAL_VALID, "spec": {}}
        with pytest.raises(ConfigValidationError) as exc_info:
            load_config(bad)
        assert any("spec.exec" in p for p in exc_info.value.problems)

    def test_args_must_be_list(self) -> None:
        bad = {**MINIMAL_VALID, "spec": {"exec": "x", "args": "not-a-list"}}
        with pytest.raises(ConfigValidationError) as exc_info:
            load_config(bad)
        assert any("spec.args" in p for p in exc_info.value.problems)

    def test_env_must_be_mapping(self) -> None:
        bad = {**MINIMAL_VALID, "spec": {"exec": "x", "env": "not-a-mapping"}}
        with pytest.raises(ConfigValidationError) as exc_info:
            load_config(bad)
        assert any("spec.env" in p for p in exc_info.value.problems)


class TestSecrets:
    def test_secret_missing_required_field(self) -> None:
        bad = {
            **MINIMAL_VALID,
            "spec": {
                "exec": "x",
                "secrets": [{"name": "K", "source": "credman"}],
            },
        }
        with pytest.raises(ConfigValidationError) as exc_info:
            load_config(bad)
        assert any("target_env" in p for p in exc_info.value.problems)

    def test_duplicate_target_env_rejected(self) -> None:
        bad = {
            **MINIMAL_VALID,
            "spec": {
                "exec": "x",
                "secrets": [
                    {"name": "A", "source": "credman", "target_env": "X"},
                    {"name": "B", "source": "env", "target_env": "X"},
                ],
            },
        }
        with pytest.raises(ConfigValidationError) as exc_info:
            load_config(bad)
        assert any(
            "target_env" in p and "duplicate" in p.lower() for p in exc_info.value.problems
        )

    def test_secrets_optional(self) -> None:
        ok = {**MINIMAL_VALID, "spec": {"exec": "x"}}
        c = load_config(ok)
        assert c.spec.secrets == ()

    def test_secret_required_default_true(self) -> None:
        ok = {
            **MINIMAL_VALID,
            "spec": {
                "exec": "x",
                "secrets": [{"name": "A", "source": "env", "target_env": "A"}],
            },
        }
        c = load_config(ok)
        assert c.spec.secrets[0].required is True


class TestHealthz:
    def test_disabled_default_no_url_required(self) -> None:
        ok = {**MINIMAL_VALID, "spec": {"exec": "x"}}
        c = load_config(ok)
        assert c.spec.healthz.enabled is False

    def test_enabled_http_requires_url(self) -> None:
        bad = {
            **MINIMAL_VALID,
            "spec": {"exec": "x", "healthz": {"enabled": True, "type": "http"}},
        }
        with pytest.raises(ConfigValidationError) as exc_info:
            load_config(bad)
        assert any("url" in p for p in exc_info.value.problems)

    def test_invalid_type(self) -> None:
        bad = {
            **MINIMAL_VALID,
            "spec": {"exec": "x", "healthz": {"type": "invalid-type"}},
        }
        with pytest.raises(ConfigValidationError) as exc_info:
            load_config(bad)
        assert any("type" in p for p in exc_info.value.problems)

    def test_zero_interval_rejected(self) -> None:
        bad = {
            **MINIMAL_VALID,
            "spec": {
                "exec": "x",
                "healthz": {"enabled": True, "url": "http://x", "interval_seconds": 0},
            },
        }
        with pytest.raises(ConfigValidationError) as exc_info:
            load_config(bad)
        assert any("interval_seconds" in p for p in exc_info.value.problems)

    def test_tcp_loads_with_host_and_port(self) -> None:
        ok = {
            **MINIMAL_VALID,
            "spec": {
                "exec": "x",
                "healthz": {
                    "enabled": True,
                    "type": "tcp",
                    "host": "127.0.0.1",
                    "port": 5432,
                },
            },
        }
        c = load_config(ok)
        assert c.spec.healthz.type == "tcp"
        assert c.spec.healthz.host == "127.0.0.1"
        assert c.spec.healthz.port == 5432

    def test_tcp_enabled_requires_host(self) -> None:
        bad = {
            **MINIMAL_VALID,
            "spec": {
                "exec": "x",
                "healthz": {"enabled": True, "type": "tcp", "port": 8080},
            },
        }
        with pytest.raises(ConfigValidationError) as exc_info:
            load_config(bad)
        assert any("host" in p for p in exc_info.value.problems)

    def test_tcp_enabled_rejects_bad_port(self) -> None:
        for bad_port in (0, -1, 70000):
            bad = {
                **MINIMAL_VALID,
                "spec": {
                    "exec": "x",
                    "healthz": {
                        "enabled": True,
                        "type": "tcp",
                        "host": "h",
                        "port": bad_port,
                    },
                },
            }
            with pytest.raises(ConfigValidationError) as exc_info:
                load_config(bad)
            assert any("port" in p for p in exc_info.value.problems), (
                f"expected port complaint for port={bad_port}, "
                f"got: {exc_info.value.problems}"
            )

    def test_tcp_disabled_does_not_require_host(self) -> None:
        ok = {
            **MINIMAL_VALID,
            "spec": {
                "exec": "x",
                "healthz": {"type": "tcp", "enabled": False},
            },
        }
        c = load_config(ok)
        assert c.spec.healthz.type == "tcp"

    def test_exec_loads_with_command(self) -> None:
        ok = {
            **MINIMAL_VALID,
            "spec": {
                "exec": "x",
                "healthz": {
                    "enabled": True,
                    "type": "exec",
                    "command": ["my-check", "--mode=quick"],
                    "expected_exit_code": 0,
                },
            },
        }
        c = load_config(ok)
        assert c.spec.healthz.type == "exec"
        assert c.spec.healthz.command == ("my-check", "--mode=quick")
        assert c.spec.healthz.expected_exit_code == 0

    def test_exec_enabled_requires_command(self) -> None:
        bad = {
            **MINIMAL_VALID,
            "spec": {
                "exec": "x",
                "healthz": {"enabled": True, "type": "exec"},
            },
        }
        with pytest.raises(ConfigValidationError) as exc_info:
            load_config(bad)
        assert any("command" in p for p in exc_info.value.problems)

    def test_exec_command_must_be_list(self) -> None:
        bad = {
            **MINIMAL_VALID,
            "spec": {
                "exec": "x",
                "healthz": {
                    "enabled": True,
                    "type": "exec",
                    "command": "my-check --mode=quick",
                },
            },
        }
        with pytest.raises(ConfigValidationError) as exc_info:
            load_config(bad)
        assert any("command" in p for p in exc_info.value.problems)

    def test_exec_custom_expected_exit_code_loads(self) -> None:
        ok = {
            **MINIMAL_VALID,
            "spec": {
                "exec": "x",
                "healthz": {
                    "enabled": True,
                    "type": "exec",
                    "command": ["custom-check"],
                    "expected_exit_code": 7,
                },
            },
        }
        c = load_config(ok)
        assert c.spec.healthz.expected_exit_code == 7


class TestRestart:
    def test_invalid_policy(self) -> None:
        bad = {**MINIMAL_VALID, "spec": {"exec": "x", "restart": {"policy": "yolo"}}}
        with pytest.raises(ConfigValidationError) as exc_info:
            load_config(bad)
        assert any("policy" in p for p in exc_info.value.problems)

    def test_invalid_backoff(self) -> None:
        bad = {**MINIMAL_VALID, "spec": {"exec": "x", "restart": {"backoff": "fibonacci"}}}
        with pytest.raises(ConfigValidationError) as exc_info:
            load_config(bad)
        assert any("backoff" in p for p in exc_info.value.problems)

    def test_max_below_initial_rejected(self) -> None:
        bad = {
            **MINIMAL_VALID,
            "spec": {
                "exec": "x",
                "restart": {"initial_delay_seconds": 60, "max_delay_seconds": 10},
            },
        }
        with pytest.raises(ConfigValidationError) as exc_info:
            load_config(bad)
        assert any("max_delay_seconds" in p for p in exc_info.value.problems)


class TestComms:
    def test_webhook_requires_url(self) -> None:
        bad = {
            **MINIMAL_VALID,
            "spec": {"exec": "x", "comms": [{"type": "webhook"}]},
        }
        with pytest.raises(ConfigValidationError) as exc_info:
            load_config(bad)
        assert any("url" in p for p in exc_info.value.problems)

    def test_only_webhook_supported(self) -> None:
        bad = {
            **MINIMAL_VALID,
            "spec": {"exec": "x", "comms": [{"type": "smoke-signal", "url": "x"}]},
        }
        with pytest.raises(ConfigValidationError) as exc_info:
            load_config(bad)
        assert any("webhook" in p for p in exc_info.value.problems)


class TestResourceLimits:
    def test_invalid_memory(self) -> None:
        bad = {
            **MINIMAL_VALID,
            "spec": {"exec": "x", "resource_limits": {"memory_mb": 0}},
        }
        with pytest.raises(ConfigValidationError) as exc_info:
            load_config(bad)
        assert any("memory_mb" in p for p in exc_info.value.problems)

    def test_invalid_cpu_percent(self) -> None:
        bad = {
            **MINIMAL_VALID,
            "spec": {"exec": "x", "resource_limits": {"cpu_percent": 200}},
        }
        with pytest.raises(ConfigValidationError) as exc_info:
            load_config(bad)
        assert any("cpu_percent" in p for p in exc_info.value.problems)


class TestFullValid:
    def test_loads_clean(self) -> None:
        c = load_config(FULL_VALID)
        assert c.metadata.name == "myservice"
        assert c.spec.exec == "python.exe"
        assert c.spec.args == ("app.py",)
        assert len(c.spec.secrets) == 2
        assert c.spec.secrets[0].name == "MY_API_KEY"
        assert c.spec.secrets[0].source == "credman"
        assert c.spec.healthz.enabled is True
        assert c.spec.healthz.url == "http://localhost:5000/api/trade/status"
        assert c.spec.restart.policy == "always"
        assert len(c.spec.comms) == 1
        assert c.spec.comms[0].url == "https://hooks.example.com/recto"
        assert c.spec.resource_limits.memory_mb == 512
        assert c.spec.admin_ui.enabled is True

    def test_round_trip_via_yaml_file(self, tmp_path: Path) -> None:
        import yaml

        p = tmp_path / "myservice.service.yaml"
        p.write_text(yaml.safe_dump(FULL_VALID), encoding="utf-8")
        c = load_config(p)
        assert c.metadata.name == "myservice"
        assert len(c.spec.secrets) == 2


class TestErrorAggregation:
    def test_multiple_problems_in_single_error(self) -> None:
        bad = {
            "apiVersion": "recto/v999",
            "kind": "DaemonSet",
            "metadata": {},
            "spec": {},
        }
        with pytest.raises(ConfigValidationError) as exc_info:
            load_config(bad)
        problems = exc_info.value.problems
        assert len(problems) >= 3
        rendered = str(exc_info.value)
        assert "apiVersion" in rendered
        assert "kind" in rendered


class TestNonDictTopLevel:
    def test_list_at_top_level_rejected(self) -> None:
        with pytest.raises(ConfigValidationError) as exc_info:
            load_config([])  # type: ignore[arg-type]
        assert any("top-level" in p for p in exc_info.value.problems)
