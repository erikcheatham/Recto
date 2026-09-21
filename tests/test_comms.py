"""Tests for recto.comms.

The webhook dispatcher's contract:

- `interpolate(template, env=, service=, event=)` substitutes
  ``${env:X}``, ``${service.X}``, ``${event.X}`` tokens; unknown tokens
  pass through.
- `event_summary(kind, ctx)` produces a single human-readable line per
  launcher event kind.
- `CommsDispatcher.dispatch(kind, ctx)` sends a JSON POST to every sink
  whose category passes the `notify_on_event` filter, swallowing all
  errors so the launcher's main loop never sees a webhook failure.

Tests stub urllib.request.urlopen at the dispatcher's `urlopen=`
injection point so no real HTTP is sent.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

import pytest

from recto.comms import (
    EVENT_KIND_TO_NOTIFY_CATEGORY,
    CommsDispatcher,
    event_summary,
    interpolate,
)
from recto.config import ServiceConfig, load_config


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def make_config_with_comms(
    *,
    name: str = "myservice",
    description: str = "Example service",
    notify_on_event: list[str] | None = None,
    comms: list[dict[str, Any]] | None = None,
) -> ServiceConfig:
    """ServiceConfig with at least one webhook sink configured."""
    if comms is None:
        comms = [
            {
                "type": "webhook",
                "url": "https://hooks.example.com/recto",
                "headers": {"X-Auth": "${env:WEBHOOK_TOKEN}"},
                "template": {
                    "subject": "[recto/${service.name}] ${event.kind}",
                    "body": "${event.summary}",
                },
            }
        ]
    spec: dict[str, Any] = {
        "exec": "python.exe",
        "comms": comms,
    }
    if notify_on_event is not None:
        spec["restart"] = {"notify_on_event": notify_on_event}
    return load_config(
        {
            "apiVersion": "recto/v1",
            "kind": "Service",
            "metadata": {"name": name, "description": description},
            "spec": spec,
        }
    )


class StubResponse:
    """urllib response object covering `.status` access for completeness.
    The dispatcher only checks for raised exceptions, but real urllib
    response objects expose .status, so exposing it here keeps the stub
    interchangeable."""

    def __init__(self, status: int = 200) -> None:
        self.status = status

    def __enter__(self) -> "StubResponse":
        return self

    def __exit__(self, *_a: Any) -> None:
        return None


class StubUrlopen:
    """Records every (url, method, data, headers, timeout) tuple the
    dispatcher would send. Returns a StubResponse so the dispatcher's
    happy path completes."""

    def __init__(
        self,
        *,
        raise_exc: BaseException | None = None,
        status: int = 200,
    ) -> None:
        self.raise_exc = raise_exc
        self.status = status
        self.calls: list[dict[str, Any]] = []

    def __call__(
        self, request: urllib.request.Request, timeout: float
    ) -> StubResponse:
        self.calls.append(
            {
                "url": request.full_url,
                "method": request.get_method(),
                "data": request.data,
                "headers": dict(request.header_items()),
                "timeout": timeout,
            }
        )
        if self.raise_exc is not None:
            raise self.raise_exc
        return StubResponse(self.status)


# ---------------------------------------------------------------------------
# interpolate
# ---------------------------------------------------------------------------


class TestInterpolate:
    def test_env_token_substituted(self) -> None:
        out = interpolate(
            "Token: ${env:FOO}",
            env={"FOO": "bar"},
            service={},
            event={},
        )
        assert out == "Token: bar"

    def test_service_token_substituted(self) -> None:
        out = interpolate(
            "Service: ${service.name}",
            env={},
            service={"name": "myservice"},
            event={},
        )
        assert out == "Service: myservice"

    def test_event_token_substituted(self) -> None:
        out = interpolate(
            "Kind: ${event.kind}",
            env={},
            service={},
            event={"kind": "child.exit"},
        )
        assert out == "Kind: child.exit"

    def test_multiple_tokens_in_one_string(self) -> None:
        out = interpolate(
            "[${service.name}] ${event.kind} (token=${env:T})",
            env={"T": "abc"},
            service={"name": "svc"},
            event={"kind": "restart.attempt"},
        )
        assert out == "[svc] restart.attempt (token=abc)"

    def test_unknown_env_var_passes_through_literal(self) -> None:
        # Unknown tokens are visible in the rendered output so the
        # operator notices the misconfiguration.
        out = interpolate(
            "Token: ${env:DOES_NOT_EXIST}",
            env={},
            service={},
            event={},
        )
        assert out == "Token: ${env:DOES_NOT_EXIST}"

    def test_unknown_service_field_passes_through(self) -> None:
        out = interpolate(
            "${service.unknown_field}",
            env={},
            service={"name": "svc"},
            event={},
        )
        assert out == "${service.unknown_field}"

    def test_bare_dollar_brace_not_recognized_grammar_left_alone(self) -> None:
        # ${FOO} (no namespace prefix) is not part of the grammar; left
        # as a literal so misuse is visible.
        out = interpolate(
            "${FOO} stays",
            env={"FOO": "bar"},
            service={},
            event={},
        )
        assert out == "${FOO} stays"

    def test_template_with_no_tokens_returns_unchanged(self) -> None:
        out = interpolate(
            "no tokens here",
            env={},
            service={},
            event={},
        )
        assert out == "no tokens here"


# ---------------------------------------------------------------------------
# event_summary
# ---------------------------------------------------------------------------


class TestEventSummary:
    def test_child_spawn_includes_cmd(self) -> None:
        out = event_summary(
            "child.spawn", {"cmd": ["python", "app.py"], "cwd": None}
        )
        assert "python app.py" in out

    def test_child_exit_natural(self) -> None:
        out = event_summary(
            "child.exit", {"returncode": 0, "healthz_signaled": False}
        )
        assert "0" in out
        assert "healthz" not in out.lower()

    def test_child_exit_healthz_signaled_mentions_probe(self) -> None:
        out = event_summary(
            "child.exit", {"returncode": 143, "healthz_signaled": True}
        )
        assert "healthz" in out.lower()
        assert "143" in out

    def test_restart_attempt_includes_attempt_and_delay(self) -> None:
        out = event_summary(
            "restart.attempt",
            {
                "attempt": 3,
                "delay_seconds": 8,
                "previous_returncode": 1,
                "backoff": "exponential",
            },
        )
        assert "3" in out
        assert "8" in out

    def test_max_attempts_reached_includes_count_and_last_rc(self) -> None:
        out = event_summary(
            "max_attempts_reached",
            {"max_attempts": 5, "last_returncode": 1},
        )
        assert "5" in out
        assert "1" in out

    def test_unknown_kind_falls_back_to_kind_in_summary(self) -> None:
        # Future event kinds without an entry should still produce
        # something useful so logs/webhooks aren't empty.
        out = event_summary("future.kind", {})
        assert "future.kind" in out


# ---------------------------------------------------------------------------
# CommsDispatcher — filtering
# ---------------------------------------------------------------------------


class TestDispatchFiltering:
    def test_no_dispatch_when_kind_not_in_filter(self) -> None:
        # Default notify_on_event from RestartSpec covers
        # restart, health_failure, max_attempts_reached — child.spawn
        # is none of those and not a wildcard, so nothing fires.
        config = make_config_with_comms()
        urlopen = StubUrlopen()
        dispatcher = CommsDispatcher(config, env={}, urlopen=urlopen)
        dispatcher.dispatch("child.spawn", {"cmd": ["x"], "cwd": None})
        assert urlopen.calls == []

    def test_dispatch_fires_for_restart_attempt(self) -> None:
        config = make_config_with_comms(notify_on_event=["restart"])
        urlopen = StubUrlopen()
        dispatcher = CommsDispatcher(config, env={}, urlopen=urlopen)
        dispatcher.dispatch(
            "restart.attempt",
            {
                "attempt": 1,
                "delay_seconds": 1,
                "previous_returncode": 1,
                "backoff": "exponential",
            },
        )
        assert len(urlopen.calls) == 1

    def test_dispatch_fires_for_max_attempts_reached(self) -> None:
        config = make_config_with_comms(
            notify_on_event=["max_attempts_reached"]
        )
        urlopen = StubUrlopen()
        dispatcher = CommsDispatcher(config, env={}, urlopen=urlopen)
        dispatcher.dispatch(
            "max_attempts_reached",
            {"max_attempts": 3, "last_returncode": 1},
        )
        assert len(urlopen.calls) == 1

    def test_health_failure_dispatches_only_when_healthz_signaled(
        self,
    ) -> None:
        # child.exit with healthz_signaled=True maps to health_failure;
        # child.exit with healthz_signaled=False does NOT map to anything
        # under the standard categories.
        config = make_config_with_comms(notify_on_event=["health_failure"])
        urlopen = StubUrlopen()
        dispatcher = CommsDispatcher(config, env={}, urlopen=urlopen)

        dispatcher.dispatch(
            "child.exit",
            {"returncode": 0, "healthz_signaled": False},
        )
        assert urlopen.calls == []  # natural exit doesn't fire

        dispatcher.dispatch(
            "child.exit",
            {"returncode": 143, "healthz_signaled": True},
        )
        assert len(urlopen.calls) == 1  # probe-driven exit fires

    def test_wildcard_fires_on_every_kind(self) -> None:
        config = make_config_with_comms(notify_on_event=["*"])
        urlopen = StubUrlopen()
        dispatcher = CommsDispatcher(config, env={}, urlopen=urlopen)

        dispatcher.dispatch("child.spawn", {"cmd": ["x"], "cwd": None})
        dispatcher.dispatch(
            "child.exit", {"returncode": 0, "healthz_signaled": False}
        )
        dispatcher.dispatch(
            "max_attempts_reached", {"max_attempts": 1, "last_returncode": 1}
        )
        dispatcher.dispatch(
            "run.final_exit",
            {"returncode": 0, "restart_attempts": 0},
        )
        # 4 dispatches × 1 sink = 4 webhook calls
        assert len(urlopen.calls) == 4

    def test_static_kind_to_category_map_covers_known_kinds(self) -> None:
        # Sanity: the launcher emits these kinds; the map should cover
        # the ones that have categories. If a launcher kind is added
        # that needs a category, this test will start to look stale.
        assert EVENT_KIND_TO_NOTIFY_CATEGORY["restart.attempt"] == "restart"
        assert (
            EVENT_KIND_TO_NOTIFY_CATEGORY["max_attempts_reached"]
            == "max_attempts_reached"
        )

    def test_no_sinks_means_no_dispatches_even_with_wildcard(self) -> None:
        # If spec.comms is empty, the dispatcher would be None in
        # production. But if a caller constructs one manually with an
        # empty sinks list, dispatch should still be a no-op.
        # We construct via load_config which requires non-empty comms,
        # but the dispatcher's filter should still short-circuit.
        config = make_config_with_comms(notify_on_event=["*"])
        # Replace the comms to be empty by reaching into the
        # dataclass — necessary because load_config rejects a
        # CommsSpec with no url and we can't construct a "comms list
        # of zero" through the loader.
        from dataclasses import replace

        empty_spec = replace(config.spec, comms=())
        empty_config = ServiceConfig(
            apiVersion=config.apiVersion,
            kind=config.kind,
            metadata=config.metadata,
            spec=empty_spec,
        )
        urlopen = StubUrlopen()
        dispatcher = CommsDispatcher(
            empty_config, env={}, urlopen=urlopen
        )
        dispatcher.dispatch(
            "restart.attempt",
            {
                "attempt": 1,
                "delay_seconds": 1,
                "previous_returncode": 1,
                "backoff": "exponential",
            },
        )
        assert urlopen.calls == []


# ---------------------------------------------------------------------------
# CommsDispatcher — payload + headers
# ---------------------------------------------------------------------------


class TestDispatchPayload:
    def test_post_url_method_and_content_type(self) -> None:
        config = make_config_with_comms(notify_on_event=["restart"])
        urlopen = StubUrlopen()
        dispatcher = CommsDispatcher(config, env={}, urlopen=urlopen)
        dispatcher.dispatch(
            "restart.attempt",
            {
                "attempt": 1,
                "delay_seconds": 0,
                "previous_returncode": 1,
                "backoff": "constant",
            },
        )
        call = urlopen.calls[0]
        assert call["url"] == "https://hooks.example.com/recto"
        assert call["method"] == "POST"
        # urllib normalizes header names to title case.
        assert call["headers"].get("Content-type") == "application/json"

    def test_payload_carries_service_and_event_envelope(self) -> None:
        config = make_config_with_comms(notify_on_event=["restart"])
        urlopen = StubUrlopen()
        dispatcher = CommsDispatcher(config, env={}, urlopen=urlopen)
        dispatcher.dispatch(
            "restart.attempt",
            {
                "attempt": 2,
                "delay_seconds": 4,
                "previous_returncode": 1,
                "backoff": "exponential",
            },
        )
        body = json.loads(urlopen.calls[0]["data"].decode("utf-8"))
        assert body["service"]["name"] == "myservice"
        assert body["service"]["description"] == "Example service"
        assert body["event"]["kind"] == "restart.attempt"
        assert "summary" in body["event"]
        assert body["event"]["context"]["attempt"] == 2
        # context_json is the same dict serialized to a string.
        ctx_from_json = json.loads(body["event"]["context_json"])
        assert ctx_from_json["attempt"] == 2

    def test_template_subject_and_body_interpolated(self) -> None:
        config = make_config_with_comms(notify_on_event=["restart"])
        urlopen = StubUrlopen()
        dispatcher = CommsDispatcher(config, env={}, urlopen=urlopen)
        dispatcher.dispatch(
            "restart.attempt",
            {
                "attempt": 1,
                "delay_seconds": 1,
                "previous_returncode": 1,
                "backoff": "exponential",
            },
        )
        body = json.loads(urlopen.calls[0]["data"].decode("utf-8"))
        assert body["subject"] == "[recto/myservice] restart.attempt"
        # body comes from ${event.summary} which event_summary()
        # produces; just check the kind appears in it.
        assert "Restart attempt 1" in body["body"]

    def test_headers_interpolated_from_env(self) -> None:
        config = make_config_with_comms(notify_on_event=["restart"])
        urlopen = StubUrlopen()
        dispatcher = CommsDispatcher(
            config,
            env={"WEBHOOK_TOKEN": "secret-abc-123"},
            urlopen=urlopen,
        )
        dispatcher.dispatch(
            "restart.attempt",
            {
                "attempt": 1,
                "delay_seconds": 1,
                "previous_returncode": 1,
                "backoff": "exponential",
            },
        )
        headers = urlopen.calls[0]["headers"]
        # urllib lowercases the first letter of header names; check
        # both normalized forms.
        auth = headers.get("X-auth") or headers.get("X-Auth")
        assert auth == "secret-abc-123"

    def test_secret_value_does_not_appear_in_payload_body(self) -> None:
        # The dispatcher should put env-sourced auth tokens in headers
        # only — the body is the structured event, which never gets
        # ${env:VAR} interpolation by default unless the operator
        # explicitly templates it. We check that the body bytes don't
        # contain the secret value when it's only used in headers.
        config = make_config_with_comms(notify_on_event=["restart"])
        urlopen = StubUrlopen()
        dispatcher = CommsDispatcher(
            config,
            env={"WEBHOOK_TOKEN": "secret-abc-123"},
            urlopen=urlopen,
        )
        dispatcher.dispatch(
            "restart.attempt",
            {
                "attempt": 1,
                "delay_seconds": 1,
                "previous_returncode": 1,
                "backoff": "exponential",
            },
        )
        body_bytes = urlopen.calls[0]["data"]
        assert b"secret-abc-123" not in body_bytes

    def test_url_interpolation_works(self) -> None:
        # ${env:X} in the URL itself should also be substituted.
        config = make_config_with_comms(
            notify_on_event=["restart"],
            comms=[
                {
                    "type": "webhook",
                    "url": "https://${env:HOOK_HOST}/recto",
                    "headers": {},
                }
            ],
        )
        urlopen = StubUrlopen()
        dispatcher = CommsDispatcher(
            config, env={"HOOK_HOST": "hooks.example.com"}, urlopen=urlopen
        )
        dispatcher.dispatch(
            "restart.attempt",
            {
                "attempt": 1,
                "delay_seconds": 1,
                "previous_returncode": 1,
                "backoff": "exponential",
            },
        )
        assert urlopen.calls[0]["url"] == "https://hooks.example.com/recto"

    def test_multiple_sinks_each_receive_dispatch(self) -> None:
        config = make_config_with_comms(
            notify_on_event=["restart"],
            comms=[
                {"type": "webhook", "url": "https://a.example.com"},
                {"type": "webhook", "url": "https://b.example.com"},
            ],
        )
        urlopen = StubUrlopen()
        dispatcher = CommsDispatcher(config, env={}, urlopen=urlopen)
        dispatcher.dispatch(
            "restart.attempt",
            {
                "attempt": 1,
                "delay_seconds": 1,
                "previous_returncode": 1,
                "backoff": "exponential",
            },
        )
        urls = sorted(c["url"] for c in urlopen.calls)
        assert urls == ["https://a.example.com", "https://b.example.com"]


# ---------------------------------------------------------------------------
# CommsDispatcher — failure handling
# ---------------------------------------------------------------------------


class TestDispatchFailures:
    def test_http_error_does_not_propagate(self) -> None:
        config = make_config_with_comms(notify_on_event=["restart"])
        urlopen = StubUrlopen(
            raise_exc=urllib.error.HTTPError(
                url="https://hooks.example.com/recto",
                code=500,
                msg="Internal Error",
                hdrs=None,  # type: ignore[arg-type]
                fp=None,
            )
        )
        dispatcher = CommsDispatcher(config, env={}, urlopen=urlopen)
        # Must not raise.
        dispatcher.dispatch(
            "restart.attempt",
            {
                "attempt": 1,
                "delay_seconds": 1,
                "previous_returncode": 1,
                "backoff": "exponential",
            },
        )

    def test_url_error_does_not_propagate(self) -> None:
        config = make_config_with_comms(notify_on_event=["restart"])
        urlopen = StubUrlopen(
            raise_exc=urllib.error.URLError("Connection refused")
        )
        dispatcher = CommsDispatcher(config, env={}, urlopen=urlopen)
        dispatcher.dispatch(
            "restart.attempt",
            {
                "attempt": 1,
                "delay_seconds": 1,
                "previous_returncode": 1,
                "backoff": "exponential",
            },
        )

    def test_timeout_does_not_propagate(self) -> None:
        config = make_config_with_comms(notify_on_event=["restart"])
        urlopen = StubUrlopen(raise_exc=TimeoutError("timed out"))
        dispatcher = CommsDispatcher(config, env={}, urlopen=urlopen)
        dispatcher.dispatch(
            "restart.attempt",
            {
                "attempt": 1,
                "delay_seconds": 1,
                "previous_returncode": 1,
                "backoff": "exponential",
            },
        )

    def test_emit_failure_callback_invoked_on_http_error(self) -> None:
        config = make_config_with_comms(notify_on_event=["restart"])
        urlopen = StubUrlopen(
            raise_exc=urllib.error.HTTPError(
                url="https://hooks.example.com/recto",
                code=503,
                msg="Service Unavailable",
                hdrs=None,  # type: ignore[arg-type]
                fp=None,
            )
        )
        emitted: list[tuple[str, dict[str, Any]]] = []

        def emit(kind: str, ctx: dict[str, Any]) -> None:
            emitted.append((kind, dict(ctx)))

        dispatcher = CommsDispatcher(
            config, env={}, urlopen=urlopen, emit_failure=emit
        )
        dispatcher.dispatch(
            "restart.attempt",
            {
                "attempt": 1,
                "delay_seconds": 1,
                "previous_returncode": 1,
                "backoff": "exponential",
            },
        )
        assert len(emitted) == 1
        kind, ctx = emitted[0]
        assert kind == "comms.dispatch_failed"
        assert ctx["sink_url"] == "https://hooks.example.com/recto"
        assert ctx["event_kind"] == "restart.attempt"
        assert "503" in ctx["reason"]

    def test_one_failing_sink_does_not_block_other_sinks(self) -> None:
        config = make_config_with_comms(
            notify_on_event=["restart"],
            comms=[
                {"type": "webhook", "url": "https://broken.example.com"},
                {"type": "webhook", "url": "https://working.example.com"},
            ],
        )
        # Custom urlopen that fails for the first URL but succeeds for
        # subsequent ones.
        calls: list[str] = []

        def selective_urlopen(
            request: urllib.request.Request, timeout: float
        ) -> StubResponse:
            calls.append(request.full_url)
            if "broken" in request.full_url:
                raise urllib.error.URLError("nope")
            return StubResponse(200)

        dispatcher = CommsDispatcher(
            config, env={}, urlopen=selective_urlopen
        )
        dispatcher.dispatch(
            "restart.attempt",
            {
                "attempt": 1,
                "delay_seconds": 1,
                "previous_returncode": 1,
                "backoff": "exponential",
            },
        )
        # Both sinks were attempted; the working one should still
        # have been called even though the broken one raised.
        assert "https://broken.example.com" in calls
        assert "https://working.example.com" in calls

    def test_emit_failure_callback_failure_does_not_propagate(self) -> None:
        # If emit_failure itself raises (e.g., stdout closed during
        # shutdown), the dispatcher must still swallow.
        config = make_config_with_comms(notify_on_event=["restart"])
        urlopen = StubUrlopen(
            raise_exc=urllib.error.URLError("nope")
        )

        def broken_emit(kind: str, ctx: dict[str, Any]) -> None:
            raise RuntimeError("emit pipe broke")

        dispatcher = CommsDispatcher(
            config, env={}, urlopen=urlopen, emit_failure=broken_emit
        )
        # Must not raise.
        dispatcher.dispatch(
            "restart.attempt",
            {
                "attempt": 1,
                "delay_seconds": 1,
                "previous_returncode": 1,
                "backoff": "exponential",
            },
        )

    def test_timeout_value_is_passed_to_urlopen(self) -> None:
        config = make_config_with_comms(notify_on_event=["restart"])
        urlopen = StubUrlopen()
        dispatcher = CommsDispatcher(
            config, env={}, urlopen=urlopen, timeout_seconds=7.5
        )
        dispatcher.dispatch(
            "restart.attempt",
            {
                "attempt": 1,
                "delay_seconds": 1,
                "previous_returncode": 1,
                "backoff": "exponential",
            },
        )
        assert urlopen.calls[0]["timeout"] == pytest.approx(7.5)


# ---------------------------------------------------------------------------
# Standalone-mode failure logging
# ---------------------------------------------------------------------------


class TestStandaloneFailureLogging:
    def test_no_emit_failure_writes_to_stderr(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # When no emit_failure is provided, dispatch failures land on
        # stderr as a JSON line. Useful when CommsDispatcher is used
        # outside the launcher.
        config = make_config_with_comms(notify_on_event=["restart"])
        urlopen = StubUrlopen(
            raise_exc=urllib.error.URLError("nope")
        )
        dispatcher = CommsDispatcher(config, env={}, urlopen=urlopen)
        dispatcher.dispatch(
            "restart.attempt",
            {
                "attempt": 1,
                "delay_seconds": 1,
                "previous_returncode": 1,
                "backoff": "exponential",
            },
        )
        captured = capsys.readouterr()
        # Find the JSON log line on stderr.
        stderr_lines = [
            line for line in captured.err.splitlines() if line.strip()
        ]
        assert any("comms.dispatch_failed" in line for line in stderr_lines)
