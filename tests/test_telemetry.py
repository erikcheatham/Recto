"""Tests for recto.telemetry.

Strategy:
- Disabled spec is a full no-op (verified by checking is_active + that
  every public method completes without invoking any tracer).
- Enabled spec on a host without opentelemetry installed falls back to
  no-op + emits a single warning. We can verify the fallback shape but
  the warning-once-only assertion needs care because tests run in a
  shared module state (the _WARNED_DEPS_MISSING flag).
- The active path is exercised via a FakeTelemetryClient subclass that
  overrides _build_tracer to return a fake-tracer recorder. Mirrors the
  CredManSource / FakeCredManSource pattern.
- coerce_attribute_value is pure; tested directly.
"""

from __future__ import annotations

from typing import Any

import pytest

from recto.config import TelemetrySpec
from recto.telemetry import TelemetryClient, coerce_attribute_value


# ---------------------------------------------------------------------------
# coerce_attribute_value
# ---------------------------------------------------------------------------


class TestCoerceAttributeValue:
    def test_none_becomes_string(self) -> None:
        assert coerce_attribute_value(None) == "<none>"

    def test_str_passes_through(self) -> None:
        assert coerce_attribute_value("hello") == "hello"

    def test_bool_passes_through(self) -> None:
        assert coerce_attribute_value(True) is True
        assert coerce_attribute_value(False) is False

    def test_int_passes_through(self) -> None:
        assert coerce_attribute_value(42) == 42

    def test_float_passes_through(self) -> None:
        assert coerce_attribute_value(3.14) == 3.14

    def test_list_of_primitives_passes_through(self) -> None:
        assert coerce_attribute_value(["a", "b", "c"]) == ["a", "b", "c"]
        assert coerce_attribute_value([1, 2, 3]) == [1, 2, 3]

    def test_list_with_none_coerces_inner(self) -> None:
        # None inside a list becomes its repr (string "None"), since
        # OTel sequences must be homogeneous-ish.
        result = coerce_attribute_value([1, None, "a"])
        assert result == [1, "None", "a"]

    def test_tuple_treated_as_list(self) -> None:
        assert coerce_attribute_value(("a", "b")) == ["a", "b"]

    def test_dict_serializes_as_json_string(self) -> None:
        result = coerce_attribute_value({"k": "v", "n": 42})
        # Order may vary, but it should be a JSON-decodable string.
        import json
        assert json.loads(result) == {"k": "v", "n": 42}

    def test_arbitrary_object_uses_repr(self) -> None:
        class Foo:
            def __repr__(self) -> str:
                return "Foo()"

        assert coerce_attribute_value(Foo()) == "Foo()"


# ---------------------------------------------------------------------------
# Disabled spec -> full no-op
# ---------------------------------------------------------------------------


class TestDisabledIsNoop:
    def test_constructor_is_inactive(self) -> None:
        client = TelemetryClient(TelemetrySpec(enabled=False))
        assert client.is_active is False

    def test_all_methods_safe_to_call(self) -> None:
        # Every public method must be callable without error on a no-op
        # client. The launcher relies on this -- it always calls
        # start_run / record_event / end_run regardless of whether
        # telemetry is enabled.
        client = TelemetryClient(TelemetrySpec(enabled=False))
        client.start_run("myservice")
        client.record_event("child.spawn", {"cmd": ["python.exe"]})
        client.end_run(0)
        client.shutdown()

    def test_default_telemetry_spec_is_disabled(self) -> None:
        # The whole point of the no-op shell: the default
        # TelemetrySpec() has enabled=False so legacy services without
        # any telemetry config keep working without OTel deps.
        client = TelemetryClient(TelemetrySpec())
        assert client.is_active is False


# ---------------------------------------------------------------------------
# Enabled spec without OTel deps -> warn-once + fallback to no-op
# ---------------------------------------------------------------------------


class TestEnabledWithoutDepsFallsBack:
    def test_enabled_without_deps_is_inactive(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # The Linux test env doesn't have opentelemetry installed (we
        # don't add it as a hard dep). Constructing an enabled client
        # should fall back to no-op rather than raising.
        client = TelemetryClient(
            TelemetrySpec(enabled=True, otlp_endpoint="http://localhost:4318")
        )
        assert client.is_active is False
        # And every public method must still be safe to call.
        client.start_run("myservice")
        client.record_event("k", {})
        client.end_run(0)
        client.shutdown()


# ---------------------------------------------------------------------------
# Active path via the _build_tracer test seam
# ---------------------------------------------------------------------------


class _FakeSpan:
    """Minimal Span-shaped recorder for the active-path tests."""

    def __init__(self) -> None:
        self.attributes: dict[str, Any] = {}
        self.events: list[tuple[str, dict[str, Any]]] = []
        self.ended = False

    def set_attribute(self, key: str, value: Any) -> None:
        self.attributes[key] = value

    def add_event(
        self, name: str, attributes: dict[str, Any] | None = None
    ) -> None:
        self.events.append((name, attributes or {}))

    def end(self) -> None:
        self.ended = True


class _FakeTracer:
    def __init__(self) -> None:
        self.spans: list[_FakeSpan] = []
        self.start_span_calls: list[tuple[str, dict[str, Any] | None]] = []

    def start_span(
        self, name: str, attributes: dict[str, Any] | None = None
    ) -> _FakeSpan:
        self.start_span_calls.append((name, attributes))
        span = _FakeSpan()
        if attributes:
            span.attributes.update(attributes)
        self.spans.append(span)
        return span


class FakeTelemetryClient(TelemetryClient):
    """Override _build_tracer so we don't need real opentelemetry.

    The launcher integration test in tests/test_launcher.py uses a
    different stub (a duck-typed object) because it doesn't care about
    the TelemetryClient internals. This subclass is for verifying the
    TelemetryClient class itself.
    """

    def __init__(self, spec: TelemetrySpec) -> None:
        self.fake_tracer = _FakeTracer()
        super().__init__(spec)

    def _build_tracer(self) -> Any:
        return self.fake_tracer


class TestActivePath:
    def test_active_when_tracer_built(self) -> None:
        client = FakeTelemetryClient(TelemetrySpec(enabled=True))
        assert client.is_active is True

    def test_start_run_creates_span_with_service_name(self) -> None:
        client = FakeTelemetryClient(TelemetrySpec(enabled=True))
        client.start_run("myservice")
        # One span started, named recto.run.<service>.
        assert len(client.fake_tracer.start_span_calls) == 1
        name, attrs = client.fake_tracer.start_span_calls[0]
        assert name == "recto.run.myservice"
        assert attrs == {"service.name": "myservice"}

    def test_start_run_with_attributes(self) -> None:
        client = FakeTelemetryClient(TelemetrySpec(enabled=True))
        client.start_run(
            "myservice",
            attributes={
                "recto.healthz.type": "http",
                "recto.restart.policy": "always",
            },
        )
        _, attrs = client.fake_tracer.start_span_calls[0]
        assert attrs["service.name"] == "myservice"
        assert attrs["recto.healthz.type"] == "http"
        assert attrs["recto.restart.policy"] == "always"

    def test_record_event_adds_event_to_span(self) -> None:
        client = FakeTelemetryClient(TelemetrySpec(enabled=True))
        client.start_run("myservice")
        client.record_event(
            "child.spawn", {"cmd": ["python.exe"], "cwd": "/tmp"}
        )
        span = client.fake_tracer.spans[0]
        assert len(span.events) == 1
        kind, attrs = span.events[0]
        assert kind == "child.spawn"
        assert attrs["cmd"] == ["python.exe"]
        assert attrs["cwd"] == "/tmp"

    def test_record_event_coerces_none(self) -> None:
        client = FakeTelemetryClient(TelemetrySpec(enabled=True))
        client.start_run("myservice")
        client.record_event("child.spawn", {"cwd": None})
        span = client.fake_tracer.spans[0]
        # cwd=None should be coerced to "<none>" so OTel doesn't choke.
        assert span.events[0][1]["cwd"] == "<none>"

    def test_record_event_before_start_is_noop(self) -> None:
        client = FakeTelemetryClient(TelemetrySpec(enabled=True))
        # No start_run -- record_event should silently do nothing.
        client.record_event("child.spawn", {"cmd": ["x"]})
        # No spans should exist.
        assert client.fake_tracer.spans == []

    def test_end_run_sets_returncode_and_ends_span(self) -> None:
        client = FakeTelemetryClient(TelemetrySpec(enabled=True))
        client.start_run("myservice")
        client.end_run(returncode=7)
        span = client.fake_tracer.spans[0]
        assert span.attributes["recto.returncode"] == 7
        assert span.ended is True

    def test_end_run_idempotent(self) -> None:
        client = FakeTelemetryClient(TelemetrySpec(enabled=True))
        client.start_run("myservice")
        client.end_run(0)
        # Second call must be safe -- the launcher's finally block may
        # call end_run after the bracket already ran it once.
        client.end_run(99)
        # Span ended once; second call doesn't re-end.
        span = client.fake_tracer.spans[0]
        assert span.ended is True
        # Returncode should be from the FIRST call (0), not 99.
        assert span.attributes["recto.returncode"] == 0

    def test_double_start_run_is_noop_on_second_call(self) -> None:
        client = FakeTelemetryClient(TelemetrySpec(enabled=True))
        client.start_run("myservice")
        client.start_run("otherservice")
        # Only one span should have been created.
        assert len(client.fake_tracer.start_span_calls) == 1


# ---------------------------------------------------------------------------
# Public methods swallow exceptions so they never break the launcher
# ---------------------------------------------------------------------------


class _ExplodingTracer:
    """Tracer whose every method raises -- defense-in-depth test."""

    def start_span(self, *_a: Any, **_kw: Any) -> Any:
        raise RuntimeError("OTel exploded")


class _ExplodingTelemetryClient(TelemetryClient):
    def _build_tracer(self) -> Any:
        return _ExplodingTracer()


class TestFailureIsolation:
    def test_start_run_swallows_tracer_failure(self) -> None:
        # If the tracer itself raises (network outage, mis-configured
        # endpoint, etc.), TelemetryClient must absorb it -- the
        # launcher must NEVER fail because telemetry failed.
        client = _ExplodingTelemetryClient(TelemetrySpec(enabled=True))
        # is_active is True (we built the tracer), but start_run will
        # fail internally and quietly leave _span as None.
        client.start_run("myservice")
        # And subsequent calls must remain safe.
        client.record_event("k", {})
        client.end_run(0)
