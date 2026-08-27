"""OpenTelemetry traces for launcher lifecycle events.

When ``spec.telemetry.enabled: true`` and the OpenTelemetry packages
are installed, every launcher lifecycle event becomes a recorded event
on a long-lived per-``run()`` span. Sinks to a configurable OTLP HTTP
endpoint (Jaeger, Tempo, Datadog, Honeycomb, anything that speaks
OTLP/HTTP).

When ``telemetry.enabled: false`` (the default), this module is a
no-op shell -- zero overhead, no imports of the heavy OTel tree. When
``enabled: true`` but the OTel packages are not installed,
``TelemetryClient`` falls back to no-op and emits a single warning to
stdout so the operator knows to ``pip install recto[otel]``.

Why optional dependency
-----------------------

OpenTelemetry's Python tree is ~10 transitive packages (api, sdk,
exporter, proto, etc.). Hard rule from CLAUDE.md is that the launcher
path must run from a default ``pip install recto`` with no extra
ceremony. The OTel deps are gated behind the ``[otel]`` extra so
operators who want traces opt in explicitly:

    pip install recto[otel]

Span shape
----------

One span per ``run()`` invocation:

    Span name:   recto.run.<service-name>
    Span kind:   INTERNAL
    Attributes:
        service.name = <metadata.name>
        recto.healthz.type = <spec.healthz.type>
        recto.restart.policy = <spec.restart.policy>
        recto.returncode = <final exit code>  (set on end)
    Events:
        child.spawn          attrs: cmd, cwd, secrets_injected (names only)
        child.exit           attrs: returncode, healthz_signaled
        restart.attempt      attrs: attempt, delay_seconds, previous_returncode
        max_attempts_reached attrs: max_attempts, last_returncode
        run.final_exit       attrs: returncode, restart_attempts
        source.teardown_failed   attrs: source, error

Each event's timestamp is preserved so a downstream trace UI shows
the full timeline of a service's run.

Test seam
---------

``TelemetryClient._build_tracer()`` is the only ctypes-equivalent --
it imports OpenTelemetry and constructs the SDK pipeline. Tests
override this method on a subclass to record what would have been
spanned without invoking the real OTel libraries.
"""

from __future__ import annotations

import sys
from typing import Any

from recto.config import TelemetrySpec

__all__ = [
    "TelemetryClient",
    "coerce_attribute_value",
]


# Sentinel: warning fired exactly once per process so a long-running
# launcher doesn't spam stdout when OTel deps aren't installed.
_WARNED_DEPS_MISSING = False


def coerce_attribute_value(value: Any) -> Any:
    """Convert a Python value into something OpenTelemetry accepts.

    OTel attribute values must be one of: str, bool, int, float, or a
    sequence of one of those. Lists of strings stay as lists; dicts
    get JSON-serialized (or repr'd if non-serializable) into a single
    string. None becomes the string ``"<none>"`` (OTel doesn't accept
    None natively).

    Tests cover the conversion paths directly so the launcher integration
    can rely on it.
    """
    if value is None:
        return "<none>"
    if isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, (list, tuple)):
        # Must be a homogeneous sequence of OTel-acceptable primitives.
        # Coerce each element; if any is non-trivial, fall back to repr.
        coerced: list[Any] = []
        for item in value:
            if isinstance(item, (str, bool, int, float)):
                coerced.append(item)
            else:
                coerced.append(repr(item))
        return coerced
    if isinstance(value, dict):
        # OTel doesn't take dicts; serialize to JSON for legibility.
        try:
            import json

            return json.dumps(value, default=str)
        except (TypeError, ValueError):
            return repr(value)
    # Last resort: stringify whatever it is.
    return repr(value)


def _coerce_ctx(ctx: dict[str, Any]) -> dict[str, Any]:
    """Apply ``coerce_attribute_value`` to every value in ``ctx``."""
    return {k: coerce_attribute_value(v) for k, v in ctx.items()}


class TelemetryClient:
    """Wrapper around the OpenTelemetry tracer for launcher events.

    Lifecycle:
        client = TelemetryClient(config.spec.telemetry)
        client.start_run(service_name="myservice")
        client.record_event("child.spawn", {"cmd": [...], "cwd": "..."})
        ... more events ...
        client.end_run(returncode=0)

    No-op when ``spec.enabled`` is False, when the OTel packages are
    not installed, or when the SDK init raises (network failure
    talking to OTLP, etc.). The client never raises out of its public
    methods -- a failed telemetry call must never break the launcher.
    """

    def __init__(self, spec: TelemetrySpec):
        self.spec = spec
        self._tracer: Any | None = None
        self._span: Any | None = None
        self._provider: Any | None = None
        if spec.enabled:
            self._tracer = self._build_tracer()

    @property
    def is_active(self) -> bool:
        """True if the underlying tracer was successfully built.

        Tests check this to confirm the no-op vs active distinction.
        """
        return self._tracer is not None

    def start_run(self, service_name: str, *, attributes: dict[str, Any] | None = None) -> None:
        """Open a span for this run() invocation.

        Idempotent on repeated calls -- if a span is already open,
        this does nothing. (Shouldn't happen in practice; defensive.)
        """
        if self._tracer is None:
            return
        if self._span is not None:
            return
        try:
            attrs = {"service.name": service_name}
            if attributes:
                attrs.update(_coerce_ctx(attributes))
            self._span = self._tracer.start_span(
                f"recto.run.{service_name}", attributes=attrs
            )
        except Exception:  # noqa: BLE001 -- never break the launcher
            self._span = None

    def record_event(self, kind: str, ctx: dict[str, Any]) -> None:
        """Record a lifecycle event on the active span.

        No-op if no span is open or if the OTel call raises.
        """
        if self._span is None:
            return
        try:
            self._span.add_event(kind, attributes=_coerce_ctx(ctx))
        except Exception:  # noqa: BLE001
            return

    def end_run(self, returncode: int) -> None:
        """Close the run span. Sets ``recto.returncode`` as an attribute.

        Idempotent: calling end_run twice (e.g. once explicitly, once
        via __del__) is a no-op the second time.
        """
        if self._span is None:
            return
        try:
            self._span.set_attribute("recto.returncode", returncode)
            self._span.end()
        except Exception:  # noqa: BLE001
            pass
        finally:
            self._span = None

    def shutdown(self) -> None:
        """Flush and shut down the OTel SDK provider.

        Called by the launcher after the run completes so any pending
        spans get pushed to the exporter before the process exits.
        Idempotent.
        """
        if self._provider is None:
            return
        try:
            self._provider.shutdown()
        except Exception:  # noqa: BLE001
            pass
        finally:
            self._provider = None

    # ------------------------------------------------------------------
    # Test seam: subclasses override this to inject a fake tracer.
    # ------------------------------------------------------------------

    def _build_tracer(self) -> Any | None:
        """Construct the OpenTelemetry tracer pipeline.

        Returns the tracer or None on any failure (missing deps,
        bad OTLP endpoint config, etc.). Failures are logged once
        per process via a warning to stdout so the operator knows
        telemetry isn't actually flowing.
        """
        global _WARNED_DEPS_MISSING
        try:
            from opentelemetry import trace
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                OTLPSpanExporter,
            )
            from opentelemetry.sdk.resources import Resource
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import BatchSpanProcessor
        except ImportError:
            if not _WARNED_DEPS_MISSING:
                _WARNED_DEPS_MISSING = True
                print(
                    "recto.telemetry: telemetry.enabled=true but the "
                    "opentelemetry packages are not installed. Falling "
                    "back to no-op. Install with: "
                    "pip install recto[otel]",
                    file=sys.stderr,
                )
            return None

        # The OTel-SDK-installed path below only executes when the
        # opentelemetry packages are available. The cross-platform Linux
        # test suite doesn't install them by default (they're an
        # optional `[otel]` extra), so `# pragma: no cover` is honest
        # here. Operators who turn on telemetry exercise this path
        # directly; the FakeTelemetryClient + ExplodingTracer tests
        # cover the higher-level lifecycle wiring without needing OTel.
        try:  # pragma: no cover
            resource = Resource.create({
                "service.name": self.spec.service_name or "recto",
            })
            provider = TracerProvider(resource=resource)
            # OTLP HTTP traces endpoint convention: <base>/v1/traces.
            # If the operator passes the full URL we use it as-is;
            # if they pass just the base, we append /v1/traces.
            endpoint = self.spec.otlp_endpoint
            if endpoint and not endpoint.rstrip("/").endswith("/v1/traces"):
                endpoint = endpoint.rstrip("/") + "/v1/traces"
            exporter = OTLPSpanExporter(endpoint=endpoint or None)
            provider.add_span_processor(BatchSpanProcessor(exporter))
            self._provider = provider
            return provider.get_tracer("recto.launcher")
        except Exception as exc:  # noqa: BLE001  # pragma: no cover
            print(
                f"recto.telemetry: failed to set up OTLP tracer "
                f"({type(exc).__name__}: {exc}). Falling back to no-op.",
                file=sys.stderr,
            )
            return None
