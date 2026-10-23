"""Webhook event dispatch for Recto launcher events.

When the supervised child crashes, the healthz probe detects deadlock,
or the restart policy gives up, recto.comms posts a structured JSON
event to every webhook declared under spec.comms in the service.yaml.

Why we have this even though _emit_event already logs to stdout
---------------------------------------------------------------

The launcher's `_emit_event` writes JSON lines to stdout - captured by
NSSM's AppStdout / AppStderr or systemd's journal - for grep-ability
on the supervisor box. That's local visibility. recto.comms is the
remote-visibility layer: ops dashboards, Slack channels, PagerDuty,
or any other external tool gets the same event stream as a webhook
POST so cross-host orchestration sees crashes the moment they happen.

Both layers run side-by-side. _emit_event is unconditional and never
fails; CommsDispatcher.dispatch is best-effort and never raises out
of the launcher's main loop.

Event categories and the notify_on_event filter
-----------------------------------------------

ARCHITECTURE.md's `restart.notify_on_event` field (a list of category
strings) picks which events fire webhooks. The categories are
*coarser* than the launcher's internal event kinds - one category
can map to several emit kinds. For instance "restart" matches every
`restart.attempt`; "health_failure" matches `child.exit` ONLY when
the healthz probe drove the termination.

Categories supported in v0.1:

- "restart"               - fires on `restart.attempt`
- "health_failure"        - fires on `child.exit` when `healthz_signaled`
- "max_attempts_reached"  - fires on `max_attempts_reached`
- "secret_rotation"       - reserved for v0.2+; no kinds map yet
- "*"                     - fires on every emit kind (debugging escape hatch)

Kinds without a mapped category (`child.spawn`, `run.final_exit`,
`source.teardown_failed`, plus natural `child.exit` without
`healthz_signaled`) fire only when the operator includes "*" in the
filter.

Template interpolation
----------------------

`CommsSpec.url`, every value in `CommsSpec.headers`, and the
`subject`/`body`/`context` slots in `CommsSpec.template` all support
`${...}` substitution against three namespaces:

- ``${env:VAR}``        - read from the env mapping passed to the
                          dispatcher (typically the composed child env
                          including resolved secrets). Unknown vars are
                          left as the literal `${env:VAR}` so the
                          operator notices in the delivered payload.
- ``${service.NAME}``   - `service.name`, `service.description`.
- ``${event.NAME}``     - `event.kind`, `event.summary`,
                          `event.context_json`.

Failure handling
----------------

A webhook timeout, 4xx, 5xx, or network error is logged via stdout as
a `comms.dispatch_failed` JSON event AND through the Python logging
module, then swallowed. The launcher's main loop never sees the
failure. We deliberately do NOT retry; webhook delivery semantics are
at-most-once for v0.1. Operators who need at-least-once stand up a
queue between Recto and their alerting system.
"""

from __future__ import annotations

import json
import logging
import re
import sys
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from typing import Any

from recto.config import CommsSpec, ServiceConfig

__all__ = [
    "CommsDispatcher",
    "EVENT_KIND_TO_NOTIFY_CATEGORY",
    "WILDCARD_CATEGORY",
    "default_urlopen",
    "event_summary",
    "interpolate",
]

logger = logging.getLogger(__name__)


UrlOpener = Callable[[urllib.request.Request, float], Any]
"""urlopen-shaped callable: (request, timeout_seconds) -> response.
Tests inject a stub that records the request and returns a fake
response object; production uses urllib.request.urlopen directly."""


WILDCARD_CATEGORY = "*"
"""Wildcard entry in `notify_on_event` that matches every emit kind."""


EVENT_KIND_TO_NOTIFY_CATEGORY: dict[str, str] = {
    "restart.attempt": "restart",
    "max_attempts_reached": "max_attempts_reached",
    # `child.exit` is special-cased by `_kind_matches_categories` because
    # its category depends on whether the probe drove the termination.
    # `child.spawn`, `run.final_exit`, `source.teardown_failed`, and
    # natural `child.exit` only fire when the wildcard "*" is configured.
}
"""Static map from launcher emit `kind` strings to the coarser category
strings that appear in `RestartSpec.notify_on_event`. See module docstring."""


# Tokens like ${env:FOO}, ${service.name}, ${event.kind}. Only the
# limited grammar above is recognized - anything else (including bare
# ${FOO}) is left as a literal so misuse is visible.
_TOKEN_RE = re.compile(
    r"\$\{(env:[A-Za-z_][A-Za-z0-9_]*|service\.[A-Za-z_]+|event\.[A-Za-z_]+)\}"
)


def interpolate(
    template: str,
    *,
    env: Mapping[str, str],
    service: Mapping[str, str],
    event: Mapping[str, str],
) -> str:
    """Substitute ``${env:X}`` / ``${service.X}`` / ``${event.X}`` in *template*.

    Unknown tokens (token format recognized but key missing in the
    relevant mapping) are left as the literal token text so the operator
    sees them in delivered output rather than getting a silent empty
    string. Tokens that don't match the recognized grammar (e.g. bare
    ``${FOO}``) are not touched.

    Args:
        template: The string to interpolate.
        env: Source for ``${env:VAR}`` lookups (typically the composed
            child env including resolved secrets).
        service: Source for ``${service.NAME}`` lookups (`name`,
            `description`).
        event: Source for ``${event.NAME}`` lookups (`kind`, `summary`,
            `context_json`).

    Returns:
        The interpolated string.
    """

    def replace(match: re.Match[str]) -> str:
        token = match.group(1)
        if token.startswith("env:"):
            key = token[len("env:") :]
            return env.get(key, match.group(0))
        if token.startswith("service."):
            key = token[len("service.") :]
            return service.get(key, match.group(0))
        if token.startswith("event."):
            key = token[len("event.") :]
            return event.get(key, match.group(0))
        return match.group(0)

    return _TOKEN_RE.sub(replace, template)


def event_summary(kind: str, ctx: Mapping[str, Any]) -> str:
    """Render a one-line human-readable summary of a launcher event.

    The summary is what `${event.summary}` interpolates to, so it ends
    up in the delivered webhook payload (and any Slack/Discord/etc.
    message body the operator templates). Keep it short and concrete -
    a human glancing at a notification should know what happened.

    Unknown kinds get a generic fallback that includes the kind so a
    new event added in a later version still produces something useful
    until the summary table is updated.
    """
    if kind == "child.spawn":
        cmd = ctx.get("cmd")
        if isinstance(cmd, list) and cmd:
            return f"Service started: {' '.join(str(p) for p in cmd)}"
        return "Service started"
    if kind == "child.exit":
        rc = ctx.get("returncode")
        if ctx.get("healthz_signaled"):
            return f"Service terminated by healthz probe (exit code {rc})"
        return f"Service exited (code {rc})"
    if kind == "restart.attempt":
        n = ctx.get("attempt")
        delay = ctx.get("delay_seconds")
        prev = ctx.get("previous_returncode")
        return (
            f"Restart attempt {n} after {delay}s "
            f"(previous exit code {prev})"
        )
    if kind == "max_attempts_reached":
        m = ctx.get("max_attempts")
        last = ctx.get("last_returncode")
        return (
            f"Restart limit reached ({m} attempts); giving up. "
            f"Last exit code {last}."
        )
    if kind == "run.final_exit":
        rc = ctx.get("returncode")
        attempts = ctx.get("restart_attempts")
        return f"Service stopped (exit code {rc}) after {attempts} restart attempt(s)"
    if kind == "source.teardown_failed":
        src = ctx.get("source")
        err = ctx.get("error")
        return f"Secret source {src!r} teardown raised {err}"
    return f"Event: {kind}"


def default_urlopen(req: urllib.request.Request, timeout: float) -> Any:
    """Default urlopen-shaped callable used by CommsDispatcher.

    Wraps `urllib.request.urlopen` with the timeout argument exposed as
    a positional parameter so the UrlOpener Protocol is satisfied
    cleanly. The response object is returned as-is - callers can read
    `.status` if they care, but CommsDispatcher only checks for raised
    exceptions.
    """
    return urllib.request.urlopen(req, timeout=timeout)  # noqa: S310 - URL is operator-controlled


class CommsDispatcher:
    """Dispatch launcher events to webhooks declared in `spec.comms`.

    Construction is cheap; the dispatcher holds the validated config,
    a snapshot of the env (used for ``${env:VAR}`` interpolation), the
    urlopen factory, and per-call options. Tests inject a stub urlopen
    and read what the dispatcher would have sent.

    Thread-safety: not safe for concurrent dispatch from multiple
    threads. The v0.1 launcher only emits from the main thread, so this
    matches reality. v0.2+ probes that emit their own events will need
    a serializing wrapper or a queue.
    """

    def __init__(
        self,
        config: ServiceConfig,
        *,
        env: Mapping[str, str],
        urlopen: UrlOpener = default_urlopen,
        timeout_seconds: float = 3.0,
        emit_failure: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> None:
        """Build a dispatcher.

        Args:
            config: Validated ServiceConfig. The dispatcher reads
                `metadata.{name,description}`, `spec.comms`, and
                `spec.restart.notify_on_event`.
            env: Mapping for ``${env:VAR}`` interpolation. In production
                this is the composed child env (so resolved secrets are
                available to header interpolation); in tests it's a
                literal dict.
            urlopen: urllib.request.urlopen-shaped callable. Tests pass
                a stub that records requests.
            timeout_seconds: Per-request timeout. Each sink gets up to
                `timeout_seconds` to respond before being treated as a
                failure. Slow webhooks add their timeout to the
                latency between launcher events; default 3.0s is a
                trade-off between giving slow services a chance and
                not blocking restart decisions.
            emit_failure: Optional callable invoked when a webhook
                dispatch fails. Receives `(kind, ctx)` matching the
                launcher's `_emit_event` signature so the failure can
                appear in the same JSON stdout stream. The callable
                MUST NOT recursively dispatch (otherwise a flapping
                webhook produces an infinite emit loop). The launcher
                provides a closure that calls `_emit_event` without a
                dispatcher.
        """
        self.config = config
        self.env = env
        self.urlopen = urlopen
        self.timeout_seconds = timeout_seconds
        self.emit_failure = emit_failure
        self._categories: frozenset[str] = frozenset(
            config.spec.restart.notify_on_event
        )
        self._wildcard: bool = WILDCARD_CATEGORY in self._categories
        self._service: dict[str, str] = {
            "name": config.metadata.name,
            "description": config.metadata.description,
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def dispatch(self, kind: str, ctx: Mapping[str, Any]) -> None:
        """POST a JSON event to every sink whose category matches `kind`.

        Filtering happens via `_kind_matches_categories` before any
        network I/O - sinks only see events that pass the category
        filter. Each sink is dispatched independently; one slow or
        broken sink doesn't stop the others. All exceptions are
        swallowed (and surfaced via `emit_failure` if provided) so the
        launcher's main loop never sees a webhook error.
        """
        if not self._kind_matches_categories(kind, ctx):
            return
        if not self.config.spec.comms:
            return
        ctx_dict = dict(ctx)
        event_view = {
            "kind": kind,
            "summary": event_summary(kind, ctx_dict),
            "context_json": json.dumps(ctx_dict, default=str),
        }
        for sink in self.config.spec.comms:
            self._post_one(sink, kind, ctx_dict, event_view)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _kind_matches_categories(
        self, kind: str, ctx: Mapping[str, Any]
    ) -> bool:
        """Return True iff `kind` should fire a dispatch under the current
        `notify_on_event` filter.

        The wildcard ``"*"`` short-circuits to True. Otherwise the kind
        is mapped to a category; `child.exit` is special-cased because
        it only counts as `health_failure` when the probe drove the
        termination.
        """
        if self._wildcard:
            return True
        if kind == "child.exit":
            if ctx.get("healthz_signaled"):
                return "health_failure" in self._categories
            return False
        category = EVENT_KIND_TO_NOTIFY_CATEGORY.get(kind)
        if category is None:
            return False
        return category in self._categories

    def _post_one(
        self,
        sink: CommsSpec,
        kind: str,
        ctx: dict[str, Any],
        event_view: dict[str, str],
    ) -> None:
        """Build the request for one sink and send it.

        Failures are logged (via `emit_failure` and Python logging) and
        swallowed; this method never raises out.
        """
        try:
            url = interpolate(
                sink.url, env=self.env, service=self._service, event=event_view
            )
            headers = {
                interpolate(
                    k, env=self.env, service=self._service, event=event_view
                ): interpolate(
                    v, env=self.env, service=self._service, event=event_view
                )
                for k, v in sink.headers.items()
            }
            payload = self._build_payload(sink, ctx, event_view)
            body = json.dumps(payload, default=str).encode("utf-8")
            request_headers = {
                "Content-Type": "application/json",
                "User-Agent": "recto/0.1",
                **headers,
            }
            req = urllib.request.Request(
                url, data=body, headers=request_headers, method="POST"
            )
        except Exception as exc:  # noqa: BLE001 - never raise out
            self._record_failure(sink, kind, "build_request", exc)
            return

        try:
            self.urlopen(req, self.timeout_seconds)
        except urllib.error.HTTPError as exc:
            self._record_failure(sink, kind, f"http_{exc.code}", exc)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            self._record_failure(sink, kind, "transport", exc)
        except Exception as exc:  # noqa: BLE001 - final safety net
            self._record_failure(sink, kind, "unexpected", exc)

    def _build_payload(
        self,
        sink: CommsSpec,
        ctx: dict[str, Any],
        event_view: dict[str, str],
    ) -> dict[str, Any]:
        """Compose the JSON body posted to one webhook.

        Every payload carries the structured `service` + `event`
        envelope (so automation can pattern-match on `event.kind`
        regardless of what the user templated). Whatever the user
        declared in `spec.comms[].template` - typically `subject`,
        `body`, `context` - is interpolated and added at the top
        level so Slack/Discord/etc. consumers can pull a single
        rendered field.
        """
        payload: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),  # noqa: UP017
            "service": dict(self._service),
            "event": {
                "kind": event_view["kind"],
                "summary": event_view["summary"],
                "context": ctx,
                "context_json": event_view["context_json"],
            },
        }
        for slot, raw in sink.template.items():
            payload[str(slot)] = interpolate(
                str(raw),
                env=self.env,
                service=self._service,
                event=event_view,
            )
        return payload

    def _record_failure(
        self,
        sink: CommsSpec,
        kind: str,
        reason: str,
        exc: BaseException,
    ) -> None:
        """Log a dispatch failure via Python logging AND `emit_failure`.

        The failure path must be airtight: a logging-side failure must
        not crash the launcher. We swallow secondary failures here.
        """
        ctx = {
            "sink_url": sink.url,
            "event_kind": kind,
            "reason": reason,
            "error_type": type(exc).__name__,
            "error_message": str(exc),
        }
        try:
            logger.warning(
                "comms dispatch failed: kind=%s reason=%s sink=%s error=%s",
                kind,
                reason,
                sink.url,
                exc,
            )
        except Exception:  # noqa: BLE001 - best-effort logging
            pass
        if self.emit_failure is not None:
            try:
                self.emit_failure("comms.dispatch_failed", ctx)
            except Exception:  # noqa: BLE001 - never raise out
                pass
        # Last-ditch JSON line so the failure is visible even if
        # emit_failure was None (e.g., dispatcher used standalone in
        # tests / scripts).
        elif self.emit_failure is None:
            try:
                line = json.dumps(
                    {
                        "ts": datetime.now(timezone.utc).isoformat(  # noqa: UP017
                            timespec="seconds"
                        ),
                        "service": self._service["name"],
                        "kind": "comms.dispatch_failed",
                        "ctx": ctx,
                    },
                    default=str,
                )
                print(line, file=sys.stderr, flush=True)
            except Exception:  # noqa: BLE001
                pass
