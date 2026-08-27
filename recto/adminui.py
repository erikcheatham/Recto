"""Read-only web admin UI for the running launcher (v0.2 scaffold).

Bound by default to ``127.0.0.1:5050``. Operators expose externally
via Cloudflare Tunnel + Cloudflare Access (or Caddy + basic auth, or
nginx + mTLS, or any reverse-proxy gating they bring). Recto itself
trusts every connection that reaches it; the auth layer is the
proxy's job.

What v0.2 ships
---------------

Three read-only JSON endpoints + a static HTML index that polls them:

    GET /                       HTML index page (single-file, embedded).
    GET /api/status             current service state (name, last
                                returncode, span of last spawn,
                                uptime, healthz/restart shape).
    GET /api/events             last N lifecycle events from the
                                in-memory ring buffer. Optional
                                query: ?kind=child.spawn&limit=50.
    GET /api/restart-history    pre-filtered events of kind
                                child.exit / restart.attempt /
                                max_attempts_reached / run.final_exit.

Deferred to a follow-up:

- POST /api/secrets/<name>/rotate (write op, needs careful auth).
- GET /api/config (needs secret-redaction pass on the YAML render).
- GET /api/secrets (names-only inventory; needs CredManSource access).
- Server-Sent Events for live tail (vs the current poll-and-refresh).

Hard rules in this module
-------------------------

- stdlib HTTP only (``http.server.ThreadingHTTPServer`` +
  ``BaseHTTPRequestHandler``). No Flask/FastAPI/Starlette. Per CLAUDE.md
  hard rule: the launcher path runs from a default ``pip install
  recto`` with no extra ceremony.
- Soft-fail on bind. If port 5050 is taken or bind raises, log a
  warning and skip the admin UI -- the supervised child must keep
  running.
- Secrets never appear in any /api response. The EventBuffer stores
  ctx dicts that already passed through ``_emit_event``'s no-secrets
  contract; if a future event ever carried a secret, that's the
  caller's bug, not ours.
- Daemon thread. The server thread is daemon=True so the launcher
  process exits cleanly even if the server hasn't fully shut down.
"""

from __future__ import annotations

import json
import threading
import time
from collections import deque
from collections.abc import Iterable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from recto.config import AdminUISpec

__all__ = [
    "AdminUIServer",
    "EventBuffer",
    "INDEX_HTML",
]


# ---------------------------------------------------------------------------
# EventBuffer: thread-safe ring of recent (kind, ctx, ts) events
# ---------------------------------------------------------------------------


class EventBuffer:
    """Thread-safe ring buffer of recent launcher events.

    The launcher's ``_emit_event`` appends here; the HTTP handler reads.
    Capacity defaults to 1000 -- enough for hours of normal operation,
    cheap to keep in memory, oldest events get dropped first.

    Events are stored as ``{"kind": str, "ts": float, "ctx": dict}``.
    The timestamp is recorded by EventBuffer.append (not by the caller)
    so the ordering is canonical even when multiple threads emit.
    """

    def __init__(self, capacity: int = 1000) -> None:
        self._buf: deque[dict[str, Any]] = deque(maxlen=capacity)
        self._lock = threading.Lock()
        self._start_time = time.time()

    @property
    def start_time(self) -> float:
        """Wall-clock timestamp of when this buffer was constructed.

        Used by /api/status to report launcher uptime.
        """
        return self._start_time

    def append(self, kind: str, ctx: dict[str, Any]) -> None:
        """Record one event. Thread-safe."""
        record = {"kind": kind, "ts": time.time(), "ctx": dict(ctx)}
        with self._lock:
            self._buf.append(record)

    def recent(
        self,
        *,
        limit: int | None = None,
        kinds: Iterable[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Return up to ``limit`` most-recent events, optionally filtered.

        Returned in chronological order (oldest first). When ``kinds``
        is supplied, only events whose ``kind`` is in that set come
        back. The lock is held briefly to snapshot the deque, then
        released before filtering -- minimizes contention with the
        producer thread.
        """
        with self._lock:
            snapshot = list(self._buf)
        if kinds is not None:
            kind_set = set(kinds)
            snapshot = [r for r in snapshot if r["kind"] in kind_set]
        if limit is not None and len(snapshot) > limit:
            snapshot = snapshot[-limit:]
        return snapshot

    def __len__(self) -> int:
        with self._lock:
            return len(self._buf)

    # ------------------------------------------------------------------
    # Derived state -- snapshots over the event stream for /api/status.
    # All four are O(n) in buffer size with default cap = 1000, so cheap
    # enough to compute on every status poll. The producer-side append
    # path stays unchanged.
    # ------------------------------------------------------------------

    def derived_state(self) -> dict[str, Any]:
        """Compute the four /api/status fields from the event stream.

        - restart_count: number of `child.exit` events.
        - last_spawn_ts: ts of the most recent `child.spawn`, or None.
        - last_exit_returncode: ctx.returncode of the most recent
          `child.exit`, or None.
        - last_healthz_signaled_ts: ts of the most recent `child.exit`
          where ctx.healthz_signaled is true, or None. Lets the
          status tab spot a service that's been flapping on probe
          failures specifically.
        """
        with self._lock:
            snapshot = list(self._buf)
        restart_count = 0
        last_spawn_ts: float | None = None
        last_exit_returncode: int | None = None
        last_healthz_signaled_ts: float | None = None
        for record in snapshot:
            kind = record["kind"]
            ctx = record["ctx"]
            ts = record["ts"]
            if kind == "child.spawn":
                last_spawn_ts = ts
            elif kind == "child.exit":
                restart_count += 1
                last_exit_returncode = ctx.get("returncode")
                if ctx.get("healthz_signaled"):
                    last_healthz_signaled_ts = ts
        return {
            "restart_count": restart_count,
            "last_spawn_ts": last_spawn_ts,
            "last_exit_returncode": last_exit_returncode,
            "last_healthz_signaled_ts": last_healthz_signaled_ts,
        }


# ---------------------------------------------------------------------------
# Embedded HTML index (single-file UI page)
# ---------------------------------------------------------------------------


INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Recto Admin</title>
<style>
:root {
    --bg: #0c0c0e;
    --panel: #15151a;
    --border: #2a2a35;
    --text: #e5e5ea;
    --text-dim: #8e8e98;
    --accent: #7aa2f7;
    --green: #9ece6a;
    --red: #f7768e;
    --amber: #e0af68;
    --mono: 'JetBrains Mono', 'Consolas', 'Menlo', monospace;
}
* { box-sizing: border-box; }
body {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    line-height: 1.5;
}
header {
    border-bottom: 1px solid var(--border);
    padding: 16px 24px;
    display: flex;
    align-items: baseline;
    gap: 16px;
}
h1 { margin: 0; font-size: 20px; font-weight: 600; }
.subtitle { color: var(--text-dim); font-size: 13px; }
nav { padding: 0 24px; border-bottom: 1px solid var(--border); }
nav button {
    background: transparent;
    border: none;
    color: var(--text-dim);
    padding: 12px 16px;
    cursor: pointer;
    font-size: 14px;
    border-bottom: 2px solid transparent;
}
nav button.active { color: var(--text); border-bottom-color: var(--accent); }
main { padding: 24px; max-width: 1200px; }
.panel {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 16px;
    margin-bottom: 16px;
}
.kv { display: grid; grid-template-columns: 200px 1fr; gap: 8px 16px; font-family: var(--mono); font-size: 13px; }
.kv .key { color: var(--text-dim); }
.event {
    font-family: var(--mono);
    font-size: 12px;
    padding: 8px 12px;
    border-bottom: 1px solid var(--border);
    display: grid;
    grid-template-columns: 180px 200px 1fr;
    gap: 16px;
    align-items: start;
}
.event:last-child { border-bottom: none; }
.event .ts { color: var(--text-dim); }
.event .kind { color: var(--accent); }
.event .ctx { color: var(--text); white-space: pre-wrap; word-break: break-all; }
.event .kind.child-spawn { color: var(--green); }
.event .kind.child-exit { color: var(--amber); }
.event .kind.restart-attempt { color: var(--amber); }
.event .kind.max-attempts-reached, .event .kind.source-teardown-failed { color: var(--red); }
.empty { color: var(--text-dim); padding: 24px; text-align: center; }
.refresh { color: var(--text-dim); font-size: 12px; }
</style>
</head>
<body>
<header>
    <h1>Recto Admin</h1>
    <span class="subtitle" id="service-name">loading...</span>
    <span class="refresh" id="refresh-status"></span>
</header>
<nav>
    <button data-tab="status" class="active">Status</button>
    <button data-tab="events">Events</button>
    <button data-tab="restarts">Restart History</button>
</nav>
<main>
    <section id="tab-status"></section>
    <section id="tab-events" hidden></section>
    <section id="tab-restarts" hidden></section>
</main>
<script>
const buttons = document.querySelectorAll('nav button');
buttons.forEach(b => b.addEventListener('click', () => {
    buttons.forEach(x => x.classList.remove('active'));
    b.classList.add('active');
    const tab = b.dataset.tab;
    document.querySelectorAll('main section').forEach(s => s.hidden = s.id !== 'tab-' + tab);
    refresh();
}));
function fmtTs(ts) {
    const d = new Date(ts * 1000);
    return d.toISOString().replace('T', ' ').replace('Z', '');
}
function fmtDuration(seconds) {
    if (seconds < 60) return seconds.toFixed(0) + 's';
    if (seconds < 3600) return (seconds / 60).toFixed(1) + 'm';
    if (seconds < 86400) return (seconds / 3600).toFixed(1) + 'h';
    return (seconds / 86400).toFixed(1) + 'd';
}
function eventClass(kind) { return 'kind ' + kind.replace(/\\./g, '-'); }
function renderEvents(targetId, events) {
    const el = document.getElementById(targetId);
    if (!events.length) { el.innerHTML = '<div class="empty">No events recorded yet.</div>'; return; }
    el.innerHTML = '<div class="panel" style="padding: 0">' + events.slice().reverse().map(e =>
        '<div class="event">' +
        '<span class="ts">' + fmtTs(e.ts) + '</span>' +
        '<span class="' + eventClass(e.kind) + '">' + e.kind + '</span>' +
        '<span class="ctx">' + JSON.stringify(e.ctx) + '</span>' +
        '</div>'
    ).join('') + '</div>';
}
function fmtNullable(v, formatter) {
    if (v === null || v === undefined) return '<span style="color: var(--text-mute)">-</span>';
    return formatter ? formatter(v) : String(v);
}
function fmtAge(ts) {
    if (ts === null || ts === undefined) return '<span style="color: var(--text-mute)">never</span>';
    const ageSeconds = (Date.now() / 1000) - ts;
    return fmtDuration(ageSeconds) + ' ago (' + fmtTs(ts) + ')';
}
async function loadStatus() {
    const r = await fetch('/api/status'); const d = await r.json();
    document.getElementById('service-name').textContent = d.service;
    const html = '<div class="panel"><div class="kv">' +
        '<span class="key">service</span><span>' + d.service + '</span>' +
        '<span class="key">healthz.type</span><span>' + d.healthz.type + '</span>' +
        '<span class="key">healthz.enabled</span><span>' + d.healthz.enabled + '</span>' +
        '<span class="key">restart.policy</span><span>' + d.restart.policy + '</span>' +
        '<span class="key">restart.backoff</span><span>' + d.restart.backoff + '</span>' +
        '<span class="key">launcher uptime</span><span>' + fmtDuration(d.uptime_seconds) + '</span>' +
        '<span class="key">events recorded</span><span>' + d.event_count + '</span>' +
        '<span class="key">restart count</span><span>' + d.restart_count + '</span>' +
        '<span class="key">last spawn</span><span>' + fmtAge(d.last_spawn_ts) + '</span>' +
        '<span class="key">last exit returncode</span><span>' + fmtNullable(d.last_exit_returncode) + '</span>' +
        '<span class="key">last healthz trip</span><span>' + fmtAge(d.last_healthz_signaled_ts) + '</span>' +
        '</div></div>';
    document.getElementById('tab-status').innerHTML = html;
}
async function loadEvents() {
    const r = await fetch('/api/events?limit=200'); const d = await r.json();
    renderEvents('tab-events', d.events);
}
async function loadRestarts() {
    const r = await fetch('/api/restart-history?limit=100'); const d = await r.json();
    renderEvents('tab-restarts', d.events);
}
async function refresh() {
    const tab = document.querySelector('nav button.active').dataset.tab;
    document.getElementById('refresh-status').textContent = 'refreshing...';
    try {
        if (tab === 'status') await loadStatus();
        else if (tab === 'events') await loadEvents();
        else if (tab === 'restarts') await loadRestarts();
        document.getElementById('refresh-status').textContent = 'updated ' + new Date().toLocaleTimeString();
    } catch (e) {
        document.getElementById('refresh-status').textContent = 'error: ' + e.message;
    }
}
refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# AdminUIServer
# ---------------------------------------------------------------------------


def _build_handler(
    server_state: "_ServerState",
) -> type[BaseHTTPRequestHandler]:
    """Build a request handler class with a closure over the shared state.

    Defining the handler inside a function lets us pass per-server state
    without touching ``HTTPServer.server_address`` or subclassing
    ``ThreadingHTTPServer``. Each Recto instance gets its own handler
    class with its own state reference -- safe even if a future test
    spins up multiple servers in the same process.
    """

    class _Handler(BaseHTTPRequestHandler):
        # Silence the noisy default access-log; the launcher's own
        # _emit_event JSON lines are the canonical record.
        def log_message(self, _format: str, *_args: Any) -> None:
            return

        def do_GET(self) -> None:  # noqa: N802 - http.server name
            parsed = urlparse(self.path)
            path = parsed.path
            query = parse_qs(parsed.query)
            try:
                if path == "/" or path == "/index.html":
                    self._respond_html(INDEX_HTML)
                elif path == "/api/status":
                    self._respond_json(server_state.status_payload())
                elif path == "/api/events":
                    self._respond_json(server_state.events_payload(query))
                elif path == "/api/restart-history":
                    self._respond_json(
                        server_state.restart_history_payload(query)
                    )
                else:
                    self._respond_json(
                        {"error": f"unknown path {path!r}"}, status=404
                    )
            except Exception as exc:  # noqa: BLE001
                # Defense in depth: a handler bug must not crash the
                # whole server (and thus the launcher's daemon thread).
                self._respond_json(
                    {"error": "internal", "exception": type(exc).__name__},
                    status=500,
                )

        def _respond_html(self, body: str) -> None:
            data = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _respond_json(
            self, payload: dict[str, Any], *, status: int = 200
        ) -> None:
            data = json.dumps(payload, default=str).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return _Handler


class _ServerState:
    """Container for the data the request handler reads.

    Held by the AdminUIServer and shared with each request via the
    handler closure. All reads are thread-safe -- EventBuffer has its
    own lock; the immutable fields (config, etc.) don't need one.
    """

    def __init__(self, *, service_name: str, buffer: EventBuffer, config: Any):
        self.service_name = service_name
        self.buffer = buffer
        self.config = config

    def status_payload(self) -> dict[str, Any]:
        spec = self.config.spec
        derived = self.buffer.derived_state()
        return {
            "service": self.service_name,
            "healthz": {
                "enabled": spec.healthz.enabled,
                "type": spec.healthz.type,
            },
            "restart": {
                "policy": spec.restart.policy,
                "backoff": spec.restart.backoff,
            },
            "uptime_seconds": time.time() - self.buffer.start_time,
            "event_count": len(self.buffer),
            # Derived from the event stream -- richer signal than uptime
            # alone for triage. Each value is None until the relevant
            # event has occurred at least once during this run.
            "restart_count": derived["restart_count"],
            "last_spawn_ts": derived["last_spawn_ts"],
            "last_exit_returncode": derived["last_exit_returncode"],
            "last_healthz_signaled_ts": derived["last_healthz_signaled_ts"],
        }

    def events_payload(self, query: dict[str, list[str]]) -> dict[str, Any]:
        limit = self._parse_limit(query, default=200, cap=2000)
        kinds = query.get("kind") or None
        events = self.buffer.recent(limit=limit, kinds=kinds)
        return {"events": events, "count": len(events)}

    def restart_history_payload(
        self, query: dict[str, list[str]]
    ) -> dict[str, Any]:
        limit = self._parse_limit(query, default=100, cap=1000)
        events = self.buffer.recent(
            limit=limit,
            kinds=(
                "child.exit",
                "restart.attempt",
                "max_attempts_reached",
                "run.final_exit",
            ),
        )
        return {"events": events, "count": len(events)}

    @staticmethod
    def _parse_limit(
        query: dict[str, list[str]], *, default: int, cap: int
    ) -> int:
        raw = query.get("limit", [None])[0]
        if raw is None:
            return default
        try:
            n = int(raw)
        except (TypeError, ValueError):
            return default
        return max(1, min(n, cap))


class AdminUIServer:
    """Thread-spawned admin UI HTTP server.

    Lifecycle:
        ui = AdminUIServer(spec.admin_ui, service_name=..., buffer=..., config=...)
        ui.start()  # spawns a daemon thread; returns immediately
        ...
        ui.stop()   # signals shutdown; joins the thread

    Construction does NOT bind. ``start()`` binds; if bind raises
    (port in use, permission denied), the failure is logged via
    ``emit_failure`` and the server stays inactive. The launcher
    must not crash because the admin UI couldn't bind.
    """

    def __init__(
        self,
        spec: AdminUISpec,
        *,
        service_name: str,
        buffer: EventBuffer,
        config: Any,
        emit_failure: Any | None = None,
    ) -> None:
        self.spec = spec
        self._state = _ServerState(
            service_name=service_name, buffer=buffer, config=config
        )
        self._emit_failure = emit_failure
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._bound_address: tuple[str, int] | None = None

    @property
    def bound_address(self) -> tuple[str, int] | None:
        """The (host, port) the server actually bound to, or None.

        Useful when ``spec.bind`` declares port 0 (let the OS pick) --
        tests inspect this to learn the runtime port.
        """
        return self._bound_address

    def start(self) -> None:
        """Bind and spawn the server thread. No-op when disabled.

        Soft-fails on bind errors -- logs a warning via emit_failure
        (or stderr if no callback is configured) and returns without
        spawning a thread. The launcher checks `bound_address` to know
        whether the UI is actually live.
        """
        if not self.spec.enabled:
            return
        host, port = self._parse_bind(self.spec.bind)
        try:
            handler_cls = _build_handler(self._state)
            self._server = ThreadingHTTPServer((host, port), handler_cls)
        except OSError as exc:
            self._emit(
                "adminui.bind_failed",
                {
                    "bind": self.spec.bind,
                    "error": type(exc).__name__,
                    "message": str(exc),
                },
            )
            self._server = None
            return
        self._bound_address = self._server.server_address[:2]
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="recto.adminui",
            daemon=True,
        )
        self._thread.start()
        self._emit(
            "adminui.started",
            {
                "bind": f"{self._bound_address[0]}:{self._bound_address[1]}"
            },
        )

    def stop(self) -> None:
        """Shut down the server cleanly. Idempotent."""
        if self._server is None:
            return
        try:
            self._server.shutdown()
            self._server.server_close()
        except Exception:  # noqa: BLE001
            pass
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        self._server = None
        self._thread = None
        self._bound_address = None

    def _emit(self, kind: str, ctx: dict[str, Any]) -> None:
        if self._emit_failure is not None:
            try:
                self._emit_failure(kind, ctx)
            except Exception:  # noqa: BLE001
                pass

    @staticmethod
    def _parse_bind(bind: str) -> tuple[str, int]:
        """Split a 'host:port' string. Defaults to 127.0.0.1:5050."""
        if ":" not in bind:
            return "127.0.0.1", 5050
        host, _, port_s = bind.rpartition(":")
        try:
            port = int(port_s)
        except (TypeError, ValueError):
            port = 5050
        return host or "127.0.0.1", port
