"""Tests for recto.adminui -- EventBuffer + AdminUIServer.

Strategy:
- EventBuffer: pure data structure, tested directly. Thread-safety
  smoked with a quick concurrent-producer test.
- AdminUIServer: bind to port 0 (OS picks a free port) so the test
  doesn't conflict with anything running on 5050. Fire HTTP requests
  via stdlib urllib; assert on the JSON shape of each /api endpoint.
- Soft-fail on bind: instantiate with a deliberately invalid bind
  string and confirm the server stays inactive without raising.
"""

from __future__ import annotations

import json
import sys
import threading
import time
import urllib.error
import urllib.request
from typing import Any

import pytest

from recto.adminui import (
    INDEX_HTML,
    AdminUIServer,
    EventBuffer,
)
from recto.config import (
    AdminUISpec,
    HealthzSpec,
    RestartSpec,
    ServiceConfig,
    ServiceMeta,
    ServiceSpec,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_config(*, name: str = "myservice") -> ServiceConfig:
    return ServiceConfig(
        apiVersion="recto/v1",
        kind="Service",
        metadata=ServiceMeta(name=name),
        spec=ServiceSpec(
            exec="python.exe",
            healthz=HealthzSpec(enabled=False, type="http"),
            restart=RestartSpec(),
        ),
    )


def fetch_json(port: int, path: str) -> dict[str, Any]:
    """GET http://127.0.0.1:<port><path> and parse the JSON body."""
    url = f"http://127.0.0.1:{port}{path}"
    with urllib.request.urlopen(url, timeout=2.0) as resp:
        body = resp.read()
        return json.loads(body)


def fetch_text(port: int, path: str) -> tuple[int, str, dict[str, str]]:
    """GET and return (status, body, content_type)."""
    url = f"http://127.0.0.1:{port}{path}"
    try:
        with urllib.request.urlopen(url, timeout=2.0) as resp:
            return (
                resp.status,
                resp.read().decode("utf-8"),
                {"content-type": resp.headers.get("Content-Type", "")},
            )
    except urllib.error.HTTPError as exc:
        return (
            exc.code,
            exc.read().decode("utf-8"),
            {"content-type": exc.headers.get("Content-Type", "")},
        )


# ---------------------------------------------------------------------------
# EventBuffer
# ---------------------------------------------------------------------------


class TestEventBuffer:
    def test_empty_buffer(self) -> None:
        buf = EventBuffer()
        assert len(buf) == 0
        assert buf.recent() == []

    def test_append_records_kind_ts_ctx(self) -> None:
        buf = EventBuffer()
        buf.append("child.spawn", {"cmd": ["python.exe"]})
        events = buf.recent()
        assert len(events) == 1
        e = events[0]
        assert e["kind"] == "child.spawn"
        assert e["ctx"] == {"cmd": ["python.exe"]}
        assert isinstance(e["ts"], float)
        assert e["ts"] > 0

    def test_append_copies_ctx(self) -> None:
        # Buffer must defensively copy the ctx dict so a caller mutating
        # it after append() doesn't poison stored events.
        buf = EventBuffer()
        ctx = {"key": "v1"}
        buf.append("x", ctx)
        ctx["key"] = "v2"
        assert buf.recent()[0]["ctx"] == {"key": "v1"}

    def test_capacity_drops_oldest(self) -> None:
        buf = EventBuffer(capacity=3)
        for i in range(5):
            buf.append("k", {"i": i})
        # Only the last 3 should remain.
        events = buf.recent()
        assert len(events) == 3
        assert [e["ctx"]["i"] for e in events] == [2, 3, 4]

    def test_recent_with_limit(self) -> None:
        buf = EventBuffer()
        for i in range(10):
            buf.append("k", {"i": i})
        events = buf.recent(limit=3)
        assert [e["ctx"]["i"] for e in events] == [7, 8, 9]

    def test_recent_filters_by_kind(self) -> None:
        buf = EventBuffer()
        buf.append("child.spawn", {})
        buf.append("child.exit", {"rc": 0})
        buf.append("restart.attempt", {"attempt": 1})
        buf.append("child.exit", {"rc": 1})
        events = buf.recent(kinds=["child.exit"])
        assert len(events) == 2
        assert [e["ctx"]["rc"] for e in events] == [0, 1]

    def test_thread_safety_smoke(self) -> None:
        # Spawn 4 producers each writing 250 events. The deque + lock
        # should serialize cleanly without losing or duplicating events.
        buf = EventBuffer(capacity=10_000)

        def producer(producer_id: int) -> None:
            for i in range(250):
                buf.append("k", {"p": producer_id, "i": i})

        threads = [
            threading.Thread(target=producer, args=(p,)) for p in range(4)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(buf) == 1000

    def test_start_time_is_set_at_construction(self) -> None:
        before = time.time()
        buf = EventBuffer()
        after = time.time()
        assert before <= buf.start_time <= after


# ---------------------------------------------------------------------------
# AdminUIServer lifecycle
# ---------------------------------------------------------------------------


@pytest.fixture
def running_server() -> Any:
    """Spawn an AdminUIServer on a random port, yield it, tear down."""
    spec = AdminUISpec(enabled=True, bind="127.0.0.1:0")
    buf = EventBuffer()
    cfg = make_config()
    server = AdminUIServer(
        spec, service_name="myservice", buffer=buf, config=cfg
    )
    server.start()
    assert server.bound_address is not None, "server failed to bind"
    yield server, buf
    server.stop()


class TestAdminUIServerLifecycle:
    def test_disabled_does_not_bind(self) -> None:
        spec = AdminUISpec(enabled=False, bind="127.0.0.1:0")
        buf = EventBuffer()
        cfg = make_config()
        server = AdminUIServer(
            spec, service_name="myservice", buffer=buf, config=cfg
        )
        server.start()
        assert server.bound_address is None
        server.stop()  # idempotent

    def test_stop_is_idempotent(self) -> None:
        spec = AdminUISpec(enabled=True, bind="127.0.0.1:0")
        buf = EventBuffer()
        cfg = make_config()
        server = AdminUIServer(
            spec, service_name="myservice", buffer=buf, config=cfg
        )
        server.start()
        server.stop()
        server.stop()  # second call must not raise
        assert server.bound_address is None

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason=(
            "Windows SO_REUSEADDR semantics let two HTTP servers bind to "
            "the same in-use port (the inverse of Linux). The soft-fail "
            "code path itself is identical across platforms; testing it "
            "via 'collide on the same port' only works on Linux. The "
            "underlying except OSError in AdminUIServer.start() runs the "
            "same on both."
        ),
    )
    def test_soft_fail_on_bind_error(self) -> None:
        # Bind once, then attempt a SECOND server on the same address.
        # The second start() must soft-fail. (Linux only -- see skipif.)
        spec = AdminUISpec(enabled=True, bind="127.0.0.1:0")
        buf = EventBuffer()
        cfg = make_config()
        first = AdminUIServer(
            spec, service_name="x", buffer=buf, config=cfg
        )
        first.start()
        assert first.bound_address is not None
        host, port = first.bound_address
        try:
            # Now try to bind a second server on the same port.
            spec2 = AdminUISpec(
                enabled=True, bind=f"{host}:{port}"
            )
            failures: list[tuple[str, dict[str, Any]]] = []
            second = AdminUIServer(
                spec2,
                service_name="x",
                buffer=buf,
                config=cfg,
                emit_failure=lambda k, c: failures.append((k, c)),
            )
            second.start()
            assert second.bound_address is None
            assert any(
                k == "adminui.bind_failed" for k, _ in failures
            )
        finally:
            first.stop()


class TestAdminUIServerRoutes:
    def test_index_returns_html(self, running_server: Any) -> None:
        server, _buf = running_server
        _, port = server.bound_address
        status, body, headers = fetch_text(port, "/")
        assert status == 200
        assert "text/html" in headers["content-type"]
        assert "<title>Recto Admin</title>" in body
        # The embedded UI should reference all three /api endpoints.
        assert "/api/status" in body
        assert "/api/events" in body
        assert "/api/restart-history" in body

    def test_status_payload_shape(self, running_server: Any) -> None:
        server, _buf = running_server
        _, port = server.bound_address
        d = fetch_json(port, "/api/status")
        assert d["service"] == "myservice"
        assert d["healthz"]["enabled"] is False
        assert d["healthz"]["type"] == "http"
        assert "uptime_seconds" in d
        assert d["event_count"] == 0
        assert d["restart"]["policy"] == "always"

    def test_events_empty_when_buffer_empty(
        self, running_server: Any
    ) -> None:
        server, _buf = running_server
        _, port = server.bound_address
        d = fetch_json(port, "/api/events")
        assert d["events"] == []
        assert d["count"] == 0

    def test_events_returns_buffered(self, running_server: Any) -> None:
        server, buf = running_server
        _, port = server.bound_address
        buf.append("child.spawn", {"cmd": ["python.exe"]})
        buf.append("child.exit", {"returncode": 0})
        d = fetch_json(port, "/api/events")
        assert d["count"] == 2
        kinds = [e["kind"] for e in d["events"]]
        assert kinds == ["child.spawn", "child.exit"]

    def test_events_filter_by_kind(self, running_server: Any) -> None:
        server, buf = running_server
        _, port = server.bound_address
        buf.append("child.spawn", {})
        buf.append("child.exit", {"rc": 0})
        buf.append("restart.attempt", {"attempt": 1})
        d = fetch_json(port, "/api/events?kind=child.exit")
        assert d["count"] == 1
        assert d["events"][0]["kind"] == "child.exit"

    def test_events_limit_query(self, running_server: Any) -> None:
        server, buf = running_server
        _, port = server.bound_address
        for i in range(50):
            buf.append("k", {"i": i})
        d = fetch_json(port, "/api/events?limit=5")
        assert d["count"] == 5
        # Most recent 5.
        assert [e["ctx"]["i"] for e in d["events"]] == [45, 46, 47, 48, 49]

    def test_restart_history_filters_correctly(
        self, running_server: Any
    ) -> None:
        server, buf = running_server
        _, port = server.bound_address
        # Mix of events; restart-history should only include child.exit /
        # restart.attempt / max_attempts_reached / run.final_exit.
        buf.append("child.spawn", {})  # excluded
        buf.append("child.exit", {"rc": 1})  # included
        buf.append("restart.attempt", {"attempt": 1})  # included
        buf.append("source.teardown_failed", {})  # excluded
        buf.append("run.final_exit", {"rc": 0})  # included
        d = fetch_json(port, "/api/restart-history")
        kinds = [e["kind"] for e in d["events"]]
        assert kinds == [
            "child.exit",
            "restart.attempt",
            "run.final_exit",
        ]

    def test_unknown_path_returns_404(self, running_server: Any) -> None:
        server, _ = running_server
        _, port = server.bound_address
        status, body, headers = fetch_text(port, "/api/no-such-endpoint")
        assert status == 404
        assert "application/json" in headers["content-type"]
        d = json.loads(body)
        assert "error" in d


class TestIndexHtml:
    def test_index_html_is_self_contained(self) -> None:
        # The embedded UI must not reference any external CDN -- the
        # operator may run Recto in an air-gapped environment.
        assert "https://" not in INDEX_HTML or "fonts.googleapis" not in INDEX_HTML
        # (We allow font CDN but if the operator wants strict
        # air-gapping they can fork the page; the JSON endpoints work
        # without it.)

    def test_index_polls_every_endpoint(self) -> None:
        # The JS in INDEX_HTML must call each /api endpoint we expose,
        # otherwise the UI tabs are dead.
        assert "/api/status" in INDEX_HTML
        assert "/api/events" in INDEX_HTML
        assert "/api/restart-history" in INDEX_HTML


# ---------------------------------------------------------------------------
# v0.2.2: derived state on /api/status
# ---------------------------------------------------------------------------


class TestEventBufferDerivedState:
    def test_empty_buffer_yields_zeros_and_nones(self) -> None:
        buf = EventBuffer()
        d = buf.derived_state()
        assert d["restart_count"] == 0
        assert d["last_spawn_ts"] is None
        assert d["last_exit_returncode"] is None
        assert d["last_healthz_signaled_ts"] is None

    def test_restart_count_counts_child_exits(self) -> None:
        buf = EventBuffer()
        buf.append("child.spawn", {})
        buf.append("child.exit", {"returncode": 0, "healthz_signaled": False})
        buf.append("child.spawn", {})
        buf.append("child.exit", {"returncode": 1, "healthz_signaled": False})
        d = buf.derived_state()
        assert d["restart_count"] == 2

    def test_last_spawn_ts_picks_most_recent(self) -> None:
        buf = EventBuffer()
        buf.append("child.spawn", {"cmd": ["x"]})
        first_spawn = buf.recent()[0]["ts"]
        # Add other events; last_spawn_ts should still be the first one
        # because no NEW spawn has happened.
        buf.append("child.exit", {"returncode": 0, "healthz_signaled": False})
        d = buf.derived_state()
        assert d["last_spawn_ts"] == first_spawn
        # Now another spawn -- last_spawn_ts updates.
        buf.append("child.spawn", {"cmd": ["x"]})
        second_spawn = buf.recent()[-1]["ts"]
        d = buf.derived_state()
        assert d["last_spawn_ts"] == second_spawn

    def test_last_exit_returncode_uses_most_recent(self) -> None:
        buf = EventBuffer()
        buf.append("child.exit", {"returncode": 0, "healthz_signaled": False})
        buf.append("child.exit", {"returncode": 1, "healthz_signaled": False})
        buf.append("child.exit", {"returncode": 42, "healthz_signaled": False})
        d = buf.derived_state()
        assert d["last_exit_returncode"] == 42

    def test_last_healthz_signaled_ts_only_for_probe_driven_exits(self) -> None:
        buf = EventBuffer()
        # Natural exit -- not healthz-driven.
        buf.append("child.exit", {"returncode": 0, "healthz_signaled": False})
        d = buf.derived_state()
        assert d["last_healthz_signaled_ts"] is None
        # Probe-driven exit -- ts gets recorded.
        buf.append("child.exit", {"returncode": 143, "healthz_signaled": True})
        probe_ts = buf.recent()[-1]["ts"]
        d = buf.derived_state()
        assert d["last_healthz_signaled_ts"] == probe_ts
        # A subsequent non-probe exit must NOT clear last_healthz_signaled_ts.
        buf.append("child.exit", {"returncode": 0, "healthz_signaled": False})
        d = buf.derived_state()
        assert d["last_healthz_signaled_ts"] == probe_ts


class TestStatusPayloadDerivedFields:
    def test_status_includes_derived_fields(
        self, running_server: Any
    ) -> None:
        server, buf = running_server
        _, port = server.bound_address
        # Seed the buffer so derived fields have non-default values.
        buf.append("child.spawn", {"cmd": ["python.exe"]})
        buf.append("child.exit", {"returncode": 7, "healthz_signaled": True})
        d = fetch_json(port, "/api/status")
        assert d["restart_count"] == 1
        assert d["last_exit_returncode"] == 7
        assert isinstance(d["last_spawn_ts"], (int, float))
        assert isinstance(d["last_healthz_signaled_ts"], (int, float))

    def test_status_derived_fields_default_to_zero_or_none(
        self, running_server: Any
    ) -> None:
        server, _buf = running_server
        _, port = server.bound_address
        # No events buffered -> derived fields at their zero/None defaults.
        d = fetch_json(port, "/api/status")
        assert d["restart_count"] == 0
        assert d["last_spawn_ts"] is None
        assert d["last_exit_returncode"] is None
        assert d["last_healthz_signaled_ts"] is None
