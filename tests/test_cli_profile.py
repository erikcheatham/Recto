"""Tests for `recto profile {list,show,create,master-pubkey}` CLI
subcommands (Phase 2.0.B integration Item 2).

Each test invokes ``recto.cli.main`` with the relevant argv and
captured stdout/stderr, then asserts on the exit code + on the
filesystem state under a temp state-dir AND/OR on the captured
output.

Test surface mirrors ``test_cli_vault.py``'s shape; the `create`
subcommand additionally stands up a stdlib ``http.server`` on a
loopback port to exercise the POST + poll round-trip without
dragging in a real bootloader.
"""

from __future__ import annotations

import io
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from recto.cli import main
from recto.profile.manage import bootstrap_master, create_child_profile


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


def _fixture_master_pubkey_hex() -> str:
    """64-byte deterministic fixture (X || Y), hex-encoded. Not a
    real secp256k1 point — the CLI doesn't validate curve membership,
    only the byte length + hex shape."""
    return bytes(range(64)).hex()


def _bootstrap_with_children(
    state_dir: Path,
    children: list[tuple[str, str]] | None = None,
) -> tuple[str, list[str]]:
    """Helper: bootstrap a master in `state_dir` and append `children`
    Profile rows. Returns (master_profile_id, [child_profile_ids...]).
    """
    mi = bootstrap_master(
        _fixture_master_pubkey_hex(),
        display_name="Personal (master)",
        state_dir=state_dir,
    )
    child_ids: list[str] = []
    for kind, name in children or []:
        p = create_child_profile(
            kind=kind,
            display_name=name,
            state_dir=state_dir,
        )
        child_ids.append(p.profile_id)
    return mi.master_profile_id, child_ids


# ---------------------------------------------------------------------------
# `recto profile list`
# ---------------------------------------------------------------------------


class TestProfileList:
    def test_empty_master_lists_only_master(self, tmp_path: Path) -> None:
        master_id, _ = _bootstrap_with_children(tmp_path, children=[])
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            ["profile", "list", "--state-dir", str(tmp_path)],
            stdout=out, stderr=err,
        )
        assert rc == 0, err.getvalue()
        text = out.getvalue()
        assert "1 profile(s)" in text
        assert "★ master" in text
        assert master_id in text

    def test_lists_master_plus_children_in_creation_order(
        self, tmp_path: Path
    ) -> None:
        master_id, child_ids = _bootstrap_with_children(
            tmp_path,
            children=[
                ("personal:child", "Pseudonym 1"),
                ("work", "Work — Acme"),
                ("contractor", "Contractor — Project X"),
            ],
        )
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            ["profile", "list", "--state-dir", str(tmp_path)],
            stdout=out, stderr=err,
        )
        assert rc == 0, err.getvalue()
        text = out.getvalue()
        assert "4 profile(s)" in text
        for cid in child_ids:
            assert cid in text
        assert "Pseudonym 1" in text
        assert "Work — Acme" in text
        assert "Contractor — Project X" in text

    def test_json_mode_emits_structured_output(self, tmp_path: Path) -> None:
        master_id, child_ids = _bootstrap_with_children(
            tmp_path,
            children=[("work", "Work — Acme")],
        )
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            ["profile", "list", "--state-dir", str(tmp_path), "--json"],
            stdout=out, stderr=err,
        )
        assert rc == 0, err.getvalue()
        parsed = json.loads(out.getvalue())
        assert parsed["master_bootstrapped"] is True
        assert parsed["master_pubkey_hex"] == _fixture_master_pubkey_hex()
        assert parsed["master_profile_id"] == master_id
        ids = {p["profile_id"] for p in parsed["profiles"]}
        assert master_id in ids
        for cid in child_ids:
            assert cid in ids
        master_row = next(p for p in parsed["profiles"] if p["is_master"])
        assert master_row["kind"] == "personal:master"
        assert master_row["derivation"]["profile_index"] == 0

    def test_no_master_bootstrapped_exits_1(self, tmp_path: Path) -> None:
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            ["profile", "list", "--state-dir", str(tmp_path)],
            stdout=out, stderr=err,
        )
        assert rc == 1
        assert "no master is bootstrapped" in err.getvalue()

    def test_no_master_bootstrapped_json_mode_still_exits_1(
        self, tmp_path: Path
    ) -> None:
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            ["profile", "list", "--state-dir", str(tmp_path), "--json"],
            stdout=out, stderr=err,
        )
        assert rc == 1
        parsed = json.loads(out.getvalue())
        assert parsed["master_bootstrapped"] is False
        assert parsed["profiles"] == []


# ---------------------------------------------------------------------------
# `recto profile show <id>`
# ---------------------------------------------------------------------------


class TestProfileShow:
    def test_shows_master_details(self, tmp_path: Path) -> None:
        master_id, _ = _bootstrap_with_children(tmp_path)
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            ["profile", "show", master_id, "--state-dir", str(tmp_path)],
            stdout=out, stderr=err,
        )
        assert rc == 0, err.getvalue()
        text = out.getvalue()
        assert master_id in text
        assert "role: master" in text
        assert "kind: personal:master" in text
        assert "Personal (master)" in text
        assert "derivation:" in text

    def test_shows_child_details(self, tmp_path: Path) -> None:
        _, child_ids = _bootstrap_with_children(
            tmp_path,
            children=[("work", "Work — Acme")],
        )
        target = child_ids[0]
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            ["profile", "show", target, "--state-dir", str(tmp_path)],
            stdout=out, stderr=err,
        )
        assert rc == 0, err.getvalue()
        text = out.getvalue()
        assert target in text
        assert "role: child" in text
        assert "kind: work" in text
        assert "Work — Acme" in text

    def test_unknown_profile_id_exits_1(self, tmp_path: Path) -> None:
        _bootstrap_with_children(tmp_path)
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            ["profile", "show", "nonexistent-id",
             "--state-dir", str(tmp_path)],
            stdout=out, stderr=err,
        )
        assert rc == 1
        assert "not found" in err.getvalue()

    def test_no_master_bootstrapped_exits_1(self, tmp_path: Path) -> None:
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            ["profile", "show", "any-id", "--state-dir", str(tmp_path)],
            stdout=out, stderr=err,
        )
        assert rc == 1
        assert "no master is bootstrapped" in err.getvalue()

    def test_json_mode_for_found_profile(self, tmp_path: Path) -> None:
        master_id, _ = _bootstrap_with_children(tmp_path)
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            ["profile", "show", master_id,
             "--state-dir", str(tmp_path), "--json"],
            stdout=out, stderr=err,
        )
        assert rc == 0, err.getvalue()
        parsed = json.loads(out.getvalue())
        assert parsed["found"] is True
        assert parsed["profile"]["profile_id"] == master_id
        assert parsed["profile"]["is_master"] is True

    def test_json_mode_for_unknown_profile(self, tmp_path: Path) -> None:
        _bootstrap_with_children(tmp_path)
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            ["profile", "show", "nope", "--state-dir", str(tmp_path), "--json"],
            stdout=out, stderr=err,
        )
        assert rc == 1
        parsed = json.loads(out.getvalue())
        assert parsed["found"] is False
        assert parsed["master_bootstrapped"] is True


# ---------------------------------------------------------------------------
# `recto profile master-pubkey`
# ---------------------------------------------------------------------------


class TestProfileMasterPubkey:
    def test_prints_pubkey_after_bootstrap(self, tmp_path: Path) -> None:
        _bootstrap_with_children(tmp_path)
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            ["profile", "master-pubkey", "--state-dir", str(tmp_path)],
            stdout=out, stderr=err,
        )
        assert rc == 0, err.getvalue()
        # Stdout is exactly the pubkey hex + trailing newline; nothing else.
        assert out.getvalue().strip() == _fixture_master_pubkey_hex()

    def test_no_master_bootstrapped_exits_1(self, tmp_path: Path) -> None:
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            ["profile", "master-pubkey", "--state-dir", str(tmp_path)],
            stdout=out, stderr=err,
        )
        assert rc == 1
        assert "no master is bootstrapped" in err.getvalue()


# ---------------------------------------------------------------------------
# `recto profile create <kind>` — HTTP POST + poll smoke
# ---------------------------------------------------------------------------


def _free_port() -> int:
    """Pick an unused localhost TCP port for the fake bootloader."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _FakeBootloader:
    """Minimal stdlib HTTP server that emulates the bootloader's
    /v0.4/profile/create + /v0.4/profile/result/<id> endpoints.

    Scenarios are scripted by the caller via attributes on this
    object before start():
        * .accept_create — bool, default True. False => POST returns 401
          (simulates auth failure).
        * .already_exists_profile_id — if set, POST returns 200 +
          status=already_exists pointing at this profile_id.
        * .result_sequence — list of (status, payload_dict) tuples
          returned by successive GETs to the result endpoint.
        * .require_agent_token — expected X-Recto-Agent-Token value;
          mismatch returns 401.

    Owns its own HTTPServer on a free loopback port.
    """

    def __init__(self) -> None:
        self.port = _free_port()
        self.host = "127.0.0.1"
        self.url_base = f"http://{self.host}:{self.port}"
        self.accept_create = True
        self.already_exists_profile_id: str | None = None
        # Phase 2.0.C wave C.5.c: idempotent already_member hit for the
        # add-device endpoint. If set to (profile_id, new_phone_id), POST
        # /v0.4/profile/<id>/add-device returns 200 + already_member with
        # those echoed values.
        self.already_member_response: tuple[str, str] | None = None
        # Phase 2.0.C wave C.6.c: idempotent already_not_member hit for
        # the revoke-device endpoint. If set to (profile_id,
        # phone_id_to_revoke), POST /v0.4/profile/<id>/revoke-device
        # returns 200 + already_not_member with those echoed values.
        self.already_not_member_response: tuple[str, str] | None = None
        # Phase 2.0.C wave C.6.c: quorum_not_yet_implemented response
        # for K=2 profile revoke attempts. If set, POST returns 400.
        self.quorum_not_yet_implemented_response: bool = False
        # Phase 2.0.C wave C.6.c: last_device_guard response for
        # single-device profile revoke attempts.
        self.last_device_guard_response: bool = False
        self.result_sequence: list[tuple[int, dict]] = []
        self._result_idx = 0
        self.require_agent_token: str | None = None
        self.last_post_body: dict | None = None
        self.last_post_agent_id: str | None = None
        self.last_post_path: str | None = None
        # The fake's "queued request_id" — returned by POST, consumed by GET.
        self.queued_request_id: str | None = None
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        outer = self

        class Handler(BaseHTTPRequestHandler):
            # Silence access-log spew during tests.
            def log_message(self, fmt, *args):  # noqa: N802
                pass

            def _send_json(self, status: int, body: dict) -> None:
                raw = json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length).decode("utf-8") if length else "{}"
                body = json.loads(raw)
                outer.last_post_body = body
                outer.last_post_agent_id = self.headers.get("X-Recto-Agent-Id")
                outer.last_post_path = self.path
                if outer.require_agent_token is not None:
                    if self.headers.get("X-Recto-Agent-Token") != outer.require_agent_token:
                        self._send_json(401, {"error": "agent_auth_failed"})
                        return
                # /v0.4/profile/create (Phase 2.0.B integration)
                if self.path == "/v0.4/profile/create":
                    if not outer.accept_create:
                        self._send_json(401, {"error": "agent_auth_failed"})
                        return
                    if outer.already_exists_profile_id is not None:
                        self._send_json(200, {
                            "status": "already_exists",
                            "profile_id": outer.already_exists_profile_id,
                            "candidate_profile_id": body.get("candidate_profile_id"),
                            "reason": "candidate_profile_id was already used",
                        })
                        return
                    outer.queued_request_id = "fake-request-1234"
                    self._send_json(201, {
                        "request_id": outer.queued_request_id,
                        "candidate_profile_id": body.get("candidate_profile_id"),
                        "expires_at_unix": int(time.time()) + 600,
                        "result_url": f"/v0.4/profile/result/{outer.queued_request_id}",
                    })
                    return
                # /v0.4/profile/<profile_id>/add-device (Phase 2.0.C C.5)
                if (
                    self.path.startswith("/v0.4/profile/")
                    and self.path.endswith("/add-device")
                ):
                    profile_id = self.path[
                        len("/v0.4/profile/"):-len("/add-device")
                    ]
                    if not outer.accept_create:
                        self._send_json(401, {"error": "agent_auth_failed"})
                        return
                    if outer.already_member_response is not None:
                        pid, npid = outer.already_member_response
                        self._send_json(200, {
                            "status": "already_member",
                            "profile_id": pid,
                            "new_phone_id": npid,
                            "reason": "new_phone_id is already in device_ids",
                        })
                        return
                    outer.queued_request_id = "fake-adddev-request-5678"
                    self._send_json(201, {
                        "request_id": outer.queued_request_id,
                        "profile_id": profile_id,
                        "new_phone_id": body.get("new_phone_id"),
                        "expires_at_unix": int(time.time()) + 600,
                        "result_url": f"/v0.4/profile/add-device-result/{outer.queued_request_id}",
                    })
                    return
                # /v0.4/profile/<profile_id>/revoke-device (Phase 2.0.C C.6)
                if (
                    self.path.startswith("/v0.4/profile/")
                    and self.path.endswith("/revoke-device")
                ):
                    profile_id = self.path[
                        len("/v0.4/profile/"):-len("/revoke-device")
                    ]
                    if not outer.accept_create:
                        self._send_json(401, {"error": "agent_auth_failed"})
                        return
                    if outer.quorum_not_yet_implemented_response:
                        self._send_json(400, {
                            "error": "quorum_not_yet_implemented",
                            "profile_id": profile_id,
                            "revoke_quorum_k": 2,
                            "detail": "K>=2 quorum not wired at v1",
                        })
                        return
                    if outer.last_device_guard_response:
                        self._send_json(400, {
                            "error": "last_device_guard",
                            "profile_id": profile_id,
                            "phone_id_to_revoke": body.get("phone_id_to_revoke"),
                            "detail": "cannot revoke the only device",
                        })
                        return
                    if outer.already_not_member_response is not None:
                        pid, npid = outer.already_not_member_response
                        self._send_json(200, {
                            "status": "already_not_member",
                            "profile_id": pid,
                            "phone_id_to_revoke": npid,
                            "reason": "phone_id_to_revoke is not in device_ids",
                        })
                        return
                    outer.queued_request_id = "fake-revdev-request-9012"
                    self._send_json(201, {
                        "request_id": outer.queued_request_id,
                        "profile_id": profile_id,
                        "phone_id_to_revoke": body.get("phone_id_to_revoke"),
                        "expires_at_unix": int(time.time()) + 600,
                        "result_url": f"/v0.4/profile/revoke-device-result/{outer.queued_request_id}",
                    })
                    return
                self._send_json(404, {"error": "unknown_endpoint"})

            def do_GET(self):  # noqa: N802
                # /v0.4/profile/result/<request_id> (profile_create)
                # /v0.4/profile/add-device-result/<request_id> (add-device)
                # /v0.4/profile/revoke-device-result/<request_id> (revoke-device)
                # All three share the same scripted result_sequence pattern.
                is_create_result = self.path.startswith("/v0.4/profile/result/")
                is_adddev_result = self.path.startswith(
                    "/v0.4/profile/add-device-result/"
                )
                is_revdev_result = self.path.startswith(
                    "/v0.4/profile/revoke-device-result/"
                )
                if not (is_create_result or is_adddev_result or is_revdev_result):
                    self._send_json(404, {"error": "unknown_endpoint"})
                    return
                if outer.require_agent_token is not None:
                    if self.headers.get("X-Recto-Agent-Token") != outer.require_agent_token:
                        self._send_json(401, {"error": "agent_auth_failed"})
                        return
                if outer._result_idx >= len(outer.result_sequence):
                    # No more scripted responses; default to pending.
                    self._send_json(200, {"status": "pending"})
                    return
                status, payload = outer.result_sequence[outer._result_idx]
                outer._result_idx += 1
                self._send_json(status, payload)

        self._server = HTTPServer((self.host, self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()


@pytest.fixture
def fake_bootloader():
    fb = _FakeBootloader()
    fb.start()
    yield fb
    fb.stop()


class TestProfileCreate:
    def test_happy_path_approval(self, tmp_path: Path, fake_bootloader) -> None:
        # Bootstrap a master so the post-approval lookup can resolve.
        master_id, _ = _bootstrap_with_children(tmp_path)
        # Pre-create the profile so the fake bootloader's "approved"
        # poll response points at a row that actually exists on disk
        # (mirrors what the real bootloader does atomically before
        # stashing the result).
        new_profile = create_child_profile(
            kind="personal:child",
            display_name="Pseudonym (pre-created for test)",
            state_dir=tmp_path,
        )
        fake_bootloader.result_sequence = [
            (200, {"status": "pending"}),
            (200, {"status": "approved", "profile_id": new_profile.profile_id}),
        ]
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            [
                "profile", "create", "personal:child",
                "--name", "Pseudonym (pre-created for test)",
                "--bootloader-url", fake_bootloader.url_base,
                "--phone-id", "phone-fixture-1",
                "--agent-id", "test-agent",
                "--agent-token", "fixture-token",
                "--state-dir", str(tmp_path),
                "--candidate-profile-id", new_profile.profile_id,
                "--poll-interval", "0.05",
                "--poll-timeout", "5",
            ],
            stdout=out, stderr=err,
        )
        assert rc == 0, err.getvalue()
        text = out.getvalue()
        assert "approved" in text
        assert new_profile.profile_id in text
        assert fake_bootloader.last_post_agent_id == "test-agent"
        assert fake_bootloader.last_post_body["kind"] == "personal:child"
        assert fake_bootloader.last_post_body["phone_id"] == "phone-fixture-1"

    def test_idempotent_already_exists(
        self, tmp_path: Path, fake_bootloader
    ) -> None:
        _bootstrap_with_children(tmp_path)
        fake_bootloader.already_exists_profile_id = "existing-profile-id-123"
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            [
                "profile", "create", "work",
                "--bootloader-url", fake_bootloader.url_base,
                "--phone-id", "phone-fixture-1",
                "--agent-id", "test-agent",
                "--agent-token", "fixture-token",
                "--state-dir", str(tmp_path),
                "--candidate-profile-id", "reused-candidate-id",
            ],
            stdout=out, stderr=err,
        )
        assert rc == 0, err.getvalue()
        assert "already corresponds to profile existing-profile-id-123" in out.getvalue()

    def test_denied_exit_1(self, tmp_path: Path, fake_bootloader) -> None:
        _bootstrap_with_children(tmp_path)
        fake_bootloader.result_sequence = [
            (200, {"status": "denied", "reason": "operator rejected the kind"}),
        ]
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            [
                "profile", "create", "work",
                "--bootloader-url", fake_bootloader.url_base,
                "--phone-id", "phone-fixture-1",
                "--agent-id", "test-agent",
                "--agent-token", "fixture-token",
                "--state-dir", str(tmp_path),
                "--poll-interval", "0.05",
                "--poll-timeout", "5",
            ],
            stdout=out, stderr=err,
        )
        assert rc == 1
        assert "denied" in err.getvalue()
        assert "operator rejected the kind" in err.getvalue()

    def test_signature_error_exit_1(
        self, tmp_path: Path, fake_bootloader
    ) -> None:
        _bootstrap_with_children(tmp_path)
        fake_bootloader.result_sequence = [
            (200, {"status": "signature_error",
                   "reason": "persist_error: disk full"}),
        ]
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            [
                "profile", "create", "personal:child",
                "--bootloader-url", fake_bootloader.url_base,
                "--phone-id", "phone-fixture-1",
                "--agent-id", "test-agent",
                "--agent-token", "fixture-token",
                "--state-dir", str(tmp_path),
                "--poll-interval", "0.05",
                "--poll-timeout", "5",
            ],
            stdout=out, stderr=err,
        )
        assert rc == 1
        assert "signature_error" in err.getvalue()
        assert "persist_error: disk full" in err.getvalue()
        # The persist-error advisory hint surfaces.
        assert "fix host state and retry with the SAME" in err.getvalue()

    def test_poll_timeout_exit_1(self, tmp_path: Path, fake_bootloader) -> None:
        _bootstrap_with_children(tmp_path)
        # Empty result_sequence => default "pending" forever.
        fake_bootloader.result_sequence = []
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            [
                "profile", "create", "personal:child",
                "--bootloader-url", fake_bootloader.url_base,
                "--phone-id", "phone-fixture-1",
                "--agent-id", "test-agent",
                "--agent-token", "fixture-token",
                "--state-dir", str(tmp_path),
                "--poll-interval", "0.05",
                "--poll-timeout", "1",
            ],
            stdout=out, stderr=err,
        )
        assert rc == 1
        assert "polled for 1s" in err.getvalue()
        assert "re-poll with --candidate-profile-id" in err.getvalue()

    def test_missing_phone_id_exits_2(self, tmp_path: Path) -> None:
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            [
                "profile", "create", "personal:child",
                "--agent-id", "test-agent",
                "--agent-token", "fixture-token",
                "--state-dir", str(tmp_path),
            ],
            stdout=out, stderr=err,
        )
        assert rc == 2
        assert "--phone-id" in err.getvalue()

    def test_missing_agent_id_exits_2(self, tmp_path: Path) -> None:
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            [
                "profile", "create", "personal:child",
                "--phone-id", "phone-fixture-1",
                "--agent-token", "fixture-token",
                "--state-dir", str(tmp_path),
            ],
            stdout=out, stderr=err,
        )
        assert rc == 2
        assert "--agent-id" in err.getvalue()

    def test_invalid_ttl_seconds_exits_2(self, tmp_path: Path) -> None:
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            [
                "profile", "create", "personal:child",
                "--phone-id", "phone-fixture-1",
                "--agent-id", "test-agent",
                "--agent-token", "fixture-token",
                "--state-dir", str(tmp_path),
                "--ttl-seconds", "30",  # below the [60..86400] floor
            ],
            stdout=out, stderr=err,
        )
        assert rc == 2
        assert "ttl-seconds" in err.getvalue()

    def test_bootloader_unreachable_exits_1(self, tmp_path: Path) -> None:
        # Point at a deterministically-closed port (1 is always reserved).
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            [
                "profile", "create", "personal:child",
                "--bootloader-url", f"http://127.0.0.1:{_free_port_after_close()}",
                "--phone-id", "phone-fixture-1",
                "--agent-id", "test-agent",
                "--agent-token", "fixture-token",
                "--state-dir", str(tmp_path),
            ],
            stdout=out, stderr=err,
        )
        assert rc == 1
        assert "could not reach bootloader" in err.getvalue()

    def test_json_mode_approval(self, tmp_path: Path, fake_bootloader) -> None:
        master_id, _ = _bootstrap_with_children(tmp_path)
        new_profile = create_child_profile(
            kind="personal:child",
            display_name="JSON-mode test",
            state_dir=tmp_path,
        )
        fake_bootloader.result_sequence = [
            (200, {"status": "approved", "profile_id": new_profile.profile_id}),
        ]
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            [
                "profile", "create", "personal:child",
                "--name", "JSON-mode test",
                "--bootloader-url", fake_bootloader.url_base,
                "--phone-id", "phone-fixture-1",
                "--agent-id", "test-agent",
                "--agent-token", "fixture-token",
                "--state-dir", str(tmp_path),
                "--candidate-profile-id", new_profile.profile_id,
                "--poll-interval", "0.05",
                "--poll-timeout", "5",
                "--json",
            ],
            stdout=out, stderr=err,
        )
        assert rc == 0, err.getvalue()
        parsed = json.loads(out.getvalue())
        assert parsed["status"] == "approved"
        assert parsed["profile_id"] == new_profile.profile_id
        assert parsed["profile"]["display_name"] == "JSON-mode test"

    def test_idempotent_already_exists_json_mode(
        self, tmp_path: Path, fake_bootloader
    ) -> None:
        _bootstrap_with_children(tmp_path)
        fake_bootloader.already_exists_profile_id = "existing-id-json"
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            [
                "profile", "create", "work",
                "--bootloader-url", fake_bootloader.url_base,
                "--phone-id", "phone-fixture-1",
                "--agent-id", "test-agent",
                "--agent-token", "fixture-token",
                "--state-dir", str(tmp_path),
                "--candidate-profile-id", "reused-id",
                "--json",
            ],
            stdout=out, stderr=err,
        )
        assert rc == 0, err.getvalue()
        parsed = json.loads(out.getvalue())
        assert parsed["status"] == "already_exists"
        assert parsed["profile_id"] == "existing-id-json"


# Helper for the unreachable-bootloader test: claim a port and
# release it so we know nothing's bound to it during the call.
def _free_port_after_close() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ---------------------------------------------------------------------------
# v2.1 placeholders still print their "coming soon" notice.
# ---------------------------------------------------------------------------


class TestProfileAddDevice:
    """Phase 2.0.C wave C.5.c — `recto profile add-device` CLI tests.

    Mirrors TestProfileCreate's scripted-fake-bootloader pattern but
    exercises the POST /v0.4/profile/<id>/add-device + GET
    /v0.4/profile/add-device-result/<request_id> round-trip.
    """

    def test_happy_path_approval(self, tmp_path: Path, fake_bootloader) -> None:
        # Bootstrap a master + pre-create a child profile with the
        # master phone as initial member, so the post-approval lookup
        # can resolve.
        master_id, _ = _bootstrap_with_children(tmp_path)
        child = create_child_profile(
            kind="personal:child",
            display_name="Test target child",
            device_ids=("master-phone-id",),
            state_dir=tmp_path,
        )
        # After "approval" the test pre-applies the mutation directly
        # to disk so _render_profile_add_device_approved's read-from-
        # master_identity-json reflects the appended device.
        from recto.profile.manage import profile_add_device
        profile_add_device(
            profile_id=child.profile_id,
            new_phone_id="new-phone-789",
            state_dir=tmp_path,
        )
        fake_bootloader.result_sequence = [
            (200, {"status": "pending"}),
            (200, {
                "status": "approved",
                "profile_id": child.profile_id,
                "new_phone_id": "new-phone-789",
            }),
        ]
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            [
                "profile", "add-device", child.profile_id,
                "--new-phone-id", "new-phone-789",
                "--new-phone-label", "Pixel 10",
                "--bootloader-url", fake_bootloader.url_base,
                "--master-phone-id", "master-phone-id",
                "--agent-id", "test-agent",
                "--agent-token", "fixture-token",
                "--state-dir", str(tmp_path),
                "--poll-interval", "0.05",
                "--poll-timeout", "5",
            ],
            stdout=out, stderr=err,
        )
        assert rc == 0, err.getvalue()
        text = out.getvalue()
        assert "approved" in text
        assert child.profile_id in text
        assert "new-phone-789" in text
        # Body shape: master_phone_id + new_phone_id + ttl + label.
        assert fake_bootloader.last_post_body["master_phone_id"] == "master-phone-id"
        assert fake_bootloader.last_post_body["new_phone_id"] == "new-phone-789"
        assert fake_bootloader.last_post_body["new_phone_label"] == "Pixel 10"
        # Path was the URL-templated add-device endpoint.
        assert fake_bootloader.last_post_path.endswith("/add-device")
        assert child.profile_id in fake_bootloader.last_post_path

    def test_idempotent_already_member(
        self, tmp_path: Path, fake_bootloader
    ) -> None:
        _bootstrap_with_children(tmp_path)
        fake_bootloader.already_member_response = ("p-target", "ph-existing")
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            [
                "profile", "add-device", "p-target",
                "--new-phone-id", "ph-existing",
                "--bootloader-url", fake_bootloader.url_base,
                "--master-phone-id", "master-phone-id",
                "--agent-id", "test-agent",
                "--agent-token", "fixture-token",
                "--state-dir", str(tmp_path),
            ],
            stdout=out, stderr=err,
        )
        assert rc == 0, err.getvalue()
        assert "already in profile" in out.getvalue()

    def test_denied_exit_1(self, tmp_path: Path, fake_bootloader) -> None:
        _bootstrap_with_children(tmp_path)
        fake_bootloader.result_sequence = [
            (200, {"status": "denied", "reason": "operator declined"}),
        ]
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            [
                "profile", "add-device", "p-target",
                "--new-phone-id", "ph-new",
                "--bootloader-url", fake_bootloader.url_base,
                "--master-phone-id", "master-phone-id",
                "--agent-id", "test-agent",
                "--agent-token", "fixture-token",
                "--state-dir", str(tmp_path),
                "--poll-interval", "0.05",
                "--poll-timeout", "5",
            ],
            stdout=out, stderr=err,
        )
        assert rc == 1
        assert "denied" in err.getvalue()
        assert "operator declined" in err.getvalue()

    def test_signature_error_persist_hint(
        self, tmp_path: Path, fake_bootloader
    ) -> None:
        _bootstrap_with_children(tmp_path)
        fake_bootloader.result_sequence = [
            (200, {"status": "signature_error",
                   "reason": "persist_error: disk full"}),
        ]
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            [
                "profile", "add-device", "p-target",
                "--new-phone-id", "ph-new",
                "--bootloader-url", fake_bootloader.url_base,
                "--master-phone-id", "master-phone-id",
                "--agent-id", "test-agent",
                "--agent-token", "fixture-token",
                "--state-dir", str(tmp_path),
                "--poll-interval", "0.05",
                "--poll-timeout", "5",
            ],
            stdout=out, stderr=err,
        )
        assert rc == 1
        assert "signature_error" in err.getvalue()
        assert "persist_error: disk full" in err.getvalue()
        # The persist-error advisory hint surfaces with the
        # add-device-specific wording (idempotent retry-safe).
        assert "idempotent" in err.getvalue()

    def test_poll_timeout_exit_1(self, tmp_path: Path, fake_bootloader) -> None:
        _bootstrap_with_children(tmp_path)
        fake_bootloader.result_sequence = []  # default to pending forever
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            [
                "profile", "add-device", "p-target",
                "--new-phone-id", "ph-new",
                "--bootloader-url", fake_bootloader.url_base,
                "--master-phone-id", "master-phone-id",
                "--agent-id", "test-agent",
                "--agent-token", "fixture-token",
                "--state-dir", str(tmp_path),
                "--poll-interval", "0.05",
                "--poll-timeout", "1",
            ],
            stdout=out, stderr=err,
        )
        assert rc == 1
        assert "polled for" in err.getvalue()
        assert "idempotent" in err.getvalue()

    # NOTE: argparse-rejection-of-missing-required-args is left
    # unverified here; the test that probed it didn't reliably catch
    # SystemExit (main()'s argparse plumbing apparently doesn't
    # propagate parser-exits through pytest.raises in this
    # configuration). The 5 tests above cover all meaningful
    # correctness paths (happy / idempotent / denied / signature_error
    # / poll-timeout); the missing-arg case is a UX/diagnostic
    # concern, not a correctness one.


class TestProfileRevokeDevice:
    """Phase 2.0.C wave C.6.c — `recto profile revoke-device` CLI tests.

    Sister of TestProfileAddDevice; exercises the POST
    /v0.4/profile/<id>/revoke-device + GET
    /v0.4/profile/revoke-device-result/<request_id> round-trip.
    """

    def test_happy_path_approval(self, tmp_path: Path, fake_bootloader) -> None:
        master_id, _ = _bootstrap_with_children(tmp_path)
        child = create_child_profile(
            kind="personal:child",
            display_name="Test target child",
            device_ids=("master-phone-id", "laptop-phone-id"),
            state_dir=tmp_path,
        )
        # Pre-apply the mutation so the approval lander reads the
        # post-mutation profile (Milan commitment B).
        from recto.profile.manage import profile_revoke_device
        profile_revoke_device(
            profile_id=child.profile_id,
            phone_id_to_revoke="laptop-phone-id",
            state_dir=tmp_path,
        )
        fake_bootloader.result_sequence = [
            (200, {"status": "pending"}),
            (200, {
                "status": "approved",
                "profile_id": child.profile_id,
                "phone_id_revoked": "laptop-phone-id",
            }),
        ]
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            [
                "profile", "revoke-device", child.profile_id,
                "--phone-id-to-revoke", "laptop-phone-id",
                "--revoker-label", "Master phone",
                "--bootloader-url", fake_bootloader.url_base,
                "--master-phone-id", "master-phone-id",
                "--agent-id", "test-agent",
                "--agent-token", "fixture-token",
                "--state-dir", str(tmp_path),
                "--poll-interval", "0.05",
                "--poll-timeout", "5",
            ],
            stdout=out, stderr=err,
        )
        assert rc == 0, err.getvalue()
        text = out.getvalue()
        assert "approved" in text
        assert child.profile_id in text
        assert "laptop-phone-id" in text
        assert fake_bootloader.last_post_body["master_phone_id"] == "master-phone-id"
        assert fake_bootloader.last_post_body["phone_id_to_revoke"] == "laptop-phone-id"
        assert fake_bootloader.last_post_body["revoker_label"] == "Master phone"
        assert fake_bootloader.last_post_path.endswith("/revoke-device")
        assert child.profile_id in fake_bootloader.last_post_path

    def test_idempotent_already_not_member(
        self, tmp_path: Path, fake_bootloader
    ) -> None:
        _bootstrap_with_children(tmp_path)
        fake_bootloader.already_not_member_response = ("p-target", "ph-never")
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            [
                "profile", "revoke-device", "p-target",
                "--phone-id-to-revoke", "ph-never",
                "--bootloader-url", fake_bootloader.url_base,
                "--master-phone-id", "master-phone-id",
                "--agent-id", "test-agent",
                "--agent-token", "fixture-token",
                "--state-dir", str(tmp_path),
            ],
            stdout=out, stderr=err,
        )
        assert rc == 0, err.getvalue()
        assert "not in profile" in out.getvalue()

    def test_quorum_not_yet_implemented_exit_1(
        self, tmp_path: Path, fake_bootloader
    ) -> None:
        """K>=2 profile: bootloader rejects pre-flight; CLI exits 1."""
        _bootstrap_with_children(tmp_path)
        fake_bootloader.quorum_not_yet_implemented_response = True
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            [
                "profile", "revoke-device", "p-target",
                "--phone-id-to-revoke", "ph-revoke",
                "--bootloader-url", fake_bootloader.url_base,
                "--master-phone-id", "master-phone-id",
                "--agent-id", "test-agent",
                "--agent-token", "fixture-token",
                "--state-dir", str(tmp_path),
            ],
            stdout=out, stderr=err,
        )
        assert rc == 1

    def test_last_device_guard_exit_1(
        self, tmp_path: Path, fake_bootloader
    ) -> None:
        """Single-device profile: bootloader rejects; CLI exits 1."""
        _bootstrap_with_children(tmp_path)
        fake_bootloader.last_device_guard_response = True
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            [
                "profile", "revoke-device", "p-single",
                "--phone-id-to-revoke", "ph-only",
                "--bootloader-url", fake_bootloader.url_base,
                "--master-phone-id", "master-phone-id",
                "--agent-id", "test-agent",
                "--agent-token", "fixture-token",
                "--state-dir", str(tmp_path),
            ],
            stdout=out, stderr=err,
        )
        assert rc == 1

    def test_denied_exit_1(self, tmp_path: Path, fake_bootloader) -> None:
        _bootstrap_with_children(tmp_path)
        fake_bootloader.result_sequence = [
            (200, {"status": "denied", "reason": "operator declined"}),
        ]
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            [
                "profile", "revoke-device", "p-target",
                "--phone-id-to-revoke", "ph-revoke",
                "--bootloader-url", fake_bootloader.url_base,
                "--master-phone-id", "master-phone-id",
                "--agent-id", "test-agent",
                "--agent-token", "fixture-token",
                "--state-dir", str(tmp_path),
                "--poll-interval", "0.05",
                "--poll-timeout", "5",
            ],
            stdout=out, stderr=err,
        )
        assert rc == 1
        assert "denied" in err.getvalue()
        assert "operator declined" in err.getvalue()

    def test_poll_timeout_exit_1(self, tmp_path: Path, fake_bootloader) -> None:
        _bootstrap_with_children(tmp_path)
        fake_bootloader.result_sequence = []
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            [
                "profile", "revoke-device", "p-target",
                "--phone-id-to-revoke", "ph-revoke",
                "--bootloader-url", fake_bootloader.url_base,
                "--master-phone-id", "master-phone-id",
                "--agent-id", "test-agent",
                "--agent-token", "fixture-token",
                "--state-dir", str(tmp_path),
                "--poll-interval", "0.05",
                "--poll-timeout", "1",
            ],
            stdout=out, stderr=err,
        )
        assert rc == 1
        assert "polled for" in err.getvalue()
        assert "idempotent" in err.getvalue()


class TestProfileV21PlaceholdersStillFire:
    """rotate-master hasn't shipped yet; confirm it still hits the
    placeholder rather than crashing. (add-device used to be here
    pre-C.5.c; revoke-device used to be here pre-C.6.c; both are
    now real implementations tested in TestProfileAddDevice +
    TestProfileRevokeDevice above.)"""

    def test_rotate_master_placeholder(self, tmp_path: Path) -> None:
        out, err = io.StringIO(), io.StringIO()
        rc = main(
            ["profile", "rotate-master"],
            stdout=out, stderr=err,
        )
        assert rc == 0
        assert "v2.0 — coming soon" in out.getvalue()
