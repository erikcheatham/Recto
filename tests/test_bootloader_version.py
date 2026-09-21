"""GATE 3 prerequisite #2 -- /v0.4/version, so a bootloader can say what it is.

Until 2026-08-18 the only way to learn which commit a bootloader was serving
was to read the Docker image label from the host. That check is good -- on its
first use it found a container serving a PRE-GENESIS build for weeks while CI
reported green -- and it is not enough, because it needs a shell on the machine.
No phone, no client, no remote operator could ask.

`recto --version` could not answer either: `__version__` was a hardcoded
"0.1.0.dev0" while pyproject declared "1.0.0". One value, two places, months of
disagreement, and the only symptom was a CLI reporting a version that had not
existed for a long time.

THE POSITIVE CONTROL HERE IS THE 404. Adding a route can turn a router into a
catch-all, and a suite that only asserts "/v0.4/version returns 200" would go
green over a server answering 200 to everything. `test_an_unknown_path_still_404s`
is what distinguishes "the route was added" from "the router stopped routing".
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any
from urllib import request as urlrequest
from urllib.error import HTTPError

import pytest

from recto import __version__
from recto.bootloader.server import ChallengeStore, create_server
from recto.bootloader.state import StateStore


def _get(url: str) -> tuple[int, dict[str, Any]]:
    try:
        with urlrequest.urlopen(url, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8") or "{}")
    except HTTPError as exc:
        raw = exc.read().decode("utf-8")
        try:
            return exc.code, json.loads(raw or "{}")
        except json.JSONDecodeError:
            return exc.code, {"raw": raw}


@pytest.fixture
def server_ctx(tmp_path: Path):
    server = create_server(
        bind_host="127.0.0.1",
        bind_port=0,
        state=StateStore(state_dir=tmp_path),
        bootloader_id="version-test-bootloader",
        challenges=ChallengeStore(),
        ssl_context=None,
    )
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)


# --------------------------------------------------------------------------
# THE POSITIVE CONTROL
# --------------------------------------------------------------------------

def test_an_unknown_path_still_404s(server_ctx):
    """Adding a route must not turn the router into a catch-all."""
    status, _ = _get(f"{server_ctx}/v0.4/definitely-not-a-route")
    assert status == 404, (
        "an unknown path did not 404 -- the router answers everything, so any "
        "other assertion in this file proves nothing about /v0.4/version."
    )


# --------------------------------------------------------------------------
# THE ENDPOINT
# --------------------------------------------------------------------------

def test_version_endpoint_reports_the_package_version(server_ctx):
    status, body = _get(f"{server_ctx}/v0.4/version")
    assert status == 200, f"/v0.4/version not served: {status} {body}"
    assert body["version"] == __version__
    assert body["bootloader_id"] == "version-test-bootloader"


def test_the_version_is_not_a_hardcoded_string(server_ctx):
    """The defect this replaced was a literal that drifted from pyproject.

    `__version__` now reads installed package metadata, so it cannot disagree
    with the declaration. A test asserting a specific number would reintroduce
    exactly the second copy that caused the problem -- so this asserts the SHAPE
    and the absence of the known-stale value instead.
    """
    _, body = _get(f"{server_ctx}/v0.4/version")
    assert body["version"] != "0.1.0.dev0", (
        "reporting the stale hardcoded version again -- check that __version__ "
        "queries the 'recto-core' distribution and not the retired 'recto' name."
    )
    assert body["version"][0].isdigit(), f"not a version: {body['version']!r}"


def test_revision_and_created_come_from_the_build_stamp(server_ctx, monkeypatch):
    """The Dockerfile has exported these into the container all along.

    Nothing read them until now, which is why the running commit was knowable
    only from outside, via the image label.
    """
    monkeypatch.setenv("RECTO_BUILD_REVISION", "abc1234")
    monkeypatch.setenv("RECTO_BUILD_CREATED", "2026-08-18T00:00:00Z")
    _, body = _get(f"{server_ctx}/v0.4/version")
    assert body["revision"] == "abc1234"
    assert body["created"] == "2026-08-18T00:00:00Z"


def test_an_unstamped_build_says_unknown_rather_than_guessing(server_ctx,
                                                              monkeypatch):
    """ABSENT AND STALE MUST NOT LOOK THE SAME.

    A build made without the stamp genuinely does not know its commit. Omitting
    the field, or substituting a plausible value, is how a container served a
    pre-genesis build unnoticed for weeks. "unknown" is the honest answer and it
    is returned verbatim.
    """
    monkeypatch.delenv("RECTO_BUILD_REVISION", raising=False)
    monkeypatch.delenv("RECTO_BUILD_CREATED", raising=False)
    _, body = _get(f"{server_ctx}/v0.4/version")
    assert body["revision"] == "unknown"
    assert body["created"] == "unknown"
    assert "revision" in body, "the field must be PRESENT and say unknown"
