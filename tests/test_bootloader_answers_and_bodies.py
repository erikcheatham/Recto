"""An answer takes a card only when it holds up; a request body has a ceiling; a quiet connection closes.

- ``POST /v0.4/respond/<id>`` reads the card and takes it only for a known decision that holds up: a decision
  that is neither ``approved`` nor ``denied``, or an approval whose signature does not verify against the paired
  phone's key, leaves the card on the queue and resolves nothing.
- A JSON body may declare at most ``MAX_JSON_BODY_BYTES``: a larger one is refused with 413 before it is read,
  and a Content-Length that is not a number is a client error.
- A connection that sends nothing closes after the handler's timeout instead of holding its thread.
"""

from __future__ import annotations

import http.client
import socket
import time
from http import HTTPStatus
from urllib.parse import urlparse

import pytest

from recto.bootloader.server import (
    MAX_JSON_BODY_BYTES,
    REQUEST_SOCKET_TIMEOUT_SECONDS,
    BootloaderHandler,
)
from recto.bootloader.state import PendingRequest
from tests.test_bootloader_signed_polls import _b64u, _http, _spawn


@pytest.fixture
def boot(tmp_path):
    ctx = _spawn(tmp_path, "advisory")
    yield ctx
    ctx["server"].shutdown()


def _card(ctx) -> PendingRequest:
    req = PendingRequest.new(
        kind="single_sign",
        service="svc",
        secret="API_KEY",
        phone_id=ctx["phone"].phone_id,
        operation_description="an answer that must hold up",
        payload_hash_b64u=_b64u(b"\x01" * 32),
        child_pid=1234,
        child_argv0="pytest",
    )
    ctx["state"].add_pending(req)
    return req


def test_an_unknown_decision_leaves_the_card(boot):
    req = _card(boot)
    status, _ = _http(f"{boot['base_url']}/v0.4/respond/{req.request_id}", method="POST",
                      body={"decision": "maybe"})
    assert status == HTTPStatus.BAD_REQUEST
    assert boot["state"].peek_pending(req.request_id) is not None


def test_an_approval_that_does_not_verify_leaves_the_card(boot):
    req = _card(boot)
    status, body = _http(f"{boot['base_url']}/v0.4/respond/{req.request_id}", method="POST",
                         body={"decision": "approved", "signature_b64u": _b64u(b"\x00" * 64)})
    assert status == HTTPStatus.BAD_REQUEST
    assert "signature invalid" in body["detail"]
    assert boot["state"].peek_pending(req.request_id) is not None


def test_a_card_answered_twice_is_taken_once(boot):
    req = _card(boot)
    url = f"{boot['base_url']}/v0.4/respond/{req.request_id}"
    assert _http(url, method="POST", body={"decision": "denied", "reason": "no"})[0] == HTTPStatus.OK
    assert boot["state"].peek_pending(req.request_id) is None
    status, body = _http(url, method="POST", body={"decision": "denied", "reason": "no"})
    assert status == HTTPStatus.BAD_REQUEST
    assert "not found" in body["detail"]


def _raw_post(ctx, path: str, *, body: bytes, headers: dict[str, str]):
    parts = urlparse(ctx["base_url"])
    conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=5)
    try:
        conn.putrequest("POST", path)
        for k, v in headers.items():
            conn.putheader(k, v)
        conn.endheaders()
        if body:
            conn.send(body)
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


def test_a_body_over_the_ceiling_is_refused_before_it_is_read(boot):
    # Declares one byte over the ceiling and sends none of it: a server that read the body would wait here.
    status, raw = _raw_post(boot, "/v0.4/secrets/read", body=b"",
                            headers={"Content-Type": "application/json",
                                     "Content-Length": str(MAX_JSON_BODY_BYTES + 1)})
    assert status == HTTPStatus.REQUEST_ENTITY_TOO_LARGE
    assert b"request_body_too_large" in raw


def test_a_content_length_that_is_not_a_number_is_a_client_error(boot):
    status, raw = _raw_post(boot, "/v0.4/secrets/read", body=b"{}",
                            headers={"Content-Type": "application/json", "Content-Length": "two"})
    assert status == HTTPStatus.BAD_REQUEST
    assert b"Content-Length" in raw


def test_the_handler_carries_a_socket_timeout():
    assert BootloaderHandler.timeout == REQUEST_SOCKET_TIMEOUT_SECONDS
    assert 0 < REQUEST_SOCKET_TIMEOUT_SECONDS <= 60


def test_a_connection_that_sends_nothing_closes(boot, monkeypatch):
    monkeypatch.setattr(BootloaderHandler, "timeout", 1)
    parts = urlparse(boot["base_url"])
    with socket.create_connection((parts.hostname, parts.port), timeout=10) as sock:
        started = time.monotonic()
        # The server closes the idle connection: recv returns b"" (or the peer resets it).
        try:
            data = sock.recv(1024)
        except ConnectionResetError:
            data = b""
        assert data == b""
        assert time.monotonic() - started < 9
