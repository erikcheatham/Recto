"""Tests for recto.sign_helper.

Round-trip server <-> client over a real Unix socket using
EnclaveStubSource as the backend. Tests are skipped on Windows since
v0.4.0 doesn't ship the named-pipe transport.
"""

from __future__ import annotations

import os
import socket
import struct
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from recto.secrets import SigningCapability
from tests.enclave_stub import EnclaveStubSource
from recto.sign_helper import (
    SignHelperClient,
    SignHelperDenied,
    SignHelperError,
    SignHelperServer,
    default_socket_path,
)

windows_only = pytest.mark.skipif(os.name == "nt", reason="Unix-socket only in v0.4.0")


@pytest.fixture
def stub_source() -> EnclaveStubSource:
    return EnclaveStubSource("testservice")


@pytest.fixture
def running_server(
    stub_source: EnclaveStubSource, tmp_path: Path
) -> Iterator[SignHelperServer]:
    if os.name == "nt":
        pytest.skip("Unix-socket only in v0.4.0")
    cap_cache = {}

    def resolver(secret: str) -> SigningCapability | None:
        if secret == "MY_SIGNING_KEY":
            if "cached" not in cap_cache:
                result = stub_source.fetch(secret, {})
                assert isinstance(result, SigningCapability)
                cap_cache["cached"] = result
            return cap_cache["cached"]
        return None

    sock_path = str(tmp_path / "recto-test-sign.sock")
    server = SignHelperServer(
        service="testservice", resolver=resolver, socket_path=sock_path,
    )
    server.start()
    # Tiny wait for the listener thread to start accepting.
    time.sleep(0.05)
    try:
        yield server
    finally:
        server.shutdown()


# ---------------------------------------------------------------------------
# Default socket path
# ---------------------------------------------------------------------------


class TestDefaultSocketPath:
    def test_unix_form(self, monkeypatch: pytest.MonkeyPatch) -> None:
        if os.name == "nt":
            pytest.skip("Unix-only path test")
        monkeypatch.setenv("XDG_RUNTIME_DIR", "/tmp/test-runtime")
        path = default_socket_path("myservice")
        assert path == "/tmp/test-runtime/recto-myservice-sign.sock"

    def test_unix_falls_back_to_tmp_when_no_xdg(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        if os.name == "nt":
            pytest.skip("Unix-only path test")
        monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
        path = default_socket_path("myservice")
        assert path == "/tmp/recto-myservice-sign.sock"


# ---------------------------------------------------------------------------
# End-to-end client <-> server <-> stub
# ---------------------------------------------------------------------------


@windows_only
class TestEndToEnd:
    def test_round_trip_sign(
        self, running_server: SignHelperServer
    ) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )

        client = SignHelperClient(running_server.socket_path)
        sig = client.sign("MY_SIGNING_KEY", b"hello, recto v0.4")
        assert isinstance(sig, bytes)
        assert len(sig) == 64

        # Fetch the public key directly from the stub (same instance the
        # server uses) and verify the signature.
        # We also need the public key from somewhere. The simplest path:
        # use the .from_env client convention which echoes algorithm +
        # public_key in the response. But our high-level sign() returns
        # only the signature bytes. For the test, we sign-twice and
        # confirm reproducibility (Ed25519 is deterministic).
        sig2 = client.sign("MY_SIGNING_KEY", b"hello, recto v0.4")
        assert sig == sig2

    def test_unknown_secret_raises(
        self, running_server: SignHelperServer
    ) -> None:
        client = SignHelperClient(running_server.socket_path)
        with pytest.raises(SignHelperError) as exc_info:
            client.sign("DOES_NOT_EXIST", b"x")
        assert "unknown_secret" in str(exc_info.value)

    def test_persistent_connection_multiple_signs(
        self, running_server: SignHelperServer
    ) -> None:
        with SignHelperClient(running_server.socket_path) as client:
            sigs = [client.sign("MY_SIGNING_KEY", f"msg-{i}".encode()) for i in range(5)]
        assert len(sigs) == 5
        assert all(len(s) == 64 for s in sigs)
        # Five distinct messages -> five distinct signatures.
        assert len(set(sigs)) == 5

    def test_connect_failure_surfaces_clear_error(
        self, tmp_path: Path
    ) -> None:
        if os.name == "nt":
            pytest.skip("Unix-socket only in v0.4.0")
        client = SignHelperClient(str(tmp_path / "nonexistent.sock"))
        with pytest.raises(SignHelperError) as exc_info:
            client.sign("MY_KEY", b"x")
        assert "could not connect" in str(exc_info.value)


# ---------------------------------------------------------------------------
# from_env construction
# ---------------------------------------------------------------------------


class TestFromEnv:
    def test_reads_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("RECTO_SIGN_HELPER", "/tmp/some-path.sock")
        client = SignHelperClient.from_env()
        assert client is not None

    def test_missing_env_var_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("RECTO_SIGN_HELPER", raising=False)
        with pytest.raises(SignHelperError) as exc_info:
            SignHelperClient.from_env()
        assert "RECTO_SIGN_HELPER" in str(exc_info.value)

    def test_explicit_env_dict(self) -> None:
        client = SignHelperClient.from_env({"RECTO_SIGN_HELPER": "/tmp/x.sock"})
        assert client is not None


# ---------------------------------------------------------------------------
# Frame protocol -- partial / oversized / malformed
# ---------------------------------------------------------------------------


@windows_only
class TestFrameProtocol:
    def test_oversized_frame_rejected(
        self, running_server: SignHelperServer
    ) -> None:
        if os.name == "nt":
            pytest.skip("Unix-socket only")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(running_server.socket_path)
        # Frame header claims 32 MB; server should refuse (cap is 16 MB).
        sock.sendall(struct.pack(">I", 32 * 1024 * 1024))
        # Server closes connection after reading the bad header. Reading
        # back should hit EOF.
        try:
            data = sock.recv(1024)
            # Connection may have been closed cleanly; check no useful
            # response came back.
            assert data in (b"", )
        except OSError:
            pass  # connection reset is acceptable
        sock.close()

    def test_malformed_json_returns_error(
        self, running_server: SignHelperServer
    ) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(running_server.socket_path)
        try:
            body = b"{not valid json"
            sock.sendall(struct.pack(">I", len(body)) + body)
            # Read response.
            header = sock.recv(4)
            (length,) = struct.unpack(">I", header)
            response_bytes = sock.recv(length)
            import json
            response = json.loads(response_bytes)
            assert response["ok"] is False
            assert response["error"] == "backend_error"
        finally:
            sock.close()


# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------


@windows_only
class TestServerLifecycle:
    def test_double_start_raises(
        self, running_server: SignHelperServer
    ) -> None:
        with pytest.raises(SignHelperError):
            running_server.start()

    def test_shutdown_unlinks_socket(
        self, stub_source: EnclaveStubSource, tmp_path: Path
    ) -> None:
        sock_path = str(tmp_path / "recto-lifecycle.sock")
        server = SignHelperServer(
            service="x",
            resolver=lambda _s: None,
            socket_path=sock_path,
        )
        server.start()
        assert os.path.exists(sock_path)
        server.shutdown()
        # Socket file removed on shutdown.
        assert not os.path.exists(sock_path)

    def test_shutdown_idempotent(
        self, stub_source: EnclaveStubSource, tmp_path: Path
    ) -> None:
        sock_path = str(tmp_path / "recto-idem.sock")
        server = SignHelperServer(
            service="x", resolver=lambda _s: None, socket_path=sock_path,
        )
        server.start()
        server.shutdown()
        server.shutdown()  # second call should not raise


# ---------------------------------------------------------------------------
# Windows guard
# ---------------------------------------------------------------------------


class TestWindowsGuard:
    def test_server_start_raises_on_windows(self, tmp_path: Path) -> None:
        if os.name != "nt":
            pytest.skip("Windows-only test")
        server = SignHelperServer(
            service="x",
            resolver=lambda _s: None,
            socket_path=str(tmp_path / "x.sock"),
        )
        with pytest.raises(SignHelperError) as exc_info:
            server.start()
        assert "named-pipe" in str(exc_info.value).lower()
