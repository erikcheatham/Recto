"""Local-socket sign-helper for v0.4 SigningCapability secrets.

When the launcher resolves a `spec.secrets[].source` to a backend that
returns SigningCapability (vs DirectSecret), it cannot inject the
secret as an env var on the child -- there's no "value", only a sign
callable. Instead the launcher exposes a local socket the child can
connect to and request sign operations over. This module implements
both ends:

- `SignHelperServer` runs in the launcher process, listening on a
  per-service Unix socket (Linux/macOS) or named pipe (Windows). Each
  client connection sends sign requests; the server routes them to
  the right SigningCapability and returns signatures.
- `SignHelperClient` ships in this same module so consumer apps can
  import and use it directly. Other languages (C#, Go, Rust) get the
  wire-protocol docs in `docs/v0.4-signhelper-clients.md` (TBD) so
  they can implement their own clients.

## Wire protocol

Length-prefixed JSON over a stream socket. Each frame is:

    [4 bytes BE length][N bytes UTF-8 JSON]

Request shape:

    {
      "kind": "sign",
      "secret": "MY_SIGNING_KEY",
      "payload_b64u": "<base64url of the payload to sign>"
    }

Response shape (success):

    {
      "ok": true,
      "signature_b64u": "<base64url of the signature>",
      "algorithm": "ed25519",
      "public_key_b64u": "<base64url of the public key>"
    }

Response shape (failure):

    {
      "ok": false,
      "error": "denied" | "unknown_secret" | "backend_error",
      "detail": "<human-readable detail>"
    }

The protocol is request-response over a single connection; clients can
keep the connection open across many sign requests, or open a fresh
connection per request. Server-side concurrency is one thread per
connection.

## Auth model

The socket / named pipe is operator-private (Linux/macOS: chmod 0600 on
the socket file; Windows: named-pipe ACL set to the service-account
SID). Any process running as the same user can connect; the launcher
trusts the OS to enforce the boundary. Out-of-process auth (per-child-
PID gating, per-secret ACLs) is followup work; v0.4.0 is "if you can
open the socket, you can ask for signatures."
"""

from __future__ import annotations

import base64
import json
import os
import socket
import struct
import sys
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from recto.secrets.base import SigningCapability

__all__ = [
    "SignHelperServer",
    "SignHelperClient",
    "SignHelperError",
    "SignHelperDenied",
    "default_socket_path",
]


class SignHelperError(Exception):
    """Generic sign-helper error (transport, framing, protocol)."""


class SignHelperDenied(SignHelperError):
    """The phone (or stub backend) denied the sign request. Distinct
    from generic transport failures so consumer apps can distinguish
    'operator said no' from 'network is broken'."""


def default_socket_path(service: str) -> str:
    """Per-service socket path. Called by the launcher when starting
    the helper, and by the client when reading the env-var-set path."""
    if os.name == "nt":
        return f"\\\\.\\pipe\\recto-{service}-sign"
    runtime = os.environ.get("XDG_RUNTIME_DIR") or "/tmp"
    return f"{runtime}/recto-{service}-sign.sock"


# ---------------------------------------------------------------------------
# Frame I/O (shared by client + server)
# ---------------------------------------------------------------------------


def _write_frame(sock: socket.socket, body: bytes) -> None:
    """Write a length-prefixed frame. Raises SignHelperError on partial
    write (which would otherwise corrupt the stream)."""
    header = struct.pack(">I", len(body))
    try:
        sock.sendall(header + body)
    except OSError as exc:
        raise SignHelperError(f"write failed: {exc}") from exc


def _read_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes. Raises SignHelperError on short read
    (peer closed mid-frame)."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise SignHelperError(
                f"connection closed mid-frame: expected {n} bytes, "
                f"got {len(buf)}"
            )
        buf.extend(chunk)
    return bytes(buf)


def _read_frame(sock: socket.socket) -> bytes:
    """Read a single length-prefixed frame body. Raises SignHelperError
    on framing errors."""
    header = _read_exact(sock, 4)
    (length,) = struct.unpack(">I", header)
    if length > 16 * 1024 * 1024:  # 16 MB cap
        raise SignHelperError(f"frame too large: {length} bytes")
    return _read_exact(sock, length)


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64u_decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


# ---------------------------------------------------------------------------
# Server (launcher side)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Resolution:
    """Result of resolving a (secret_name) to a SigningCapability."""

    capability: SigningCapability


CapabilityResolver = Callable[[str], SigningCapability | None]
"""Callable that takes a secret_name and returns the SigningCapability
to sign with, or None if the secret is unknown to this server."""


class SignHelperServer:
    """Listen on a per-service socket; route sign requests to backends.

    The launcher constructs one of these per service that has any
    SigningCapability secrets, passes a resolver callable that maps
    secret_name -> SigningCapability, and starts it on a background
    thread. The server runs until `shutdown()` is called (typically
    when the launcher itself shuts down).
    """

    def __init__(
        self,
        *,
        service: str,
        resolver: CapabilityResolver,
        socket_path: str | None = None,
    ):
        self._service = service
        self._resolver = resolver
        self._path = socket_path if socket_path is not None else default_socket_path(service)
        self._listener: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    @property
    def socket_path(self) -> str:
        return self._path

    def start(self) -> None:
        """Bind, listen, and spawn the accept thread. Returns once the
        socket is ready to accept connections (so the launcher can set
        the env var on the child knowing the path resolves)."""
        if self._listener is not None:
            raise SignHelperError("server already started")
        if os.name == "nt":
            raise SignHelperError(
                "Windows named-pipe transport not yet implemented; "
                "v0.4.0 ships Unix sockets only. Pass a custom socket_path "
                "via SignHelperServer constructor for cross-platform stubs."
            )
        # Unlink any stale socket from a previous run.
        try:
            os.unlink(self._path)
        except FileNotFoundError:
            pass
        self._listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._listener.bind(self._path)
        os.chmod(self._path, 0o600)
        self._listener.listen(8)
        self._listener.settimeout(0.5)
        self._thread = threading.Thread(
            target=self._accept_loop, name=f"recto-sign-helper-{self._service}",
            daemon=True,
        )
        self._thread.start()

    def shutdown(self) -> None:
        """Stop accepting new connections; let in-flight handlers finish.
        Safe to call multiple times."""
        self._stop_event.set()
        if self._listener is not None:
            try:
                self._listener.close()
            except OSError:
                pass
            self._listener = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        try:
            os.unlink(self._path)
        except FileNotFoundError:
            pass

    def _accept_loop(self) -> None:
        listener = self._listener
        if listener is None:
            return
        while not self._stop_event.is_set():
            try:
                conn, _ = listener.accept()
            except (TimeoutError, OSError):
                continue
            handler = threading.Thread(
                target=self._handle_connection, args=(conn,), daemon=True,
            )
            handler.start()

    def _handle_connection(self, conn: socket.socket) -> None:
        try:
            with conn:
                while not self._stop_event.is_set():
                    try:
                        body = _read_frame(conn)
                    except SignHelperError:
                        return
                    response = self._dispatch(body)
                    _write_frame(conn, response)
        except OSError:
            return

    def _dispatch(self, request_bytes: bytes) -> bytes:
        try:
            req = json.loads(request_bytes.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return self._error("backend_error", "invalid JSON")
        if not isinstance(req, dict):
            return self._error("backend_error", "request must be a JSON object")
        kind = req.get("kind")
        if kind != "sign":
            return self._error("backend_error", f"unknown kind {kind!r}")
        secret = req.get("secret", "")
        payload_b64u = req.get("payload_b64u", "")
        if not secret or not payload_b64u:
            return self._error("backend_error", "secret and payload_b64u required")
        try:
            payload = _b64u_decode(payload_b64u)
        except (ValueError, base64.binascii.Error):
            return self._error("backend_error", "payload_b64u not valid base64url")
        cap = self._resolver(secret)
        if cap is None:
            return self._error("unknown_secret", f"secret {secret!r} not configured")
        try:
            sig = cap.sign(payload)
        except SignHelperDenied as exc:
            return self._error("denied", str(exc))
        except Exception as exc:  # noqa: BLE001
            return self._error("backend_error", f"sign failed: {exc}")
        body = json.dumps({
            "ok": True,
            "signature_b64u": _b64u(sig),
            "algorithm": cap.algorithm,
            "public_key_b64u": _b64u(cap.public_key),
        }).encode("utf-8")
        return body

    @staticmethod
    def _error(code: str, detail: str) -> bytes:
        return json.dumps({
            "ok": False,
            "error": code,
            "detail": detail,
        }).encode("utf-8")


# ---------------------------------------------------------------------------
# Client (child-process side)
# ---------------------------------------------------------------------------


class SignHelperClient:
    """Reference Python client. Connects on demand, signs, returns.

    Typical use from a consumer app:

        from recto.sign_helper import SignHelperClient
        client = SignHelperClient.from_env()  # reads RECTO_SIGN_HELPER
        sig = client.sign("MY_SIGNING_KEY", b"hello")
        # sig is the raw 64-byte Ed25519 signature

    The client opens a fresh connection per `sign()` call by default.
    For high-frequency signing, use `connect()` once + reuse `sign()`
    on the persistent connection.
    """

    def __init__(self, socket_path: str):
        self._path = socket_path
        self._conn: socket.socket | None = None

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> SignHelperClient:
        """Construct from the RECTO_SIGN_HELPER env var. Raises
        SignHelperError if the var isn't set."""
        env = env if env is not None else os.environ
        path = env.get("RECTO_SIGN_HELPER")
        if not path:
            raise SignHelperError(
                "RECTO_SIGN_HELPER env var not set; this consumer app is "
                "expected to be launched under Recto with a v0.4 enclave-"
                "backed secret. If you're running standalone, set the env "
                "var to the launcher's sign-helper socket path."
            )
        return cls(path)

    def connect(self) -> None:
        """Open a persistent connection. Call sign() repeatedly; close
        with disconnect() when done."""
        if self._conn is not None:
            return
        if os.name == "nt":
            raise SignHelperError(
                "Windows named-pipe client not yet implemented; "
                "v0.4.0 ships Unix sockets only."
            )
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(self._path)
        except OSError as exc:
            raise SignHelperError(
                f"could not connect to sign helper at {self._path}: {exc}"
            ) from exc
        self._conn = sock

    def disconnect(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except OSError:
                pass
            self._conn = None

    def sign(self, secret: str, payload: bytes) -> bytes:
        """Request a signature. Returns the raw 64-byte Ed25519
        signature on success.

        Raises SignHelperDenied if the operator (or stub backend)
        refused the sign request. Raises SignHelperError on any other
        protocol or transport failure.
        """
        own_conn = False
        if self._conn is None:
            self.connect()
            own_conn = True
        conn = self._conn
        if conn is None:  # pragma: no cover - connect() raises on failure
            raise SignHelperError("connect failed silently")
        try:
            req = json.dumps({
                "kind": "sign",
                "secret": secret,
                "payload_b64u": _b64u(payload),
            }).encode("utf-8")
            _write_frame(conn, req)
            response_bytes = _read_frame(conn)
            response = json.loads(response_bytes.decode("utf-8"))
            if not isinstance(response, dict):
                raise SignHelperError("response was not a JSON object")
            if not response.get("ok"):
                err = response.get("error", "unknown")
                detail = response.get("detail", "")
                if err == "denied":
                    raise SignHelperDenied(detail)
                raise SignHelperError(f"sign failed: {err}: {detail}")
            sig_b64u = response.get("signature_b64u", "")
            return _b64u_decode(sig_b64u)
        finally:
            if own_conn:
                self.disconnect()

    def __enter__(self) -> SignHelperClient:
        self.connect()
        return self

    def __exit__(self, *_args: Any) -> None:
        self.disconnect()
