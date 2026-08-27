#!/usr/bin/env python3
"""
Recto v0.4 mock bootloader. Single-file dev harness for the phone app.

Implements the two protocol endpoints the phone needs at pairing time
(`GET /v0.4/registration_challenge` and `POST /v0.4/register`), plus a
small operator-side index page where you can mint pairing codes, watch
incoming requests, and clear state.

Stdlib only. Optionally uses the `cryptography` package
(`pip install cryptography`) to verify the phone's Ed25519 signature;
absent it, the mock accepts any signature and prints a startup warning.

Usage:
    python mock-bootloader.py
    python mock-bootloader.py --port 8443 --no-verify

Then in the phone app:
    bootloader URL = http://localhost:8443
    pairing code   = (printed at startup; mint more via the index page)
"""
from __future__ import annotations

import argparse
import atexit
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import pathlib
import secrets
import ssl
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import deque
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# Auto-locate the Recto repo root so recto.solana / recto.stellar /
# recto.ripple / recto.bitcoin / recto.ethereum are importable without
# the operator having to pre-set PYTHONPATH. The mock lives at
# <repo>/phone/RectoMAUIBlazor/dev-tools/mock-bootloader.py — the repo
# root is three directories up. Without this, hosts that run the mock
# from a non-repo-rooted Python (e.g. via a build cache or a
# PYTHONPATH-stripped wrapper) hit "No module named 'recto'" on every
# chain-side address-recovery / signature-verify step and operators see
# "address recovery failed" warnings next to perfectly-valid signatures.
# Self-locating sidesteps that — the mock now Just Works from any cwd,
# any Python invocation, as long as the source tree is laid out
# canonically.
_repo_root = pathlib.Path(__file__).resolve().parents[3]
if (_repo_root / "recto").is_dir() and str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    from cryptography.x509.oid import NameOID
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

# Stash for the SPKI pin so the operator UI can surface it. Set during main()
# when --tls is on; left as None when running over plain HTTP. Using a module-
# level global rather than threading state on STATE keeps the cert ephemeral
# and obviously-not-persisted (it's regenerated every startup, by design --
# the phone captures the pin during pairing and it's good for the lifetime
# of that pairing).
TLS_SPKI_PIN: str | None = None

# v0.4.1 push-send credentials. Configured in main() from CLI flags; absent
# means the corresponding transport falls back to the "would send" log stub.
# OAuth2 access tokens (FCM) and provider JWTs (APNs) are cached under
# module-level locks since they're valid for an hour at a time and re-issuing
# on every send would be wasteful.
_FCM_CONFIG: dict | None = None
_FCM_OAUTH_TOKEN: dict | None = None  # {access_token, expires_at_unix}
_FCM_LOCK = threading.Lock()
_APNS_CONFIG: dict | None = None       # {key_path, key_id, team_id, bundle_id, environment}
_APNS_JWT: dict | None = None          # {token, expires_at_unix}
_APNS_LOCK = threading.Lock()

# Algorithms the mock knows how to verify. Mirrors the v0.4 protocol RFC's
# `supported_algorithms` enumeration; phone advertises one, mock verifies with it.
ALG_ED25519 = "ed25519"
ALG_ECDSA_P256 = "ecdsa-p256"
KNOWN_ALGORITHMS = (ALG_ED25519, ALG_ECDSA_P256)


# ---- in-memory state -------------------------------------------------------

class State:
    """Single mock state. Locked because the HTTP handler is threaded."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.bootloader_id = str(uuid.uuid4())
        # code -> expires_at_unix
        self.pairing_codes: dict[str, float] = {}
        # code -> (challenge_b64u, expires_at_unix)
        self.challenges: dict[str, tuple[str, float]] = {}
        # [{phone_id, device_label, public_key_b64u, algorithm, paired_at}, ...]
        self.registered: list[dict] = []
        # request_id -> PendingRequest dict (with extra "phone_id" + "queued_at")
        self.pending_requests: dict[str, dict] = {}
        # most recent responses, newest first
        self.responses: deque = deque(maxlen=20)
        # alias -> {"secret_b32", "period_seconds", "digits", "algorithm",
        #           "phone_id" (target), "queued_at"}. Server-side mirror so we
        # can verify codes the phone returns on totp_generate.
        self.totp_secrets: dict[str, dict] = {}
        # Counter for auto-generated TOTP aliases.
        self._totp_counter: int = 0
        # Round 6: issued capability JWTs the phone signed back via
        # session_issuance approvals. Newest first.
        self.issued_jwts: deque = deque(maxlen=20)
        # v0.4.1: persistent per-phone audit log of every approve / deny
        # / sign / TOTP / JWT / WebAuthn / push-rotation event. Larger
        # cap than the per-event-class deques above so the phone-side
        # History view can show meaningful depth. Keyed by event_id and
        # filtered phone-side via the _phone_id field.
        self.audit_log: deque = deque(maxlen=500)
        # v0.4.1: WebAuthn demo result cache. When a webauthn_assert
        # is approved, the demo browser page polls /v0.4/webauthn/result/
        # {request_id} until it lands. Cached for 5 minutes then evicted.
        # Keyed by request_id; values are full assertion dicts.
        self.webauthn_results: dict[str, dict] = {}
        # Phase 5 Wave B: capability_request results store. When the
        # phone approves a capability_request, the mock assembles the
        # final 3-part JWS and stashes it here for an external agent
        # (e.g. MyService-side Darwin) to fetch via the result endpoint.
        # Keyed by request_id; values are {status, capability_jws,
        # reason, agent_id, completed_at_unix} dicts. Mirrors the
        # production server's CapabilityResult dataclass.
        self.capability_results: dict[str, dict] = {}
        # Round 7: per-phone single-use revocation challenges (60s TTL).
        # Separate from pairing challenges so a pairing challenge can't be
        # replayed to authorize a revocation.
        self.revoke_challenges: dict[str, tuple[str, float]] = {}
        # recent HTTP requests for the operator UI
        self.history: deque = deque(maxlen=50)
        # Canned secret-name templates. Algorithm is filled in per-registration
        # from the phone's advertised algorithm, so iOS-paired phones see
        # `ecdsa-p256` and Android/Windows-paired phones see `ed25519`.
        self.managed_secret_names: list[tuple[str, str]] = [
            ("myservice", "MY_API_KEY"),
            ("myservice", "WEBHOOK_TOKEN"),
        ]
        self.verify_signatures = True

    def managed_secrets_for(self, algorithm: str) -> list[dict]:
        return [
            {"service": svc, "secret": name, "algorithm": algorithm}
            for svc, name in self.managed_secret_names
        ]

    def mint_pairing_code(self, ttl_seconds: int = 300) -> str:
        with self._lock:
            code = "".join(secrets.choice("0123456789") for _ in range(6))
            self.pairing_codes[code] = time.time() + ttl_seconds
            return code

    def consume_pairing_code(self, code: str) -> bool:
        """Returns True if the code was valid + unexpired. Removes it (one-shot)."""
        with self._lock:
            expires = self.pairing_codes.pop(code, None)
            if expires is None:
                return False
            return time.time() < expires

    def mint_challenge(self, code: str, ttl_seconds: int = 60) -> str:
        with self._lock:
            challenge_bytes = secrets.token_bytes(32)
            challenge_b64u = b64u_encode(challenge_bytes)
            self.challenges[code] = (challenge_b64u, time.time() + ttl_seconds)
            return challenge_b64u

    def consume_challenge(self, challenge_b64u: str) -> bool:
        """Returns True if the challenge matches one we issued recently. One-shot."""
        with self._lock:
            for code, (issued_b64u, expires) in list(self.challenges.items()):
                if issued_b64u == challenge_b64u and time.time() < expires:
                    del self.challenges[code]
                    return True
            return False

    def register(
        self,
        phone_id: str,
        device_label: str,
        public_key_b64u: str,
        algorithm: str,
        push_token: str | None = None,
        push_platform: str | None = None,
    ) -> bool:
        """Register a phone. Returns True if this was a re-pair (replaced
        an existing entry), False if a fresh registration."""
        was_repair = False
        with self._lock:
            entry = {
                "phone_id": phone_id,
                "device_label": device_label,
                "public_key_b64u": public_key_b64u,
                "algorithm": algorithm,
                "paired_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "push_token": push_token,
                "push_platform": push_platform,
            }
            # Round 7 dedup: when an existing phone_id re-pairs, replace its
            # entry in-place rather than appending. The operator just
            # authorized a re-pair via biometric so the new public key
            # supersedes the old. If the phone_id is new, append.
            for i, existing in enumerate(self.registered):
                if existing["phone_id"] == phone_id:
                    self.registered[i] = entry
                    was_repair = True
                    break
            else:
                self.registered.append(entry)
        if was_repair:
            self.record_audit_event(phone_id, "repair",
                                    detail=f"Replaced prior registration with new {algorithm} key")
        return was_repair

    def update_push_token(self, phone_id: str, push_token: str, push_platform: str) -> bool:
        """In-place update of a registered phone's push token. Used by the
        rotation endpoint when FCM / APNs hands the phone a fresh token.
        Returns True if the phone was found and updated, False otherwise."""
        updated = False
        with self._lock:
            for entry in self.registered:
                if entry["phone_id"] == phone_id:
                    entry["push_token"] = push_token
                    entry["push_platform"] = push_platform
                    updated = True
                    break
        if updated:
            self.record_audit_event(phone_id, "push_token_rotation",
                                    detail=f"Updated to {push_platform} token {push_token[:12]}...")
        return updated

    def list_other_phones(self, phone_id: str) -> list[dict]:
        """All registered phones EXCEPT the caller. Used by the management UI."""
        with self._lock:
            return [
                {
                    "phone_id": p["phone_id"],
                    "device_label": p["device_label"],
                    "algorithm": p["algorithm"],
                    "paired_at": p["paired_at"],
                }
                for p in self.registered
                if p["phone_id"] != phone_id
            ]

    def mint_revoke_challenge(self, phone_id: str, ttl_seconds: int = 60) -> str:
        """Mints a single-use 32-byte challenge for the calling phone to sign
        as the authorization for a subsequent /v0.4/manage/revoke POST."""
        with self._lock:
            challenge_bytes = secrets.token_bytes(32)
            challenge_b64u = b64u_encode(challenge_bytes)
            self.revoke_challenges[phone_id] = (challenge_b64u, time.time() + ttl_seconds)
            return challenge_b64u

    def consume_revoke_challenge(self, phone_id: str, challenge_b64u: str) -> bool:
        """Returns True if the caller's challenge matches one we issued recently
        and removes it (single-use). False on any mismatch / expired / absent."""
        with self._lock:
            stored = self.revoke_challenges.pop(phone_id, None)
            if stored is None:
                return False
            issued, expires = stored
            return issued == challenge_b64u and time.time() < expires

    def remove_phone(self, phone_id: str) -> bool:
        """Drops a registered phone, any pending requests targeting it, and any
        active revoke challenge for it. Returns True if the phone was present."""
        with self._lock:
            before = len(self.registered)
            self.registered = [p for p in self.registered if p["phone_id"] != phone_id]
            removed = len(self.registered) < before
            if removed:
                self.pending_requests = {
                    rid: r for rid, r in self.pending_requests.items()
                    if r.get("_phone_id") != phone_id
                }
                self.revoke_challenges.pop(phone_id, None)
            return removed

    def clear(self) -> None:
        with self._lock:
            self.pairing_codes.clear()
            self.challenges.clear()
            self.registered.clear()
            self.pending_requests.clear()
            self.responses.clear()
            self.totp_secrets.clear()
            self._totp_counter = 0
            self.issued_jwts.clear()
            self.revoke_challenges.clear()

    def store_issued_jwt(self, jwt_str: str, claims: dict, phone_id: str,
                          verify_error: str | None) -> None:
        with self._lock:
            self.issued_jwts.appendleft({
                "phone_id": phone_id,
                "jwt": jwt_str,
                "iss": claims.get("iss"),
                "sub": claims.get("sub"),
                "aud": claims.get("aud"),
                "bearer": claims.get("recto:bearer"),
                "scope": claims.get("recto:scope"),
                "max_uses": claims.get("recto:max_uses"),
                "exp": claims.get("exp"),
                "issued_at": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                "verify_error": verify_error,
            })

    def next_totp_alias(self) -> str:
        with self._lock:
            self._totp_counter += 1
            return f"myservice.totp.demo{self._totp_counter}"

    def store_totp_secret(self, alias: str, secret_b32: str, period: int,
                          digits: int, algorithm: str, phone_id: str) -> None:
        with self._lock:
            self.totp_secrets[alias] = {
                "secret_b32": secret_b32,
                "period_seconds": period,
                "digits": digits,
                "algorithm": algorithm,
                "phone_id": phone_id,
                "queued_at": datetime.now(timezone.utc).strftime("%H:%M:%S"),
            }

    def get_totp_secret(self, alias: str) -> dict | None:
        with self._lock:
            return self.totp_secrets.get(alias)

    def most_recent_totp_alias_for(self, phone_id: str) -> str | None:
        with self._lock:
            for alias in reversed(self.totp_secrets):
                if self.totp_secrets[alias].get("phone_id") == phone_id:
                    return alias
            return None

    def find_phone(self, phone_id: str) -> dict | None:
        with self._lock:
            return next((p for p in self.registered if p["phone_id"] == phone_id), None)

    def queue_pending_request(self, phone_id: str, service: str, secret: str,
                              operation_description: str) -> dict:
        """Mint a fake single-sign request. Returns the public PendingRequest dict."""
        with self._lock:
            request_id = str(uuid.uuid4())
            payload_hash = secrets.token_bytes(32)
            req = {
                "request_id": request_id,
                "kind": "single_sign",
                "service": service,
                "secret": secret,
                "context": {
                    "child_pid": secrets.randbelow(60000) + 1000,
                    "child_argv0": "python.exe",
                    "requested_at_unix": int(time.time()),
                    "operation_description": operation_description,
                    "payload_hash_b64u": b64u_encode(payload_hash),
                },
                # Mock-internal extras (not sent on the wire):
                "_phone_id": phone_id,
                "_queued_at": datetime.now(timezone.utc).strftime("%H:%M:%S"),
            }
            self.pending_requests[request_id] = req
            return req

    def list_pending_for_phone(self, phone_id: str) -> list[dict]:
        with self._lock:
            return [
                {k: v for k, v in r.items() if not k.startswith("_")}
                for r in self.pending_requests.values()
                if r.get("_phone_id") == phone_id
            ]

    def take_pending(self, request_id: str) -> dict | None:
        with self._lock:
            return self.pending_requests.pop(request_id, None)

    def record_response(self, request_id: str, phone_id: str, decision: str,
                        signature_b64u: str | None, reason: str | None,
                        verified: bool, service: str, secret: str,
                        kind: str | None = None,
                        extras: dict | None = None,
                        payload_hash_b64u: str | None = None,
                        totp_alias: str | None = None,
                        webauthn_rp_id: str | None = None) -> None:
        kind = kind or "single_sign"
        now_unix = int(time.time())
        with self._lock:
            entry = {
                "request_id": request_id,
                "phone_id": phone_id,
                "service": service,
                "secret": secret,
                "kind": kind,
                "decision": decision,
                "signature_b64u": signature_b64u,
                "reason": reason,
                "verified": verified,
                "responded_at": datetime.now(timezone.utc).strftime("%H:%M:%S"),
            }
            if extras:
                entry.update(extras)
            self.responses.appendleft(entry)

            # Mirror into the audit log for the per-phone History view.
            self.audit_log.appendleft({
                "event_id": str(uuid.uuid4()),
                "_phone_id": phone_id,
                "kind": kind,
                "decision": decision,
                "verified": verified,
                "service": service,
                "secret": secret,
                "payload_hash_b64u": payload_hash_b64u,
                "totp_alias": totp_alias,
                "webauthn_rp_id": webauthn_rp_id,
                "recorded_at_unix": now_unix,
                "detail": reason if decision == "denied" else None,
            })

    def record_audit_event(self, phone_id: str, kind: str,
                           detail: str | None = None,
                           **fields) -> None:
        """Append a non-response event (re-pair, push token rotation,
        revocation) to the audit log."""
        with self._lock:
            self.audit_log.appendleft({
                "event_id": str(uuid.uuid4()),
                "_phone_id": phone_id,
                "kind": kind,
                "decision": None,
                "verified": None,
                "service": fields.get("service"),
                "secret": fields.get("secret"),
                "payload_hash_b64u": fields.get("payload_hash_b64u"),
                "totp_alias": fields.get("totp_alias"),
                "webauthn_rp_id": fields.get("webauthn_rp_id"),
                "recorded_at_unix": int(time.time()),
                "detail": detail,
            })

    def list_audit_for_phone(self, phone_id: str, limit: int) -> list[dict]:
        """Return public-facing audit-log entries for one phone, newest-first.
        Strips the _phone_id internal field from each row."""
        with self._lock:
            return [
                {k: v for k, v in entry.items() if not k.startswith("_")}
                for entry in self.audit_log
                if entry.get("_phone_id") == phone_id
            ][:limit]

    def record(self, method: str, path: str, status: int, summary: str = "") -> None:
        with self._lock:
            self.history.appendleft({
                "ts": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                "method": method,
                "path": path,
                "status": status,
                "summary": (summary or "")[:160],
            })


STATE = State()


# ---- helpers ---------------------------------------------------------------

def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(s: str) -> bytes:
    pad = -len(s) % 4
    return base64.urlsafe_b64decode(s + ("=" * pad))


def verify_ed25519(public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
    """Returns True if the Ed25519 signature verifies (or if cryptography isn't installed)."""
    if not HAS_CRYPTOGRAPHY:
        return True
    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(signature, message)
        return True
    except Exception:
        return False


def verify_ecdsa_p256(public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
    """Returns True if the ECDSA P-256 signature verifies (or if cryptography isn't installed).

    Public-key wire format: 64 bytes raw X || Y (no 0x04 prefix, big-endian).
    Signature wire format:  64 bytes raw R || S (no DER, big-endian).
    Phone SHA-256-hashes the message before signing.
    """
    if not HAS_CRYPTOGRAPHY:
        return True
    try:
        if len(public_key_bytes) != 64 or len(signature) != 64:
            return False
        x = int.from_bytes(public_key_bytes[:32], "big")
        y = int.from_bytes(public_key_bytes[32:], "big")
        public_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
        public_key = public_numbers.public_key()

        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        der_sig = encode_dss_signature(r, s)

        public_key.verify(der_sig, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def verify_signature(algorithm: str, public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
    if algorithm == ALG_ED25519:
        return verify_ed25519(public_key_bytes, message, signature)
    if algorithm == ALG_ECDSA_P256:
        return verify_ecdsa_p256(public_key_bytes, message, signature)
    return False


# ---- Capability JWT verification (round 6) ---------------------------------

def verify_capability_jwt(jwt_str: str, public_key_b64u: str, algorithm: str,
                          expected_aud: str) -> tuple[dict | None, str | None]:
    """Verifies a Recto capability JWT signature manually (no pyjwt dependency).

    Returns (claims, error). On success: (claims_dict, None). On failure:
    (None, error_message).
    """
    if not HAS_CRYPTOGRAPHY:
        # Without cryptography we can still extract the claims for display, but
        # signature verification is a no-op (matches the existing pattern).
        try:
            parts = jwt_str.split(".")
            if len(parts) != 3:
                return None, "JWT does not have three parts"
            claims = json.loads(b64u_decode(parts[1]))
            return claims, None
        except Exception as ex:
            return None, f"JWT parse failed: {ex}"

    try:
        parts = jwt_str.split(".")
        if len(parts) != 3:
            return None, "JWT does not have three parts"
        header_b64, payload_b64, sig_b64 = parts
        header = json.loads(b64u_decode(header_b64))
        payload = json.loads(b64u_decode(payload_b64))

        expected_alg = "EdDSA" if algorithm == ALG_ED25519 else "ES256"
        if header.get("alg") != expected_alg:
            return None, f"alg mismatch: header={header.get('alg')!r}, expected={expected_alg!r}"

        if header.get("typ") != "JWT":
            return None, f"typ mismatch: {header.get('typ')!r}"

        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        sig = b64u_decode(sig_b64)
        pub_bytes = b64u_decode(public_key_b64u)

        if algorithm == ALG_ED25519:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            Ed25519PublicKey.from_public_bytes(pub_bytes).verify(sig, signing_input)
        elif algorithm == ALG_ECDSA_P256:
            from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
            from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
            from cryptography.hazmat.primitives import hashes
            if len(pub_bytes) != 64:
                return None, f"ECDSA P-256 public key must be 64 bytes, got {len(pub_bytes)}"
            if len(sig) != 64:
                return None, f"ECDSA P-256 signature must be 64 bytes raw R||S, got {len(sig)}"
            x = int.from_bytes(pub_bytes[:32], "big")
            y = int.from_bytes(pub_bytes[32:], "big")
            from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers, SECP256R1
            pk = EllipticCurvePublicNumbers(x, y, SECP256R1()).public_key()
            r = int.from_bytes(sig[:32], "big")
            s = int.from_bytes(sig[32:], "big")
            der_sig = encode_dss_signature(r, s)
            pk.verify(der_sig, signing_input, ECDSA(hashes.SHA256()))
        else:
            return None, f"unsupported algorithm '{algorithm}'"

        # Claim checks: aud + exp.
        if payload.get("aud") != expected_aud:
            return None, f"aud mismatch: claim={payload.get('aud')!r}, expected={expected_aud!r}"
        now = int(time.time())
        exp = payload.get("exp")
        if not isinstance(exp, int) or exp < now:
            return None, f"JWT expired (exp={exp}, now={now})"

        return payload, None
    except Exception as ex:
        return None, f"signature verification failed: {ex.__class__.__name__}: {ex}"


# ---- TOTP helpers (RFC 6238) -----------------------------------------------

def b32_random_secret(length_bytes: int = 20) -> str:
    """Generate a fresh base32 TOTP secret. 20 bytes = 160 bits is the RFC 4226 minimum."""
    raw = secrets.token_bytes(length_bytes)
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def b32_decode_padded(b32: str) -> bytes:
    cleaned = b32.strip().replace("=", "").replace(" ", "").upper()
    padding = (8 - len(cleaned) % 8) % 8
    return base64.b32decode(cleaned + "=" * padding)


def compute_totp(secret_bytes: bytes, t_unix: int, period: int = 30,
                 digits: int = 6, algorithm: str = "SHA1") -> str:
    """RFC 6238 TOTP. Pure-math; same code shipped phone-side in TotpCodeCalculator."""
    counter = t_unix // period
    counter_bytes = counter.to_bytes(8, byteorder="big", signed=False)
    alg = algorithm.upper()
    if alg == "SHA1":
        digest = hmac.new(secret_bytes, counter_bytes, hashlib.sha1).digest()
    elif alg == "SHA256":
        digest = hmac.new(secret_bytes, counter_bytes, hashlib.sha256).digest()
    elif alg == "SHA512":
        digest = hmac.new(secret_bytes, counter_bytes, hashlib.sha512).digest()
    else:
        raise ValueError(f"Unsupported TOTP algorithm: {algorithm}")
    offset = digest[-1] & 0x0f
    code_int = (
        ((digest[offset] & 0x7f) << 24)
        | ((digest[offset + 1] & 0xff) << 16)
        | ((digest[offset + 2] & 0xff) << 8)
        | (digest[offset + 3] & 0xff)
    )
    return str(code_int % (10 ** digits)).zfill(digits)


def verify_totp_code(submitted: str, alias_record: dict) -> tuple[bool, str]:
    """Returns (matched, expected_at_window_0). Checks ±1 window for clock skew."""
    secret_bytes = b32_decode_padded(alias_record["secret_b32"])
    period = alias_record["period_seconds"]
    digits = alias_record["digits"]
    algorithm = alias_record["algorithm"]
    now = int(time.time())
    expected_now = compute_totp(secret_bytes, now, period, digits, algorithm)
    for window_offset in (-1, 0, 1):
        expected = compute_totp(
            secret_bytes,
            now + window_offset * period,
            period,
            digits,
            algorithm,
        )
        if expected == submitted:
            return True, expected_now
    return False, expected_now


# ---- Push send: FCM v1 HTTP -----------------------------------------------

def configure_fcm(service_account_path: str) -> str:
    """Load a Firebase service-account JSON and stash it for FCM v1 sends.
    Returns the configured client_email so main() can echo it at startup.
    """
    global _FCM_CONFIG
    with open(service_account_path, "r", encoding="utf-8") as f:
        _FCM_CONFIG = json.load(f)
    if "private_key" not in _FCM_CONFIG or "client_email" not in _FCM_CONFIG:
        raise ValueError(f"{service_account_path} is missing private_key / client_email")
    return _FCM_CONFIG["client_email"]


def _fcm_oauth_token() -> str:
    """Mint or return a cached OAuth2 access token for FCM v1. Tokens are
    valid 1hr; we refresh when within 5 minutes of expiry.
    """
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding

    with _FCM_LOCK:
        global _FCM_OAUTH_TOKEN
        now = time.time()
        if _FCM_OAUTH_TOKEN and _FCM_OAUTH_TOKEN["expires_at_unix"] > now + 300:
            return _FCM_OAUTH_TOKEN["access_token"]

        cfg = _FCM_CONFIG
        if cfg is None:
            raise RuntimeError("FCM not configured")

        # Build a service-account assertion JWT (RS256) per RFC 7523.
        header = {"alg": "RS256", "typ": "JWT"}
        iat = int(now)
        payload = {
            "iss": cfg["client_email"],
            "scope": "https://www.googleapis.com/auth/firebase.messaging",
            "aud": cfg.get("token_uri", "https://oauth2.googleapis.com/token"),
            "iat": iat,
            "exp": iat + 3600,
        }
        header_b64 = b64u_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        payload_b64 = b64u_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")

        private_key = serialization.load_pem_private_key(
            cfg["private_key"].encode("utf-8"),
            password=None,
        )
        signature = private_key.sign(signing_input, rsa_padding.PKCS1v15(), hashes.SHA256())
        sig_b64 = b64u_encode(signature)
        assertion = f"{header_b64}.{payload_b64}.{sig_b64}"

        # Exchange the assertion for an access token.
        data = urllib.parse.urlencode({
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion,
        }).encode("ascii")
        req = urllib.request.Request(
            cfg.get("token_uri", "https://oauth2.googleapis.com/token"),
            data=data,
            method="POST",
        )
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read().decode("utf-8"))

        _FCM_OAUTH_TOKEN = {
            "access_token": body["access_token"],
            "expires_at_unix": now + int(body.get("expires_in", 3600)),
        }
        return body["access_token"]


def _send_fcm(push_token: str, request_id: str, kind: str) -> tuple[bool, str]:
    """Send a wakeup push via FCM v1 HTTP. Returns (success, detail)."""
    if _FCM_CONFIG is None:
        return False, "FCM not configured"
    try:
        access_token = _fcm_oauth_token()
        message = {
            "message": {
                "token": push_token,
                # data-only: client app handles wakeup; we don't paint a
                # user-visible notification (operator already sees the
                # pending request in the foreground UI when it arrives).
                "data": {
                    "request_id": request_id,
                    "kind": kind,
                    "issued_at_unix": str(int(time.time())),
                },
                "android": {
                    # high-priority data messages bypass Doze restrictions
                    # so the wakeup actually fires within ~1s rather than
                    # being batched into the next maintenance window.
                    "priority": "high",
                },
            }
        }
        url = (f"https://fcm.googleapis.com/v1/projects/"
               f"{_FCM_CONFIG['project_id']}/messages:send")
        data = json.dumps(message).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Authorization", f"Bearer {access_token}")
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        return True, body.get("name", "(no name)")
    except urllib.error.HTTPError as e:
        try:
            error_body = e.read().decode("utf-8")[:300]
        except Exception:
            error_body = "(unreadable)"
        return False, f"HTTP {e.code}: {error_body}"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


# ---- Push send: APNs HTTP/2 -----------------------------------------------

def configure_apns(key_path: str, key_id: str, team_id: str,
                   bundle_id: str, environment: str) -> None:
    """Stash APNs send credentials. Validates the .p8 is parseable before
    returning so a bad key fails loudly at startup, not on the first push."""
    from cryptography.hazmat.primitives import serialization
    with open(key_path, "rb") as f:
        # Just parse to validate; we re-load on each token mint since
        # cryptography keys aren't picklable across threads cleanly.
        serialization.load_pem_private_key(f.read(), password=None)

    global _APNS_CONFIG
    _APNS_CONFIG = {
        "key_path": key_path,
        "key_id": key_id,
        "team_id": team_id,
        "bundle_id": bundle_id,
        "environment": environment,
    }


def _apns_jwt() -> str:
    """Mint or return a cached APNs provider JWT (ES256, valid 1hr per
    Apple's guidance; longer-lived tokens are rejected). Refreshes when
    within 5 minutes of expiry."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    with _APNS_LOCK:
        global _APNS_JWT
        now = time.time()
        if _APNS_JWT and _APNS_JWT["expires_at_unix"] > now + 300:
            return _APNS_JWT["token"]

        cfg = _APNS_CONFIG
        if cfg is None:
            raise RuntimeError("APNs not configured")

        header = {"alg": "ES256", "kid": cfg["key_id"]}
        payload = {"iss": cfg["team_id"], "iat": int(now)}
        header_b64 = b64u_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        payload_b64 = b64u_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")

        with open(cfg["key_path"], "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)

        # ECDSA P-256 sign produces DER-encoded signature; APNs JWT requires
        # raw R||S concatenation (RFC 7515 / RFC 7518 ES256). Convert.
        der_sig = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der_sig)
        raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        sig_b64 = b64u_encode(raw_sig)

        token = f"{header_b64}.{payload_b64}.{sig_b64}"
        # Apple recommends rotating tokens every ~50 minutes; we cap our
        # cache lifetime at 55 minutes to give a 5-minute safety margin
        # before Apple's hard 1-hour expiry would reject our token.
        _APNS_JWT = {"token": token, "expires_at_unix": now + 55 * 60}
        return token


def _send_apns(push_token: str, request_id: str, kind: str) -> tuple[bool, str]:
    """Send a wakeup push via APNs HTTP/2. Requires the `httpx` package
    with HTTP/2 support (`pip install 'httpx[http2]'`). Apple's APNs gateway
    is HTTP/2-only, so stdlib http.client (HTTP/1.1) cannot reach it.
    """
    if _APNS_CONFIG is None:
        return False, "APNs not configured"
    try:
        import httpx  # noqa: F401
    except ImportError:
        return False, "httpx not installed (pip install 'httpx[http2]')"

    cfg = _APNS_CONFIG
    try:
        token = _apns_jwt()
    except Exception as e:
        return False, f"JWT mint failed: {type(e).__name__}: {e}"

    host = (
        "api.sandbox.push.apple.com"
        if cfg["environment"] == "development"
        else "api.push.apple.com"
    )
    url = f"https://{host}/3/device/{push_token}"

    # APNs payload: aps dict for the user-visible alert + custom keys
    # alongside it for app-internal data. content-available=1 wakes the
    # app in the background even when the alert is silent.
    payload = {
        "aps": {
            "alert": {
                "title": "Recto",
                "body": f"Pending request waiting ({kind})",
            },
            "sound": "default",
            "content-available": 1,
        },
        "request_id": request_id,
        "kind": kind,
    }

    headers = {
        "authorization": f"bearer {token}",
        "apns-topic": cfg["bundle_id"],
        "apns-push-type": "alert",
        "apns-priority": "10",
    }

    try:
        import httpx
        # Per-request client; APNs's connection-coalescing tolerates short-
        # lived connections fine for low-volume wakeup traffic. Higher-
        # volume deployments would pool a long-lived client.
        with httpx.Client(http2=True, timeout=10.0) as client:
            resp = client.post(url, json=payload, headers=headers)
        if resp.status_code == 200:
            return True, "delivered"
        return False, f"HTTP {resp.status_code}: {resp.text[:300]}"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


def send_push_wakeup(phone: dict, request_id: str, kind: str) -> None:
    """Best-effort push wakeup to a phone with a registered token. Routes
    to FCM (Android) or APNs (iOS) based on the phone's recorded
    push_platform; logs success/failure regardless of outcome so the
    operator can correlate "phone never woke up" reports against the
    transport-side delivery state.

    When the corresponding transport credentials aren't configured (no
    --fcm-service-account / --apns-key flags), falls back to the
    "would send ..." log stub for visibility into when wakeups would
    have fired in a fully-provisioned deployment.
    """
    push_token = phone.get("push_token")
    platform = phone.get("push_platform")
    if not push_token or not platform:
        return  # phone paired without push (Windows / Mac Catalyst dev)

    short = push_token[:30]
    if platform == "fcm":
        if _FCM_CONFIG is not None:
            ok, detail = _send_fcm(push_token, request_id, kind)
            marker = "delivered" if ok else "FAILED"
            print(f"[push] FCM {marker} -> {short}... ({kind}, request_id={request_id[:8]}): {detail}", flush=True)
        else:
            print(f"[push] would send FCM wakeup to {short}... ({kind}, request_id={request_id[:8]})", flush=True)
    elif platform == "apns":
        if _APNS_CONFIG is not None:
            ok, detail = _send_apns(push_token, request_id, kind)
            marker = "delivered" if ok else "FAILED"
            print(f"[push] APNs {marker} -> {short}... ({kind}, request_id={request_id[:8]}): {detail}", flush=True)
        else:
            print(f"[push] would send APNs wakeup to {short}... ({kind}, request_id={request_id[:8]})", flush=True)
    else:
        print(f"[push] unknown platform '{platform}' for phone {phone.get('phone_id', '?')[:8]}...; skipping", flush=True)


def verify_webauthn_assertion(
    *,
    client_data_b64u: str,
    authenticator_data_b64u: str,
    signature_b64u: str,
    expected_challenge_b64u: str,
    expected_origin: str,
    expected_rp_id: str,
    public_key_b64u: str,
    algorithm: str,
) -> tuple[bool, str | None, dict]:
    """Verify a WebAuthn assertion the way a real RP would.

    Returns ``(verified, error_or_none, captured_fields)``. The captured
    fields are surfaced in the operator-UI response panel so we can show
    e.g. the parsed clientDataJSON type / origin without leaking phone-side
    state.

    Verification steps (per W3C WebAuthn Level 3 section 7.2):
    1. Parse clientDataJSON, ensure type == "webauthn.get".
    2. Verify the challenge matches what we sent.
    3. Verify the origin matches the expected RP origin.
    4. Decode authenticatorData; verify rpIdHash == sha256(rp_id).
    5. Verify the UP flag is set.
    6. Verify the signature over (authenticatorData || sha256(clientDataJSON))
       against the phone's public key.
    """
    captured: dict = {}
    try:
        client_data_bytes = b64u_decode(client_data_b64u)
        authenticator_data = b64u_decode(authenticator_data_b64u)
        signature = b64u_decode(signature_b64u)
    except Exception as ex:
        return False, f"base64url decode failed: {ex}", captured

    try:
        client_data = json.loads(client_data_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as ex:
        return False, f"clientDataJSON not parseable: {ex}", captured

    captured["wa_type"] = client_data.get("type")
    captured["wa_origin"] = client_data.get("origin")
    captured["wa_challenge"] = client_data.get("challenge")

    if client_data.get("type") != "webauthn.get":
        return False, f"clientDataJSON.type != 'webauthn.get' (got '{client_data.get('type')}')", captured
    if client_data.get("challenge") != expected_challenge_b64u:
        return False, "clientDataJSON.challenge does not match the queued challenge", captured
    if client_data.get("origin") != expected_origin:
        return False, f"clientDataJSON.origin '{client_data.get('origin')}' != expected '{expected_origin}'", captured

    if len(authenticator_data) < 37:
        return False, f"authenticatorData too short ({len(authenticator_data)} < 37)", captured
    expected_rp_id_hash = hashlib.sha256(expected_rp_id.encode("utf-8")).digest()
    if authenticator_data[0:32] != expected_rp_id_hash:
        return False, "authenticatorData rpIdHash does not match sha256(rp_id)", captured
    flags = authenticator_data[32]
    captured["wa_flags"] = f"0x{flags:02x}"
    if not (flags & 0x01):
        return False, "authenticatorData UP flag (user-present) not set", captured

    # Canonical signing input: authenticatorData || sha256(clientDataJSON).
    client_data_hash = hashlib.sha256(client_data_bytes).digest()
    signing_input = authenticator_data + client_data_hash

    try:
        public_key_bytes = b64u_decode(public_key_b64u)
    except Exception as ex:
        return False, f"public key decode failed: {ex}", captured

    verified = verify_signature(algorithm, public_key_bytes, signing_input, signature)
    if not verified:
        return False, f"{algorithm} signature does not verify against the registered public key", captured
    return True, None, captured


# ---- HTTP handler ----------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    # Silence the default per-request logger; we have our own history.
    def log_message(self, fmt, *args):
        pass

    # -- response helpers --
    def _send_json(self, status: int, body: dict) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
        STATE.record(self.command, self.path, status, json.dumps(body))
        # Mirror outgoing protocol responses to stdout so the wire is visible live.
        if not self.path.startswith("/_"):
            ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
            line = f"[{ts}] {self.command} {self.path} -> {status}"
            if status >= 400:
                line += f"  error: {body.get('error', '')}"
            print(line, flush=True)

    def _send_html(self, body: str) -> None:
        payload = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _send_redirect(self, location: str) -> None:
        self.send_response(303)
        self.send_header("Location", location)
        self.end_headers()
        STATE.record(self.command, self.path, 303)

    # -- routes --
    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/":
            self._send_html(render_index())
            return
        if url.path == "/v0.4/registration_challenge":
            qs = parse_qs(url.query)
            code = (qs.get("code") or [""])[0]
            if not STATE.consume_pairing_code(code):
                self._send_json(404, {"error": "unknown or expired pairing code"})
                return
            challenge = STATE.mint_challenge(code)
            self._send_json(200, {
                "challenge_b64u": challenge,
                "expires_at_unix": int(time.time() + 60),
            })
            return
        if url.path == "/v0.4/pending":
            qs = parse_qs(url.query)
            phone_id = (qs.get("phone_id") or [""])[0]
            if not phone_id:
                self._send_json(400, {"error": "phone_id query param is required"})
                return
            pending = STATE.list_pending_for_phone(phone_id)
            self._send_json(200, {"requests": pending})
            return
        if url.path == "/v0.4/manage/phones":
            qs = parse_qs(url.query)
            phone_id = (qs.get("phone_id") or [""])[0]
            if not phone_id:
                self._send_json(400, {"error": "phone_id query param is required"})
                return
            phones = STATE.list_other_phones(phone_id)
            self._send_json(200, {"phones": phones})
            return
        if url.path == "/demo/webauthn":
            self._send_html(WEBAUTHN_DEMO_HTML)
            return
        if url.path.startswith("/v0.4/webauthn/result/"):
            request_id = url.path[len("/v0.4/webauthn/result/"):]
            with STATE._lock:
                result = STATE.webauthn_results.get(request_id)
                pending_still = request_id in STATE.pending_requests
            if result is not None:
                self._send_json(200, result)
                return
            if pending_still:
                self._send_json(202, {"status": "pending", "request_id": request_id})
                return
            self._send_json(404, {"status": "unknown", "request_id": request_id})
            return
        if url.path == "/v0.4/manage/audit":
            qs = parse_qs(url.query)
            phone_id = (qs.get("phone_id") or [""])[0]
            if not phone_id:
                self._send_json(400, {"error": "phone_id query param is required"})
                return
            try:
                limit = int((qs.get("limit") or ["50"])[0])
            except ValueError:
                limit = 50
            limit = max(1, min(limit, 500))
            events = STATE.list_audit_for_phone(phone_id, limit)
            self._send_json(200, {"events": events})
            return
        if url.path == "/v0.4/manage/revoke_challenge":
            qs = parse_qs(url.query)
            phone_id = (qs.get("phone_id") or [""])[0]
            if not phone_id:
                self._send_json(400, {"error": "phone_id query param is required"})
                return
            if STATE.find_phone(phone_id) is None:
                self._send_json(404, {"error": f"unknown phone_id '{phone_id}'"})
                return
            challenge = STATE.mint_revoke_challenge(phone_id)
            self._send_json(200, {
                "challenge_b64u": challenge,
                "expires_at_unix": int(time.time() + 60),
            })
            return
        self._send_json(404, {"error": f"no route {url.path}"})

    def do_POST(self):
        url = urlparse(self.path)

        # Operator-side index actions.
        if url.path == "/_mint":
            STATE.mint_pairing_code()
            self._send_redirect("/")
            return
        if url.path == "/_clear":
            STATE.clear()
            self._send_redirect("/")
            return
        if url.path == "/_queue":
            # Pick the most-recently-registered phone + a random managed secret
            # and queue a single-sign request against it.
            with STATE._lock:
                target_phone = STATE.registered[-1] if STATE.registered else None
            if target_phone is None:
                self._send_redirect("/")
                return
            svc, name = secrets.choice(STATE.managed_secret_names)
            req = STATE.queue_pending_request(
                phone_id=target_phone["phone_id"],
                service=svc,
                secret=name,
                operation_description=f"Sign mock challenge for {svc}/{name}",
            )
            send_push_wakeup(target_phone, req["request_id"], "single_sign")
            self._send_redirect("/")
            return
        if url.path == "/_queue_totp_provision":
            # Mint a fresh TOTP secret and queue a totp_provision request.
            with STATE._lock:
                target_phone = STATE.registered[-1] if STATE.registered else None
            if target_phone is None:
                self._send_redirect("/")
                return
            alias = STATE.next_totp_alias()
            secret_b32 = b32_random_secret()
            period, digits, algorithm = 30, 6, "SHA1"
            STATE.store_totp_secret(alias, secret_b32, period, digits, algorithm,
                                    phone_id=target_phone["phone_id"])
            request_id = str(uuid.uuid4())
            with STATE._lock:
                STATE.pending_requests[request_id] = {
                    "request_id": request_id,
                    "kind": "totp_provision",
                    "service": "myservice",
                    "secret": alias.split(".")[-1],
                    "context": {
                        "child_pid": secrets.randbelow(60000) + 1000,
                        "child_argv0": "python.exe",
                        "requested_at_unix": int(time.time()),
                        "operation_description": f"Provision TOTP secret for {alias}",
                        "totp_alias": alias,
                        "totp_secret_b32": secret_b32,
                        "totp_period_seconds": period,
                        "totp_digits": digits,
                        "totp_algorithm": algorithm,
                    },
                    "_phone_id": target_phone["phone_id"],
                    "_queued_at": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                }
            send_push_wakeup(target_phone, request_id, "totp_provision")
            self._send_redirect("/")
            return
        if url.path == "/_queue_totp_generate":
            # Queue a totp_generate request for the phone's most-recently-provisioned alias.
            with STATE._lock:
                target_phone = STATE.registered[-1] if STATE.registered else None
            if target_phone is None:
                self._send_redirect("/")
                return
            alias = STATE.most_recent_totp_alias_for(target_phone["phone_id"])
            if alias is None:
                self._send_redirect("/")
                return
            request_id = str(uuid.uuid4())
            with STATE._lock:
                STATE.pending_requests[request_id] = {
                    "request_id": request_id,
                    "kind": "totp_generate",
                    "service": "myservice",
                    "secret": alias.split(".")[-1],
                    "context": {
                        "child_pid": secrets.randbelow(60000) + 1000,
                        "child_argv0": "python.exe",
                        "requested_at_unix": int(time.time()),
                        "operation_description": f"Generate TOTP code for {alias}",
                        "totp_alias": alias,
                    },
                    "_phone_id": target_phone["phone_id"],
                    "_queued_at": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                }
            send_push_wakeup(target_phone, request_id, "totp_generate")
            self._send_redirect("/")
            return
        if url.path == "/_queue_session_issuance":
            # Queue a session_issuance request: ask the phone to sign a JWT
            # capability for service+secret with a 24h lifetime / 1000 uses,
            # bearer = "bootloader" (cached internally for sign-replay).
            with STATE._lock:
                target_phone = STATE.registered[-1] if STATE.registered else None
            if target_phone is None:
                self._send_redirect("/")
                return
            svc, name = secrets.choice(STATE.managed_secret_names)
            request_id = str(uuid.uuid4())
            with STATE._lock:
                STATE.pending_requests[request_id] = {
                    "request_id": request_id,
                    "kind": "session_issuance",
                    "service": svc,
                    "secret": name,
                    "context": {
                        "child_pid": secrets.randbelow(60000) + 1000,
                        "child_argv0": "python.exe",
                        "requested_at_unix": int(time.time()),
                        "operation_description": f"Issue 24h capability for {svc}/{name} (bearer: bootloader)",
                        "session_bearer": "bootloader",
                        "session_scope": ["sign"],
                        "session_lifetime_seconds": 24 * 3600,
                        "session_max_uses": 1000,
                        "session_bootloader_id": STATE.bootloader_id,
                    },
                    "_phone_id": target_phone["phone_id"],
                    "_queued_at": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                }
            send_push_wakeup(target_phone, request_id, "session_issuance")
            self._send_redirect("/")
            return
        if url.path == "/_queue_pkcs11_sign":
            with STATE._lock:
                target_phone = STATE.registered[-1] if STATE.registered else None
            if target_phone is None:
                self._send_redirect("/")
                return
            request_id = str(uuid.uuid4())
            payload_hash = secrets.token_bytes(32)
            with STATE._lock:
                STATE.pending_requests[request_id] = {
                    "request_id": request_id,
                    "kind": "pkcs11_sign",
                    "service": "ssh",
                    "secret": "id_recto.pub",
                    "context": {
                        "child_pid": secrets.randbelow(60000) + 1000,
                        "child_argv0": "ssh-agent",
                        "requested_at_unix": int(time.time()),
                        "operation_description": "SSH login to git.example.com",
                        "payload_hash_b64u": b64u_encode(payload_hash),
                        "purpose": "ssh-login",
                        "pkcs11_consumer_label": "OpenSSH agent",
                    },
                    "_phone_id": target_phone["phone_id"],
                    "_queued_at": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                }
            send_push_wakeup(target_phone, request_id, "pkcs11_sign")
            self._send_redirect("/")
            return
        if url.path == "/_queue_pgp_sign":
            with STATE._lock:
                target_phone = STATE.registered[-1] if STATE.registered else None
            if target_phone is None:
                self._send_redirect("/")
                return
            request_id = str(uuid.uuid4())
            payload_hash = secrets.token_bytes(32)
            with STATE._lock:
                STATE.pending_requests[request_id] = {
                    "request_id": request_id,
                    "kind": "pgp_sign",
                    "service": "git",
                    "secret": "commit-signing",
                    "context": {
                        "child_pid": secrets.randbelow(60000) + 1000,
                        "child_argv0": "gpg-agent",
                        "requested_at_unix": int(time.time()),
                        "operation_description": "Sign git commit on main",
                        "payload_hash_b64u": b64u_encode(payload_hash),
                        "purpose": "git-commit",
                        "pgp_key_label": "Recto operator <ops@recto.example>",
                        "pgp_operation": "sign",
                    },
                    "_phone_id": target_phone["phone_id"],
                    "_queued_at": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                }
            send_push_wakeup(target_phone, request_id, "pgp_sign")
            self._send_redirect("/")
            return
        # ---- Bitcoin family message_signing endpoints ----
        # Same shape across BTC / LTC / DOGE / BCH. The crypto primitives
        # are identical (secp256k1, double-SHA-256, BIP-137 compact sig);
        # differences are the preamble string, BIP-44 path, and address
        # format — all encoded in the helper below.
        _BTC_FAMILY_CONFIG = {
            "btc":  {"ticker": "BTC",  "path": "m/84'/0'/0'/0/0",   "addr": "bc1qplaceholder0000000000000000000000000",  "secret": "btc-wallet-login"},
            "ltc":  {"ticker": "LTC",  "path": "m/84'/2'/0'/0/0",   "addr": "ltc1qplaceholder000000000000000000000000", "secret": "ltc-wallet-login"},
            "doge": {"ticker": "DOGE", "path": "m/44'/3'/0'/0/0",   "addr": "DPlaceholder1111111111111111111111",       "secret": "doge-wallet-login"},
            "bch":  {"ticker": "BCH",  "path": "m/44'/145'/0'/0/0", "addr": "1Placeholder1111111111111111111111",       "secret": "bch-wallet-login"},
        }

        def _queue_btc_family_message_sign(coin: str) -> None:
            """Mint a login-style message and queue a btc_sign request
            for the given coin. Phone derives secp256k1 key from the
            shared mnemonic at the coin's default BIP-44 path, computes
            the coin-specific BIP-137 hash (preamble varies; BTC + BCH
            share Bitcoin's), signs, returns 65-byte compact sig +
            Ed25519 envelope. Mock-side respond handler recovers the
            signer address using recto.bitcoin.recover_address with
            the same coin parameter.
            """
            cfg = _BTC_FAMILY_CONFIG[coin]
            with STATE._lock:
                target_phone = STATE.registered[-1] if STATE.registered else None
            if target_phone is None:
                self._send_redirect("/")
                return
            request_id = str(uuid.uuid4())
            payload_hash = secrets.token_bytes(32)
            ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            message_text = f"Login to demo.recto.example at {ts} ({cfg['ticker']})"
            ctx = {
                "child_pid": secrets.randbelow(60000) + 1000,
                "child_argv0": "browser",
                "requested_at_unix": int(time.time()),
                "operation_description": f"{cfg['ticker']} message_signing: {message_text!r}",
                "payload_hash_b64u": b64u_encode(payload_hash),
                "btc_network": "mainnet",
                "btc_message_kind": "message_signing",
                "btc_address": cfg["addr"],
                "btc_derivation_path": cfg["path"],
                "btc_message_text": message_text,
            }
            # Only emit btc_coin field when non-default — backward compat
            # with v0.5 phones that pre-date the multi-coin extension.
            if coin != "btc":
                ctx["btc_coin"] = coin
            with STATE._lock:
                STATE.pending_requests[request_id] = {
                    "request_id": request_id,
                    "kind": "btc_sign",
                    "service": "demo.recto.example",
                    "secret": cfg["secret"],
                    "context": ctx,
                    "_phone_id": target_phone["phone_id"],
                    "_queued_at": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                }
            send_push_wakeup(target_phone, request_id, "btc_sign")
            self._send_redirect("/")

        if url.path == "/_queue_btc_message_sign":
            _queue_btc_family_message_sign("btc")
            return
        if url.path == "/_queue_ltc_message_sign":
            _queue_btc_family_message_sign("ltc")
            return
        if url.path == "/_queue_doge_message_sign":
            _queue_btc_family_message_sign("doge")
            return
        if url.path == "/_queue_bch_message_sign":
            _queue_btc_family_message_sign("bch")
            return

        # ---- Wave-8 ed25519-chain message_signing endpoints (SOL / XLM / XRP) ----
        # Same shape across the three chains. The crypto primitive (raw
        # 64-byte ed25519 signature over a 32-byte SHA-256 of
        # chain_preamble || message_bytes) is identical; differences are
        # the SLIP-0010 path, address encoding, and message preamble —
        # all encoded in the helper below.
        _ED_CHAIN_CONFIG = {
            "sol":  {"ticker": "SOL", "path": "m/44'/501'/0'/0'",     "addr": "11111111111111111111111111111112",                              "secret": "sol-wallet-login"},
            "xlm":  {"ticker": "XLM", "path": "m/44'/148'/0'",        "addr": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",     "secret": "xlm-wallet-login"},
            "xrp":  {"ticker": "XRP", "path": "m/44'/144'/0'/0'/0'",  "addr": "rPlaceholder111111111111111111111",                            "secret": "xrp-wallet-login"},
        }

        def _queue_ed_chain_message_sign(chain: str) -> None:
            """Mint a login-style message and queue an ed_sign request
            for the given ed25519 chain. Phone derives ed25519 seed from
            the shared mnemonic at the chain's default SLIP-0010 path,
            computes the chain-specific signed-message hash (preamble
            varies — Recto-convention: 'Solana signed message:\\n' /
            'Stellar signed message:\\n' / 'XRP signed message:\\n'),
            signs, returns 64-byte raw signature + 32-byte pubkey hex +
            Ed25519 envelope. Mock-side respond handler (verifies the
            chain signature using recto.solana / recto.stellar /
            recto.ripple) is a follow-up.
            """
            cfg = _ED_CHAIN_CONFIG[chain]
            with STATE._lock:
                target_phone = STATE.registered[-1] if STATE.registered else None
            if target_phone is None:
                self._send_redirect("/")
                return
            request_id = str(uuid.uuid4())
            payload_hash = secrets.token_bytes(32)
            ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            message_text = f"Login to demo.recto.example at {ts} ({cfg['ticker']})"
            ctx = {
                "child_pid": secrets.randbelow(60000) + 1000,
                "child_argv0": "browser",
                "requested_at_unix": int(time.time()),
                "operation_description": f"{cfg['ticker']} message_signing: {message_text!r}",
                "payload_hash_b64u": b64u_encode(payload_hash),
                "ed_chain": chain,
                "ed_message_kind": "message_signing",
                "ed_address": cfg["addr"],
                "ed_derivation_path": cfg["path"],
                "ed_message_text": message_text,
            }
            with STATE._lock:
                STATE.pending_requests[request_id] = {
                    "request_id": request_id,
                    "kind": "ed_sign",
                    "service": "demo.recto.example",
                    "secret": cfg["secret"],
                    "context": ctx,
                    "_phone_id": target_phone["phone_id"],
                    "_queued_at": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                }
            send_push_wakeup(target_phone, request_id, "ed_sign")
            self._send_redirect("/")

        if url.path == "/_queue_sol_message_sign":
            _queue_ed_chain_message_sign("sol")
            return
        if url.path == "/_queue_xlm_message_sign":
            _queue_ed_chain_message_sign("xlm")
            return
        if url.path == "/_queue_xrp_message_sign":
            _queue_ed_chain_message_sign("xrp")
            return

        if url.path == "/_queue_capability_request":
            # Phase 5 Wave B routing test: queue a capability_request
            # PendingRequest carrying a sample CapabilityClaims for the
            # generic "darwin" agent. Phone-side render arm + cap-
            # signature signing land in Wave B part 2 — for part 1 the
            # phone shows a generic "Unknown request kind
            # capability_request" until the render arm ships, and any
            # response it sends won't carry cap_signature_b64u so the
            # mock will record signature_error. The wire-shape on
            # /v0.4/pending is what the test exercises.
            with STATE._lock:
                target_phone = STATE.registered[-1] if STATE.registered else None
            if target_phone is None:
                self._send_redirect("/")
                return
            now = int(time.time())
            request_id = str(uuid.uuid4())
            # Construct a sample CapabilityClaims using the v1 starter
            # shape from the IM (Darwin staging-deploys, weight 18, Tier
            # 1, 24h expiry). The same claim shape the test fixture
            # pins.
            claims_dict = {
                "iss": "phone:operator:enclave",
                "sub": "agent:darwin@staging",
                "aud": ["consumer-app", "recto:vault"],
                "iat": now,
                "nbf": now,
                "exp": now + 86400,
                "jti": f"cap_{now}_{secrets.token_hex(4)}",
                "cap": {
                    "tier": 1,
                    "registry_version": "2026-05-05",
                    "groups": [
                        "darwin:doc-edits",
                        "darwin:staging-deploys",
                        "darwin:secret-reads",
                        "darwin:public-comms",
                    ],
                    "scope": {
                        "env": ["staging"],
                        "services": ["web", "darwin"],
                        "repos": ["consumer-app", "recto"],
                    },
                    "allow_actions": [],
                    "deny_actions": ["secret:rotate"],
                    "limits": {
                        "per_hour": {},
                        "per_day": {"deploy:staging": 5, "secret:read": 100},
                        "per_session": {},
                    },
                },
                "purpose": "Darwin v1 staging operations — Tier 0/1 autonomous",
            }
            # Canonicalize via the same encoder verifiers use. Lazy
            # import to avoid a hard dep when the mock is launched
            # outside a Recto checkout (developer convenience).
            try:
                from recto.capability.jwt import (
                    _canonical_json as _cap_canonical_json,
                )
            except Exception as e:
                # Fallback: pure-stdlib canonical-json — same options
                # the recto.capability impl uses (sort_keys, no
                # separators-with-spaces). The bytes match exactly.
                def _cap_canonical_json(obj):
                    return json.dumps(
                        obj, sort_keys=True, separators=(",", ":"),
                    ).encode("utf-8")
            header_dict = {"alg": "ES256K", "typ": "JWT"}
            header_b64 = b64u_encode(_cap_canonical_json(header_dict))
            payload_b64 = b64u_encode(_cap_canonical_json(claims_dict))
            signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
            payload_hash = hashlib.sha256(signing_input).digest()
            with STATE._lock:
                STATE.pending_requests[request_id] = {
                    "request_id": request_id,
                    "kind": "capability_request",
                    "service": "recto",
                    "secret": "capability",
                    "context": {
                        "child_pid": 0,
                        "child_argv0": "(external-agent)",
                        "requested_at_unix": now,
                        "operation_description": (
                            "Capability request: agent=darwin@staging, "
                            "tier=1, weight=18, exp=24h"
                        ),
                        "payload_hash_b64u": b64u_encode(payload_hash),
                        "cap_header_b64": header_b64,
                        "cap_payload_b64": payload_b64,
                        "cap_agent_id": "darwin",
                    },
                    "_phone_id": target_phone["phone_id"],
                    "_queued_at": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                }
            send_push_wakeup(target_phone, request_id, "capability_request")
            self._send_redirect("/")
            return

        if url.path == "/_queue_tron_message_sign":
            # Wave-9 TRON message_signing. Same shape as ETH personal_sign
            # since both share secp256k1 + Keccak-256, but with TIP-191
            # preamble + base58check addresses. Phone derives the
            # secp256k1 key from its BIP-39 mnemonic at the default
            # m/44'/195'/0'/0/0 path (SLIP-0044 coin-type 195 for TRON),
            # signs the TIP-191 hash AND the standard payload_hash_b64u
            # (Ed25519 envelope), and POSTs back via /v0.4/respond/<id>.
            with STATE._lock:
                target_phone = STATE.registered[-1] if STATE.registered else None
            if target_phone is None:
                self._send_redirect("/")
                return
            request_id = str(uuid.uuid4())
            payload_hash = secrets.token_bytes(32)
            # 34-char T-prefixed placeholder. The mock-side respond
            # handler suppresses the "differs from expected" warning
            # when the queued address starts with "TPlaceholder" (real
            # phone-derived addresses won't have this prefix). Pattern
            # mirrors the ETH all-zero-bytes and SOL 24-ones placeholder
            # suppression already in place.
            placeholder_address = "TPlaceholder111111111111111111111A"
            assert len(placeholder_address) == 34
            ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            message_text = f"Login to demo.recto.example at {ts} (TRON)"
            with STATE._lock:
                STATE.pending_requests[request_id] = {
                    "request_id": request_id,
                    "kind": "tron_sign",
                    "service": "demo.recto.example",
                    "secret": "tron-wallet-login",
                    "context": {
                        "child_pid": secrets.randbelow(60000) + 1000,
                        "child_argv0": "browser",
                        "requested_at_unix": int(time.time()),
                        "operation_description": (
                            f"TRON message_signing: {message_text!r}"
                        ),
                        "payload_hash_b64u": b64u_encode(payload_hash),
                        # Six TRON context fields per the protocol RFC.
                        "tron_network": "mainnet",
                        "tron_message_kind": "message_signing",
                        "tron_address": placeholder_address,
                        "tron_derivation_path": "m/44'/195'/0'/0/0",
                        "tron_message_text": message_text,
                    },
                    "_phone_id": target_phone["phone_id"],
                    "_queued_at": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                }
            send_push_wakeup(target_phone, request_id, "tron_sign")
            self._send_redirect("/")
            return

        if url.path == "/_queue_eth_personal_sign":
            # v0.5+ ETH personal_sign request. Mints a fixed login-style
            # message, queues an eth_sign PendingRequest with the seven
            # ETH context fields, and returns. The phone derives the
            # secp256k1 key from its BIP39 mnemonic at the default
            # m/44'/60'/0'/0/0 path, signs both the EIP-191 personal_sign
            # hash AND the standard payload_hash_b64u (Ed25519 envelope),
            # and POSTs back via /v0.4/respond/<id>.
            with STATE._lock:
                target_phone = STATE.registered[-1] if STATE.registered else None
            if target_phone is None:
                self._send_redirect("/")
                return
            request_id = str(uuid.uuid4())
            payload_hash = secrets.token_bytes(32)
            # The "expected address" placeholder is a sentinel that the
            # phone overwrites when it derives a real address. The mock
            # accepts any address the phone returns and recovers the
            # actual signer from the rsv signature for display (see the
            # eth_sign branch in the respond handler). Real production
            # launchers would pin the expected address from a
            # service.yaml entry; this is dev-tooling and stays loose.
            placeholder_address = "0x" + "00" * 20
            # Wave-9 polish: chain_id from `?chain=<id>` query param, defaults
            # to Base 8453. Operator UI's chain selector wires the dropdown
            # value into each ETH form's action URL on submit. EIP-191
            # personal_sign doesn't include chain_id in the signed preimage
            # (purely metadata), so the signature itself is identical across
            # chains -- but operators may still want to test the label flow.
            try:
                chain_id = int(parse_qs(url.query).get("chain", ["8453"])[0])
            except (ValueError, TypeError):
                chain_id = 8453
            message_text = (
                f"Login to demo.recto.example "
                f"at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
            )
            with STATE._lock:
                STATE.pending_requests[request_id] = {
                    "request_id": request_id,
                    "kind": "eth_sign",
                    "service": "demo.recto.example",
                    "secret": "wallet-login",
                    "context": {
                        "child_pid": secrets.randbelow(60000) + 1000,
                        "child_argv0": "browser",
                        "requested_at_unix": int(time.time()),
                        "operation_description": f"ETH personal_sign: {message_text!r}",
                        "payload_hash_b64u": b64u_encode(payload_hash),
                        # The seven ETH context fields per the protocol RFC.
                        "eth_chain_id": chain_id,
                        "eth_message_kind": "personal_sign",
                        "eth_address": placeholder_address,
                        "eth_derivation_path": "m/44'/60'/0'/0/0",
                        "eth_message_text": message_text,
                    },
                    "_phone_id": target_phone["phone_id"],
                    "_queued_at": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                }
            send_push_wakeup(target_phone, request_id, "eth_sign")
            self._send_redirect("/")
            return

        if url.path == "/_queue_eth_typed_data":
            # v0.5+ ETH typed_data (EIP-712) request. Mints a sample
            # structured-data payload — an EIP-2612 permit — and queues
            # it for phone-side signing. The phone derives the secp256k1
            # key from its BIP39 mnemonic, hashes the typed data per
            # EIP-712, signs with secp256k1 + RFC-6979 deterministic-k,
            # and POSTs back r||s||v with v ∈ {27, 28} (canonical
            # OZ/viem/ethers shape).
            with STATE._lock:
                target_phone = STATE.registered[-1] if STATE.registered else None
            if target_phone is None:
                self._send_redirect("/")
                return
            request_id = str(uuid.uuid4())
            payload_hash = secrets.token_bytes(32)
            placeholder_address = "0x" + "00" * 20
            # Wave-9 polish: chain_id from `?chain=<id>` query param. Unlike
            # personal_sign, EIP-712 typed_data DOES include chainId in the
            # domain separator, so a different chain produces a different
            # signed digest and therefore a different signature. Operator
            # UI's chain selector lets you actually exercise that.
            try:
                chain_id = int(parse_qs(url.query).get("chain", ["8453"])[0])
            except (ValueError, TypeError):
                chain_id = 8453
            # Sample EIP-2612 permit — a common real-world EIP-712 use
            # case (ERC-20 token approval via off-chain signature). The
            # specific values are illustrative; cross-wallet compat is
            # established by the typed-data hash matching what other
            # wallets compute over the same envelope.
            deadline = int(time.time()) + 3600
            owner_addr = "0x" + secrets.token_hex(20)
            spender_addr = "0x" + secrets.token_hex(20)
            verifying_contract = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"  # USDC on mainnet (illustrative)
            typed_data = {
                "types": {
                    "EIP712Domain": [
                        {"name": "name", "type": "string"},
                        {"name": "version", "type": "string"},
                        {"name": "chainId", "type": "uint256"},
                        {"name": "verifyingContract", "type": "address"},
                    ],
                    "Permit": [
                        {"name": "owner", "type": "address"},
                        {"name": "spender", "type": "address"},
                        {"name": "value", "type": "uint256"},
                        {"name": "nonce", "type": "uint256"},
                        {"name": "deadline", "type": "uint256"},
                    ],
                },
                "primaryType": "Permit",
                "domain": {
                    "name": "USD Coin",
                    "version": "2",
                    "chainId": chain_id,
                    "verifyingContract": verifying_contract,
                },
                "message": {
                    "owner": owner_addr,
                    "spender": spender_addr,
                    "value": "1000000000",  # 1000 USDC (6 decimals)
                    "nonce": "0",
                    "deadline": str(deadline),
                },
            }
            typed_data_json = json.dumps(typed_data, separators=(",", ":"))
            with STATE._lock:
                STATE.pending_requests[request_id] = {
                    "request_id": request_id,
                    "kind": "eth_sign",
                    "service": "demo.recto.example",
                    "secret": "wallet-permit",
                    "context": {
                        "child_pid": secrets.randbelow(60000) + 1000,
                        "child_argv0": "browser",
                        "requested_at_unix": int(time.time()),
                        "operation_description": f"ETH typed_data permit for spender {spender_addr[:10]}...",
                        "payload_hash_b64u": b64u_encode(payload_hash),
                        "eth_chain_id": chain_id,
                        "eth_message_kind": "typed_data",
                        "eth_address": placeholder_address,
                        "eth_derivation_path": "m/44'/60'/0'/0/0",
                        "eth_typed_data_json": typed_data_json,
                    },
                    "_phone_id": target_phone["phone_id"],
                    "_queued_at": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                }
            send_push_wakeup(target_phone, request_id, "eth_sign")
            self._send_redirect("/")
            return

        if url.path == "/_queue_eth_transaction":
            # v0.5+ ETH transaction (EIP-1559 type-2) request. Mints a
            # sample transfer transaction and queues it for phone-side
            # signing. The phone derives the secp256k1 key from its
            # BIP39 mnemonic, computes the EIP-1559 hash
            # keccak256(0x02 || rlp([chainId, nonce, maxPriority, maxFee,
            # gas, to, value, data, accessList])), signs with secp256k1
            # + RFC-6979, and returns the FULL signed raw-transaction
            # bytes (0x02 || rlp([fields..., yParity, r, s])) ready for
            # eth_sendRawTransaction.
            with STATE._lock:
                target_phone = STATE.registered[-1] if STATE.registered else None
            if target_phone is None:
                self._send_redirect("/")
                return
            request_id = str(uuid.uuid4())
            payload_hash = secrets.token_bytes(32)
            placeholder_address = "0x" + "00" * 20
            # Wave-9 polish: chain_id from `?chain=<id>` query param.
            # EIP-1559 transactions encode chainId directly into the RLP-
            # signed payload (replay protection per EIP-155), so a different
            # chain produces a completely different signed transaction.
            try:
                chain_id = int(parse_qs(url.query).get("chain", ["8453"])[0])
            except (ValueError, TypeError):
                chain_id = 8453
            recipient = "0x" + secrets.token_hex(20)
            transaction = {
                "chainId": chain_id,
                "nonce": 0,
                "maxPriorityFeePerGas": "1000000",      # 0.001 gwei priority on Base
                "maxFeePerGas": "10000000",             # 0.01 gwei max
                "gasLimit": 21000,                      # standard ETH transfer
                "to": recipient,
                "value": "100000000000000",             # 0.0001 ETH (1e14 wei)
                "data": "0x",
                "accessList": [],
            }
            transaction_json = json.dumps(transaction, separators=(",", ":"))
            with STATE._lock:
                STATE.pending_requests[request_id] = {
                    "request_id": request_id,
                    "kind": "eth_sign",
                    "service": "demo.recto.example",
                    "secret": "wallet-transfer",
                    "context": {
                        "child_pid": secrets.randbelow(60000) + 1000,
                        "child_argv0": "browser",
                        "requested_at_unix": int(time.time()),
                        "operation_description": f"ETH transfer 0.0001 ETH to {recipient[:10]}... on chain {chain_id}",
                        "payload_hash_b64u": b64u_encode(payload_hash),
                        "eth_chain_id": chain_id,
                        "eth_message_kind": "transaction",
                        "eth_address": placeholder_address,
                        "eth_derivation_path": "m/44'/60'/0'/0/0",
                        "eth_transaction_json": transaction_json,
                    },
                    "_phone_id": target_phone["phone_id"],
                    "_queued_at": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                }
            send_push_wakeup(target_phone, request_id, "eth_sign")
            self._send_redirect("/")
            return

        if url.path == "/_queue_webauthn_assert":
            # Queue a webauthn_assert request: stand in as the relying party
            # for a fictional web app at https://demo.recto.example. Phone
            # produces a real WebAuthn assertion (clientDataJSON +
            # authenticatorData + signature) which we verify the same way a
            # real RP would. Foundation for the Keycloak-replacement
            # browser-login bridge -- the verification math here is identical
            # to what a production Recto-equipped Keycloak adapter would run.
            with STATE._lock:
                target_phone = STATE.registered[-1] if STATE.registered else None
            if target_phone is None:
                self._send_redirect("/")
                return
            request_id = str(uuid.uuid4())
            challenge_bytes = secrets.token_bytes(32)
            challenge_b64u = b64u_encode(challenge_bytes)
            rp_id = "demo.recto.example"
            origin = f"https://{rp_id}"
            with STATE._lock:
                STATE.pending_requests[request_id] = {
                    "request_id": request_id,
                    "kind": "webauthn_assert",
                    "service": rp_id,
                    "secret": "passkey-login",
                    "context": {
                        "child_pid": 0,
                        "child_argv0": "browser",
                        "requested_at_unix": int(time.time()),
                        "operation_description": f"Sign in to {rp_id} as user demo@recto.example",
                        "webauthn_rp_id": rp_id,
                        "webauthn_origin": origin,
                        "webauthn_challenge_b64u": challenge_b64u,
                    },
                    "_phone_id": target_phone["phone_id"],
                    "_queued_at": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                    # Stash the raw challenge bytes so we can verify exact
                    # match in clientDataJSON when the phone responds.
                    "_webauthn_challenge_b64u_expected": challenge_b64u,
                    "_webauthn_rp_id_expected": rp_id,
                    "_webauthn_origin_expected": origin,
                }
            send_push_wakeup(target_phone, request_id, "webauthn_assert")
            self._send_redirect("/")
            return

        # Read body for protocol endpoints.
        length = int(self.headers.get("Content-Length") or 0)
        content_type = self.headers.get("Content-Type") or "(none)"
        body_raw = self.rfile.read(length).decode("utf-8") if length else ""

        # Mirror incoming protocol-endpoint requests to stdout so the wire is visible.
        # Always print Content-Length / Content-Type / body (even if empty) so we can
        # diagnose serialization issues (e.g. an empty body would surface here).
        if not url.path.startswith("/_"):
            ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
            preview = body_raw if len(body_raw) <= 600 else body_raw[:600] + "..."
            preview_line = preview if body_raw else "(empty)"
            print(
                f"[{ts}] {self.command} {url.path}\n"
                f"  Content-Type: {content_type}  Content-Length: {length}\n"
                f"  body: {preview_line}",
                flush=True,
            )

        if url.path == "/v0.4/register":
            try:
                body = json.loads(body_raw) if body_raw else {}
            except json.JSONDecodeError as ex:
                self._send_json(400, {"error": f"invalid JSON: {ex}"})
                return

            phone_id = body.get("phone_id")
            device_label = body.get("device_label")
            public_key_b64u = body.get("public_key_b64u")
            supported_algorithms = body.get("supported_algorithms") or []
            registration_proof = body.get("registration_proof") or {}
            challenge_b64u = registration_proof.get("challenge")
            signature_b64u = registration_proof.get("signature_b64u")

            missing = [
                name for name, val in [
                    ("phone_id", phone_id),
                    ("device_label", device_label),
                    ("public_key_b64u", public_key_b64u),
                    ("registration_proof.challenge", challenge_b64u),
                    ("registration_proof.signature_b64u", signature_b64u),
                ] if not val
            ]
            if missing:
                self._send_json(400, {"error": f"missing required field(s): {', '.join(missing)}"})
                return

            # Algorithm: phone advertises one in supported_algorithms; we verify
            # with whatever it picked. v0.4.0 expects exactly one element.
            if not supported_algorithms:
                self._send_json(400, {"error": "supported_algorithms is empty"})
                return
            algorithm = supported_algorithms[0]
            if algorithm not in KNOWN_ALGORITHMS:
                self._send_json(400, {
                    "error": f"unsupported algorithm '{algorithm}' "
                             f"(known: {', '.join(KNOWN_ALGORITHMS)})",
                })
                return

            if not STATE.consume_challenge(challenge_b64u):
                self._send_json(400, {"error": "unknown or expired challenge"})
                return

            if STATE.verify_signatures:
                try:
                    pub = b64u_decode(public_key_b64u)
                    sig = b64u_decode(signature_b64u)
                    chal = b64u_decode(challenge_b64u)
                except Exception as ex:
                    self._send_json(400, {"error": f"base64url decode failed: {ex}"})
                    return
                if not verify_signature(algorithm, pub, chal, sig):
                    self._send_json(400, {
                        "error": f"{algorithm} signature does not verify against the supplied public key",
                    })
                    return

            push_token = body.get("push_token")
            push_platform = body.get("push_platform")
            STATE.register(
                phone_id, device_label, public_key_b64u, algorithm,
                push_token=push_token, push_platform=push_platform,
            )
            if push_token:
                print(
                    f"[push] phone {phone_id[:8]}... registered with "
                    f"{push_platform} token {push_token[:30]}...",
                    flush=True,
                )
            self._send_json(200, {
                "registered": True,
                "phone_id": phone_id,
                "bootloader_id": STATE.bootloader_id,
                "managed_secrets": STATE.managed_secrets_for(algorithm),
            })
            return

        if url.path == "/v0.4/webauthn/begin":
            # Demo-page entry point: queue a webauthn_assert request for
            # the most-recently-registered phone and return a request_id
            # that the page can poll for the eventual assertion.
            with STATE._lock:
                target_phone = STATE.registered[-1] if STATE.registered else None
            if target_phone is None:
                self._send_json(400, {"error": "no phones registered to handle this webauthn flow"})
                return
            try:
                body = json.loads(body_raw) if body_raw else {}
            except json.JSONDecodeError as ex:
                self._send_json(400, {"error": f"invalid JSON: {ex}"})
                return
            rp_id = body.get("rp_id") or "demo.recto.example"
            origin = body.get("origin") or f"https://{rp_id}"
            request_id = str(uuid.uuid4())
            challenge_b64u = b64u_encode(secrets.token_bytes(32))
            with STATE._lock:
                STATE.pending_requests[request_id] = {
                    "request_id": request_id,
                    "kind": "webauthn_assert",
                    "service": rp_id,
                    "secret": "passkey-login",
                    "context": {
                        "child_pid": 0,
                        "child_argv0": "browser",
                        "requested_at_unix": int(time.time()),
                        "operation_description": f"Sign in to {rp_id}",
                        "webauthn_rp_id": rp_id,
                        "webauthn_origin": origin,
                        "webauthn_challenge_b64u": challenge_b64u,
                    },
                    "_phone_id": target_phone["phone_id"],
                    "_queued_at": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                    "_webauthn_challenge_b64u_expected": challenge_b64u,
                    "_webauthn_rp_id_expected": rp_id,
                    "_webauthn_origin_expected": origin,
                }
            send_push_wakeup(target_phone, request_id, "webauthn_assert")
            self._send_json(200, {
                "request_id": request_id,
                "rp_id": rp_id,
                "origin": origin,
                "challenge_b64u": challenge_b64u,
                "phone_id": target_phone["phone_id"],
                "phone_label": target_phone.get("device_label", ""),
            })
            return
        if url.path == "/v0.4/manage/push_token":
            try:
                body = json.loads(body_raw) if body_raw else {}
            except json.JSONDecodeError as ex:
                self._send_json(400, {"error": f"invalid JSON: {ex}"})
                return
            phone_id = body.get("phone_id")
            push_token = body.get("push_token")
            push_platform = body.get("push_platform")
            missing = [n for n, v in [
                ("phone_id", phone_id),
                ("push_token", push_token),
                ("push_platform", push_platform),
            ] if not v]
            if missing:
                self._send_json(400, {"error": f"missing required field(s): {', '.join(missing)}"})
                return
            updated = STATE.update_push_token(phone_id, push_token, push_platform)
            if not updated:
                self._send_json(404, {"error": f"unknown phone_id '{phone_id}'"})
                return
            print(
                f"[push] phone {phone_id[:8]}... rotated to "
                f"{push_platform} token {push_token[:30]}...",
                flush=True,
            )
            self._send_json(200, {"updated": True, "phone_id": phone_id})
            return

        if url.path == "/v0.4/manage/revoke":
            try:
                body = json.loads(body_raw) if body_raw else {}
            except json.JSONDecodeError as ex:
                self._send_json(400, {"error": f"invalid JSON: {ex}"})
                return

            revoking_phone_id = body.get("revoking_phone_id")
            target_phone_id = body.get("target_phone_id")
            challenge_b64u = body.get("challenge")
            signature_b64u = body.get("signature_b64u")

            missing = [
                name for name, val in [
                    ("revoking_phone_id", revoking_phone_id),
                    ("target_phone_id", target_phone_id),
                    ("challenge", challenge_b64u),
                    ("signature_b64u", signature_b64u),
                ] if not val
            ]
            if missing:
                self._send_json(400, {"error": f"missing required field(s): {', '.join(missing)}"})
                return

            revoking_phone = STATE.find_phone(revoking_phone_id)
            if revoking_phone is None:
                self._send_json(404, {"error": f"unknown revoking_phone_id '{revoking_phone_id}'"})
                return

            if STATE.find_phone(target_phone_id) is None:
                self._send_json(404, {"error": f"unknown target_phone_id '{target_phone_id}'"})
                return

            if revoking_phone_id == target_phone_id:
                self._send_json(400, {"error": "a phone cannot revoke itself; unpair instead"})
                return

            if not STATE.consume_revoke_challenge(revoking_phone_id, challenge_b64u):
                self._send_json(400, {"error": "unknown or expired revoke challenge"})
                return

            if STATE.verify_signatures:
                try:
                    pub = b64u_decode(revoking_phone["public_key_b64u"])
                    sig = b64u_decode(signature_b64u)
                    chal = b64u_decode(challenge_b64u)
                except Exception as ex:
                    self._send_json(400, {"error": f"base64url decode failed: {ex}"})
                    return
                verified = verify_signature(revoking_phone["algorithm"], pub, chal, sig)
                if not verified:
                    self._send_json(400, {
                        "error": f"{revoking_phone['algorithm']} signature does not verify "
                                 f"against the registered public key for the revoking phone",
                    })
                    return

            removed = STATE.remove_phone(target_phone_id)
            if removed:
                STATE.record_audit_event(
                    revoking_phone_id, "phone_revoked",
                    detail=f"Revoked {target_phone_id[:8]}...",
                )
            self._send_json(200, {
                "revoked": removed,
                "target_phone_id": target_phone_id,
            })
            return

        if url.path.startswith("/v0.4/respond/"):
            request_id = url.path[len("/v0.4/respond/"):]
            if not request_id:
                self._send_json(400, {"error": "missing request_id in path"})
                return

            try:
                body = json.loads(body_raw) if body_raw else {}
            except json.JSONDecodeError as ex:
                self._send_json(400, {"error": f"invalid JSON: {ex}"})
                return

            phone_id = body.get("phone_id")
            decision = body.get("decision")
            signature_b64u = body.get("signature_b64u")
            totp_code = body.get("totp_code")
            session_jwt = body.get("session_jwt")
            reason = body.get("reason")
            webauthn_client_data_b64u = body.get("webauthn_client_data_b64u")
            webauthn_authenticator_data_b64u = body.get("webauthn_authenticator_data_b64u")
            # v0.5+ ETH: opaque secp256k1 r||s||v signature the phone produced
            # over the requested digest. Bootloader does NOT validate this
            # signature itself — that's the consumer's job (smart contract /
            # off-chain verifier). We just structure-check + stash for display.
            eth_signature_rsv = body.get("eth_signature_rsv")
            # v0.5+ BTC: opaque BIP-137 compact signature (65 bytes
            # base64-encoded) the phone produced over the BIP-137
            # signed-message hash. Same opaque-forwarding posture as ETH.
            btc_signature_base64 = body.get("btc_signature_base64")
            # Wave-8 ED25519 chains (SOL / XLM / XRP): raw 64-byte
            # ed25519 signature base64-encoded + the 32-byte ed25519
            # public key hex. Both required because XRP addresses are
            # HASH160s and don't carry the pubkey; SOL/XLM carry it
            # for protocol uniformity. Same opaque-forwarding posture
            # as ETH/BTC.
            ed_signature_base64 = body.get("ed_signature_base64")
            ed_pubkey_hex = body.get("ed_pubkey_hex")
            # Wave-9 TRON: opaque secp256k1 r||s||v signature (65 bytes
            # hex) the phone produced over the TIP-191 hash. Same
            # opaque-forwarding posture as ETH; the bootloader does NOT
            # verify the secp256k1 sig itself (consumer's job).
            tron_signature_rsv = body.get("tron_signature_rsv")

            if not phone_id or not decision:
                self._send_json(400, {"error": "phone_id and decision are required"})
                return
            if decision not in ("approved", "denied"):
                self._send_json(400, {"error": f"unknown decision '{decision}'"})
                return

            pending = STATE.take_pending(request_id)
            if pending is None:
                self._send_json(404, {"error": f"no pending request with id '{request_id}'"})
                return
            if pending.get("_phone_id") != phone_id:
                self._send_json(403, {"error": "phone_id does not match the request's target phone"})
                return
            kind = pending.get("kind")

            phone = STATE.find_phone(phone_id)
            if phone is None:
                self._send_json(404, {"error": f"unknown phone_id '{phone_id}'"})
                return

            verified = False
            extra_response_fields: dict = {}

            if decision == "approved":
                if kind in ("single_sign", "pkcs11_sign", "pgp_sign"):
                    # All three "raw signature over a payload-hash" kinds share
                    # the verification path: phone signs the SHA-256 the
                    # bootloader queued, bootloader verifies against the
                    # phone's stored public key with its registered algorithm.
                    if not signature_b64u:
                        self._send_json(400, {"error": f"{kind} approval requires signature_b64u"})
                        return
                    if STATE.verify_signatures:
                        try:
                            pub = b64u_decode(phone["public_key_b64u"])
                            sig = b64u_decode(signature_b64u)
                            payload = b64u_decode(pending["context"]["payload_hash_b64u"])
                        except Exception as ex:
                            self._send_json(400, {"error": f"base64url decode failed: {ex}"})
                            return
                        verified = verify_signature(phone["algorithm"], pub, payload, sig)
                        if not verified:
                            self._send_json(400, {
                                "error": f"{phone['algorithm']} signature does not verify "
                                         f"against the registered public key for this phone",
                            })
                            return
                    else:
                        verified = True
                elif kind == "totp_provision":
                    # Phone confirmed it stored the secret. Nothing to verify on this side
                    # beyond the fact the response came in; the server already has the
                    # secret stored from when we queued the request.
                    verified = True
                elif kind == "totp_generate":
                    if not totp_code:
                        self._send_json(400, {"error": "totp_generate approval requires totp_code"})
                        return
                    alias = pending["context"].get("totp_alias")
                    record = STATE.get_totp_secret(alias) if alias else None
                    if record is None:
                        self._send_json(404, {"error": f"unknown totp alias '{alias}'"})
                        return
                    matched, expected_now = verify_totp_code(totp_code, record)
                    verified = matched
                    extra_response_fields["totp_code"] = totp_code
                    extra_response_fields["totp_expected"] = expected_now
                elif kind == "session_issuance":
                    if not session_jwt:
                        self._send_json(400, {"error": "session_issuance approval requires session_jwt"})
                        return
                    claims, jwt_error = verify_capability_jwt(
                        session_jwt,
                        phone["public_key_b64u"],
                        phone["algorithm"],
                        expected_aud=STATE.bootloader_id,
                    )
                    verified = jwt_error is None
                    if not verified:
                        # Still store the JWT for inspection but mark unverified;
                        # respond 400 so the phone sees the failure.
                        STATE.store_issued_jwt(session_jwt, claims or {}, phone_id, jwt_error)
                        self._send_json(400, {"error": f"JWT verify failed: {jwt_error}"})
                        return
                    STATE.store_issued_jwt(session_jwt, claims or {}, phone_id, None)
                    extra_response_fields["jwt_iss"] = (claims or {}).get("iss")
                    extra_response_fields["jwt_bearer"] = (claims or {}).get("recto:bearer")
                    extra_response_fields["jwt_exp"] = (claims or {}).get("exp")
                elif kind == "eth_sign":
                    # v0.5+ Ethereum signing capability. The phone derived a
                    # secp256k1 private key from its BIP39 mnemonic at the
                    # requested BIP32 path, computed the EIP-191 / EIP-712 /
                    # RLP digest of the queued payload, and signed it. The
                    # phone ALSO signs the standard payload_hash_b64u with
                    # its registration Ed25519 key (same envelope as
                    # single_sign) so the bootloader can prove the response
                    # came from the paired phone. We verify the Ed25519
                    # envelope here and structure-check the rsv signature;
                    # full secp256k1 verification belongs to the consumer
                    # (smart contract on chain, off-chain verifier, etc.)
                    # per the protocol RFC.
                    if not signature_b64u:
                        self._send_json(400, {"error": "eth_sign approval requires signature_b64u (Ed25519 envelope)"})
                        return
                    if not eth_signature_rsv:
                        self._send_json(400, {"error": "eth_sign approval requires eth_signature_rsv"})
                        return
                    rsv_clean = (
                        eth_signature_rsv[2:]
                        if eth_signature_rsv.startswith(("0x", "0X"))
                        else eth_signature_rsv
                    )
                    msg_kind_for_len = pending["context"].get("eth_message_kind", "personal_sign")
                    if msg_kind_for_len == "transaction":
                        # transaction returns the FULL signed raw-tx bytes
                        # (0x02 || rlp([fields..., yParity, r, s])) which
                        # varies in length. Sane minimum: ~200 hex chars.
                        if len(rsv_clean) < 200:
                            self._send_json(400, {
                                "error": f"eth_signature_rsv for transaction must be at least 200 hex chars (signed-tx is too short to be valid), got {len(rsv_clean)}",
                            })
                            return
                    else:
                        if len(rsv_clean) != 130:
                            self._send_json(400, {
                                "error": f"eth_signature_rsv for {msg_kind_for_len} must be 130 hex chars after optional 0x prefix, got {len(rsv_clean)}",
                            })
                            return
                    try:
                        bytes.fromhex(rsv_clean)
                    except ValueError as ex:
                        self._send_json(400, {"error": f"eth_signature_rsv not hex: {ex}"})
                        return
                    if STATE.verify_signatures:
                        try:
                            pub = b64u_decode(phone["public_key_b64u"])
                            sig = b64u_decode(signature_b64u)
                            payload = b64u_decode(pending["context"]["payload_hash_b64u"])
                        except Exception as ex:
                            self._send_json(400, {"error": f"base64url decode failed: {ex}"})
                            return
                        verified = verify_signature(phone["algorithm"], pub, payload, sig)
                        if not verified:
                            self._send_json(400, {
                                "error": f"{phone['algorithm']} envelope signature does not verify "
                                         f"against the registered public key for this phone",
                            })
                            return
                    else:
                        verified = True
                    extra_response_fields["eth_signature_rsv"] = eth_signature_rsv
                    extra_response_fields["eth_chain_id"] = pending["context"].get("eth_chain_id")
                    extra_response_fields["eth_message_kind"] = pending["context"].get("eth_message_kind")
                    extra_response_fields["eth_address"] = pending["context"].get("eth_address")
                    # Stash the message text post-approval so external-verifier
                    # workflows (MyCrypto / etherscan / etc.) can grab the
                    # exact bytes that were signed without having to copy
                    # them out of the pending panel before it disappears.
                    extra_response_fields["eth_message_text"] = pending["context"].get("eth_message_text")
                    extra_response_fields["eth_typed_data_json"] = pending["context"].get("eth_typed_data_json")
                    extra_response_fields["eth_transaction_json"] = pending["context"].get("eth_transaction_json")
                    # Best-effort address recovery — purely informational.
                    # If recto.ethereum is on PYTHONPATH (e.g. mock running
                    # from inside the Recto checkout), recover the signer
                    # address from the rsv and surface it in the response
                    # listing. Operators can eyeball "expected vs recovered"
                    # at a glance. Failure here is non-fatal; the protocol
                    # RFC explicitly says the bootloader doesn't validate
                    # the secp256k1 sig.
                    try:
                        from recto.ethereum import (
                            personal_sign_hash,
                            recover_address,
                        )

                        msg_kind = pending["context"].get("eth_message_kind")
                        digest = None
                        rsv_for_recovery = eth_signature_rsv
                        if msg_kind == "personal_sign":
                            msg_text = pending["context"].get("eth_message_text", "")
                            digest = personal_sign_hash(msg_text.encode("utf-8"))
                        elif msg_kind == "typed_data":
                            from recto.ethereum import typed_data_hash
                            typed_data_json = pending["context"].get("eth_typed_data_json", "")
                            if typed_data_json:
                                td = json.loads(typed_data_json)
                                digest = typed_data_hash(td)
                        elif msg_kind == "transaction":
                            # Transaction returns the FULL signed raw-tx
                            # bytes, not r||s||v. To recover the signer we
                            # need to (a) re-derive the unsigned hash from
                            # the queued JSON, and (b) extract r/s/yParity
                            # from the signed RLP. Cleanest is to recompute
                            # the hash AND parse the FULL signed-tx via the
                            # python helper that exists for verification.
                            from recto.ethereum import transaction_hash_eip1559
                            tx_json = pending["context"].get("eth_transaction_json", "")
                            if tx_json:
                                tx = json.loads(tx_json)
                                digest = transaction_hash_eip1559(tx)
                                # Decode the signed raw-tx to extract r||s||v.
                                # Format: 0x02 || rlp([..., yParity, r, s])
                                # We pull yParity (last 3rd item), r, s from
                                # the END of the signed payload by RLP-decoding.
                                from recto.ethereum import rlp_decode
                                raw_bytes = bytes.fromhex(rsv_clean)
                                if raw_bytes[0] != 0x02:
                                    raise ValueError(f"signed tx must start with 0x02, got 0x{raw_bytes[0]:02x}")
                                decoded = rlp_decode(raw_bytes[1:])
                                # decoded is the list with [...payload, yParity, r, s]
                                y_parity_b = decoded[-3]
                                r_b = decoded[-2]
                                s_b = decoded[-1]
                                # yParity is a 0 or 1 integer (RLP-encoded
                                # as empty bytes for 0). r and s are 32-byte
                                # big-endian integers (may have leading zeros
                                # stripped — left-pad).
                                y_parity = int.from_bytes(y_parity_b or b"\x00", "big")
                                r_padded = (b"\x00" * (32 - len(r_b))) + r_b
                                s_padded = (b"\x00" * (32 - len(s_b))) + s_b
                                # recover_address expects 27/28 v (canonical)
                                v_canonical = 27 + y_parity
                                rsv_assembled = r_padded + s_padded + bytes([v_canonical])
                                rsv_for_recovery = "0x" + rsv_assembled.hex()
                        if digest is not None:
                            recovered = recover_address(digest, rsv_for_recovery)
                            extra_response_fields["eth_recovered_address"] = recovered
                            expected_addr = (pending["context"].get("eth_address") or "").lower()
                            # Suppress the match comparison when the queued
                            # address is a placeholder (all-zero or empty).
                            # Operator-UI queues use the placeholder when
                            # the phone hasn't pre-registered an address;
                            # the recovered address is then the only useful
                            # info, not a mismatch warning.
                            placeholder_addrs = {"", "0x" + "00" * 20, "0x"}
                            if expected_addr in placeholder_addrs:
                                # leave eth_address_match unset → UI shows
                                # "recovered: <addr>" without match marker
                                pass
                            else:
                                extra_response_fields["eth_address_match"] = (
                                    recovered.lower() == expected_addr
                                )
                    except Exception as ex:  # noqa: BLE001
                        extra_response_fields["eth_recovery_error"] = str(ex)
                elif kind == "tron_sign":
                    # Wave-9 TRON message_signing. Same secp256k1 + Keccak-256
                    # primitive as ETH but with TIP-191 preamble + base58check
                    # T-prefixed addresses. The bootloader doesn't verify the
                    # secp256k1 sig (consumer's job) but DOES recover-and-display
                    # the signer's TRON address for the operator-UI panel so
                    # "expected vs recovered" is eyeball-checkable. Failure
                    # is non-fatal -- the protocol RFC says structure-check only.
                    if not signature_b64u:
                        self._send_json(400, {"error": "tron_sign approval requires signature_b64u (Ed25519 envelope)"})
                        return
                    if not tron_signature_rsv:
                        self._send_json(400, {"error": "tron_sign approval requires tron_signature_rsv"})
                        return
                    rsv_clean_tron = (
                        tron_signature_rsv[2:]
                        if tron_signature_rsv.startswith(("0x", "0X"))
                        else tron_signature_rsv
                    )
                    if len(rsv_clean_tron) != 130:
                        self._send_json(400, {
                            "error": (
                                f"tron_signature_rsv must be 130 hex chars after "
                                f"optional 0x prefix, got {len(rsv_clean_tron)}"
                            ),
                        })
                        return
                    try:
                        bytes.fromhex(rsv_clean_tron)
                    except ValueError as ex:
                        self._send_json(400, {"error": f"tron_signature_rsv not hex: {ex}"})
                        return
                    if STATE.verify_signatures:
                        try:
                            pub_t = b64u_decode(phone["public_key_b64u"])
                            sig_t = b64u_decode(signature_b64u)
                            envelope_payload = b64u_decode(
                                pending["context"]["payload_hash_b64u"]
                            )
                        except Exception as ex:
                            self._send_json(400, {"error": f"base64url decode failed: {ex}"})
                            return
                        verified = verify_signature(
                            phone["algorithm"], pub_t, envelope_payload, sig_t
                        )
                        if not verified:
                            self._send_json(400, {
                                "error": (
                                    f"{phone['algorithm']} signature does not verify "
                                    f"against the registered public key for this phone"
                                ),
                            })
                            return
                    else:
                        verified = True
                    extra_response_fields["tron_signature_rsv"] = tron_signature_rsv
                    extra_response_fields["tron_network"] = pending["context"].get("tron_network")
                    extra_response_fields["tron_message_kind"] = pending["context"].get("tron_message_kind")
                    extra_response_fields["tron_address"] = pending["context"].get("tron_address")
                    extra_response_fields["tron_message_text"] = pending["context"].get("tron_message_text")
                    # Best-effort signer-address recovery for operator
                    # display. If recto.tron is on PYTHONPATH, recover
                    # the signer address from the TIP-191 hash + rsv and
                    # surface it inline. Failure here is non-fatal.
                    try:
                        from recto.tron import (
                            signed_message_hash as _tron_msg_hash,
                            recover_address as _tron_recover_addr,
                        )

                        msg_text_tron = pending["context"].get(
                            "tron_message_text", ""
                        )
                        digest_tron = _tron_msg_hash(
                            msg_text_tron.encode("utf-8")
                        )
                        recovered_tron = _tron_recover_addr(
                            digest_tron, tron_signature_rsv
                        )
                        extra_response_fields["tron_recovered_address"] = recovered_tron
                        expected_addr_tron = (
                            pending["context"].get("tron_address") or ""
                        )
                        # Suppress the match comparison when the queued
                        # address is a placeholder. The operator-UI's
                        # "/_queue_tron_message_sign" handler uses
                        # "TPlaceholder111111111111111111111A" as the
                        # placeholder; any real phone-derived address
                        # won't match this prefix.
                        if expected_addr_tron.startswith("TPlaceholder"):
                            # Leave tron_address_match unset -- UI shows
                            # "recovered: <addr>" without a marker.
                            pass
                        else:
                            extra_response_fields["tron_address_match"] = (
                                recovered_tron == expected_addr_tron
                            )
                    except Exception as ex:  # noqa: BLE001
                        extra_response_fields["tron_recovery_error"] = str(ex)
                elif kind == "btc_sign":
                    # v0.5+ Bitcoin signing capability. Same shape as
                    # eth_sign: phone derives a secp256k1 private key from
                    # its BIP-39 mnemonic at the requested BIP-32 path
                    # (default m/84'/0'/0'/0/0 native-SegWit), computes
                    # the BIP-137 hash of the signed-message preimage,
                    # signs, and returns the 65-byte BIP-137 compact
                    # signature base64-encoded. The phone ALSO Ed25519-
                    # signs the standard payload_hash_b64u so the
                    # bootloader proves response provenance.
                    if not signature_b64u:
                        self._send_json(400, {"error": "btc_sign approval requires signature_b64u (Ed25519 envelope)"})
                        return
                    if not btc_signature_base64:
                        self._send_json(400, {"error": "btc_sign approval requires btc_signature_base64"})
                        return
                    try:
                        decoded_btc_sig = base64.b64decode(btc_signature_base64.strip(), validate=False)
                    except Exception as ex:
                        self._send_json(400, {"error": f"btc_signature_base64 not valid base64: {ex}"})
                        return
                    if len(decoded_btc_sig) != 65:
                        self._send_json(400, {
                            "error": f"btc_signature_base64 must decode to 65 bytes, got {len(decoded_btc_sig)}",
                        })
                        return
                    btc_header = decoded_btc_sig[0]
                    if btc_header < 27 or btc_header > 42:
                        self._send_json(400, {
                            "error": f"BIP-137 header byte must be in 27..42, got {btc_header}",
                        })
                        return
                    if STATE.verify_signatures:
                        try:
                            pub = b64u_decode(phone["public_key_b64u"])
                            sig = b64u_decode(signature_b64u)
                            payload = b64u_decode(pending["context"]["payload_hash_b64u"])
                        except Exception as ex:
                            self._send_json(400, {"error": f"base64url decode failed: {ex}"})
                            return
                        verified = verify_signature(phone["algorithm"], pub, payload, sig)
                        if not verified:
                            self._send_json(400, {
                                "error": f"{phone['algorithm']} envelope signature does not verify "
                                         f"against the registered public key for this phone",
                            })
                            return
                    else:
                        verified = True
                    extra_response_fields["btc_signature_base64"] = btc_signature_base64
                    extra_response_fields["btc_network"] = pending["context"].get("btc_network")
                    extra_response_fields["btc_message_kind"] = pending["context"].get("btc_message_kind")
                    extra_response_fields["btc_address"] = pending["context"].get("btc_address")
                    extra_response_fields["btc_message_text"] = pending["context"].get("btc_message_text")
                    # Wave-7: Bitcoin-family coin discriminator.
                    # MUST be set OUTSIDE the recto-import try below,
                    # because the renderer's per-coin ticker dispatch
                    # ("BTC" / "LTC" / "DOGE" / "BCH") uses this field
                    # and we want correct labels even on hosts where
                    # recto.bitcoin can't be imported. Without this
                    # hoist, all btc-family rows fall back to the
                    # "BTC" default ticker and operators see
                    # "BTC message_signing" next to a Litecoin or
                    # Dogecoin login — wrong, and not safe to leave
                    # in production.
                    coin_btc = pending["context"].get("btc_coin", "btc") or "btc"
                    extra_response_fields["btc_coin"] = coin_btc
                    # Best-effort signer-address recovery — purely
                    # informational. If recto.bitcoin is on PYTHONPATH
                    # (mock running from inside the Recto checkout),
                    # recover the signer address from the BIP-137 compact
                    # sig and surface inline. Failure here is non-fatal;
                    # the protocol RFC says the bootloader doesn't
                    # validate the secp256k1 sig.
                    try:
                        from recto.bitcoin import (
                            signed_message_hash as _btc_msg_hash,
                            recover_address as _btc_recover_addr,
                        )

                        msg_kind_btc = pending["context"].get("btc_message_kind")
                        network_btc = pending["context"].get("btc_network", "mainnet")
                        if msg_kind_btc == "message_signing":
                            msg_text_btc = pending["context"].get("btc_message_text", "")
                            digest_btc = _btc_msg_hash(msg_text_btc.encode("utf-8"), coin=coin_btc)
                            recovered_btc = _btc_recover_addr(digest_btc, btc_signature_base64, network=network_btc, coin=coin_btc)
                            extra_response_fields["btc_recovered_address"] = recovered_btc
                            expected_addr_btc = (pending["context"].get("btc_address") or "").lower()
                            # Suppress the match comparison when the queued
                            # address is a placeholder (operator-UI default
                            # for phones that haven't pre-registered an
                            # address). Each coin has its own placeholder
                            # prefix; lowercase-comparing against the
                            # known prefixes catches them all.
                            placeholder_prefixes = (
                                "bc1qplaceholder",   # BTC
                                "ltc1qplaceholder",  # LTC
                                "dplaceholder",      # DOGE (lowercase 'd')
                                "1placeholder",      # BCH legacy
                            )
                            if not expected_addr_btc or expected_addr_btc.startswith(placeholder_prefixes):
                                pass  # leave btc_address_match unset; UI shows recovered without marker
                            else:
                                extra_response_fields["btc_address_match"] = (
                                    recovered_btc.lower() == expected_addr_btc
                                )
                        # psbt recovery is a follow-up — needs full BIP-174 parse.
                    except Exception as ex:  # noqa: BLE001
                        extra_response_fields["btc_recovery_error"] = str(ex)
                elif kind == "ed_sign":
                    # Wave-8 ed25519 chains (SOL / XLM / XRP). Same shape
                    # as eth_sign / btc_sign: phone derives a 32-byte
                    # ed25519 seed from its BIP-39 mnemonic at the
                    # requested SLIP-0010 path, computes the chain-
                    # specific signed-message hash (preamble varies per
                    # chain), signs, and returns a raw 64-byte ed25519
                    # signature base64-encoded PLUS the 32-byte public
                    # key hex (XRP needs the explicit pubkey because its
                    # addresses are HASH160s; SOL and XLM carry it for
                    # protocol uniformity). The phone ALSO Ed25519-signs
                    # the standard payload_hash_b64u so the bootloader
                    # proves response provenance.
                    if not signature_b64u:
                        self._send_json(400, {"error": "ed_sign approval requires signature_b64u (Ed25519 envelope)"})
                        return
                    if not ed_signature_base64:
                        self._send_json(400, {"error": "ed_sign approval requires ed_signature_base64"})
                        return
                    if not ed_pubkey_hex:
                        self._send_json(400, {"error": "ed_sign approval requires ed_pubkey_hex"})
                        return
                    try:
                        decoded_ed_sig = base64.b64decode(ed_signature_base64.strip(), validate=False)
                    except Exception as ex:
                        self._send_json(400, {"error": f"ed_signature_base64 not valid base64: {ex}"})
                        return
                    if len(decoded_ed_sig) != 64:
                        self._send_json(400, {
                            "error": f"ed_signature_base64 must decode to 64 bytes, got {len(decoded_ed_sig)}",
                        })
                        return
                    ed_pubkey_clean = (
                        ed_pubkey_hex[2:]
                        if ed_pubkey_hex.startswith(("0x", "0X"))
                        else ed_pubkey_hex
                    )
                    if len(ed_pubkey_clean) != 64:
                        self._send_json(400, {
                            "error": f"ed_pubkey_hex must be 64 hex chars (32-byte ed25519 pubkey) "
                                     f"after optional 0x prefix, got {len(ed_pubkey_clean)}",
                        })
                        return
                    try:
                        ed_pubkey_bytes = bytes.fromhex(ed_pubkey_clean)
                    except ValueError as ex:
                        self._send_json(400, {"error": f"ed_pubkey_hex not hex: {ex}"})
                        return
                    if STATE.verify_signatures:
                        try:
                            pub = b64u_decode(phone["public_key_b64u"])
                            sig = b64u_decode(signature_b64u)
                            payload = b64u_decode(pending["context"]["payload_hash_b64u"])
                        except Exception as ex:
                            self._send_json(400, {"error": f"base64url decode failed: {ex}"})
                            return
                        verified = verify_signature(phone["algorithm"], pub, payload, sig)
                        if not verified:
                            self._send_json(400, {
                                "error": f"{phone['algorithm']} envelope signature does not verify "
                                         f"against the registered public key for this phone",
                            })
                            return
                    else:
                        verified = True
                    extra_response_fields["ed_signature_base64"] = ed_signature_base64
                    extra_response_fields["ed_pubkey_hex"] = ed_pubkey_clean
                    extra_response_fields["ed_chain"] = pending["context"].get("ed_chain")
                    extra_response_fields["ed_message_kind"] = pending["context"].get("ed_message_kind")
                    extra_response_fields["ed_address"] = pending["context"].get("ed_address")
                    extra_response_fields["ed_message_text"] = pending["context"].get("ed_message_text")
                    # Best-effort chain-signature verification + address
                    # derivation. If recto.solana / recto.stellar /
                    # recto.ripple are on PYTHONPATH (mock running from
                    # inside the Recto checkout), verify the ed25519
                    # signature against the supplied pubkey AND derive
                    # the address from the pubkey, comparing to the
                    # operator-approved expected address. Failure here
                    # is non-fatal; the protocol RFC says the bootloader
                    # doesn't validate the chain sig.
                    try:
                        ed_chain_resp = pending["context"].get("ed_chain", "sol")
                        msg_text_ed = pending["context"].get("ed_message_text", "") or ""
                        if ed_chain_resp == "sol":
                            from recto.solana import (
                                signed_message_hash as _sol_msg_hash,
                                verify_signature as _sol_verify,
                                address_from_public_key as _sol_addr,
                            )
                            digest_ok = _sol_verify(msg_text_ed.encode("utf-8"), decoded_ed_sig, ed_pubkey_bytes)
                            derived_addr = _sol_addr(ed_pubkey_bytes)
                            extra_response_fields["ed_signature_verified"] = bool(digest_ok)
                            extra_response_fields["ed_derived_address"] = derived_addr
                        elif ed_chain_resp == "xlm":
                            from recto.stellar import (
                                verify_signature as _xlm_verify,
                                address_from_public_key as _xlm_addr,
                            )
                            digest_ok = _xlm_verify(msg_text_ed.encode("utf-8"), decoded_ed_sig, ed_pubkey_bytes)
                            derived_addr = _xlm_addr(ed_pubkey_bytes)
                            extra_response_fields["ed_signature_verified"] = bool(digest_ok)
                            extra_response_fields["ed_derived_address"] = derived_addr
                        elif ed_chain_resp == "xrp":
                            from recto.ripple import (
                                verify_signature as _xrp_verify,
                                address_from_public_key as _xrp_addr,
                            )
                            digest_ok = _xrp_verify(msg_text_ed.encode("utf-8"), decoded_ed_sig, ed_pubkey_bytes)
                            derived_addr = _xrp_addr(ed_pubkey_bytes)
                            extra_response_fields["ed_signature_verified"] = bool(digest_ok)
                            extra_response_fields["ed_derived_address"] = derived_addr
                        else:
                            extra_response_fields["ed_recovery_error"] = f"unknown ed_chain: {ed_chain_resp}"
                            derived_addr = None
                        # Compare derived vs expected (operator-approved
                        # address from queue time). Suppress the match
                        # comparison when the queued address is a
                        # placeholder (the operator-UI default queue uses
                        # one).
                        expected_addr_ed = (pending["context"].get("ed_address") or "").strip()
                        placeholder_prefixes = (
                            # SOL: queue default uses the System Program
                            # pubkey "11111...1112" (31 ones + a '2'),
                            # but a literal 32-zero-bytes pubkey base58s
                            # to "11111...1111" (32 ones). Match both
                            # via a 24-ones prefix -- any real ed25519
                            # pubkey is high-entropy and will never
                            # collide with this much-ones run.
                            "111111111111111111111111",
                            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",  # XLM all-zeros prefix
                            "rPlaceholder",                      # XRP
                        )
                        if derived_addr is not None:
                            if not expected_addr_ed or expected_addr_ed.startswith(placeholder_prefixes):
                                pass  # leave ed_address_match unset
                            else:
                                extra_response_fields["ed_address_match"] = (
                                    derived_addr == expected_addr_ed
                                )
                    except Exception as ex:  # noqa: BLE001
                        extra_response_fields["ed_recovery_error"] = str(ex)
                elif kind == "webauthn_assert":
                    missing = [
                        name for name, val in [
                            ("webauthn_client_data_b64u", webauthn_client_data_b64u),
                            ("webauthn_authenticator_data_b64u", webauthn_authenticator_data_b64u),
                            ("signature_b64u", signature_b64u),
                        ] if not val
                    ]
                    if missing:
                        self._send_json(400, {
                            "error": f"webauthn_assert approval requires: {', '.join(missing)}",
                        })
                        return
                    expected_challenge = pending.get("_webauthn_challenge_b64u_expected")
                    expected_origin = pending.get("_webauthn_origin_expected")
                    expected_rp_id = pending.get("_webauthn_rp_id_expected")
                    if not expected_challenge or not expected_origin or not expected_rp_id:
                        self._send_json(500, {"error": "queued webauthn_assert request lost its expected fields"})
                        return
                    ok, wa_error, captured = verify_webauthn_assertion(
                        client_data_b64u=webauthn_client_data_b64u,
                        authenticator_data_b64u=webauthn_authenticator_data_b64u,
                        signature_b64u=signature_b64u,
                        expected_challenge_b64u=expected_challenge,
                        expected_origin=expected_origin,
                        expected_rp_id=expected_rp_id,
                        public_key_b64u=phone["public_key_b64u"],
                        algorithm=phone["algorithm"],
                    )
                    verified = ok
                    extra_response_fields.update(captured)
                    if not verified:
                        self._send_json(400, {"error": f"WebAuthn assertion verify failed: {wa_error}"})
                        return
                    # Cache for demo-page polling (5min TTL, soft-evicted on
                    # next access). Demo at /demo/webauthn polls
                    # /v0.4/webauthn/result/{request_id} until this lands.
                    with STATE._lock:
                        STATE.webauthn_results[request_id] = {
                            "status": "completed",
                            "request_id": request_id,
                            "verified": True,
                            "rp_id": expected_rp_id,
                            "origin": expected_origin,
                            "challenge_b64u": expected_challenge,
                            "phone_id": phone_id,
                            "phone_label": phone.get("device_label", ""),
                            "client_data_b64u": webauthn_client_data_b64u,
                            "authenticator_data_b64u": webauthn_authenticator_data_b64u,
                            "signature_b64u": signature_b64u,
                            "completed_at_unix": int(time.time()),
                        }
                elif kind == "capability_request":
                    # Phase 5 Wave B routing: phone signs SHA-256 of
                    # `{cap_header_b64}.{cap_payload_b64}` ASCII bytes
                    # with the operator's secp256k1 BIP-39-derived key
                    # and returns the 64-byte raw r||s on
                    # cap_signature_b64u (base64url-encoded). Mock
                    # assembles the final 3-part JWS via
                    # recto.capability.jwt.assemble_jws and stashes it
                    # for the agent's result-poll fetch. Until Wave B
                    # part 2 ships phone-side cap-signature signing,
                    # the phone won't include cap_signature_b64u in
                    # its response — mock records a "signature_error"
                    # response in that case so the operator sees what
                    # part of the loop is missing.
                    cap_signature_b64u = body.get("cap_signature_b64u")
                    if not cap_signature_b64u:
                        # Until phone-side part 2 ships, this is the
                        # expected branch on every approval. Stash a
                        # signature_error result so the agent's poll
                        # endpoint at least gets a clean status.
                        with STATE._lock:
                            STATE.capability_results[request_id] = {
                                "status": "signature_error",
                                "request_id": request_id,
                                "reason": (
                                    "cap_signature_b64u missing on "
                                    "capability_request approval (phone-side "
                                    "Wave B part 2 not yet shipped)"
                                ),
                                "agent_id": pending["context"].get("cap_agent_id"),
                                "completed_at_unix": int(time.time()),
                            }
                        verified = True  # Ed25519 envelope was checked above
                        extra_response_fields["cap_status"] = "signature_error"
                        extra_response_fields["cap_reason"] = (
                            "phone did not return cap_signature_b64u "
                            "(Wave B part 2 not shipped)"
                        )
                    else:
                        # Decode the 64-byte raw r||s.
                        try:
                            cap_pad = "=" * (-len(cap_signature_b64u) % 4)
                            cap_sig_bytes = base64.urlsafe_b64decode(
                                cap_signature_b64u + cap_pad
                            )
                        except Exception as ex:  # noqa: BLE001
                            self._send_json(400, {
                                "error": f"cap_signature_b64u not base64url: {ex}"
                            })
                            return
                        if len(cap_sig_bytes) != 64:
                            self._send_json(400, {
                                "error": (
                                    f"cap_signature_b64u must decode to 64 "
                                    f"bytes (raw r||s); got {len(cap_sig_bytes)}"
                                ),
                            })
                            return
                        # Assemble final JWS.
                        try:
                            from recto.capability.jwt import (
                                assemble_jws as _cap_assemble,
                            )
                            cap_jws = _cap_assemble(
                                pending["context"]["cap_header_b64"],
                                pending["context"]["cap_payload_b64"],
                                cap_sig_bytes,
                            )
                        except Exception as ex:  # noqa: BLE001
                            self._send_json(500, {
                                "error": f"capability JWS assembly failed: {ex}"
                            })
                            return
                        verified = True  # Ed25519 envelope already verified above
                        # Best-effort recovery of the operator pubkey from
                        # the cap signature — non-fatal, purely informational
                        # for the recent-responses display pane.
                        recovered_iss = None
                        try:
                            from recto.capability.jwt import (
                                verify_jws as _cap_verify,
                            )
                            from recto.ethereum import recover_public_key
                            # Try recovering pubkey from synthetic rsv
                            # (mirrors the verify_jws internal logic).
                            digest_capreq = hashlib.sha256(
                                f"{pending['context']['cap_header_b64']}."
                                f"{pending['context']['cap_payload_b64']}"
                                .encode("ascii")
                            ).digest()
                            for rec_id in (0, 1):
                                synth = cap_sig_bytes + bytes([27 + rec_id])
                                try:
                                    pub = recover_public_key(
                                        digest_capreq, synth,
                                    )
                                    recovered_iss = pub.hex()
                                    break
                                except Exception:
                                    continue
                        except Exception:
                            pass
                        with STATE._lock:
                            STATE.capability_results[request_id] = {
                                "status": "approved",
                                "request_id": request_id,
                                "capability_jws": cap_jws,
                                "agent_id": pending["context"].get("cap_agent_id"),
                                "completed_at_unix": int(time.time()),
                            }
                        extra_response_fields["cap_status"] = "approved"
                        extra_response_fields["capability_jws"] = cap_jws
                        if recovered_iss:
                            extra_response_fields["cap_recovered_pubkey_hex"] = recovered_iss
                else:
                    self._send_json(400, {"error": f"unknown request kind '{kind}'"})
                    return

            STATE.record_response(
                request_id=request_id,
                phone_id=phone_id,
                decision=decision,
                signature_b64u=signature_b64u,
                reason=reason,
                verified=verified,
                service=pending["service"],
                secret=pending["secret"],
                kind=kind,
                extras=extra_response_fields,
                # Audit-log fields: shape varies by kind, all optional.
                payload_hash_b64u=pending.get("context", {}).get("payload_hash_b64u"),
                totp_alias=pending.get("context", {}).get("totp_alias"),
                webauthn_rp_id=pending.get("context", {}).get("webauthn_rp_id"),
            )
            self._send_json(200, {"recorded": True})
            return

        self._send_json(404, {"error": f"no route {url.path}"})


# ---- index page ------------------------------------------------------------

def render_index() -> str:
    now = time.time()

    codes_html = "".join(
        f"<li><code>{code}</code> &mdash; <span class='dim'>expires in {int(expires - now)}s</span></li>"
        for code, expires in STATE.pairing_codes.items()
        if expires > now
    ) or "<li class='dim'>(none)</li>"

    def _phone_label(r: dict) -> str:
        push_token = r.get("push_token")
        push_platform = r.get("push_platform")
        push_html = (
            f", push <code>{push_platform}:{push_token[:18]}...</code>"
            if push_token and push_platform
            else ", <span class='dim'>no push (poll fallback)</span>"
        )
        return (
            f"<li><code>{r['phone_id']}</code> &mdash; {r['device_label']} "
            f"<span class='dim'>(<code>{r.get('algorithm', '?')}</code>, "
            f"paired {r['paired_at']}{push_html})</span></li>"
        )

    registered_html = "".join(
        _phone_label(r) for r in STATE.registered
    ) or "<li class='dim'>(no phones registered yet)</li>"

    def _pending_label(r: dict) -> str:
        kind = r.get("kind", "single_sign")
        if kind == "totp_provision":
            return f"<span class='dim'>TOTP provision</span> <code>{r['context'].get('totp_alias', '?')}</code>"
        if kind == "totp_generate":
            return f"<span class='dim'>TOTP generate</span> <code>{r['context'].get('totp_alias', '?')}</code>"
        if kind == "session_issuance":
            bearer = r["context"].get("session_bearer", "?")
            return (
                f"<span class='dim'>session issuance</span> "
                f"<code>{r['service']}</code>/<code>{r['secret']}</code> "
                f"&rarr; bearer <code>{bearer}</code>"
            )
        if kind == "webauthn_assert":
            rp_id = r["context"].get("webauthn_rp_id", "?")
            return (
                f"<span class='dim'>passkey assertion</span> "
                f"&rarr; <code>{rp_id}</code>"
            )
        if kind == "pkcs11_sign":
            purpose = r["context"].get("purpose", "?")
            return (
                f"<span class='dim'>PKCS#11 sign</span> "
                f"<code>{r['service']}</code>/<code>{r['secret']}</code> "
                f"({purpose})"
            )
        if kind == "pgp_sign":
            op = r["context"].get("pgp_operation", "?")
            return (
                f"<span class='dim'>PGP {op}</span> "
                f"<code>{r['service']}</code>/<code>{r['secret']}</code>"
            )
        if kind == "eth_sign":
            msg_kind = r["context"].get("eth_message_kind", "?")
            chain_id = r["context"].get("eth_chain_id", "?")
            if msg_kind == "personal_sign":
                # Trim the message text so it fits on one line.
                msg_text = r["context"].get("eth_message_text", "") or ""
                preview = msg_text if len(msg_text) <= 64 else msg_text[:61] + "..."
                return (
                    f"<span class='dim'>ETH {msg_kind}</span> "
                    f"<code>chain {chain_id}</code> "
                    f"&mdash; <code>{preview}</code>"
                )
            return (
                f"<span class='dim'>ETH {msg_kind}</span> "
                f"<code>chain {chain_id}</code>"
            )
        if kind == "btc_sign":
            msg_kind = r["context"].get("btc_message_kind", "?")
            network = r["context"].get("btc_network", "?")
            # Wave-7: coin-aware ticker. Dispatches on btc_coin so
            # LTC / DOGE / BCH pending rows show the correct ticker
            # instead of all hardcoding "BTC". Default "btc" preserves
            # backward compat with v0.5 launchers that pre-date the
            # multi-coin extension.
            coin_pending = r["context"].get("btc_coin", "btc") or "btc"
            ticker_pending = {
                "btc": "BTC", "ltc": "LTC", "doge": "DOGE", "bch": "BCH",
            }.get(coin_pending, "BTC")
            if msg_kind == "message_signing":
                msg_text = r["context"].get("btc_message_text", "") or ""
                preview = msg_text if len(msg_text) <= 64 else msg_text[:61] + "..."
                return (
                    f"<span class='dim'>{ticker_pending} {msg_kind}</span> "
                    f"<code>{network}</code> "
                    f"&mdash; <code>{preview}</code>"
                )
            return (
                f"<span class='dim'>{ticker_pending} {msg_kind}</span> "
                f"<code>{network}</code>"
            )
        if kind == "ed_sign":
            msg_kind = r["context"].get("ed_message_kind", "?")
            chain = r["context"].get("ed_chain", "?")
            ticker = {"sol": "SOL", "xlm": "XLM", "xrp": "XRP"}.get(chain, chain.upper())
            if msg_kind == "message_signing":
                msg_text = r["context"].get("ed_message_text", "") or ""
                preview = msg_text if len(msg_text) <= 64 else msg_text[:61] + "..."
                return (
                    f"<span class='dim'>{ticker} {msg_kind}</span> "
                    f"&mdash; <code>{preview}</code>"
                )
            return f"<span class='dim'>{ticker} {msg_kind}</span>"
        return f"<span class='dim'>sign</span> <code>{r['service']}</code>/<code>{r['secret']}</code>"

    pending_html = "".join(
        f"<li><code>{r['request_id'][:8]}&hellip;</code> &mdash; {_pending_label(r)} "
        f"&mdash; <span class='dim'>queued {r['_queued_at']}, "
        f"target phone <code>{r['_phone_id'][:8]}&hellip;</code></span></li>"
        for r in STATE.pending_requests.values()
    ) or "<li class='dim'>(none)</li>"

    totp_provisioned_html = "".join(
        f"<li><code>{alias}</code> &mdash; <span class='dim'>"
        f"period {r['period_seconds']}s, {r['digits']} digits, {r['algorithm']}, "
        f"queued {r['queued_at']}</span></li>"
        for alias, r in STATE.totp_secrets.items()
    ) or "<li class='dim'>(none)</li>"

    def _jwt_label(j: dict) -> str:
        exp = j.get("exp")
        exp_label = (
            datetime.fromtimestamp(exp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            if isinstance(exp, int)
            else "?"
        )
        scope = j.get("scope") or []
        scope_label = ", ".join(scope) if scope else "(none)"
        marker = (
            "<span class='verified'>verified</span>"
            if j.get("verify_error") is None
            else f"<span class='warn'>verify error: {j.get('verify_error')}</span>"
        )
        return (
            f"<span class='dim'>{j['issued_at']}</span> "
            f"<code>{j.get('sub', '?')}</code> &rarr; bearer <code>{j.get('bearer', '?')}</code>, "
            f"scope [{scope_label}], max_uses {j.get('max_uses', '?')}, "
            f"exp {exp_label} &mdash; {marker}"
        )

    issued_jwts_html = "".join(
        f"<li>{_jwt_label(j)}</li>"
        for j in STATE.issued_jwts
    ) or "<li class='dim'>(none)</li>"

    def _resp_label(r: dict) -> str:
        if r["decision"] != "approved":
            return f"<strong>denied</strong> &mdash; reason: {r.get('reason') or '(none)'}"
        verify_marker = "<span class='verified'>verified</span>" if r.get("verified") else "<span class='warn'>unverified</span>"
        kind = r.get("kind", "single_sign")
        if kind == "single_sign":
            sig_short = (r.get("signature_b64u") or "")[:16] + "&hellip;"
            return f"<strong>approved</strong> &mdash; sig <code>{sig_short}</code> &mdash; {verify_marker}"
        if kind == "totp_provision":
            return f"<strong>approved</strong> &mdash; secret stored on phone &mdash; {verify_marker}"
        if kind == "totp_generate":
            code = r.get("totp_code") or "(none)"
            expected = r.get("totp_expected") or "(none)"
            match_marker = (
                f"<span class='verified'>matches expected {expected}</span>"
                if r.get("verified")
                else f"<span class='warn'>expected {expected}</span>"
            )
            return f"<strong>approved</strong> &mdash; code <code>{code}</code> &mdash; {match_marker}"
        if kind == "session_issuance":
            bearer = r.get("jwt_bearer") or "?"
            exp = r.get("jwt_exp")
            exp_label = f"exp {datetime.fromtimestamp(exp, tz=timezone.utc).strftime('%H:%M:%S')}" if isinstance(exp, int) else "exp ?"
            return f"<strong>approved</strong> &mdash; JWT bearer <code>{bearer}</code>, {exp_label} &mdash; {verify_marker}"
        if kind == "webauthn_assert":
            origin = r.get("wa_origin") or "?"
            flags = r.get("wa_flags") or "?"
            return (
                f"<strong>approved</strong> &mdash; passkey assertion "
                f"origin <code>{origin}</code>, flags <code>{flags}</code> "
                f"&mdash; {verify_marker}"
            )
        if kind == "eth_sign":
            rsv = r.get("eth_signature_rsv") or ""
            rsv_short = rsv[:14] + "&hellip;" + rsv[-6:] if len(rsv) > 26 else rsv
            chain_id = r.get("eth_chain_id", "?")
            msg_kind = r.get("eth_message_kind", "?")
            recovered = r.get("eth_recovered_address")
            msg_text = r.get("eth_message_text") or ""
            # Render the message text on its own line so operators can copy
            # it into external verifiers (MyCrypto / etherscan) post-approval.
            msg_text_html = (
                f"<br><span class='dim'>msg:</span> <code>{msg_text}</code>"
                if msg_text else ""
            )
            # Render the FULL rsv on its own line, untruncated, with
            # word-break so a long hex value wraps cleanly. Operators
            # copy this verbatim into MyCrypto / etherscan / etc.
            rsv_full_html = (
                f"<br><span class='dim'>rsv (full):</span> "
                f"<code style='word-break: break-all;'>{rsv}</code>"
                if rsv else ""
            )
            recovery_html = ""
            if recovered:
                if r.get("eth_address_match") is True:
                    recovery_html = (
                        f" &mdash; recovered <code>{recovered}</code> "
                        f"<span class='verified'>matches expected</span>"
                    )
                elif r.get("eth_address_match") is False:
                    expected = r.get("eth_address") or "?"
                    recovery_html = (
                        f" &mdash; recovered <code>{recovered}</code> "
                        f"<span class='warn'>differs from expected {expected}</span>"
                    )
                else:
                    recovery_html = f" &mdash; recovered <code>{recovered}</code>"
            elif r.get("eth_recovery_error"):
                recovery_html = (
                    f" &mdash; <span class='warn'>"
                    f"address recovery failed: {r.get('eth_recovery_error')}</span>"
                )
            return (
                f"<strong>approved</strong> &mdash; ETH {msg_kind} "
                f"<code>chain {chain_id}</code>, rsv <code>{rsv_short}</code>"
                f"{recovery_html} &mdash; {verify_marker}"
                f"{msg_text_html}"
                f"{rsv_full_html}"
            )
        if kind == "btc_sign":
            btc_sig = r.get("btc_signature_base64") or ""
            btc_sig_short = (
                btc_sig[:10] + "&hellip;" + btc_sig[-6:]
                if len(btc_sig) > 22 else btc_sig
            )
            network_btc = r.get("btc_network", "?")
            msg_kind_btc = r.get("btc_message_kind", "?")
            recovered_btc = r.get("btc_recovered_address")
            msg_text_btc = r.get("btc_message_text") or ""
            recovery_html_btc = ""
            if recovered_btc:
                if r.get("btc_address_match") is True:
                    recovery_html_btc = (
                        f" &mdash; recovered <code>{recovered_btc}</code> "
                        f"<span class='verified'>matches expected</span>"
                    )
                elif r.get("btc_address_match") is False:
                    expected = r.get("btc_address") or "?"
                    recovery_html_btc = (
                        f" &mdash; recovered <code>{recovered_btc}</code> "
                        f"<span class='warn'>differs from expected {expected}</span>"
                    )
                else:
                    recovery_html_btc = f" &mdash; recovered <code>{recovered_btc}</code>"
            elif r.get("btc_recovery_error"):
                recovery_html_btc = (
                    f" &mdash; <span class='warn'>"
                    f"address recovery failed: {r.get('btc_recovery_error')}</span>"
                )
            msg_text_html_btc = (
                f"<br><span class='dim'>msg:</span> <code>{msg_text_btc}</code>"
                if msg_text_btc else ""
            )
            sig_full_html_btc = (
                f"<br><span class='dim'>sig (full base64):</span> "
                f"<code style='word-break: break-all;'>{btc_sig}</code>"
                if btc_sig else ""
            )
            # Wave-7: ticker reflects the actual coin, not always "BTC".
            coin_btc_resp = r.get("btc_coin", "btc") or "btc"
            ticker_btc = {"btc": "BTC", "ltc": "LTC", "doge": "DOGE", "bch": "BCH"}.get(coin_btc_resp, "BTC")
            return (
                f"<strong>approved</strong> &mdash; {ticker_btc} {msg_kind_btc} "
                f"<code>{network_btc}</code>, sig <code>{btc_sig_short}</code>"
                f"{recovery_html_btc} &mdash; {verify_marker}"
                f"{msg_text_html_btc}"
                f"{sig_full_html_btc}"
            )
        if kind == "ed_sign":
            ed_sig = r.get("ed_signature_base64") or ""
            ed_sig_short = (
                ed_sig[:10] + "&hellip;" + ed_sig[-6:]
                if len(ed_sig) > 22 else ed_sig
            )
            ed_pub = r.get("ed_pubkey_hex") or ""
            ed_pub_short = (
                ed_pub[:10] + "&hellip;" + ed_pub[-6:]
                if len(ed_pub) > 22 else ed_pub
            )
            chain_ed = r.get("ed_chain", "?")
            msg_kind_ed = r.get("ed_message_kind", "?")
            derived_addr_ed = r.get("ed_derived_address")
            msg_text_ed = r.get("ed_message_text") or ""
            ticker_ed = {"sol": "SOL", "xlm": "XLM", "xrp": "XRP"}.get(chain_ed, chain_ed.upper())
            recovery_html_ed = ""
            if derived_addr_ed:
                if r.get("ed_address_match") is True:
                    recovery_html_ed = (
                        f" &mdash; address <code>{derived_addr_ed}</code> "
                        f"<span class='verified'>matches expected</span>"
                    )
                elif r.get("ed_address_match") is False:
                    expected = r.get("ed_address") or "?"
                    recovery_html_ed = (
                        f" &mdash; address <code>{derived_addr_ed}</code> "
                        f"<span class='warn'>differs from expected {expected}</span>"
                    )
                else:
                    recovery_html_ed = f" &mdash; address <code>{derived_addr_ed}</code>"
            elif r.get("ed_recovery_error"):
                recovery_html_ed = (
                    f" &mdash; <span class='warn'>"
                    f"address derivation failed: {r.get('ed_recovery_error')}</span>"
                )
            sig_verified_marker = ""
            if r.get("ed_signature_verified") is True:
                sig_verified_marker = " <span class='verified'>(chain sig verified)</span>"
            elif r.get("ed_signature_verified") is False:
                sig_verified_marker = " <span class='warn'>(chain sig FAILED verify)</span>"
            msg_text_html_ed = (
                f"<br><span class='dim'>msg:</span> <code>{msg_text_ed}</code>"
                if msg_text_ed else ""
            )
            sig_full_html_ed = (
                f"<br><span class='dim'>sig (full base64):</span> "
                f"<code style='word-break: break-all;'>{ed_sig}</code>"
                if ed_sig else ""
            )
            pub_full_html_ed = (
                f"<br><span class='dim'>pubkey (hex):</span> "
                f"<code style='word-break: break-all;'>{ed_pub}</code>"
                if ed_pub else ""
            )
            return (
                f"<strong>approved</strong> &mdash; {ticker_ed} {msg_kind_ed}, "
                f"sig <code>{ed_sig_short}</code>, pub <code>{ed_pub_short}</code>"
                f"{recovery_html_ed}{sig_verified_marker} &mdash; {verify_marker}"
                f"{msg_text_html_ed}"
                f"{sig_full_html_ed}"
                f"{pub_full_html_ed}"
            )
        if kind == "tron_sign":
            # Wave-9 TRON message_signing render. Same shape as ETH
            # (recover-and-display the signer's address) but with a
            # T-prefixed base58check address and a TIP-191 hashed
            # message instead of EIP-191. No chain-id since TRON's
            # network distinction lives at RPC, not at the signature
            # layer; tron_network ("mainnet" / "shasta" / "nile")
            # surfaces here as the network label instead.
            rsv_t = r.get("tron_signature_rsv") or ""
            rsv_t_short = (
                rsv_t[:14] + "&hellip;" + rsv_t[-6:]
                if len(rsv_t) > 26 else rsv_t
            )
            network_tron = r.get("tron_network", "?")
            msg_kind_tron = r.get("tron_message_kind", "?")
            recovered_tron = r.get("tron_recovered_address")
            msg_text_tron = r.get("tron_message_text") or ""
            recovery_html_tron = ""
            if recovered_tron:
                if r.get("tron_address_match") is True:
                    recovery_html_tron = (
                        f" &mdash; recovered <code>{recovered_tron}</code> "
                        f"<span class='verified'>matches expected</span>"
                    )
                elif r.get("tron_address_match") is False:
                    expected = r.get("tron_address") or "?"
                    recovery_html_tron = (
                        f" &mdash; recovered <code>{recovered_tron}</code> "
                        f"<span class='warn'>differs from expected {expected}</span>"
                    )
                else:
                    recovery_html_tron = (
                        f" &mdash; recovered <code>{recovered_tron}</code>"
                    )
            elif r.get("tron_recovery_error"):
                recovery_html_tron = (
                    f" &mdash; <span class='warn'>"
                    f"address recovery failed: {r.get('tron_recovery_error')}</span>"
                )
            msg_text_html_tron = (
                f"<br><span class='dim'>msg:</span> <code>{msg_text_tron}</code>"
                if msg_text_tron else ""
            )
            rsv_full_html_tron = (
                f"<br><span class='dim'>rsv (full):</span> "
                f"<code style='word-break: break-all;'>{rsv_t}</code>"
                if rsv_t else ""
            )
            return (
                f"<strong>approved</strong> &mdash; TRON {msg_kind_tron} "
                f"<code>{network_tron}</code>, rsv <code>{rsv_t_short}</code>"
                f"{recovery_html_tron} &mdash; {verify_marker}"
                f"{msg_text_html_tron}"
                f"{rsv_full_html_tron}"
            )
        return f"<strong>approved</strong> &mdash; kind <code>{kind}</code> &mdash; {verify_marker}"

    responses_html = "".join(
        f"<li><span class='dim'>{r['responded_at']}</span> "
        f"<code>{r['service']}</code>/<code>{r['secret']}</code> &mdash; {_resp_label(r)}</li>"
        for r in STATE.responses
    ) or "<li class='dim'>(none)</li>"

    history_html = "".join(
        f"<li><span class='dim'>{r['ts']}</span> "
        f"<strong>{r['method']}</strong> <code>{r['path']}</code> "
        f"&mdash; {r['status']}</li>"
        for r in list(STATE.history)[:20]
    ) or "<li class='dim'>(no requests yet)</li>"

    verify_status = "on" if STATE.verify_signatures else "off"
    crypto_note = (
        "" if HAS_CRYPTOGRAPHY else
        " <span class='warn'>(cryptography pkg not installed; verify is a no-op)</span>"
    )
    tls_pin_html = (
        f"<p class='dim'>TLS SPKI pin: <code>{TLS_SPKI_PIN}</code> "
        f"<span class='dim'>(sha256 base64url, no padding; ephemeral &mdash; "
        f"regenerated every startup)</span></p>"
        if TLS_SPKI_PIN
        else "<p class='dim'>TLS: <span class='warn'>off</span> "
             "<span class='dim'>(serving cleartext HTTP; restart with --tls to enable)</span></p>"
    )

    return f"""<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<title>Mock Recto bootloader</title>
<style>
  body {{ font-family: -apple-system, system-ui, "Segoe UI", Roboto, sans-serif;
          max-width: 760px; margin: 2rem auto; padding: 0 1rem; color: #222; }}
  h1 {{ font-size: 1.5rem; }}
  h2 {{ font-size: 1rem; margin-top: 2rem; color: #555; text-transform: uppercase;
        letter-spacing: 0.05em; }}
  code {{ background: #f4f4f4; padding: 0.1em 0.3em; border-radius: 3px;
          font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; }}
  ul {{ padding-left: 1.2rem; }}
  li {{ margin: 0.25rem 0; }}
  .dim {{ color: #999; }}
  .warn {{ color: #b85c00; }}
  .verified {{ color: #1d7f3a; }}
  form {{ display: inline-block; margin: 0 0.5rem 0.5rem 0; }}
  button {{ padding: 0.65rem 0.9rem; font-size: 0.95rem; cursor: pointer;
            border: 1px solid #999; background: #fafafa; border-radius: 4px; }}
  button:hover {{ background: #f0f0f0; }}
  button:disabled {{ opacity: 0.5; cursor: not-allowed; }}
  /* Wave-9 polish: section-boxes split the request-queueing buttons
     into Identity (single_sign / TOTP / session / WebAuthn / PKCS#11 /
     PGP) and Cryptocurrencies (EVM + Bitcoin family + ed25519 chains
     + TRON), mirroring the phone-side Home.razor layout. */
  .section-box {{
    border: 1px solid #ccc;
    border-radius: 6px;
    padding: 0.75rem 1rem 0.4rem 1rem;
    margin: 0.5rem 0 1rem 0;
    background: #fcfcfc;
  }}
  .section-box-title {{
    display: block;
    font-size: 0.8rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: #555;
    margin-bottom: 0.6rem;
  }}
  .section-box-identity {{ border-color: #b8c4d4; background: #f4f7fb; }}
  .section-box-identity .section-box-title {{ color: #2e4a73; }}
  .section-box-crypto   {{ border-color: #d4b88c; background: #fbf6ec; }}
  .section-box-crypto .section-box-title {{ color: #6b4a17; }}
  /* Wave-9 polish: 2x2 grid for the top four meta sections
     (bootloader info / pairing codes / registered phones / pending
     requests). Centered with a max-width so wide screens don't
     stretch into uselessness. min-height per cell stabilizes the
     layout against the 3s auto-reload -- when the count of phones
     or pending requests changes, the cells stay the same size and
     siblings don't reflow. */
  body {{ max-width: 1200px; margin: 0 auto; padding: 0 1rem 2rem 1rem; }}
  .top-grid {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
    margin: 1rem 0 1.5rem 0;
  }}
  .top-cell {{
    border: 1px solid #ccc;
    border-radius: 6px;
    padding: 0.75rem 1rem;
    background: #fcfcfc;
    min-height: 9rem;
  }}
  .top-cell h2 {{ margin-top: 0; }}
  .top-cell ul {{ margin: 0.25rem 0 0.5rem 0; }}
  /* Wave-9 polish: log panels for the bottom three sections (issued
     JWTs / recent responses / recent requests). Fixed-height scrollable
     containers stop the page from growing as activity accumulates --
     server-side buffers are already capped (responses=20, history=50)
     but rendering them all inline grew the page taller and taller.
     overflow-y: auto gives native scrollbar; min-height stabilizes
     against quiet periods so the layout stays put when the panel
     temporarily empties; the panel border + tint match the section-box
     pattern used above. */
  .log-grid {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
    margin: 0.5rem 0 1rem 0;
  }}
  /* In-grid panel (TOTP aliases + JWT capabilities side-by-side).
     These two surfaces have lighter content (one or two lines per
     entry) so a shorter fixed height fits the typical state. */
  .log-panel {{
    border: 1px solid #ccc;
    border-radius: 6px;
    background: #fcfcfc;
    padding: 0.75rem 1rem;
    height: 14rem;
    overflow-y: auto;
  }}
  /* Full-width panel (Recent responses + Recent requests, each its
     own row). These benefit from horizontal space because each entry
     is multi-line (timestamp + service/secret + verb + recovered
     address + full rsv hex on its own line). Taller height so
     2-3 entries are visible without scroll during a typical smoke. */
  .log-panel-wide {{
    border: 1px solid #ccc;
    border-radius: 6px;
    background: #fcfcfc;
    padding: 0.75rem 1rem;
    height: 22rem;
    overflow-y: auto;
    margin: 0.5rem 0 1rem 0;
  }}
  .log-panel h2, .log-panel-wide h2 {{
    margin-top: 0;
    font-size: 1rem;
    color: #555;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }}
  .log-panel ul, .log-panel-wide ul {{ margin-top: 0.25rem; }}
</style>
</head><body>
<h1 style="text-align: center; margin-bottom: 0.25rem;">Mock Recto bootloader</h1>

<div class="top-grid">
  <div class="top-cell">
    <h2 style="font-size: 1rem; color: #555; text-transform: uppercase; letter-spacing: 0.05em;">Bootloader</h2>
    <p class="dim" style="margin: 0.25rem 0;">bootloader_id: <code>{STATE.bootloader_id}</code></p>
    <p class="dim" style="margin: 0.25rem 0;">signature verification: <code>{verify_status}</code>{crypto_note}</p>
    {tls_pin_html}
  </div>
  <div class="top-cell">
    <h2 style="font-size: 1rem; color: #555; text-transform: uppercase; letter-spacing: 0.05em;">Pairing codes</h2>
    <ul>{codes_html}</ul>
    <form method="post" action="/_mint"><button type="submit">Mint pairing code</button></form>
    <form method="post" action="/_clear"><button type="submit">Clear all state</button></form>
  </div>
  <div class="top-cell">
    <h2 style="font-size: 1rem; color: #555; text-transform: uppercase; letter-spacing: 0.05em;">Registered phones</h2>
    <ul>{registered_html}</ul>
  </div>
  <div class="top-cell">
    <h2 style="font-size: 1rem; color: #555; text-transform: uppercase; letter-spacing: 0.05em;">Pending requests</h2>
    <ul>{pending_html}</ul>
  </div>
</div>

<div class="section-box section-box-identity">
<span class="section-box-title">Identity &amp; access</span>
<form method="post" action="/_queue">
  <button type="submit"{'' if STATE.registered else ' disabled'}>Queue sign request</button>
</form>
<form method="post" action="/_queue_totp_provision">
  <button type="submit"{'' if STATE.registered else ' disabled'}>Queue TOTP provision</button>
</form>
<form method="post" action="/_queue_totp_generate">
  <button type="submit"{'' if STATE.registered and STATE.totp_secrets else ' disabled'}>Queue TOTP generate</button>
</form>
<form method="post" action="/_queue_session_issuance">
  <button type="submit"{'' if STATE.registered else ' disabled'}>Queue session issuance</button>
</form>
<form method="post" action="/_queue_webauthn_assert">
  <button type="submit"{'' if STATE.registered else ' disabled'}>Queue WebAuthn assert</button>
</form>
<form method="post" action="/_queue_pkcs11_sign">
  <button type="submit"{'' if STATE.registered else ' disabled'}>Queue PKCS#11 sign</button>
</form>
<form method="post" action="/_queue_pgp_sign">
  <button type="submit"{'' if STATE.registered else ' disabled'}>Queue PGP sign</button>
</form>
</div><!-- /section-box-identity -->

<div class="section-box section-box-crypto">
<span class="section-box-title">Crypto tokens</span>
<div style="display:inline-block; margin-right:0.5rem; padding:0.4rem 0.6rem; border:1px solid #888; border-radius:4px; background:#f7f7f7; vertical-align:middle;">
  <label for="ethChainSel" style="font-size:0.9rem; color:#555; margin-right:0.4rem;">EVM chain:</label>
  <select id="ethChainSel" onchange="_updateEthFormActions()" style="font-size:0.9rem; padding:0.15rem 0.3rem;">
    <option value="1">Ethereum Mainnet (1)</option>
    <option value="8453" selected>Base (8453)</option>
    <option value="137">Polygon (137)</option>
    <option value="42161">Arbitrum One (42161)</option>
    <option value="10">Optimism (10)</option>
    <option value="56">BNB Smart Chain (56)</option>
    <option value="43114">Avalanche C-Chain (43114)</option>
    <option value="11155111">Sepolia testnet (11155111)</option>
    <option value="84532">Base Sepolia testnet (84532)</option>
  </select>
</div>
<form id="_formEthPersonalSign" method="post" action="/_queue_eth_personal_sign">
  <button type="submit"{'' if STATE.registered else ' disabled'}>Queue ETH personal_sign</button>
</form>
<form id="_formEthTypedData" method="post" action="/_queue_eth_typed_data">
  <button type="submit"{'' if STATE.registered else ' disabled'}>Queue ETH typed_data (EIP-712)</button>
</form>
<form id="_formEthTransaction" method="post" action="/_queue_eth_transaction">
  <button type="submit"{'' if STATE.registered else ' disabled'}>Queue ETH transaction (EIP-1559)</button>
</form>
<script>
// Wave-9 polish: wire the EVM chain selector into the three ETH queue
// form actions so each Queue button POSTs with ?chain=<id>. Server-side
// handlers parse url.query for "chain" and fall back to 8453 (Base) if
// absent. Same handler accepts every supported EVM chain ID; the
// signature shape is identical across chains for personal_sign (where
// chain is metadata only), but DIFFERS for typed_data (chainId in the
// EIP-712 domain separator) and transaction (chainId in the RLP).
// NOTE: this whole block lives inside a Python f-string template, so
// curly braces below are doubled per the f-string escape convention
// (same as the CSS rules earlier in the same template).
var _rectoChainRestored = false;
function _updateEthFormActions() {{
  var sel = document.getElementById("ethChainSel");
  if (!sel) return;
  // Persist chain selection across page auto-reloads via localStorage.
  // The HTML's selected attribute is hardcoded to Base, so without
  // persistence the dropdown snaps back to Base on every 3s reload.
  // Page-load behavior: restore from localStorage if a saved value
  // exists. Subsequent calls (operator-driven onchange events): just
  // persist the new value; do NOT override it with the saved value
  // (that would defeat the operator's pick on every dropdown change).
  try {{
    if (!_rectoChainRestored) {{
      var saved = localStorage.getItem("rectoEthChain");
      if (saved && sel.value !== saved) {{
        for (var j = 0; j < sel.options.length; j++) {{
          if (sel.options[j].value === saved) {{ sel.selectedIndex = j; break; }}
        }}
      }}
      _rectoChainRestored = true;
    }}
    localStorage.setItem("rectoEthChain", sel.value);
  }} catch (e) {{ /* localStorage unavailable; continue with current value */ }}
  var chain = sel.value || "8453";
  var ids = ["_formEthPersonalSign", "_formEthTypedData", "_formEthTransaction"];
  var bases = ["/_queue_eth_personal_sign", "/_queue_eth_typed_data", "/_queue_eth_transaction"];
  for (var i = 0; i < ids.length; i++) {{
    var f = document.getElementById(ids[i]);
    if (f) f.action = bases[i] + "?chain=" + encodeURIComponent(chain);
  }}
}}
_updateEthFormActions();
</script>
<form method="post" action="/_queue_btc_message_sign">
  <button type="submit"{'' if STATE.registered else ' disabled'}>Queue BTC message_sign</button>
</form>
<form method="post" action="/_queue_ltc_message_sign">
  <button type="submit"{'' if STATE.registered else ' disabled'}>Queue LTC message_sign</button>
</form>
<form method="post" action="/_queue_doge_message_sign">
  <button type="submit"{'' if STATE.registered else ' disabled'}>Queue DOGE message_sign</button>
</form>
<form method="post" action="/_queue_bch_message_sign">
  <button type="submit"{'' if STATE.registered else ' disabled'}>Queue BCH message_sign</button>
</form>
<form method="post" action="/_queue_sol_message_sign">
  <button type="submit"{'' if STATE.registered else ' disabled'}>Queue SOL message_sign</button>
</form>
<form method="post" action="/_queue_xlm_message_sign">
  <button type="submit"{'' if STATE.registered else ' disabled'}>Queue XLM message_sign</button>
</form>
<form method="post" action="/_queue_xrp_message_sign">
  <button type="submit"{'' if STATE.registered else ' disabled'}>Queue XRP message_sign</button>
</form>
<form method="post" action="/_queue_tron_message_sign">
  <button type="submit"{'' if STATE.registered else ' disabled'}>Queue TRON message_sign</button>
</form>
<form method="post" action="/_queue_capability_request">
  <button type="submit"{'' if STATE.registered else ' disabled'}>Queue capability_request (Darwin staging)</button>
</form>
</div><!-- /section-box-crypto -->

<div class="dim" style="font-size: 0.85rem; margin-top: 0.4rem;">
  Sign request targets the most-recently-registered phone with a random managed secret.
  TOTP provision mints a fresh random base32 secret and stores it server-side for later code verification.
  TOTP generate uses the most-recently-provisioned alias for that phone.
  Session issuance asks the phone to sign a 24h capability JWT (bearer = bootloader) for a random managed secret.
  WebAuthn assert stands in as the relying party for a fictional <code>demo.recto.example</code>
  passkey login &mdash; phone produces a real WebAuthn assertion (clientDataJSON + authenticatorData
  + signature) which we verify exactly the way a real RP would.
  ETH personal_sign mints an EIP-191 login-style message on Base (chain 8453) and asks the phone
  to sign with a secp256k1 key derived from its BIP39 mnemonic at <code>m/44'/60'/0'/0/0</code>;
  the mock recovers the signer address from the returned r||s||v and surfaces it for inspection.
  ETH typed_data mints a sample EIP-2612 permit (USDC token approval) on Base and asks the phone
  to sign per EIP-712; the resulting r||s||v can be plugged into a real <code>permit(...)</code>
  call. ETH transaction mints a sample EIP-1559 (type-2) ETH transfer on Base and asks the phone
  to return the FULL signed raw-transaction bytes ready for <code>eth_sendRawTransaction</code>.
  BTC message_sign mints a BIP-137 login-style message on Bitcoin mainnet and asks the phone to
  sign with a secp256k1 key derived from the SAME mnemonic at <code>m/84'/0'/0'/0/0</code>
  (native-SegWit P2WPKH); the mock recovers the bech32 <code>bc1q...</code> address from the
  returned compact signature and surfaces it for inspection.
</div>

<div class="log-grid">
  <div class="log-panel">
    <h2>Provisioned TOTP aliases</h2>
    <ul>{totp_provisioned_html}</ul>
  </div>
  <div class="log-panel">
    <h2>Issued JWT capabilities</h2>
    <ul>{issued_jwts_html}</ul>
  </div>
</div>

<div class="log-panel-wide">
  <h2>Recent responses</h2>
  <ul>{responses_html}</ul>
</div>

<div class="log-panel-wide">
  <h2>Recent requests</h2>
  <ul>{history_html}</ul>
</div>

<script>
// Auto-refresh the operator UI every 3s so newly-queued requests +
// approved responses appear without manual interaction. Smart-skip
// the reload when the operator is mid-interaction so dropdown
// selections + text selection survive: skip if the active element
// is a SELECT / INPUT / TEXTAREA (operator is typing / picking) or
// if there's any non-empty text selection (operator is mid-copy).
setInterval(function () {{
  try {{
    var ae = document.activeElement;
    if (ae) {{
      var tag = (ae.tagName || "").toUpperCase();
      if (tag === "SELECT" || tag === "INPUT" || tag === "TEXTAREA") return;
    }}
    var sel = window.getSelection ? window.getSelection() : null;
    if (sel && sel.toString().length > 0) return;
  }} catch (e) {{ /* fall through to reload */ }}
  location.reload();
}}, 3000);
</script>
</body></html>
"""


# ---- TLS self-signed cert generation --------------------------------------

def _compute_spki_pin_b64u(public_key) -> str:
    """SHA-256 of the SubjectPublicKeyInfo, base64url-encoded, no padding.
    Matches CertPinHelpers.ComputeSpkiPin on the C# phone side exactly."""
    spki_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashlib.sha256(spki_der).digest()
    b64 = base64.b64encode(digest).decode("ascii")
    return b64.rstrip("=").replace("+", "-").replace("/", "_")


def generate_self_signed_cert(host: str) -> tuple[str, str, str]:
    """Generate an ephemeral ECDSA P-256 self-signed cert for `host`.

    Returns (cert_pem_path, key_pem_path, spki_pin_b64u). The PEM files live
    in the OS temp dir for the lifetime of the process and are removed via
    atexit. The cert carries SAN entries for localhost, 127.0.0.1, ::1, and
    10.0.2.2 (the Android emulator's host loopback) so the same cert can be
    served to phones connecting via any of those names.
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    spki_pin = _compute_spki_pin_b64u(private_key.public_key())

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, host),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Recto mock bootloader"),
    ])
    san = x509.SubjectAlternativeName([
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        x509.IPAddress(ipaddress.IPv6Address("::1")),
        x509.IPAddress(ipaddress.IPv4Address("10.0.2.2")),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(san, critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    cert_fd, cert_path = tempfile.mkstemp(prefix="recto-mock-", suffix=".cert.pem")
    os.write(cert_fd, cert_pem)
    os.close(cert_fd)

    key_fd, key_path = tempfile.mkstemp(prefix="recto-mock-", suffix=".key.pem")
    os.write(key_fd, key_pem)
    os.close(key_fd)

    def _cleanup():
        for p in (cert_path, key_path):
            try:
                os.unlink(p)
            except OSError:
                pass
    atexit.register(_cleanup)

    return cert_path, key_path, spki_pin


# ---- WebAuthn demo page ----------------------------------------------------

WEBAUTHN_DEMO_HTML = """<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<title>Sign in with Recto - demo</title>
<style>
  body { font-family: -apple-system, system-ui, "Segoe UI", Roboto, sans-serif;
         max-width: 560px; margin: 4rem auto; padding: 0 1rem;
         background: #1E1B4B; color: #f5f5f5; min-height: 90vh; }
  h1 { font-size: 1.5rem; font-weight: 500; }
  p { color: #c5c5d8; line-height: 1.5; }
  .card { background: rgba(255,255,255,0.04);
          border: 1px solid rgba(255,255,255,0.10);
          border-radius: 8px; padding: 1.5rem; margin: 2rem 0; }
  button { padding: 0.7rem 1.4rem; font-size: 1rem; cursor: pointer;
           border: 1px solid #888; background: #2d2961; color: #f5f5f5;
           border-radius: 6px; font-weight: 500; }
  button:hover { background: #3b3478; }
  button:disabled { opacity: 0.5; cursor: not-allowed; }
  .status { margin-top: 1rem; font-size: 0.95rem; color: #b5b5c8; }
  .status.success { color: #66e088; }
  .status.error { color: #ff8888; }
  code { background: rgba(0,0,0,0.3); padding: 0.1em 0.4em;
         border-radius: 3px; font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
         font-size: 0.85em; }
  .detail { font-size: 0.85em; color: #888; word-break: break-all;
            margin-top: 0.5rem; }
</style>
</head><body>
<h1>Sign in with Recto</h1>
<p>This demo simulates a relying-party web app using Recto as a passkey
authenticator. Click the button to send a WebAuthn challenge to your most-
recently-paired phone; approve on the phone via biometric; the assertion
flows back here and verifies.</p>

<div class="card">
  <button id="signin">Sign in with Recto</button>
  <div id="status" class="status"></div>
  <div id="detail" class="detail"></div>
</div>

<p style="font-size:0.85em;color:#888;">
  Real production: a Recto-equipped Keycloak adapter speaks this same
  WebAuthn assertion protocol. The browser side is identical to any FIDO2
  passkey flow; only the authenticator (phone) differs.
</p>

<script>
const btn = document.getElementById("signin");
const status = document.getElementById("status");
const detail = document.getElementById("detail");

btn.addEventListener("click", async () => {
  btn.disabled = true;
  status.className = "status";
  status.textContent = "Sending challenge to phone...";
  detail.textContent = "";

  try {
    const beginResp = await fetch("/v0.4/webauthn/begin", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({})
    });
    if (!beginResp.ok) throw new Error("begin failed: " + beginResp.status);
    const begin = await beginResp.json();
    status.textContent = "Waiting for phone approval (request_id: " + begin.request_id.slice(0, 8) + "...)";
    detail.textContent = "Targeting " + begin.phone_label + " (" + begin.phone_id.slice(0, 8) + "...). Open Recto on the phone and tap Approve.";

    // Poll for the result.
    const start = Date.now();
    let result = null;
    while (Date.now() - start < 120000) {  // 2-min cap
      await new Promise(r => setTimeout(r, 1500));
      const resp = await fetch("/v0.4/webauthn/result/" + begin.request_id);
      if (resp.status === 200) {
        result = await resp.json();
        break;
      }
      if (resp.status === 404) throw new Error("request expired or denied");
    }

    if (!result) throw new Error("timed out waiting for phone");

    status.className = "status success";
    status.textContent = "Signed in!";
    detail.innerHTML = "Verified WebAuthn assertion from <code>" + result.phone_label + "</code><br>" +
                        "RP ID: <code>" + result.rp_id + "</code><br>" +
                        "Origin: <code>" + result.origin + "</code><br>" +
                        "Signature: <code>" + result.signature_b64u.slice(0, 32) + "...</code>";
  } catch (e) {
    status.className = "status error";
    status.textContent = "Failed: " + e.message;
  } finally {
    btn.disabled = false;
  }
});
</script>
</body></html>
"""


# ---- main ------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(description="Recto v0.4 mock bootloader (dev harness).")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Bind address (default: 127.0.0.1).")
    parser.add_argument("--port", type=int, default=8443,
                        help="Port to listen on (default: 8443).")
    parser.add_argument("--no-verify", action="store_true",
                        help="Skip Ed25519 signature verification on /v0.4/register.")
    parser.add_argument("--tls", action="store_true",
                        help="Serve over HTTPS with an ephemeral self-signed cert. "
                             "Prints the SPKI pin at startup so the phone can capture it "
                             "during pairing. Requires the `cryptography` package.")
    # Push-notification credentials. When configured, send_push_wakeup
    # delivers real pushes to the phone; absent, it logs "would send ...".
    parser.add_argument("--fcm-service-account", default=None,
                        help="Path to Firebase Admin SDK service-account JSON. "
                             "When set, FCM-platform phones receive real wakeup pushes.")
    parser.add_argument("--apns-key", default=None,
                        help="Path to APNs auth key .p8 file from the Apple Developer Console. "
                             "Requires httpx (pip install 'httpx[http2]').")
    parser.add_argument("--apns-key-id", default=None,
                        help="APNs auth key ID (10-char alphanumeric).")
    parser.add_argument("--apns-team-id", default=None,
                        help="Apple Developer team ID (10-char alphanumeric).")
    parser.add_argument("--apns-bundle-id", default=None,
                        help="App bundle ID matching the registered App ID in Apple Dev Console.")
    parser.add_argument("--apns-environment", default="development",
                        choices=("development", "production"),
                        help="APNs gateway: development (sandbox) or production.")
    args = parser.parse_args(argv)

    if args.no_verify:
        STATE.verify_signatures = False
    if not HAS_CRYPTOGRAPHY:
        print("Warning: `cryptography` not installed; signature verification will accept any value.")
        print("         Install it with: pip install cryptography")
        print()

    if args.tls and not HAS_CRYPTOGRAPHY:
        print("Error: --tls requires the `cryptography` package. Install with: pip install cryptography")
        return 1

    global TLS_SPKI_PIN
    cert_path = key_path = None
    if args.tls:
        cert_path, key_path, TLS_SPKI_PIN = generate_self_signed_cert(args.host)

    # Wire push-send credentials. Either / both / neither can be set;
    # phones whose platform doesn't have credentials configured still
    # work but fall back to the 3s poll cycle.
    if args.fcm_service_account:
        try:
            client_email = configure_fcm(args.fcm_service_account)
            print(f"FCM       : configured ({client_email})")
        except Exception as e:
            print(f"FCM       : FAILED to configure: {type(e).__name__}: {e}")
            return 1
    else:
        print("FCM       : not configured (Android phones will get 'would send' logs)")

    if args.apns_key:
        if not all([args.apns_key_id, args.apns_team_id, args.apns_bundle_id]):
            print("Error: --apns-key requires --apns-key-id + --apns-team-id + --apns-bundle-id")
            return 1
        try:
            configure_apns(
                args.apns_key, args.apns_key_id, args.apns_team_id,
                args.apns_bundle_id, args.apns_environment,
            )
            print(f"APNs      : configured (key {args.apns_key_id}, team {args.apns_team_id}, "
                  f"bundle {args.apns_bundle_id}, env {args.apns_environment})")
        except Exception as e:
            print(f"APNs      : FAILED to configure: {type(e).__name__}: {e}")
            return 1
    else:
        print("APNs      : not configured (iOS phones will get 'would send' logs)")

    code = STATE.mint_pairing_code()
    print(f"Pairing code: {code}  (valid for 5 minutes)")
    print()
    scheme = "https" if args.tls else "http"
    print(f"Mock Recto bootloader running on {scheme}://{args.host}:{args.port}")
    print(f"Operator UI    : {scheme}://{args.host}:{args.port}/")
    print(f"Phone app field: bootloader URL = {scheme}://{args.host}:{args.port}")
    if args.tls:
        print()
        print(f"TLS SPKI pin   : {TLS_SPKI_PIN}")
        print("                 (sha256 base64url no padding; phone captures this at pairing)")
        print("                 Cert is ephemeral -- regenerated every startup, by design.")
    print()

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    if args.tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
        # Self-signed; nothing in the chain to verify.
        ctx.verify_mode = ssl.CERT_NONE
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
    return 0


if __name__ == "__main__":
    main()
