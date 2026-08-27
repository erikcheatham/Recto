"""Session JWT helpers: EdDSA encode/verify against registered phone keys.

The bootloader caches session JWTs (one per `(service, secret)` pair)
issued by the phone. This module wraps `pyjwt`'s EdDSA support to:

- Encode a JWT issuance request for the phone to sign (the bootloader
  doesn't actually encode -- the phone does -- but this module defines
  the canonical claim shape).
- Verify a JWT received from the phone against the registered public
  key.
- Verify a per-operation signature against a session JWT (the phone
  signs operations within a session using the same Ed25519 key, NOT
  the session JWT itself; the JWT just authorizes the bootloader to
  cache approval).

Imports of `cryptography` and `jwt` are lazy at function level so that
importing this module without the [v0_4] extra installed produces a
clear runtime error rather than ImportError at module load time.
"""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass
from typing import Any

from recto.bootloader import BootloaderError

__all__ = [
    "SessionClaims",
    "verify_jwt",
    "verify_signature",
    "build_session_issuance_payload",
    "build_sign_request_payload",
]


@dataclass(frozen=True, slots=True)
class SessionClaims:
    """Decoded JWT claims for a session. Mirrors RFC 7519 standard
    fields plus Recto-specific extensions under the "recto:" prefix."""

    iss: str  # phone-public-key fingerprint (b64u of BLAKE2s-128 of pubkey)
    sub: str  # "{service}:{secret}"
    aud: str  # bootloader_id
    exp: int  # unix ts
    iat: int  # unix ts
    jti: str  # uuid4
    recto_scope: tuple[str, ...]
    recto_max_uses: int

    @property
    def service(self) -> str:
        return self.sub.split(":", 1)[0]

    @property
    def secret(self) -> str:
        return self.sub.split(":", 1)[1]

    @property
    def is_expired(self) -> bool:
        return time.time() >= self.exp


def _public_key_from_b64u(public_key_b64u: str, algorithm: str = "ed25519"):
    """Decode a base64url public key into a cryptography key object.

    Supports two wire formats:
      - ``ed25519``: 32 raw bytes.
      - ``ecdsa-p256`` (NIST P-256, SECP256R1): 64 raw bytes uncompressed
        ``X || Y``, or 65 bytes ``0x04 || X || Y`` (SEC1 uncompressed).
        iOS Secure Enclave's native curve. Apple's keychain exports
        public bytes as the 64-byte raw X||Y form.

    Raises BootloaderError on import failure, decode failure, or wrong
    byte length for the chosen algorithm.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
        from cryptography.hazmat.primitives.asymmetric import ec
    except ImportError as exc:
        raise BootloaderError(
            "v0.4 bootloader requires `cryptography`; install via "
            "`pip install recto[v0_4]`."
        ) from exc
    padding = "=" * (-len(public_key_b64u) % 4)
    raw = base64.urlsafe_b64decode(public_key_b64u + padding)

    if algorithm == "ed25519":
        if len(raw) != 32:
            raise BootloaderError(
                f"ed25519 public key must decode to 32 bytes; got {len(raw)}"
            )
        return Ed25519PublicKey.from_public_bytes(raw)

    if algorithm == "ecdsa-p256":
        # Accept either raw X||Y (64 bytes) or SEC1 uncompressed
        # 0x04||X||Y (65 bytes). Apple Secure Enclave exports the
        # 64-byte raw form via SecKeyCopyExternalRepresentation when
        # configured for kSecAttrKeyTypeECSECPrimeRandom.
        if len(raw) == 65 and raw[0] == 0x04:
            x = int.from_bytes(raw[1:33], "big")
            y = int.from_bytes(raw[33:65], "big")
        elif len(raw) == 64:
            x = int.from_bytes(raw[:32], "big")
            y = int.from_bytes(raw[32:], "big")
        else:
            raise BootloaderError(
                f"ecdsa-p256 public key must decode to 64 bytes (X||Y) "
                f"or 65 bytes (0x04||X||Y); got {len(raw)}"
            )
        return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()

    raise BootloaderError(f"unsupported algorithm: {algorithm!r}")


def verify_jwt(token: str, *, public_key_b64u: str, audience: str) -> SessionClaims:
    """Verify a session JWT signed by the phone.

    Returns parsed claims on success. Raises BootloaderError on:
    - Bad signature (key mismatch)
    - Expired token
    - Wrong audience
    - Missing required claims
    - Malformed JWT structure
    """
    try:
        import jwt
    except ImportError as exc:
        raise BootloaderError(
            "v0.4 bootloader requires `pyjwt`; install via "
            "`pip install recto[v0_4]`."
        ) from exc

    pub_key = _public_key_from_b64u(public_key_b64u)
    try:
        claims = jwt.decode(
            token,
            pub_key,
            algorithms=["EdDSA"],
            audience=audience,
            options={
                "require": ["iss", "sub", "aud", "exp", "iat", "jti"],
                "verify_aud": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_signature": True,
            },
        )
    except jwt.ExpiredSignatureError as exc:
        raise BootloaderError("session JWT expired") from exc
    except jwt.InvalidAudienceError as exc:
        raise BootloaderError(
            f"session JWT audience mismatch (expected {audience!r})"
        ) from exc
    except jwt.InvalidSignatureError as exc:
        raise BootloaderError("session JWT signature invalid") from exc
    except jwt.MissingRequiredClaimError as exc:
        raise BootloaderError(f"session JWT missing claim: {exc}") from exc
    except jwt.InvalidTokenError as exc:
        raise BootloaderError(f"session JWT malformed: {exc}") from exc

    return SessionClaims(
        iss=str(claims["iss"]),
        sub=str(claims["sub"]),
        aud=str(claims["aud"]),
        exp=int(claims["exp"]),
        iat=int(claims["iat"]),
        jti=str(claims["jti"]),
        recto_scope=tuple(claims.get("recto:scope", ())),
        recto_max_uses=int(claims.get("recto:max_uses", 0)),
    )


def _maybe_decoded_payload(payload: bytes) -> bytes | None:
    """If `payload` is the ASCII bytes of a valid base64url string, return
    the decoded raw bytes; otherwise None.

    Workaround for the iOS C# phone client bug (2026-05-11): it decodes the
    server-issued challenge_b64u before signing, while fake_phone.py + the
    server's canonical convention sign the literal ASCII string. verify_signature
    tries the canonical payload first, falls back to the decoded form if that
    fails, so iOS phones pre-fix still pair. Remove this once the phone-side
    Home.razor:966 + :1971 are fixed to sign Encoding.ASCII.GetBytes(challenge).
    """
    try:
        s = payload.decode("ascii")
    except UnicodeDecodeError:
        return None
    try:
        padding = "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(s + padding)
    except Exception:
        return None


# --- GATE 2a: the algorithm vocabulary, declared in ONE place ---------------
# Before 2026-08-17 no such list existed. `algorithm` was whatever string the
# phone happened to send, passed straight to verification, and THREE separate
# defaults on the enrollment path resolved silence to "ed25519":
#
#     server.py:799   body.get("supported_algorithms", ["ed25519"])
#     server.py:814   algos[0] if algos else "ed25519"
#     this function   algorithm: str = "ed25519"
#
# So a phone that sent an empty list, or omitted the field entirely, was
# ENROLLED AS SOFTWARE-KEYED BY SILENCE -- in a system whose whole claim is that
# the private key is hardware-held and non-exportable. The brief's phrasing is
# exact: a hardware-root system must never enroll a software key by omission.
#
# NOTE THE AMBIGUITY THIS DOES NOT RESOLVE, AND CANNOT. "ed25519" is sent by
# Android StrongBox phones AND by the software fallback path; the string alone
# does not distinguish hardware from software. Only ATTESTATION does, and that
# is GATE 2b (Android KeyStore attestation + iOS App Attest). This constant
# closes enrollment-by-silence; it does NOT make an algorithm name evidence of
# a hardware root. Do not read it as one.
SUPPORTED_ALGORITHMS: tuple[str, ...] = ("ed25519", "ecdsa-p256")


def verify_signature(
    *, payload: bytes, signature_b64u: str, public_key_b64u: str,
    algorithm: str = "ed25519",
) -> bool:
    """Verify a signature over a payload.

    Supports two algorithms (chosen by ``algorithm``):
      - ``ed25519``: Ed25519 over raw 64-byte signature.
      - ``ecdsa-p256``: ECDSA-P256 over SHA-256, raw 64-byte ``r || s``
        signature (NOT DER-encoded). iOS Secure Enclave's native algo.
        Apple's ``SecKeyCreateSignature`` with
        ``kSecKeyAlgorithmECDSASignatureMessageX962SHA256`` returns
        DER-encoded; the phone-side adapter converts to raw r||s
        before sending. We re-DER-encode here for ``cryptography``'s
        verify call, which expects DER.

    Returns True on valid, False on invalid. Does NOT raise on
    invalid-signature -- callers usually want to convert the verdict
    into a deny response, not propagate an exception. Raises
    BootloaderError only on import/decode failures or unsupported
    algorithm.
    """
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import (
            encode_dss_signature,
        )
    except ImportError as exc:
        raise BootloaderError(
            "v0.4 bootloader requires `cryptography`; install via "
            "`pip install recto[v0_4]`."
        ) from exc

    pub_key = _public_key_from_b64u(public_key_b64u, algorithm=algorithm)
    padding = "=" * (-len(signature_b64u) % 4)
    sig = base64.urlsafe_b64decode(signature_b64u + padding)
    if len(sig) != 64:
        return False

    def _verify(payload_to_try: bytes) -> bool:
        if algorithm == "ed25519":
            try:
                pub_key.verify(sig, payload_to_try)
                return True
            except InvalidSignature:
                return False
        if algorithm == "ecdsa-p256":
            # Convert raw r||s to DER for cryptography's verify.
            r = int.from_bytes(sig[:32], "big")
            s = int.from_bytes(sig[32:], "big")
            try:
                der_sig = encode_dss_signature(r, s)
                pub_key.verify(der_sig, payload_to_try, ec.ECDSA(hashes.SHA256()))
                return True
            except InvalidSignature:
                return False
            except Exception:
                # encode_dss_signature can raise on r/s out of range, etc.
                # Treat as invalid signature rather than propagate.
                return False
        raise BootloaderError(f"unsupported algorithm: {algorithm!r}")

    # Try the canonical payload first (literal ASCII bytes of base64url string).
    if _verify(payload):
        return True
    # Fallback: iOS C# phone bug — it signs the decoded raw bytes.
    decoded = _maybe_decoded_payload(payload)
    if decoded is not None and _verify(decoded):
        return True
    return False


def build_session_issuance_payload(
    *,
    service: str,
    secret: str,
    bootloader_id: str,
    lifetime_seconds: int,
    max_uses: int,
) -> dict[str, Any]:
    """The canonical claim shape the phone should encode into the JWT
    when issuing a session. The phone receives this from the bootloader
    via the pending-request mechanism, fills in `iat` / `exp` / `jti`,
    signs, and returns.

    Returned dict is JSON-serializable with sorted keys for
    canonicalization.
    """
    return {
        "sub": f"{service}:{secret}",
        "aud": bootloader_id,
        "recto:scope": ["sign"],
        "recto:max_uses": max_uses,
        "recto:lifetime_seconds": lifetime_seconds,
    }


def build_sign_request_payload(
    *,
    service: str,
    secret: str,
    payload_hash_b64u: str,
    requested_at_unix: int,
    request_id: str,
) -> dict[str, Any]:
    """The canonical shape the phone signs when responding to a single
    sign request. The phone signs the BLAKE2b-256 hash of the payload,
    not the raw payload, so the wire format doesn't have to carry the
    full data being signed (which might be large)."""
    return {
        "request_id": request_id,
        "service": service,
        "secret": secret,
        "payload_hash_b64u": payload_hash_b64u,
        "requested_at_unix": requested_at_unix,
    }
