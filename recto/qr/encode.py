"""
recto.qr.encode — QR encoding primitives for signed payloads.

This module provides the substrate-level encode path: take a JWS
string OR a structured QRPayloadV1 dict, and return a QR-rendered
PNG / SVG ready to display on a screen or print on paper. The QR
is a transport layer — its bytes carry the same signed payload that
HTTP / folder-drop transports already carry; nothing about the
authority chain changes between transports.

Per Recto Hard Rule #13 (artifact-as-canonical-record), the encoded
QR bytes ARE the canonical record. The signature inside the payload
chains back to the operator's master pubkey; the QR transport itself
adds no trust dimension and removes none.

v1 ships encode-only (PNG and SVG output). Decode (QR image → JWS
string) is deferred to v2 because:
  - Recto Phone (the canonical first consumer) has its own native
    QR scanner via MAUI Blazor; it doesn't need Python decode.
  - Python decode would require pyzbar (libzbar native dep) or
    zxing-cpp (native C++); v1 stays pure-Python to keep the
    substrate's dependency footprint small.

The `qrcode` library (BSD, pure-Python except for Pillow PNG output)
is the encode backend. Available via the `recto[qr]` optional
extra; the import is lazy so callers who never invoke encode
primitives don't pay the import cost.
"""

from __future__ import annotations

import json
from typing import Any

from recto.qr.types import (
    QR_FORMAT_PNGV1,
    QR_FORMAT_SVGV1,
    QR_MAX_SIZE_BYTES_V40_L,
    QRMeta,
    QRPayloadV1,
)


# Default error-correction level. M (15% recovery) balances capacity
# against scratch/dirt tolerance — better default than L for trust
# artifacts that may be printed, photographed, or screen-captured
# through lossy chains. Capacity at v40-M is still 2331 bytes which
# fits any single capability JWS comfortably.
DEFAULT_ERROR_CORRECTION = "M"

# Default per-module pixel size for PNG output. 8px gives a scannable
# QR at typical phone-camera distances (12-18 inches); 4px is too
# small for casual scanning; 16px+ is print-ready. Tuned for the
# Recto Phone v1.1 TLS-pin-disclosure use case.
DEFAULT_BOX_SIZE = 8

# Default quiet-zone border (in modules). 4 is the QR spec minimum;
# anything smaller risks scan failures on some readers.
DEFAULT_BORDER = 4


def _error_correction_constant(level: str) -> int:
    """Map error-correction-level string to the qrcode library's enum.

    Lazy-imports qrcode so the module loads cleanly when the optional
    extra isn't installed (callers who never invoke encode primitives
    don't pay the import cost; missing-dep errors only surface when
    encode is actually called).
    """
    try:
        import qrcode.constants as constants
    except ImportError as exc:
        raise ImportError(
            "qrcode library not installed. "
            "Install via `pip install recto[qr]`."
        ) from exc

    level_upper = level.upper()
    if level_upper == "L":
        return constants.ERROR_CORRECT_L
    if level_upper == "M":
        return constants.ERROR_CORRECT_M
    if level_upper == "Q":
        return constants.ERROR_CORRECT_Q
    if level_upper == "H":
        return constants.ERROR_CORRECT_H
    raise ValueError(
        f"Unknown error_correction level '{level}'. Must be one of L, M, Q, H."
    )


def _canonical_json(obj: Any) -> str:
    """Serialize a dict to canonical JSON for byte-parity across runtimes.

    Same convention as `recto.capability.jwt._canonical_json`: sorted
    keys, no whitespace separators, ASCII-escaped non-ASCII. This is
    the canonical encoding that makes signatures verifiable across
    Python and C# (and any other runtime that respects the same
    sort + separator + escape rules).

    Returns a `str` (not bytes); callers encode to UTF-8 themselves
    where the QR library expects bytes.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _strip_qr_meta(payload: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of `payload` with the `_qr_meta` key removed.

    Used when computing the signing input for QRPayloadV1 — the QR
    metadata is transport bookkeeping, NOT part of the signed claim
    set. Two consumers reading the same signed payload via different
    transports (HTTP vs QR vs folder-drop) should derive identical
    signing inputs because `_qr_meta` is omitted from the signature
    scope.
    """
    return {k: v for k, v in payload.items() if k != "_qr_meta"}


def qr_encode_jws(
    jws: str,
    *,
    image_format: str = "png",
    error_correction: str = DEFAULT_ERROR_CORRECTION,
    box_size: int = DEFAULT_BOX_SIZE,
    border: int = DEFAULT_BORDER,
) -> bytes:
    """Encode a JWS string directly as a QR code image.

    The simplest QR encoding path: take a 3-part JWS string
    (header.payload.signature, base64url-encoded segments separated
    by dots) and emit a PNG / SVG QR that any QR reader can decode
    back to the original string. No envelope wrapping; the JWS string
    IS the payload.

    Used for capability_request JWS, pairing JWS, and other single-
    payload artifacts where the JWS string is self-contained (header
    + body + signature all in one).

    Args:
        jws: The JWS string to encode. Typically 500-800 bytes for
            capability JWS; well under the QR capacity limit even at
            higher error-correction levels.
        image_format: "png" (default) or "svg". PNG is the canonical
            output for the Recto-Phone-displays-QR use case; SVG is
            preferred for print-ready / vector-quality scenarios.
        error_correction: "L" (7%), "M" (15%, default), "Q" (25%),
            or "H" (30%). Higher = more scratch/dirt tolerance at
            cost of capacity. M is the default for trust artifacts.
        box_size: Pixels per QR module (PNG only; ignored for SVG).
            8 is the default for phone-screen display; bump to 16-24
            for print.
        border: Quiet-zone border width in modules. 4 is the QR spec
            minimum; smaller values risk scan failures on some
            readers.

    Returns:
        PNG or SVG bytes ready for `Path.write_bytes()` or HTTP
        response. The QR encodes the JWS string verbatim.

    Raises:
        ImportError: If the `recto[qr]` optional extra isn't
            installed (qrcode library missing).
        ValueError: If `error_correction` isn't L/M/Q/H or
            `image_format` isn't png/svg.
    """
    if not jws:
        raise ValueError("jws must be a non-empty string")
    if image_format not in ("png", "svg"):
        raise ValueError(
            f"Unknown image_format '{image_format}'. Must be 'png' or 'svg'."
        )

    try:
        import qrcode
    except ImportError as exc:
        raise ImportError(
            "qrcode library not installed. "
            "Install via `pip install recto[qr]`."
        ) from exc

    qr = qrcode.QRCode(
        version=None,  # auto-size to smallest version that fits
        error_correction=_error_correction_constant(error_correction),
        box_size=box_size,
        border=border,
    )
    qr.add_data(jws)
    qr.make(fit=True)

    import io

    buf = io.BytesIO()

    if image_format == "png":
        img = qr.make_image(fill_color="black", back_color="white")
        img.save(buf, format="PNG")
    else:
        # SVG path — use qrcode's SVG factory. Available since
        # qrcode 5.0+; no Pillow dependency for this path.
        try:
            from qrcode.image.svg import SvgImage
        except ImportError as exc:
            raise ImportError(
                "qrcode SVG support requires qrcode>=5.0."
            ) from exc

        img = qr.make_image(image_factory=SvgImage)
        img.save(buf)

    return buf.getvalue()


def qr_encode_payload(
    payload: QRPayloadV1 | dict[str, Any],
    *,
    image_format: str = "png",
    error_correction: str = DEFAULT_ERROR_CORRECTION,
    box_size: int = DEFAULT_BOX_SIZE,
    border: int = DEFAULT_BORDER,
) -> bytes:
    """Encode a structured QRPayloadV1 as a QR code image.

    For artifacts that need more than a bare JWS — multi-witness
    contracts, structured citation receipts, promotion certificates
    with embedded metadata. The payload is canonical-JSON-encoded
    (byte-parity with `recto.capability.jwt._canonical_json`) before
    rendering, so the QR's bytes are reproducible across runtimes.

    The `_qr_meta` field on the payload is included in the encoded
    JSON (consumers need it to know how to interpret the QR bytes)
    but is NOT part of any signature scope — consumers verify the
    signature against the payload-MINUS-_qr_meta.

    Args:
        payload: A QRPayloadV1 dataclass instance OR a dict matching
            the QRPayloadV1 schema. Dict input is convenient for
            ad-hoc payloads + future schema extensions; dataclass
            input is type-checked.
        image_format: "png" (default) or "svg".
        error_correction: "L" / "M" / "Q" / "H". M default.
        box_size: PNG pixels per module (PNG only).
        border: Quiet-zone border width in modules.

    Returns:
        PNG or SVG bytes. The QR encodes the canonical-JSON-encoded
        payload (a string), which any QR reader can decode back to
        the canonical JSON and any JSON parser can decode back to the
        payload dict.

    Raises:
        ImportError: If `recto[qr]` extra isn't installed.
        ValueError: If args are invalid.
    """
    if isinstance(payload, QRPayloadV1):
        # Convert dataclass to dict for serialization. Field order
        # doesn't matter because canonical-JSON sorts by key.
        payload_dict: dict[str, Any] = {
            "v": payload.v,
            "kind": payload.kind,
            "iss": payload.iss,
            "aud": list(payload.aud),
            "iat": payload.iat,
            "exp": payload.exp,
            "jti": payload.jti,
            "body": dict(payload.body),
            "_qr_meta": {
                "format": payload._qr_meta.format,
                "max_size_bytes": payload._qr_meta.max_size_bytes,
                "fragmentation": payload._qr_meta.fragmentation,
            },
        }
    elif isinstance(payload, dict):
        payload_dict = payload
    else:
        raise ValueError(
            f"payload must be QRPayloadV1 or dict; got {type(payload).__name__}"
        )

    canonical = _canonical_json(payload_dict)

    # Sanity check: refuse to encode if the canonical JSON exceeds
    # the QR capacity at the requested error-correction level. v1
    # supports single-QR encoding only; future v2 may extend to
    # multi-QR fragmentation.
    if len(canonical.encode("utf-8")) > QR_MAX_SIZE_BYTES_V40_L:
        raise ValueError(
            f"payload canonical-JSON encoding is "
            f"{len(canonical.encode('utf-8'))} bytes, exceeds QR v40 "
            f"capacity of {QR_MAX_SIZE_BYTES_V40_L} bytes (at L error-"
            f"correction; lower at M/Q/H). Multi-QR fragmentation is "
            f"reserved for v2."
        )

    return qr_encode_jws(
        canonical,
        image_format=image_format,
        error_correction=error_correction,
        box_size=box_size,
        border=border,
    )


def build_qr_meta(
    *,
    image_format: str = "png",
    error_correction: str = DEFAULT_ERROR_CORRECTION,
) -> QRMeta:
    """Build a QRMeta envelope matching the encode arguments.

    Convenience helper for consumers building QRPayloadV1 instances.
    Translates the human-readable args (image_format, EC level) into
    the canonical `format` string the schema expects.
    """
    format_str = QR_FORMAT_PNGV1 if image_format == "png" else QR_FORMAT_SVGV1

    # Capacity bookkeeping: max bytes at the requested EC level. v40
    # capacities per QR spec.
    capacities = {
        "L": 2953,
        "M": 2331,
        "Q": 1663,
        "H": 1273,
    }
    max_size = capacities.get(error_correction.upper(), 2953)

    return QRMeta(
        format=format_str,
        max_size_bytes=max_size,
        fragmentation=None,
    )


def canonical_signing_input(payload: dict[str, Any]) -> bytes:
    """Compute the canonical signing input for a QRPayloadV1.

    Strips the `_qr_meta` transport metadata (which is NOT signed)
    and returns the canonical-JSON-encoded bytes of the remaining
    fields. Consumers sign these bytes with their secp256k1 / Ed25519
    keys; verifiers reconstruct the same bytes from the QR-decoded
    payload (also stripping `_qr_meta`) to recover the signature.

    Cross-references: `recto.capability.jwt._canonical_json` uses
    the same convention for capability JWS signing inputs. Both
    paths produce byte-identical output for the same input dict,
    so a capability JWS and its QR-wrapped counterpart sign over
    equivalent bytes.

    Args:
        payload: The QRPayloadV1 dict (with or without `_qr_meta`).

    Returns:
        UTF-8 bytes of the canonical-JSON encoding, with `_qr_meta`
        excluded.
    """
    return _canonical_json(_strip_qr_meta(payload)).encode("utf-8")
