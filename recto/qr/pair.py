"""
recto.qr.pair — emitter for recto://pair?... deep-link URLs + QR images.

Python sister of the C# Recto.Shared.Services.PairDeepLinkEmitter +
Recto.Shared.QR.PairDeepLinkQrEmitter primitives (banked 2026-06-01
alongside the demo-mode QR primitive, task #41).

Cross-language byte parity: a URL produced by Python's `build_pair_url`
parses byte-identically through the C# `PairDeepLinkParser.TryParse` (and
vice versa). Tests pin this contract in both languages by sharing the
canonical demo URL fixture.

Two flows mirrored from the C# side:

  - `service` kind (default) — Phase H end-user pair-a-service flow.
    Code is 8 alphanumeric characters. Bootloader URL optional. URLs
    omit the `kind=` query param for back-compat with v0.1 URLs
    minted before the kind extension.

  - `bootloader` kind — initial-trust handshake with a bootloader.
    Code is 6 numeric digits (the demo sentinel "000000" is the only
    canonical use case today). Bootloader URL required. URLs include
    `&kind=bootloader`.

The canonical demo URL (App Store reviewer flow):

    recto://pair?code=000000&bootloader=demo%3A%2F%2Frecto-app-review&kind=bootloader

When this URL is encoded as a QR and scanned by Recto Phone on iOS or
Android, the OS routes it through the URL scheme handler (CFBundleURLTypes
/ [IntentFilter] on MainActivity) → PairDeepLinkParser.TryParse →
InMemoryPairDeepLinkState → Home.razor consumes on first render → form
pre-fills with the demo code + sentinel URL → operator (the App Store
reviewer) hits Pair → demo mode activates (biometric + Secure Enclave +
ECDSA all fire real, only HTTP handshake is mocked).

Canonical use cases (consumer side, Python-callable):

  1. Bootloader-side QR rendering for App Store demo flow — when Recto's
     marketing site / a developer portal needs to generate the canonical
     demo QR PNG for download or display. `build_demo_bootloader_pair_url()`
     + `recto.qr.qr_encode_jws()` (or any text-encode primitive) produces
     the bytes.

  2. Cross-language test fixtures — Python tests pin the canonical wire
     bytes; C# tests pin identical bytes. If the canonical URL ever
     drifts (encoding change, constant rename, etc.), both languages'
     tests catch it.

  3. Downstream Python consumers (future integration test harnesses,
     CI-side QR generation for App Store screenshot bundles, etc.).

See `Recto.Shared.Services.PairDeepLinkConstants` for the canonical
constant values (URL scheme, host, param names, kind wire values, demo
sentinels). This module's `_*` private constants mirror those values
EXACTLY for byte parity — do not drift one side without the other.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Optional
from urllib.parse import quote

# ---------------------------------------------------------------------------
# Canonical constants -- mirror of Recto.Shared.Services.PairDeepLinkConstants
# ---------------------------------------------------------------------------
#
# These MUST match the C# constants byte-for-byte. Any drift produces wire-
# format incompatibility that tests would catch at CI but is otherwise
# silent. House rule: when changing any of these values, change BOTH the
# C# Constants.cs AND this file in the same commit. The canonical demo URL
# test fixture (CANONICAL_DEMO_PAIR_URL below) is the cross-language
# byte-parity pin.

URL_SCHEME = "recto"
PAIR_HOST = "pair"
CODE_PARAM_NAME = "code"
BOOTLOADER_PARAM_NAME = "bootloader"
KIND_PARAM_NAME = "kind"
KIND_SERVICE_WIRE_VALUE = "service"
KIND_BOOTLOADER_WIRE_VALUE = "bootloader"

# Demo-mode sentinels (App Store reviewer flow). Match the placeholder text
# the reviewer sees in the bootloader-pair form input fields.
DEMO_PAIRING_CODE = "000000"
DEMO_BOOTLOADER_URL = "demo://recto-app-review"
DEMO_BOOTLOADER_ID = "demo-bootloader-app-review"

# Cross-language byte-parity pin. Python's `build_demo_bootloader_pair_url()`
# MUST emit exactly these bytes; C# `PairDeepLinkEmitter.BuildDemoBootloaderPairUrl()`
# MUST emit the same bytes. Tests in tests/test_qr_pair.py + the C# test in
# Recto.Shared.Tests/Services/PairDeepLinkEmitterTests.cs both pin against
# this string.
CANONICAL_DEMO_PAIR_URL = (
    "recto://pair?code=000000&bootloader=demo%3A%2F%2Frecto-app-review&kind=bootloader"
)


class PairDeepLinkKind(str, Enum):
    """
    Discriminator for which Recto pair-deep-link flow a URL targets.

    Determines code-shape validation rules. Sister of
    Recto.Shared.Services.PairDeepLinkKind (C#) — value strings are the
    canonical wire form so this Enum doubles as the wire serializer.
    """

    SERVICE = KIND_SERVICE_WIRE_VALUE
    BOOTLOADER = KIND_BOOTLOADER_WIRE_VALUE


# Service-kind: 8 alphanumeric characters (mixed case tolerated; Recto
# Phone consumer-side does its own canonicalization).
_SERVICE_CODE_RE = re.compile(r"^[A-Za-z0-9]{8}$")

# Bootloader-kind: 6 numeric digits.
_BOOTLOADER_CODE_RE = re.compile(r"^[0-9]{6}$")


def build_pair_url(
    code: str,
    bootloader_url: Optional[str] = None,
    kind: PairDeepLinkKind = PairDeepLinkKind.SERVICE,
) -> str:
    """
    Build a canonical recto://pair?... deep-link URL.

    Args:
        code: Pairing code. Shape varies by kind (8 alphanumeric for
            service, 6 numeric for bootloader). Validated by regex;
            raises ValueError on shape mismatch.
        bootloader_url: Optional URL for service-kind; REQUIRED for
            bootloader-kind. Emitted verbatim (percent-encoded for URL
            safety) without further shape validation -- the demo
            sentinel "demo://recto-app-review" is intentionally non-HTTP
            and must round-trip cleanly.
        kind: Discriminator. Default SERVICE for back-compat.

    Returns:
        The canonical URL string. Service-kind URLs omit the kind= query
        param so v0.1-compatible URLs round-trip byte-identically. URL
        produced by this function parses cleanly through both
        `recto.qr.pair.parse_pair_url` (if/when shipped) AND through the
        C# `PairDeepLinkParser.TryParse`.

    Raises:
        ValueError: If code shape is invalid for the given kind, OR if
            kind=BOOTLOADER and bootloader_url is empty/None.
    """
    _validate_code_shape(code, kind)

    if kind == PairDeepLinkKind.BOOTLOADER and not bootloader_url:
        raise ValueError(
            "bootloader_url is required for Bootloader-kind pair URLs."
        )

    # Build incrementally. Match the C# emitter's parameter ordering
    # (code → bootloader → kind) so wire bytes are byte-identical
    # across languages.
    parts = [f"{URL_SCHEME}://{PAIR_HOST}?{CODE_PARAM_NAME}={code}"]

    if bootloader_url:
        # urllib.parse.quote with safe="" matches Uri.EscapeDataString
        # encoding closely enough for our wire-format needs. Key
        # equivalences pinned by tests:
        #   :  -> %3A
        #   /  -> %2F
        # quote() defaults safe="/" which would NOT encode "/", so we
        # explicitly set safe="" to match C#'s EscapeDataString shape.
        encoded = quote(bootloader_url, safe="")
        parts.append(f"&{BOOTLOADER_PARAM_NAME}={encoded}")

    # Emit kind= ONLY for non-default kinds. Service-kind URLs omit the
    # param entirely so back-compat URLs minted before the kind
    # extension parse identically to URLs produced now.
    if kind != PairDeepLinkKind.SERVICE:
        parts.append(f"&{KIND_PARAM_NAME}={kind.value}")

    return "".join(parts)


def build_service_pair_url(
    code: str,
    bootloader_url: Optional[str] = None,
) -> str:
    """
    Convenience for Phase H end-user pair-a-service URLs.

    Equivalent to ``build_pair_url(code, bootloader_url,
    PairDeepLinkKind.SERVICE)`` but reads more clearly at call sites that
    explicitly want the service-kind flow.
    """
    return build_pair_url(code, bootloader_url, PairDeepLinkKind.SERVICE)


def build_bootloader_pair_url(code: str, bootloader_url: str) -> str:
    """
    Convenience for bootloader-pair URLs (initial-trust handshake).

    Equivalent to ``build_pair_url(code, bootloader_url,
    PairDeepLinkKind.BOOTLOADER)``. Bootloader URL is required; raises
    ValueError on empty.
    """
    return build_pair_url(code, bootloader_url, PairDeepLinkKind.BOOTLOADER)


def build_demo_bootloader_pair_url() -> str:
    """
    Build the canonical App Store reviewer demo URL.

    Returns the same byte-stable URL pinned in CANONICAL_DEMO_PAIR_URL.
    Encode as a QR via ``recto.qr.qr_encode_jws(build_demo_bootloader_pair_url())``
    for the canonical demo PNG.
    """
    return build_bootloader_pair_url(DEMO_PAIRING_CODE, DEMO_BOOTLOADER_URL)


def _validate_code_shape(code: str, kind: PairDeepLinkKind) -> None:
    """
    Per-kind code-shape validator. Sister of C#
    PairDeepLinkEmitter.ValidateCodeShape. Raises ValueError on mismatch.
    """
    if not code:
        raise ValueError("code is required and must be non-empty.")

    if kind == PairDeepLinkKind.SERVICE:
        if not _SERVICE_CODE_RE.match(code):
            raise ValueError(
                f"Service-kind code must be [A-Za-z0-9]{{8}} (got: {code!r})."
            )
    elif kind == PairDeepLinkKind.BOOTLOADER:
        if not _BOOTLOADER_CODE_RE.match(code):
            raise ValueError(
                f"Bootloader-kind code must be [0-9]{{6}} (got: {code!r})."
            )
    else:
        raise ValueError(f"Unknown PairDeepLinkKind: {kind!r}")
