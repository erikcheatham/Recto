"""
recto.qr — QR-as-visual-transport primitive for signed payloads.

The QR substrate primitive shipped as Phase 1 of the artifact-as-
canonical-record canonical pivot (banked 2026-05-20 morning in
Recto/CLAUDE.md). Downstream of Hard Rule #13: signed payloads are
portable artifacts; the bytes themselves are the canonical record,
NOT a row in any centralized database. QR codes are one transport
layer for those bytes (alongside HTTP and the folder-drop event bus
banked the prior evening).

This module ships v1 ENCODE-only:

  - `qr_encode_jws(jws)` — JWS string → QR PNG/SVG (simplest path;
    use for capability_request JWS, pairing JWS, manumission JWS,
    any single-payload artifact where the JWS string is self-
    contained)
  - `qr_encode_payload(payload)` — structured QRPayloadV1 →
    QR PNG/SVG (used for multi-witness contracts, citation receipts,
    promotion certificates, future-N rich-payload kinds)
  - `create_multi_witness_contract(...)` + `add_witness_signature(...)`
    + `encode_multi_witness_qr(...)` — the multi-witness contract
    extension (each witness's signature added before re-rendering;
    final QR IS the canonical contract document)

Decode (QR image → JWS string / payload dict) is deferred to v2:
  - Recto Phone (the canonical first consumer at Phase 2) has its
    own native QR scanner via MAUI Blazor; it doesn't need Python
    decode.
  - Python decode requires `pyzbar` (libzbar native dep) or
    `zxing-cpp` (native C++); v1 stays pure-Python except for the
    Pillow PNG output to keep the substrate's dependency footprint
    small.

To install:
  pip install recto[qr]

This pulls `qrcode>=7.4` + `Pillow>=10.0`. Both are pure-Python
except Pillow's image-codec backends; both have permissive BSD/HPND
licenses. SVG output is available via qrcode's built-in SVG factory
(no Pillow dependency for the SVG path).

See `recto/qr/SPEC.md` for the wire-format specification and
Recto/CLAUDE.md "QR-as-visual-transport for capability JWS +
signed-payload contracts" section for the canonical architectural
framework + per-wave sequencing roadmap.
"""

from __future__ import annotations

from recto.qr.encode import (
    DEFAULT_BORDER,
    DEFAULT_BOX_SIZE,
    DEFAULT_ERROR_CORRECTION,
    build_qr_meta,
    canonical_signing_input,
    qr_encode_jws,
    qr_encode_payload,
)
from recto.qr.pair import (
    CANONICAL_DEMO_PAIR_URL,
    DEMO_BOOTLOADER_ID,
    DEMO_BOOTLOADER_URL,
    DEMO_PAIRING_CODE,
    PairDeepLinkKind,
    build_bootloader_pair_url,
    build_demo_bootloader_pair_url,
    build_pair_url,
    build_service_pair_url,
)
from recto.qr.multi_witness import (
    add_witness_signature,
    canonical_signing_input_for_witness,
    create_multi_witness_contract,
    encode_multi_witness_qr,
)
from recto.qr.types import (
    QR_FORMAT_PNGV1,
    QR_FORMAT_SVGV1,
    QR_MAX_SIZE_BYTES_V40_H,
    QR_MAX_SIZE_BYTES_V40_L,
    QR_MAX_SIZE_BYTES_V40_M,
    QR_MAX_SIZE_BYTES_V40_Q,
    QR_SCHEMA_VERSION,
    MultiWitnessContract,
    QRMeta,
    QRPayloadV1,
    Witness,
)

__all__ = [
    # Encode primitives
    "qr_encode_jws",
    "qr_encode_payload",
    "build_qr_meta",
    "canonical_signing_input",
    # Multi-witness contract primitives
    "create_multi_witness_contract",
    "add_witness_signature",
    "canonical_signing_input_for_witness",
    "encode_multi_witness_qr",
    # Pair-deep-link URL emitter (banked 2026-06-01 for #41)
    "build_pair_url",
    "build_service_pair_url",
    "build_bootloader_pair_url",
    "build_demo_bootloader_pair_url",
    "PairDeepLinkKind",
    # Pair-deep-link constants (App Store reviewer demo sentinels)
    "DEMO_PAIRING_CODE",
    "DEMO_BOOTLOADER_URL",
    "DEMO_BOOTLOADER_ID",
    "CANONICAL_DEMO_PAIR_URL",
    # Wire-format dataclasses
    "QRMeta",
    "QRPayloadV1",
    "MultiWitnessContract",
    "Witness",
    # Constants
    "QR_SCHEMA_VERSION",
    "QR_FORMAT_PNGV1",
    "QR_FORMAT_SVGV1",
    "QR_MAX_SIZE_BYTES_V40_L",
    "QR_MAX_SIZE_BYTES_V40_M",
    "QR_MAX_SIZE_BYTES_V40_Q",
    "QR_MAX_SIZE_BYTES_V40_H",
    # Defaults
    "DEFAULT_ERROR_CORRECTION",
    "DEFAULT_BOX_SIZE",
    "DEFAULT_BORDER",
]
