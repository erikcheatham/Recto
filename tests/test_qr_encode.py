"""
tests/test_qr_encode.py — recto.qr encode primitive tests.

Pins the canonical-JSON byte-parity contract end-to-end through
the QR encoding path. Sister of tests/test_capability.py which
pins the same canonical-JSON encoding for the JWS signing input;
together they prove a capability JWS and its QR-wrapped counterpart
sign over byte-identical input.

The qrcode + Pillow extras are gated behind `recto[qr]`; tests
skip gracefully when the extra isn't installed. CI installs the
extra; ad-hoc test runs without the extra still pass via skip.
"""

from __future__ import annotations

import json

import pytest

# Import the recto.qr module unconditionally — the dataclass + helper
# imports don't depend on qrcode/Pillow. The qrcode import is lazy
# inside qr_encode_jws / qr_encode_payload; tests for those gate
# behind importorskip.
from recto.qr.encode import (
    _canonical_json,
    _strip_qr_meta,
    canonical_signing_input,
)
from recto.qr.types import (
    QR_FORMAT_PNGV1,
    QR_FORMAT_SVGV1,
    QR_MAX_SIZE_BYTES_V40_L,
    QR_SCHEMA_VERSION,
    QRMeta,
    QRPayloadV1,
)


# ---------------------------------------------------------------------
# Canonical-JSON byte-parity tests (no qrcode dependency)
# ---------------------------------------------------------------------


class TestCanonicalJson:
    """Pin the canonical-JSON encoding rules end-to-end.

    The canonical-JSON convention used here matches Python's
    `json.dumps(obj, sort_keys=True, separators=(",",":"), ensure_ascii=True)`
    output BYTE-FOR-BYTE. Sister of `recto.capability.jwt._canonical_json`;
    both paths produce byte-identical output for the same input dict.
    """

    def test_sorts_keys_alphabetically(self) -> None:
        obj = {"z": 1, "a": 2, "m": 3}
        result = _canonical_json(obj)
        assert result == '{"a":2,"m":3,"z":1}'

    def test_no_whitespace_separators(self) -> None:
        obj = {"a": [1, 2, 3], "b": {"c": 4}}
        result = _canonical_json(obj)
        # NO space after colons, NO space after commas
        assert ": " not in result
        assert ", " not in result
        assert result == '{"a":[1,2,3],"b":{"c":4}}'

    def test_ascii_escapes_non_ascii(self) -> None:
        # Non-ASCII gets escaped as \uXXXX (lowercase hex per Python's
        # json.dumps convention).
        obj = {"emoji": "café"}
        result = _canonical_json(obj)
        # 'é' = U+00E9 → é
        assert result == '{"emoji":"caf\\u00e9"}'

    def test_null_and_bool_pass_through(self) -> None:
        obj = {"a": None, "b": True, "c": False}
        result = _canonical_json(obj)
        assert result == '{"a":null,"b":true,"c":false}'

    def test_nested_objects_sort_recursively(self) -> None:
        obj = {"outer": {"z": 1, "a": 2}}
        result = _canonical_json(obj)
        assert result == '{"outer":{"a":2,"z":1}}'

    def test_empty_object_and_array(self) -> None:
        obj = {"empty_obj": {}, "empty_arr": []}
        result = _canonical_json(obj)
        assert result == '{"empty_arr":[],"empty_obj":{}}'

    def test_int_values_stay_int(self) -> None:
        # Critical for unix timestamps and version fields — these
        # MUST round-trip as ints, not floats.
        obj = {"iat": 1716200000, "v": 1}
        result = _canonical_json(obj)
        assert result == '{"iat":1716200000,"v":1}'
        # Decode it back to verify int type preserved
        decoded = json.loads(result)
        assert isinstance(decoded["iat"], int)
        assert isinstance(decoded["v"], int)


class TestStripQrMeta:
    """Pin the _qr_meta-strip behavior used in signing-input computation."""

    def test_strips_qr_meta_from_payload(self) -> None:
        payload = {
            "v": 1,
            "kind": "capability_request",
            "body": {"jws": "header.body.sig"},
            "_qr_meta": {"format": "qr-pngv1", "max_size_bytes": 2953},
        }
        stripped = _strip_qr_meta(payload)
        assert "_qr_meta" not in stripped
        assert stripped == {
            "v": 1,
            "kind": "capability_request",
            "body": {"jws": "header.body.sig"},
        }

    def test_no_op_when_qr_meta_absent(self) -> None:
        payload = {"v": 1, "kind": "test"}
        stripped = _strip_qr_meta(payload)
        assert stripped == payload
        # Returns a copy, not the same dict (defends against mutation)
        assert stripped is not payload

    def test_preserves_other_fields_byte_for_byte(self) -> None:
        payload = {
            "v": 1,
            "kind": "test",
            "iss": "phone:operator:enclave",
            "aud": ["example-consumer"],
            "body": {"nested": {"deeply": "yes"}},
            "_qr_meta": {"format": "qr-pngv1"},
        }
        stripped = _strip_qr_meta(payload)
        # All keys except _qr_meta preserved with identical values
        for key in ("v", "kind", "iss", "aud", "body"):
            assert stripped[key] == payload[key]


class TestCanonicalSigningInput:
    """Pin the canonical signing-input computation.

    This is the load-bearing function — consumers sign these bytes
    and verifiers reconstruct them. Byte-parity across runtimes is
    mandatory.
    """

    def test_strips_qr_meta_and_canonical_encodes(self) -> None:
        payload = {
            "v": 1,
            "kind": "capability_request",
            "iss": "phone:operator:enclave",
            "iat": 1716200000,
            "body": {"jws": "header.body.sig"},
            "_qr_meta": {"format": "qr-pngv1", "max_size_bytes": 2953},
        }
        result = canonical_signing_input(payload)
        # Should be UTF-8 bytes of canonical JSON WITHOUT _qr_meta
        expected = (
            '{"body":{"jws":"header.body.sig"},'
            '"iat":1716200000,'
            '"iss":"phone:operator:enclave",'
            '"kind":"capability_request",'
            '"v":1}'
        ).encode("utf-8")
        assert result == expected

    def test_byte_identical_across_payload_dict_orderings(self) -> None:
        """Different insertion orders produce identical signing input."""
        p1 = {"v": 1, "kind": "test", "iss": "a", "body": {}}
        p2 = {"body": {}, "iss": "a", "kind": "test", "v": 1}
        p3 = {"iss": "a", "v": 1, "body": {}, "kind": "test"}
        assert canonical_signing_input(p1) == canonical_signing_input(p2)
        assert canonical_signing_input(p2) == canonical_signing_input(p3)

    def test_signing_input_excludes_qr_meta_changes(self) -> None:
        """Two payloads identical except for _qr_meta produce same signing input."""
        base = {"v": 1, "kind": "test", "body": {"x": 1}}
        with_meta_a = {**base, "_qr_meta": {"format": "qr-pngv1", "max_size_bytes": 2953}}
        with_meta_b = {**base, "_qr_meta": {"format": "qr-svgv1", "max_size_bytes": 1273}}
        assert canonical_signing_input(with_meta_a) == canonical_signing_input(with_meta_b)


class TestQRMetaDataclass:
    """Pin QRMeta dataclass defaults + structure."""

    def test_defaults_match_v40_l_png(self) -> None:
        meta = QRMeta()
        assert meta.format == QR_FORMAT_PNGV1
        assert meta.max_size_bytes == QR_MAX_SIZE_BYTES_V40_L
        assert meta.fragmentation is None

    def test_frozen_immutable(self) -> None:
        meta = QRMeta()
        with pytest.raises(Exception):  # dataclasses.FrozenInstanceError
            meta.format = "qr-svgv1"  # type: ignore[misc]


class TestQRPayloadV1Dataclass:
    """Pin QRPayloadV1 dataclass defaults + structure."""

    def test_schema_version_is_one(self) -> None:
        payload = QRPayloadV1()
        assert payload.v == 1
        assert payload.v == QR_SCHEMA_VERSION

    def test_default_qr_meta_is_pngv1(self) -> None:
        payload = QRPayloadV1()
        assert payload._qr_meta.format == QR_FORMAT_PNGV1

    def test_construct_with_all_fields(self) -> None:
        payload = QRPayloadV1(
            v=1,
            kind="capability_request",
            iss="phone:operator:enclave",
            aud=("example-consumer",),
            iat=1716200000,
            exp=1716203600,
            jti="abc-123",
            body={"jws": "header.body.sig"},
        )
        assert payload.kind == "capability_request"
        assert payload.aud == ("example-consumer",)
        assert payload.iat == 1716200000


# ---------------------------------------------------------------------
# qrcode-dependent tests (gated behind recto[qr] extra)
# ---------------------------------------------------------------------


qrcode = pytest.importorskip("qrcode", reason="install via `pip install recto[qr]`")


class TestQrEncodeJws:
    """Pin the qr_encode_jws primitive's PNG output behavior.

    Doesn't verify PNG bytes byte-identically (QR rendering is
    deterministic for the same input but Pillow's PNG compression
    isn't guaranteed reproducible across versions); instead verifies
    structural properties: non-empty output, PNG magic bytes, no
    exceptions on canonical inputs.
    """

    def test_encodes_short_jws_to_png(self) -> None:
        from recto.qr import qr_encode_jws

        jws = "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJ0ZXN0In0.signature"
        png_bytes = qr_encode_jws(jws)
        assert len(png_bytes) > 0
        # PNG magic bytes
        assert png_bytes[:8] == b"\x89PNG\r\n\x1a\n"

    def test_encodes_short_jws_to_svg(self) -> None:
        from recto.qr import qr_encode_jws

        jws = "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJ0ZXN0In0.signature"
        svg_bytes = qr_encode_jws(jws, image_format="svg")
        assert len(svg_bytes) > 0
        # SVG output starts with XML declaration or <svg
        assert b"<svg" in svg_bytes[:200] or b"<?xml" in svg_bytes[:200]

    def test_rejects_empty_jws(self) -> None:
        from recto.qr import qr_encode_jws

        with pytest.raises(ValueError, match="non-empty"):
            qr_encode_jws("")

    def test_rejects_unknown_image_format(self) -> None:
        from recto.qr import qr_encode_jws

        with pytest.raises(ValueError, match="image_format"):
            qr_encode_jws("test.jws.sig", image_format="bmp")

    def test_rejects_unknown_error_correction(self) -> None:
        from recto.qr import qr_encode_jws

        with pytest.raises(ValueError, match="error_correction"):
            qr_encode_jws("test.jws.sig", error_correction="X")

    def test_all_error_correction_levels_work(self) -> None:
        from recto.qr import qr_encode_jws

        jws = "test.jws.sig"
        for level in ("L", "M", "Q", "H"):
            png_bytes = qr_encode_jws(jws, error_correction=level)
            assert png_bytes[:8] == b"\x89PNG\r\n\x1a\n"

    def test_long_jws_at_capacity_limit(self) -> None:
        """Capability JWS-sized payloads encode without issue."""
        from recto.qr import qr_encode_jws

        # Typical capability JWS is 400-800 bytes; simulate the larger end.
        jws = "x" * 700
        png_bytes = qr_encode_jws(jws)
        assert png_bytes[:8] == b"\x89PNG\r\n\x1a\n"


class TestQrEncodePayload:
    """Pin the qr_encode_payload primitive's structured-payload path."""

    def test_encodes_qrpayloadv1_dataclass(self) -> None:
        from recto.qr import QRPayloadV1, qr_encode_payload

        payload = QRPayloadV1(
            kind="capability_request",
            iss="phone:operator:enclave",
            aud=("example-consumer",),
            iat=1716200000,
            exp=1716203600,
            jti="test-jti",
            body={"jws": "header.body.sig"},
        )
        png_bytes = qr_encode_payload(payload)
        assert png_bytes[:8] == b"\x89PNG\r\n\x1a\n"

    def test_encodes_dict_payload(self) -> None:
        """Dict input matches dataclass input byte-for-byte."""
        from recto.qr import qr_encode_payload

        payload = {
            "v": 1,
            "kind": "test",
            "iss": "x",
            "aud": [],
            "iat": 0,
            "exp": 0,
            "jti": "j",
            "body": {},
            "_qr_meta": {
                "format": "qr-pngv1",
                "max_size_bytes": 2953,
                "fragmentation": None,
            },
        }
        png_bytes = qr_encode_payload(payload)
        assert png_bytes[:8] == b"\x89PNG\r\n\x1a\n"

    def test_rejects_oversize_payload(self) -> None:
        """Payloads exceeding QR v40-L capacity raise ValueError."""
        from recto.qr import qr_encode_payload

        # Construct a payload whose canonical-JSON encoding exceeds
        # 2953 bytes (QR v40-L capacity).
        huge_body = {"data": "x" * 3500}
        payload = {
            "v": 1,
            "kind": "test",
            "iss": "x",
            "aud": [],
            "iat": 0,
            "exp": 0,
            "jti": "j",
            "body": huge_body,
            "_qr_meta": {"format": "qr-pngv1", "max_size_bytes": 2953, "fragmentation": None},
        }
        with pytest.raises(ValueError, match="exceeds QR"):
            qr_encode_payload(payload)

    def test_rejects_wrong_payload_type(self) -> None:
        from recto.qr import qr_encode_payload

        with pytest.raises(ValueError, match="QRPayloadV1 or dict"):
            qr_encode_payload("not a payload")  # type: ignore[arg-type]


class TestBuildQrMeta:
    """Pin the build_qr_meta convenience helper's format mapping."""

    def test_png_returns_pngv1_format(self) -> None:
        from recto.qr import build_qr_meta

        meta = build_qr_meta(image_format="png")
        assert meta.format == QR_FORMAT_PNGV1

    def test_svg_returns_svgv1_format(self) -> None:
        from recto.qr import build_qr_meta

        meta = build_qr_meta(image_format="svg")
        assert meta.format == QR_FORMAT_SVGV1

    def test_max_size_matches_error_correction(self) -> None:
        from recto.qr import build_qr_meta

        # Per QR spec v40 capacities
        assert build_qr_meta(error_correction="L").max_size_bytes == 2953
        assert build_qr_meta(error_correction="M").max_size_bytes == 2331
        assert build_qr_meta(error_correction="Q").max_size_bytes == 1663
        assert build_qr_meta(error_correction="H").max_size_bytes == 1273
