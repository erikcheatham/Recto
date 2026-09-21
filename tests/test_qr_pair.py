"""
tests/test_qr_pair.py — recto.qr.pair URL-emitter tests.

Pins the wire-format byte shape of recto://pair?... URLs emitted by the
Python sister of Recto.Shared.Services.PairDeepLinkEmitter (C#).

Cross-language byte parity: the canonical demo URL pinned here MUST
match the canonical URL pinned in
phone/RectoMAUIBlazor/Recto/Recto.Shared.Tests/Services/PairDeepLinkEmitterTests.cs
(see ``CanonicalDemoUrl`` constant there). Any drift triggers test failure
on both sides simultaneously.

Banked 2026-06-01 alongside the demo-mode QR primitive (#41).
"""

from __future__ import annotations

import pytest

from recto.qr import (
    CANONICAL_DEMO_PAIR_URL,
    DEMO_BOOTLOADER_URL,
    DEMO_PAIRING_CODE,
    PairDeepLinkKind,
    build_bootloader_pair_url,
    build_demo_bootloader_pair_url,
    build_pair_url,
    build_service_pair_url,
)


# ----------------------------------------------------------------------
# Canonical byte-parity pin -- the cross-language fixture.
# ----------------------------------------------------------------------


def test_canonical_demo_pair_url_is_byte_stable() -> None:
    """
    The canonical demo URL constant matches the cross-language fixture
    pinned in the C# tests. Both languages must emit byte-identical
    bytes for App Store reviewer QR rendering.
    """
    expected = "recto://pair?code=000000&bootloader=demo%3A%2F%2Frecto-app-review&kind=bootloader"
    assert CANONICAL_DEMO_PAIR_URL == expected


def test_build_demo_bootloader_pair_url_matches_canonical() -> None:
    """``build_demo_bootloader_pair_url()`` emits the canonical wire bytes."""
    assert build_demo_bootloader_pair_url() == CANONICAL_DEMO_PAIR_URL


def test_build_demo_uses_canonical_constants() -> None:
    """Verifies the demo URL uses the canonical constant values verbatim."""
    url = build_demo_bootloader_pair_url()
    assert DEMO_PAIRING_CODE in url  # "000000"
    # bootloader URL appears percent-encoded in the wire shape
    assert "demo%3A%2F%2Frecto-app-review" in url


# ----------------------------------------------------------------------
# Service-kind (Phase H end-user pair-a-service).
# ----------------------------------------------------------------------


def test_service_pair_url_with_bootloader_canonical_shape() -> None:
    url = build_service_pair_url("ABCD1234", "https://bootloader.example/")
    assert url == (
        "recto://pair?code=ABCD1234"
        "&bootloader=https%3A%2F%2Fbootloader.example%2F"
    )


def test_service_pair_url_without_bootloader_omits_param() -> None:
    url = build_service_pair_url("ABCD1234")
    assert url == "recto://pair?code=ABCD1234"
    assert "bootloader=" not in url
    assert "kind=" not in url


def test_service_pair_url_omits_kind_param_for_back_compat() -> None:
    """
    Service-kind URLs MUST omit the kind= param so they're byte-identical
    to v0.1 URLs minted before the kind extension. Closes the back-compat
    contract.
    """
    url = build_service_pair_url("ABCD1234", "https://x.example/")
    assert "kind=" not in url


@pytest.mark.parametrize(
    "code",
    [
        "abcd1234",  # all lowercase
        "ABCD1234",  # all uppercase
        "AbCd1234",  # mixed case
        "00000000",  # all digits
        "ZZZZZZZZ",  # all alpha
    ],
)
def test_service_pair_url_accepts_valid_codes(code: str) -> None:
    url = build_service_pair_url(code)
    assert f"code={code}" in url


@pytest.mark.parametrize(
    "bad_code",
    [
        "ABCD123",  # 7 chars (too short)
        "ABCD12345",  # 9 chars (too long)
        "",  # empty
        "ABCD-234",  # hyphen (non-alphanumeric)
        "ABCD 234",  # space
        "ABCD!234",  # punctuation
    ],
)
def test_service_pair_url_rejects_invalid_codes(bad_code: str) -> None:
    with pytest.raises(ValueError):
        build_service_pair_url(bad_code)


# ----------------------------------------------------------------------
# Bootloader-kind (initial-trust + demo flow).
# ----------------------------------------------------------------------


def test_bootloader_pair_url_canonical_shape() -> None:
    url = build_bootloader_pair_url("123456", "https://bootloader.example/")
    assert url == (
        "recto://pair?code=123456"
        "&bootloader=https%3A%2F%2Fbootloader.example%2F"
        "&kind=bootloader"
    )


def test_bootloader_pair_url_requires_bootloader_url() -> None:
    with pytest.raises(ValueError):
        build_bootloader_pair_url("123456", "")


def test_bootloader_pair_url_emits_kind_param() -> None:
    url = build_bootloader_pair_url("123456", "https://x.example/")
    assert "kind=bootloader" in url


@pytest.mark.parametrize(
    "bad_code",
    [
        "12345",  # 5 digits (too short)
        "1234567",  # 7 digits (too long)
        "abcdef",  # all alpha (rejected -- bootloader requires digits)
        "12345A",  # mixed (rejected)
        "",  # empty
    ],
)
def test_bootloader_pair_url_rejects_invalid_codes(bad_code: str) -> None:
    with pytest.raises(ValueError):
        build_bootloader_pair_url(bad_code, "https://x.example/")


# ----------------------------------------------------------------------
# Bootloader-URL percent-encoding (cross-language byte parity).
# ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "bootloader, expected_encoded",
    [
        ("https://x.example/", "https%3A%2F%2Fx.example%2F"),
        ("demo://recto-app-review", "demo%3A%2F%2Frecto-app-review"),
        ("http://192.0.2.10:8765/", "http%3A%2F%2F192.0.2.10%3A8765%2F"),
    ],
)
def test_build_pair_url_percent_encodes_bootloader_url(
    bootloader: str, expected_encoded: str
) -> None:
    """
    Pins the percent-encoding behavior so a URL emitted Python-side
    parses byte-identically on the C# side (and vice-versa).
    """
    url = build_service_pair_url("ABCD1234", bootloader)
    assert f"bootloader={expected_encoded}" in url


# ----------------------------------------------------------------------
# PairDeepLinkKind enum -- value strings are the wire form.
# ----------------------------------------------------------------------


def test_pair_deep_link_kind_wire_values() -> None:
    assert PairDeepLinkKind.SERVICE.value == "service"
    assert PairDeepLinkKind.BOOTLOADER.value == "bootloader"


def test_build_pair_url_explicit_service_kind_omits_param() -> None:
    """Explicit SERVICE kind behaves identically to default (omit kind=)."""
    url = build_pair_url("ABCD1234", None, PairDeepLinkKind.SERVICE)
    assert "kind=" not in url


def test_build_pair_url_explicit_bootloader_kind_emits_param() -> None:
    url = build_pair_url("123456", "https://x.example/", PairDeepLinkKind.BOOTLOADER)
    assert "kind=bootloader" in url
