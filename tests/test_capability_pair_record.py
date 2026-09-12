"""Tests for ``recto/capability/pair_record.py``: canonical bytes,
fingerprint, named refusals. The bootloader's use of the record is
covered in ``test_bootloader_devices_pair.py``."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from recto.capability.pair_record import (
    GRANT_ACTION_NOT_PAIR,
    GRANT_AUDIENCE_NOT_BOOTLOADER,
    GRANT_CODE_MISMATCH,
    GRANT_SCOPE_FINGERPRINT_MISMATCH,
    GRANT_SCOPE_MISSING_FINGERPRINT,
    GRANT_SIGNER_NOT_RECORD_PHONE,
    GRANT_WINDOW_EXCEEDS_CEILING,
    PAIR_ACTION,
    PAIR_RECORD_FIELDS,
    PAIR_WINDOW_CEILING_SECONDS,
    RECORD_EXPIRED,
    RECORD_FIELD_EMPTY,
    RECORD_NOT_AFTER_MALFORMED,
    RECORD_PUBKEY_MALFORMED,
    PairRecord,
    PairRefused,
    verify_pair_grant,
)
from recto.capability.types import (
    CapabilityClaims,
    CapabilityClause,
    CapabilityScope,
)

_MANIFEST_VERSION: str = json.loads(
    (Path(__file__).parent.parent / "recto" / "capability" / "manifest_v1.json")
    .read_text(encoding="utf-8")
)["version"]

_PHONE = "ab" * 64
_OTHER_PHONE = "cd" * 64
_NOW = 1_800_000_000
_BOOTLOADER = "bl-test"


def _record(**overrides) -> PairRecord:
    base = dict(
        bootloader_id=_BOOTLOADER,
        user_id="user-1",
        phone_pubkey=_PHONE,
        code="A1B2C3D4",
        not_after=_NOW + 600,
    )
    base.update(overrides)
    return PairRecord(**base)


def _claims(
    *,
    fingerprint: str | None,
    code: str | None = None,
    action: str = PAIR_ACTION,
    aud: list[str] | None = None,
    window: int = 300,
) -> CapabilityClaims:
    return CapabilityClaims(
        iss="phone:user:enclave",
        sub="user:user-1",
        aud=aud if aud is not None else [_BOOTLOADER],
        iat=_NOW,
        nbf=_NOW,
        exp=_NOW + window,
        jti="jti-1",
        cap=CapabilityClause(
            tier=0,
            registry_version=_MANIFEST_VERSION,
            scope=CapabilityScope(payload_sha256=fingerprint, pairing_code=code),
            allow_actions=[action],
        ),
        purpose="pair",
        max_uses=1,
    )


# ---------------------------------------------------------------------------
# The record
# ---------------------------------------------------------------------------


def test_fields_are_the_five_sorted():
    assert PAIR_RECORD_FIELDS == ("bootloader_id", "code", "not_after", "phone_pubkey", "user_id")
    assert list(_record().to_dict().keys()) == list(PAIR_RECORD_FIELDS)


def test_canonical_bytes_are_sorted_and_whitespace_free():
    b = _record().canonical_bytes()
    assert b == (
        b'{"bootloader_id":"bl-test","code":"A1B2C3D4","not_after":1800000600,'
        b'"phone_pubkey":"' + _PHONE.encode() + b'","user_id":"user-1"}'
    )


def test_fingerprint_is_sha256_of_canonical_bytes_and_stable():
    r = _record()
    assert r.fingerprint() == hashlib.sha256(r.canonical_bytes()).hexdigest()
    assert r.fingerprint() == _record().fingerprint()
    assert len(r.fingerprint()) == 64 and r.fingerprint() == r.fingerprint().lower()


@pytest.mark.parametrize("field", ["bootloader_id", "user_id", "phone_pubkey", "code", "not_after"])
def test_every_field_moves_the_fingerprint(field):
    changed = {
        "bootloader_id": "bl-other",
        "user_id": "user-2",
        "phone_pubkey": _OTHER_PHONE,
        "code": "Z9Y8X7W6",
        "not_after": _NOW + 601,
    }[field]
    assert _record(**{field: changed}).fingerprint() != _record().fingerprint()


def test_from_dict_normalises_pubkey_case_and_prefix_only():
    a = PairRecord.from_dict(
        {"bootloader_id": _BOOTLOADER, "user_id": "user-1", "code": "A1B2C3D4",
         "not_after": str(_NOW + 600), "phone_pubkey": "0x04" + _PHONE.upper()}
    )
    assert a == _record()


@pytest.mark.parametrize(
    "overrides, name",
    [
        ({"phone_pubkey": _PHONE[:-2]}, RECORD_PUBKEY_MALFORMED),
        ({"phone_pubkey": _PHONE.upper()}, RECORD_PUBKEY_MALFORMED),
        ({"code": " "}, RECORD_FIELD_EMPTY),
        ({"user_id": ""}, RECORD_FIELD_EMPTY),
        ({"not_after": 0}, RECORD_NOT_AFTER_MALFORMED),
        ({"not_after": True}, RECORD_NOT_AFTER_MALFORMED),
    ],
)
def test_malformed_record_is_refused_by_name(overrides, name):
    with pytest.raises(PairRefused) as ei:
        _record(**overrides)
    assert ei.value.name == name


# ---------------------------------------------------------------------------
# The verifier — one refusal per name
# ---------------------------------------------------------------------------


def test_grant_naming_the_fingerprint_is_admitted():
    r = _record()
    fp = verify_pair_grant(
        _claims(fingerprint=r.fingerprint()), r,
        signer_pubkey_hex=_PHONE, bootloader_id=_BOOTLOADER, now=_NOW,
    )
    assert fp == r.fingerprint()


def test_grant_may_carry_the_alias_beside_the_fingerprint():
    r = _record()
    verify_pair_grant(
        _claims(fingerprint=r.fingerprint(), code=r.code), r,
        signer_pubkey_hex="0x04" + _PHONE.upper(), bootloader_id=_BOOTLOADER, now=_NOW,
    )


def _refused(claims, record=None, **kw):
    record = record or _record()
    args = dict(signer_pubkey_hex=_PHONE, bootloader_id=_BOOTLOADER, now=_NOW)
    args.update(kw)
    with pytest.raises(PairRefused) as ei:
        verify_pair_grant(claims, record, **args)
    return ei.value.name


def test_scope_with_only_the_code_is_refused():
    assert _refused(_claims(fingerprint=None, code="A1B2C3D4")) == GRANT_SCOPE_MISSING_FINGERPRINT


def test_scope_naming_another_records_fingerprint_is_refused():
    other = _record(user_id="user-2").fingerprint()
    assert _refused(_claims(fingerprint=other)) == GRANT_SCOPE_FINGERPRINT_MISMATCH


def test_alias_contradicting_the_record_is_refused():
    r = _record()
    assert _refused(_claims(fingerprint=r.fingerprint(), code="Z9Y8X7W6")) == GRANT_CODE_MISMATCH


def test_wrong_action_is_refused():
    r = _record()
    assert _refused(_claims(fingerprint=r.fingerprint(), action="devices:revoke")) == GRANT_ACTION_NOT_PAIR


def test_audience_naming_another_bootloader_is_refused():
    r = _record()
    assert _refused(_claims(fingerprint=r.fingerprint(), aud=["bl-other"])) == GRANT_AUDIENCE_NOT_BOOTLOADER


def test_signer_that_is_not_the_records_phone_is_refused():
    r = _record()
    assert _refused(_claims(fingerprint=r.fingerprint()), signer_pubkey_hex=_OTHER_PHONE) == GRANT_SIGNER_NOT_RECORD_PHONE


def test_expired_record_is_refused():
    r = _record()
    assert _refused(_claims(fingerprint=r.fingerprint()), now=r.not_after) == RECORD_EXPIRED


def test_window_past_the_ceiling_is_refused():
    r = _record()
    assert _refused(
        _claims(fingerprint=r.fingerprint(), window=PAIR_WINDOW_CEILING_SECONDS + 1)
    ) == GRANT_WINDOW_EXCEEDS_CEILING


def test_window_at_the_ceiling_is_admitted():
    r = _record()
    verify_pair_grant(
        _claims(fingerprint=r.fingerprint(), window=PAIR_WINDOW_CEILING_SECONDS), r,
        signer_pubkey_hex=_PHONE, bootloader_id=_BOOTLOADER, now=_NOW,
    )
