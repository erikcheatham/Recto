"""Tests for ``recto/capability/pair_record.py``.

1. The record: canonical bytes, fingerprint, named refusals.
2. ``POST /v0.4/devices/pair`` must refuse a grant whose scope names the
   code but not the fingerprint. Fails today (the relay does not read the
   grant); ``xfail(strict=True)`` until it does.
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
from pathlib import Path
from urllib import request as urlrequest
from urllib.error import HTTPError

import pytest

from recto.bootloader.server import ChallengeStore, create_server
from recto.bootloader.state import StateStore
from recto.capability.jwt import build_signing_input
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
# 1. The record
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
# 1b. The verifier — one refusal per name
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


# ---------------------------------------------------------------------------
# 2. The relay must read the grant (fails until it does)
# ---------------------------------------------------------------------------


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _mint(claims: CapabilityClaims, priv_int: int) -> str:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    digest, header_b64, payload_b64 = build_signing_input(claims)
    priv = ec.derive_private_key(priv_int, ec.SECP256K1(), default_backend())
    r, s = utils.decode_dss_signature(priv.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256()))))
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    if s > n // 2:
        s = n - s
    return f"{header_b64}.{payload_b64}.{_b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


@pytest.fixture
def phone_keypair():
    pytest.importorskip("cryptography")
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import ec

    priv = ec.generate_private_key(ec.SECP256K1(), default_backend())
    nums = priv.public_key().public_numbers()
    return priv.private_numbers().private_value, (nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")).hex()


@pytest.fixture
def relay_server(tmp_path: Path):
    """Bootloader with one registered consumer nothing listens on."""
    server = create_server(
        bind_host="127.0.0.1",
        bind_port=0,
        state=StateStore(state_dir=tmp_path),
        bootloader_id=_BOOTLOADER,
        challenges=ChallengeStore(),
        ssl_context=None,
        devices_pair_consumer_webhook_tokens={"http://127.0.0.1:9": "consumer-token-fixture"},
        devices_pair_consumer_timeout_seconds=1.0,
    )
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)


def _post(url: str, body: dict) -> tuple[int, dict]:
    req = urlrequest.Request(
        url, data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urlrequest.urlopen(req, timeout=5.0) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, {"_raw_body": raw}


@pytest.mark.xfail(
    strict=True,
    reason="the relay does not yet verify the grant against the pairing record",
)
def test_relay_refuses_a_grant_that_names_the_code_but_not_the_act(relay_server, phone_keypair):
    priv_int, pubkey_hex = phone_keypair
    now = int(time.time())
    claims = CapabilityClaims(
        iss="phone:user:enclave", sub="user:user-1", aud=[_BOOTLOADER],
        iat=now, nbf=now, exp=now + 300, jti="jti-relay-1",
        cap=CapabilityClause(
            tier=0, registry_version=_MANIFEST_VERSION,
            scope=CapabilityScope(pairing_code="A1B2C3D4"),
            allow_actions=[PAIR_ACTION],
        ),
        purpose="pair", max_uses=1,
    )
    status, body = _post(
        f"{relay_server}/v0.4/devices/pair",
        {
            "consumer_base_url": "http://127.0.0.1:9",
            "pairing_code": "A1B2C3D4",
            "user_pubkey_hex": pubkey_hex,
            "user_jws": _mint(claims, priv_int),
        },
    )
    assert status == 403
    assert body.get("error") == GRANT_SCOPE_MISSING_FINGERPRINT
