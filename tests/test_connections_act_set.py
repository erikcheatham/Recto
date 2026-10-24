"""Vault SET: the store side of a phone-signed set.

The value is typed at the desk and travels with the grant; the record the
operator signs carries only its SHA-256 (``value_sha256``) and the card shows
the first 12 hex of it. ``recto.connections.act_set`` stores the value only
when SHA-256 over its exact UTF-8 bytes is the signed digest, and writes it
through the same ``set_connection`` the operator-token upsert uses.

These tests need no bootloader: the verifier takes claims, and the store
takes a path and a vault factory. Every value here is an obvious fake.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from recto.capability.types import CapabilityClaims, CapabilityClause, CapabilityLimits, CapabilityScope
from recto.connections.act_record import ActRecord, ActRefused, verify_act_grant
from recto.connections.act_set import VALUE_MAX_BYTES, apply_set, check_act_value, value_sha256
from recto.connections.manage import get_connection_meta, set_connection
from recto.secrets.base import DirectSecret, SecretMaterial, SecretNotFoundError, SecretSourceError

BL = "rb1-0123456789abcdef0123456789abcdef"
SERVICE = "ServiceA"
VALUE = "fake-value-for-tests-7c1e"
OTHER = "fake-other-value-for-tests-d40b"


class _MemoryVault:
    def __init__(self, fail_writes: bool = False) -> None:
        self.data: dict[tuple[str, str], str] = {}
        self.writes = 0
        self.fail_writes = fail_writes

    def factory(self, service: str) -> _MemorySource:
        return _MemorySource(self, service)


class _MemorySource:
    def __init__(self, vault: _MemoryVault, service: str) -> None:
        self._vault, self._service = vault, service

    def fetch(self, secret_name: str, config: dict[str, Any]) -> SecretMaterial:
        value = self._vault.data.get((self._service, secret_name))
        if value is None:
            raise SecretNotFoundError(f"{self._service}/{secret_name}")
        return DirectSecret(value=value)

    def write(self, secret_name: str, value: str, comment: str = "") -> None:
        if self._vault.fail_writes:
            raise SecretSourceError(f"write failed for {secret_name!r}")
        self._vault.writes += 1
        self._vault.data[(self._service, secret_name)] = value

    def delete(self, secret_name: str) -> None:
        self._vault.data.pop((self._service, secret_name), None)


def _set_record(value: str = VALUE, key: str = "alpha", **over: Any) -> ActRecord:
    fields: dict[str, Any] = {"bootloader_id": BL, "service": SERVICE, "key": key, "verb": "set",
                              "not_after": int(time.time()) + 240,
                              "value_sha256": hashlib.sha256(value.encode("utf-8")).hexdigest()}
    fields.update(over)
    return ActRecord(**fields)


def _claims(record: ActRecord, **over: Any) -> CapabilityClaims:
    now = int(time.time())
    scope = CapabilityScope(services=[record.service], payload_sha256=record.fingerprint())
    cap = CapabilityClause(tier=2, registry_version="2026-10-19", scope=scope, allow_actions=[record.action],
                           limits=CapabilityLimits())
    claims = CapabilityClaims(
        iss="phone:operator:enclave", sub="agent:web-agent", aud=[BL], iat=now, nbf=now - 5, exp=record.not_after,
        jti=f"set-test-{now}", cap=cap, purpose=record.purpose(), max_uses=1,
    )
    return replace(claims, **over)


# -- the digest helper -------------------------------------------------------------------------------------------------

def test_value_sha256_is_the_hex_digest_of_the_utf8_bytes():
    assert value_sha256("example-value") == "818e58a60e89a101edc08fc72f666d4e10706c74fb208c60b95c25b927aa16bc"
    assert value_sha256("café-\U0001F600-value") == (
        "b764465fcd4edcc48b8515093d51587e5f49f614062f0d7764c4e2d1b050406b")


# -- the verifier: a set is admitted only where the caller routes its value to the check -------------------------------

class TestTheVerifierAndSet:
    def test_a_set_grant_is_refused_where_the_caller_does_not_admit_set(self):
        record = _set_record()
        with pytest.raises(ActRefused) as e:
            verify_act_grant(_claims(record), record, bootloader_id=BL)
        assert e.value.name == "action_not_admitted"

    def test_a_set_grant_for_exactly_its_record_is_admitted_where_set_is(self):
        record = _set_record()
        assert verify_act_grant(_claims(record), record, bootloader_id=BL, admit_set=True) == record.fingerprint()

    def test_the_phase_one_verbs_verify_alike_with_or_without_set_admitted(self):
        for verb in ("enable", "disable", "delete"):
            record = ActRecord(bootloader_id=BL, service=SERVICE, key="alpha", verb=verb,
                               not_after=int(time.time()) + 240)
            assert verify_act_grant(_claims(record), record, bootloader_id=BL) == record.fingerprint()
            assert verify_act_grant(_claims(record), record, bootloader_id=BL, admit_set=True) == record.fingerprint()

    def test_a_set_record_under_a_delete_grant_is_a_tuple_mismatch(self):
        record = _set_record()
        claims = _claims(record)
        claims = replace(claims, cap=replace(claims.cap, allow_actions=["connections:delete"]))
        with pytest.raises(ActRefused) as e:
            verify_act_grant(claims, record, bootloader_id=BL, admit_set=True)
        assert e.value.name == "tuple_mismatch"

    def test_a_record_carrying_another_values_digest_is_a_payload_mismatch(self):
        signed = _set_record(VALUE)
        swapped = replace(signed, value_sha256=value_sha256(OTHER))
        with pytest.raises(ActRefused) as e:
            verify_act_grant(_claims(signed), swapped, bootloader_id=BL, admit_set=True)
        assert e.value.name == "payload_mismatch"

    def test_a_purpose_naming_another_fingerprint_is_a_purpose_mismatch(self):
        record = _set_record()
        lie = record.purpose().replace(record.value_sha256[:12], value_sha256(OTHER)[:12])
        assert lie != record.purpose()
        with pytest.raises(ActRefused) as e:
            verify_act_grant(_claims(record, purpose=lie), record, bootloader_id=BL, admit_set=True)
        assert e.value.name == "purpose_mismatch"

    def test_a_phase_one_purpose_on_a_set_record_is_a_purpose_mismatch(self):
        record = _set_record()
        bare = f"Vault SET: {SERVICE}/alpha on {BL} - until " + record.purpose().rsplit(" - until ", 1)[1]
        with pytest.raises(ActRefused) as e:
            verify_act_grant(_claims(record, purpose=bare), record, bootloader_id=BL, admit_set=True)
        assert e.value.name == "purpose_mismatch"


# -- the value check ---------------------------------------------------------------------------------------------------

class TestCheckActValue:
    def test_a_value_whose_digest_is_the_records_is_returned(self):
        assert check_act_value(_set_record(VALUE), VALUE) == VALUE

    def test_a_value_whose_digest_differs_is_a_fingerprint_mismatch(self):
        with pytest.raises(ActRefused) as e:
            check_act_value(_set_record(VALUE), OTHER)
        assert e.value.name == "value_fingerprint_mismatch"

    @pytest.mark.parametrize("where", ["after_the_card_prefix", "last_hex"])
    def test_a_digest_that_differs_past_the_card_prefix_is_a_fingerprint_mismatch(self, where):
        # The card shows 12 hex of value_sha256; the store compares all 64.
        full = value_sha256(VALUE)
        if where == "after_the_card_prefix":
            near = full[:12] + ("0" * 52 if full[12:] != "0" * 52 else "1" * 52)
        else:
            near = full[:-1] + ("0" if full[-1] != "0" else "1")
        assert near != full and near[:12] == full[:12]
        with pytest.raises(ActRefused) as e:
            check_act_value(_set_record(VALUE, value_sha256=near), VALUE)
        assert e.value.name == "value_fingerprint_mismatch"

    @pytest.mark.parametrize("value, name", [
        (None, "value_missing"),
        (12345, "value_not_string"),
        (True, "value_not_string"),
        (b"fake-bytes", "value_not_string"),
        (["fake"], "value_not_string"),
        ({"value": "fake"}, "value_not_string"),
        ("", "value_empty"),
    ])
    def test_a_missing_or_shapeless_value_is_refused_by_name(self, value, name):
        with pytest.raises(ActRefused) as e:
            check_act_value(_set_record(VALUE), value)
        assert e.value.name == name

    def test_the_size_cap_is_on_the_utf8_bytes(self):
        at_cap = "a" * VALUE_MAX_BYTES
        assert check_act_value(_set_record(at_cap), at_cap) == at_cap
        over = "a" * (VALUE_MAX_BYTES + 1)
        with pytest.raises(ActRefused) as e:
            check_act_value(_set_record(over), over)
        assert e.value.name == "value_too_large"
        # Under the cap in characters, over it in bytes: two bytes each.
        wide = "é" * (VALUE_MAX_BYTES // 2 + 1)
        assert len(wide) < VALUE_MAX_BYTES < len(wide.encode("utf-8"))
        with pytest.raises(ActRefused) as e:
            check_act_value(_set_record(wide), wide)
        assert e.value.name == "value_too_large"

    def test_a_value_with_no_utf8_form_is_not_storable_and_the_refusal_holds_no_trace_of_it(self):
        value = "fake-\ud800-value"  # a lone surrogate: JSON can carry it, UTF-8 cannot
        record = _set_record("anything")
        with pytest.raises(ActRefused) as e:
            check_act_value(record, value)
        assert e.value.name == "value_not_storable"
        assert e.value.__context__ is None and e.value.__cause__ is None, "the encoder's error holds the value"

    @pytest.mark.parametrize("verb", ["enable", "disable", "delete"])
    def test_a_value_on_any_other_verb_is_refused_and_none_is_nothing_to_check(self, verb):
        record = ActRecord(bootloader_id=BL, service=SERVICE, key="alpha", verb=verb, not_after=int(time.time()) + 240)
        with pytest.raises(ActRefused) as e:
            check_act_value(record, VALUE)
        assert e.value.name == "value_not_admitted"
        assert check_act_value(record, None) is None

    def test_no_refusal_names_the_value(self):
        record = _set_record(VALUE)
        for bad in (OTHER, "", 7, "x" * (VALUE_MAX_BYTES + 1), "fake-\udfff"):
            with pytest.raises(ActRefused) as e:
                check_act_value(record, bad)
            text = f"{e.value!s} {e.value!r} {e.value.detail} {e.value.args!r}"
            assert VALUE not in text and OTHER not in text and "fake-" not in text
            assert record.value_sha256 not in text, "not even the signed digest is echoed"


# -- the store ---------------------------------------------------------------------------------------------------------

class TestApplySet:
    def _path(self, tmp_path: Path) -> Path:
        return tmp_path / "connections.json"

    def test_a_matching_value_adds_a_new_key_with_the_stores_defaults(self, tmp_path):
        vault = _MemoryVault()
        meta = apply_set(self._path(tmp_path), _set_record(VALUE, "gamma"), VALUE, secret_source_factory=vault.factory)
        assert vault.data == {(SERVICE, "conn.gamma"): VALUE}
        assert vault.writes == 1
        assert (meta.key, meta.display_name, meta.category, meta.enabled, meta.has_secret) == (
            "gamma", "gamma", "uncategorized", True, True)
        assert meta.rotated_at_unix > 0
        assert get_connection_meta(self._path(tmp_path), SERVICE, "gamma") == meta
        assert VALUE not in self._path(tmp_path).read_text(encoding="utf-8")

    def test_a_rotation_replaces_the_value_and_keeps_the_rows_metadata(self, tmp_path):
        vault = _MemoryVault()
        path = self._path(tmp_path)
        set_connection(path, service=SERVICE, key="alpha", display_name="Alpha API", category="ai", secret=OTHER,
                       config={"region": "eu"}, enabled=False, health_url="https://example.invalid/health",
                       secret_source_factory=vault.factory)
        meta = apply_set(path, _set_record(VALUE, "alpha"), VALUE, secret_source_factory=vault.factory)
        assert vault.data[(SERVICE, "conn.alpha")] == VALUE
        assert (meta.display_name, meta.category, meta.enabled, meta.config, meta.health_url) == (
            "Alpha API", "ai", False, {"region": "eu"}, "https://example.invalid/health"), "a set writes the value only"

    @pytest.mark.parametrize("value", [OTHER, None, 7, "", "x" * (VALUE_MAX_BYTES + 1), "fake-\ud800"])
    def test_a_refused_value_stores_nothing(self, tmp_path, value):
        vault = _MemoryVault()
        path = self._path(tmp_path)
        with pytest.raises(ActRefused):
            apply_set(path, _set_record(VALUE), value, secret_source_factory=vault.factory)
        assert vault.data == {} and vault.writes == 0
        assert not path.exists(), "no row either"

    def test_a_padded_value_is_digested_and_stored_byte_exact_never_trimmed(self, tmp_path):
        padded = " fake-padded-value-for-tests-3e7a\t "  # a paste with a space before and a tab and space after
        assert value_sha256(padded) == "38313d890269f82c28dfeda3a7a248902e5ae772cb78dc0dfa1f258d169e7338"
        record = _set_record(padded)
        assert check_act_value(record, padded) == padded
        with pytest.raises(ActRefused) as e:
            check_act_value(record, padded.strip())
        assert e.value.name == "value_fingerprint_mismatch"
        vault = _MemoryVault()
        apply_set(self._path(tmp_path), record, padded, secret_source_factory=vault.factory)
        assert vault.data == {(SERVICE, "conn.alpha"): padded}, "stored exactly as signed: never trimmed or normalised"

    def test_a_non_set_record_stores_nothing(self, tmp_path):
        vault = _MemoryVault()
        record = ActRecord(bootloader_id=BL, service=SERVICE, key="alpha", verb="enable",
                           not_after=int(time.time()) + 240)
        for value in (VALUE, None):
            with pytest.raises(ActRefused) as e:
                apply_set(self._path(tmp_path), record, value, secret_source_factory=vault.factory)
            assert e.value.name == "value_not_admitted"
        assert vault.data == {} and not self._path(tmp_path).exists()

    def test_a_store_that_refuses_the_write_is_named_and_leaves_no_row(self, tmp_path):
        vault = _MemoryVault(fail_writes=True)
        with pytest.raises(ActRefused) as e:
            apply_set(self._path(tmp_path), _set_record(VALUE), VALUE, secret_source_factory=vault.factory)
        assert e.value.name == "value_store_failed"
        assert VALUE not in str(e.value) and e.value.__context__ is None
        assert not self._path(tmp_path).exists()

    def test_the_value_never_reaches_a_log(self, tmp_path, caplog):
        caplog.set_level(logging.DEBUG)
        vault = _MemoryVault()
        apply_set(self._path(tmp_path), _set_record(VALUE), VALUE, secret_source_factory=vault.factory)
        for bad in (OTHER, "", 9):
            with pytest.raises(ActRefused):
                apply_set(self._path(tmp_path), _set_record(VALUE), bad, secret_source_factory=vault.factory)
        assert VALUE not in caplog.text and OTHER not in caplog.text
        assert VALUE not in json.dumps([r.getMessage() for r in caplog.records])
