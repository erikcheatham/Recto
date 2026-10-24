"""Phone-signed vault SET through ``POST /v0.4/connections/act``.

The body is ``{jws, record, value}``: the record (signed, carded) carries the
value's SHA-256, the value rides beside it, and the bootloader stores the
value only when its digest is the signed one. A set is one ordinary card:
single use, no operator token, the purpose naming the service, the key and
the first 12 hex of the value's digest. The value is never logged, never
echoed and never in a refusal.

Shares the live-bootloader fixture and grant helpers with
``tests/test_bootloader_connections_act.py``.
"""

# The shared fixtures are imported by name, and each test takes them as arguments.
# ruff: noqa: F811

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import asdict
from typing import Any

import pytest

import tests.test_bootloader_connections_act as phase1
from recto.connections.act_record import ActRecord
from recto.connections.act_set import VALUE_MAX_BYTES
from recto.connections.manage import get_connection_secret
from recto.secrets.base import SecretSourceError
from tests.test_bootloader_connections_act import (  # noqa: F401 - fixtures are found by name
    AGENT_HDR,
    SERVICE,
    _claims,
    _http,
    _mint,
    _record,
    _rows,
    boot,
    operator_keypair,
)

STORED = phase1.VALUE  # what the fixture seeded alpha and beta with
NEW = "fake-rotated-value-for-tests-91d2"
WRONG = "fake-wrong-value-for-tests-5ab0"
_ABSENT = object()


def _set_record(key: str = "alpha", value: str = NEW, *, not_after: int | None = None) -> ActRecord:
    return ActRecord(bootloader_id=phase1.BOOTLOADER_ID, service=SERVICE, key=key, verb="set",
                     not_after=not_after if not_after is not None else int(time.time()) + 240,
                     value_sha256=hashlib.sha256(value.encode("utf-8")).hexdigest())


def _act(ctx, record: ActRecord, jws: str, value: Any = _ABSENT):
    body: dict[str, Any] = {"jws": jws, "record": record.to_dict()}
    if value is not _ABSENT:
        body["value"] = value
    return _http(f"{ctx['base']}/v0.4/connections/act", body)


def _stored(ctx, key: str) -> str | None:
    return ctx["vault"].data.get((SERVICE, f"conn.{key}"))


class TestSetAtTheActRoute:
    def test_a_good_set_stores_once_and_its_second_presentation_is_replayed(self, boot):
        record = _set_record("alpha", NEW)
        jws = _mint(_claims(record), boot["priv"])
        status, body = _act(boot, record, jws, NEW)
        assert status == 200, body
        assert body["verb"] == "set" and body["connection"]["key"] == "alpha" and body["connection"]["has_secret"]
        assert _stored(boot, "alpha") == NEW
        # What the agent read path serves (the same store call /v0.4/connections/secret makes).
        assert get_connection_secret(SERVICE, "alpha", secret_source_factory=boot["vault"].factory) == NEW
        status, body = _act(boot, record, jws, NEW)
        assert (status, body["error"]) == (403, "grant_replayed")
        assert _stored(boot, "alpha") == NEW

    def test_a_set_adds_a_key_that_did_not_exist(self, boot):
        record = _set_record("gamma", NEW)
        status, body = _act(boot, record, _mint(_claims(record), boot["priv"]), NEW)
        assert status == 200, body
        row = _rows(boot)["gamma"]
        assert (row["display_name"], row["category"], row["enabled"], row["has_secret"]) == (
            "gamma", "uncategorized", True, True)
        assert _stored(boot, "gamma") == NEW

    def test_a_set_writes_the_value_and_leaves_the_rows_flags(self, boot):
        off = _record("disable", "alpha")
        assert phase1._act(boot, off, _mint(_claims(off), boot["priv"]))[0] == 200
        record = _set_record("alpha", NEW)
        status, body = _act(boot, record, _mint(_claims(record), boot["priv"]), NEW)
        assert status == 200 and body["connection"]["enabled"] is False
        assert _stored(boot, "alpha") == NEW

    def test_a_padded_value_is_stored_byte_exact_through_the_route(self, boot):
        padded = " fake-padded-value-for-tests-3e7a\t "
        record = _set_record("alpha", padded)
        status, body = _act(boot, record, _mint(_claims(record), boot["priv"]), padded)
        assert status == 200, body
        assert _stored(boot, "alpha") == padded, "never trimmed between the JSON body and the store"

    def test_a_mismatched_value_stores_nothing_and_the_grant_is_spent(self, boot):
        record = _set_record("alpha", NEW)
        jws = _mint(_claims(record), boot["priv"])
        status, body = _act(boot, record, jws, WRONG)
        assert (status, body["error"]) == (403, "value_fingerprint_mismatch")
        assert _stored(boot, "alpha") == STORED
        status, body = _act(boot, record, jws, NEW)
        assert (status, body["error"]) == (403, "grant_replayed"), "a refused set is never retried with the same card"
        assert _stored(boot, "alpha") == STORED

    @pytest.mark.parametrize("value, name", [
        (_ABSENT, "value_missing"),
        (None, "value_missing"),
        (12345, "value_not_string"),
        (["fake"], "value_not_string"),
        ("", "value_empty"),
        ("x" * (VALUE_MAX_BYTES + 1), "value_too_large"),
        ("fake-\ud800", "value_not_storable"),
    ], ids=["absent", "null", "int", "list", "empty", "oversize", "lone-surrogate"])
    def test_a_shapeless_value_is_refused_by_name_and_stores_nothing(self, boot, value, name):
        record = _set_record("alpha", NEW)
        status, body = _act(boot, record, _mint(_claims(record), boot["priv"]), value)
        assert (status, body["error"]) == (403, name), body
        assert _stored(boot, "alpha") == STORED and "gamma" not in _rows(boot)

    @pytest.mark.parametrize("verb", ["enable", "disable", "delete"])
    def test_a_value_beside_any_other_verb_is_refused_and_nothing_changes(self, boot, verb):
        record = _record(verb, "beta")
        status, body = phase1._http(f"{boot['base']}/v0.4/connections/act",
                                    {"jws": _mint(_claims(record), boot["priv"]), "record": record.to_dict(),
                                     "value": NEW})
        assert (status, body["error"]) == (403, "value_not_admitted")
        assert _rows(boot)["beta"]["enabled"] is True and _stored(boot, "beta") == STORED

    def test_a_record_carrying_another_digest_than_the_signed_one_is_a_payload_mismatch(self, boot):
        signed = _set_record("alpha", NEW)
        jws = _mint(_claims(signed), boot["priv"])
        swapped = _set_record("alpha", WRONG, not_after=signed.not_after)
        status, body = _act(boot, swapped, jws, WRONG)
        assert (status, body["error"]) == (403, "payload_mismatch")
        assert _stored(boot, "alpha") == STORED

    @pytest.mark.parametrize("key", ["alpha", "gamma"])
    def test_a_store_that_refuses_the_write_is_named_and_the_grant_is_spent(self, boot, monkeypatch, caplog, capsys,
                                                                           key):
        caplog.set_level(logging.DEBUG)

        def _refuse(self, secret_name: str, value: str, comment: str = "") -> None:
            raise SecretSourceError("the test backend refuses every write")

        monkeypatch.setattr(phase1._MemorySource, "write", _refuse)
        before = _rows(boot)
        record = _set_record(key, NEW)
        jws = _mint(_claims(record), boot["priv"])
        answers = [_act(boot, record, jws, NEW)]
        assert (answers[0][0], answers[0][1]["error"]) == (403, "value_store_failed"), answers[0]
        assert _rows(boot) == before, "a refused write adds or changes no row"
        assert _stored(boot, key) == (STORED if key == "alpha" else None)
        answers.append(_act(boot, record, jws, NEW))
        assert (answers[1][0], answers[1][1]["error"]) == (403, "grant_replayed")
        out = capsys.readouterr()
        seen = "\n".join([caplog.text, out.out, out.err, json.dumps(answers)])
        assert NEW not in seen and STORED not in seen, "a value leaked"
        assert "connections act REFUSED value_store_failed" in caplog.text
        assert "Traceback" not in out.out + out.err

    def test_an_os_error_in_the_store_is_the_generic_failure_and_leaks_no_value(self, boot, monkeypatch, caplog,
                                                                                capsys):
        # A bare OSError is never named value_store_failed: inside the store it can also come from saving the row,
        # after the vault already holds the new value, so the act may have landed. It stays the generic 500.
        caplog.set_level(logging.DEBUG)

        def _fail(self, secret_name: str, value: str, comment: str = "") -> None:
            raise PermissionError(13, "the test backend is read-only")

        monkeypatch.setattr(phase1._MemorySource, "write", _fail)
        record = _set_record("alpha", NEW)
        jws = _mint(_claims(record), boot["priv"])
        answers = [_act(boot, record, jws, NEW), _act(boot, record, jws, NEW)]
        assert (answers[0][0], answers[0][1]["error"]) == (500, "internal"), answers[0]
        assert (answers[1][0], answers[1][1]["error"]) == (403, "grant_replayed"), "the grant is spent before the store"
        assert _stored(boot, "alpha") == STORED
        out = capsys.readouterr()
        seen = "\n".join([caplog.text, out.out, out.err, json.dumps(answers)])
        assert NEW not in seen and STORED not in seen, "a value leaked"

    def test_an_operator_token_is_no_authority_for_a_set(self, boot):
        record = _set_record("alpha", NEW)
        status, _ = _http(f"{boot['base']}/v0.4/connections/act", {"record": record.to_dict(), "value": NEW},
                          {"X-Recto-Operator-Token": phase1.OPERATOR_TOKEN})
        assert status == 400
        assert _stored(boot, "alpha") == STORED

    def test_the_value_never_appears_in_the_log_the_output_or_an_answer(self, boot, caplog, capsys):
        caplog.set_level(logging.DEBUG)
        answers = []
        good = _set_record("alpha", NEW)
        answers.append(_act(boot, good, _mint(_claims(good), boot["priv"]), NEW))
        assert answers[-1][0] == 200
        for value in (WRONG, "", 7, "x" * (VALUE_MAX_BYTES + 1), "fake-\udfff"):
            r = _set_record("beta", NEW)
            answers.append(_act(boot, r, _mint(_claims(r), boot["priv"]), value))
        d = _record("delete", "beta")
        answers.append(phase1._http(f"{boot['base']}/v0.4/connections/act",
                                    {"jws": _mint(_claims(d), boot["priv"]), "record": d.to_dict(), "value": WRONG}))
        out = capsys.readouterr()
        seen = "\n".join([caplog.text, out.out, out.err, json.dumps(answers)])
        for secret in (NEW, WRONG, STORED, "fake-"):
            assert secret not in seen, f"a value leaked: {secret[:5]}..."
        assert "connections act DONE" in caplog.text and "'set'" in caplog.text and "'alpha'" in caplog.text
        assert f"sha256:{good.value_sha256[:12]}" in caplog.text, "the audit line names the value by its fingerprint"
        assert good.value_sha256 not in caplog.text, "only the prefix the card shows"
        assert "connections act REFUSED value_fingerprint_mismatch" in caplog.text


class TestSetAtTheRequestRoute:
    def _request(self, boot, claims, record: ActRecord | dict, **extra: Any):
        body: dict[str, Any] = {"phone_id": boot["phone_id"], "claims": asdict(claims), "operation_description": "t",
                                "connections_act": record.to_dict() if isinstance(record, ActRecord) else record}
        body.update(extra)
        return _http(f"{boot['base']}/v0.4/capability/request", body, AGENT_HDR)

    def _queued(self, boot) -> int:
        return len(boot["state"].list_pending_for_phone(boot["phone_id"]))

    def test_a_set_is_carded_with_its_rendered_purpose_and_no_value(self, boot):
        record = _set_record("alpha", NEW)
        status, body = self._request(boot, _claims(record), record)
        assert status == 201, body
        assert self._queued(boot) == 1
        assert f"= sha256:{record.value_sha256[:12]}... on " in record.purpose()

    def test_a_set_purpose_without_the_fingerprint_is_refused_before_the_card(self, boot):
        record = _set_record("alpha", NEW)
        bare = record.purpose().replace(f" = sha256:{record.value_sha256[:12]}...", "")
        status, body = self._request(boot, _claims(record, purpose=bare), record)
        assert (status, body["error"]) == (403, "purpose_mismatch")
        assert self._queued(boot) == 0

    def test_a_set_record_without_its_digest_is_refused_before_the_card(self, boot):
        record = _set_record("alpha", NEW)
        d = {k: v for k, v in record.to_dict().items() if k != "value_sha256"}
        status, body = self._request(boot, _claims(record), d)
        assert (status, body["error"]) == (403, "record_field_empty")
        assert self._queued(boot) == 0
