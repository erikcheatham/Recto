"""Phone-signed connection acts (2026-10-15).

``POST /v0.4/connections/act`` enables, disables or deletes ONE connection on
an operator-signed grant, and ``POST /v0.4/capability/request`` cards a
``connections:*`` request only for the exact record it will act on. The
grant is the only authority on the act route: no operator token is read.

The card shows a grant's purpose (cut at 240 characters) and only a prefix
of ``cap.scope.payload_sha256``, so a connection act's purpose is the
record's own rendering and a grant whose purpose differs is refused. Its
window is never re-stamped at card-open (no ``grant_ttl_seconds``).
"""

from __future__ import annotations

import base64
import json
import logging
import threading
import time
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any
from urllib import request as urlrequest
from urllib.error import HTTPError

import pytest

from recto.bootloader.server import BootloaderHandler, ChallengeStore, create_server
from recto.bootloader.state import PhoneRegistration, StateStore
from recto.capability.jwt import build_signing_input
from recto.capability.types import CapabilityClaims, CapabilityClause, CapabilityLimits, CapabilityScope
from recto.connections.act_record import (
    ACT_WINDOW_SECONDS,
    PURPOSE_MAX_CHARS,
    ActRecord,
    ActRefused,
)
from recto.secrets.base import DirectSecret, SecretMaterial, SecretNotFoundError

VECTOR_ID = "rb1-0123456789abcdef0123456789abcdef"
# The live server derives its id from the operator key; the fixture reads it after spawn.
BOOTLOADER_ID = VECTOR_ID
SERVICE = "ServiceA"
VALUE = "never-print-this-value-3f9a"
OPERATOR_TOKEN = "op-root-token"
AGENT_HDR = {"X-Recto-Agent-Id": "web-agent", "X-Recto-Agent-Token": "web-tok"}


# -- the in-memory vault (the connections tests' double) ------------------------------------------------------------

class _MemoryVault:
    def __init__(self) -> None:
        self.data: dict[tuple[str, str], str] = {}

    def factory(self, service: str) -> "_MemorySource":
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
        self._vault.data[(self._service, secret_name)] = value

    def delete(self, secret_name: str) -> None:
        self._vault.data.pop((self._service, secret_name), None)


# -- keys and grants --------------------------------------------------------------------------------------------------

def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _keypair():
    pytest.importorskip("cryptography")
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import ec
    priv = ec.generate_private_key(ec.SECP256K1(), default_backend())
    nums = priv.public_key().public_numbers()
    return priv.private_numbers().private_value, nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")


@pytest.fixture(scope="session")
def operator_keypair():
    return _keypair()


@pytest.fixture(scope="session")
def other_keypair():
    return _keypair()


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


_JTI = [0]


def _record(verb: str = "disable", key: str = "alpha", *, not_after: int | None = None, service: str = SERVICE,
            bootloader_id: str | None = None) -> ActRecord:
    return ActRecord(bootloader_id=bootloader_id or BOOTLOADER_ID, service=service, key=key, verb=verb,
                     not_after=not_after if not_after is not None else int(time.time()) + 240)


def _claims(record: ActRecord, **over: Any) -> CapabilityClaims:
    """A grant for exactly ``record``; ``over`` breaks one thing at a time."""
    _JTI[0] += 1
    now = int(time.time())
    scope = CapabilityScope(services=[record.service], payload_sha256=record.fingerprint())
    cap = CapabilityClause(tier=2, registry_version="2026-10-15", scope=scope, allow_actions=[record.action],
                           limits=CapabilityLimits())
    claims = CapabilityClaims(
        iss="phone:operator:enclave", sub="agent:web-agent", aud=[BOOTLOADER_ID],
        iat=now,
        nbf=now - 5, exp=record.not_after, jti=f"act-test-{_JTI[0]}-{now}", cap=cap,
        purpose=record.purpose(), max_uses=1,
    )
    cap_over = {k[4:]: over.pop(k) for k in list(over) if k.startswith("cap_")}
    scope_over = {k[6:]: over.pop(k) for k in list(over) if k.startswith("scope_")}
    if scope_over:
        cap_over["scope"] = replace(claims.cap.scope, **scope_over)
    if cap_over:
        claims = replace(claims, cap=replace(claims.cap, **cap_over))
    return replace(claims, **over)


# -- the live bootloader ----------------------------------------------------------------------------------------------

def _http(url: str, body: dict | None = None, headers: dict | None = None):
    data = json.dumps(body).encode() if body is not None else None
    h = {"Content-Type": "application/json", **(headers or {})}
    req = urlrequest.Request(url, data=data, headers=h, method="POST" if body is not None else "GET")
    try:
        with urlrequest.urlopen(req, timeout=5.0) as resp:
            return resp.status, json.loads(resp.read().decode())
    except HTTPError as e:
        return e.code, json.loads(e.read().decode())


@pytest.fixture
def boot(tmp_path: Path, operator_keypair):
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    state = StateStore(state_dir=tmp_path)
    ed_pub = Ed25519PrivateKey.generate().public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    phone = PhoneRegistration.new(device_label="Test Phone", public_key_b64u=_b64u(ed_pub),
                                  supported_algorithms=("ed25519",))
    state.register_phone(phone)
    vault = _MemoryVault()
    made = []

    def spawn(**over: Any):
        kw: dict[str, Any] = dict(
            bind_host="127.0.0.1", bind_port=0, state=state, bootloader_id=BOOTLOADER_ID,
            challenges=ChallengeStore(), ssl_context=None,
            capability_operator_pubkey=operator_keypair[1],
            capability_operator_token=OPERATOR_TOKEN,
            capability_agent_tokens={"web-agent": "web-tok"},
            connections_path=str(tmp_path / "connections.json"),
            connections_agent_services={"web-agent": SERVICE},
            connections_secret_source_factory=vault.factory,
        )
        kw.update(over)
        server = create_server(**kw)
        host, port = server.server_address
        threading.Thread(target=server.serve_forever, daemon=True).start()
        made.append(server)
        return f"http://{host}:{port}"

    global BOOTLOADER_ID
    base = spawn()
    BOOTLOADER_ID = BootloaderHandler.config.bootloader_id
    for key in ("alpha", "beta"):
        status, _ = _http(f"{base}/v0.4/connections", {"service": SERVICE, "key": key, "secret": VALUE},
                          {"X-Recto-Operator-Token": OPERATOR_TOKEN})
        assert status == 200
    ctx = {"base": base, "spawn": spawn, "vault": vault, "state": state, "phone_id": phone.phone_id,
           "priv": operator_keypair[0], "tmp": tmp_path}
    yield ctx
    for server in made:
        server.shutdown()
        server.server_close()


def _rows(ctx) -> dict[str, dict]:
    status, body = _http(f"{ctx['base']}/v0.4/connections", None, AGENT_HDR)
    assert status == 200
    return {r["key"]: r for r in body["connections"]}


def _act(ctx, record: ActRecord | dict, jws: str):
    rec = record.to_dict() if isinstance(record, ActRecord) else record
    return _http(f"{ctx['base']}/v0.4/connections/act", {"jws": jws, "record": rec})


# -- the record -------------------------------------------------------------------------------------------------------

class TestActRecord:
    def test_the_fingerprint_is_the_sorted_compact_json_pinned_by_a_vector(self):
        r = ActRecord(bootloader_id=VECTOR_ID, service="ExampleService", key="example-key", verb="delete", not_after=1792050000)
        assert r.canonical_bytes() == (b'{"bootloader_id":"rb1-0123456789abcdef0123456789abcdef","key":"example-key",'
                                       b'"not_after":1792050000,"service":"ExampleService","verb":"delete"}')
        assert r.fingerprint() == __import__("hashlib").sha256(r.canonical_bytes()).hexdigest()
        assert r.purpose() == "Vault DELETE: ExampleService/example-key on rb1-0123456789abcdef0123456789abcdef - until 2026-10-15 07:40Z"

    @pytest.mark.parametrize("field, value, name", [
        ("key", "Alpha", "record_key_malformed"),
        ("key", " alpha", "record_field_empty"),
        ("verb", "set", "record_verb_unknown"),
        ("not_after", "1792050000", "record_not_after_malformed"),
        ("not_after", True, "record_not_after_malformed"),
        ("service", "", "record_field_empty"),
    ])
    def test_a_malformed_record_is_refused_by_name(self, field, value, name):
        d = _record().to_dict()
        d[field] = value
        with pytest.raises(ActRefused) as e:
            ActRecord.from_dict(d)
        assert e.value.name == name

    def test_an_unexpected_field_is_refused(self):
        d = {**_record().to_dict(), "enabled": True}
        with pytest.raises(ActRefused) as e:
            ActRecord.from_dict(d)
        assert e.value.name == "record_fields_unexpected"

    def test_a_purpose_past_what_the_card_shows_is_refused(self):
        with pytest.raises(ActRefused) as e:
            _record(service="S" * 200)
        assert e.value.name == "purpose_too_long"
        assert len(_record(service="S" * 100).purpose()) <= PURPOSE_MAX_CHARS


# -- the act route ----------------------------------------------------------------------------------------------------

class TestTheActRoute:
    def test_a_good_grant_disables_once_and_its_second_presentation_is_replayed(self, boot):
        record = _record("disable")
        jws = _mint(_claims(record), boot["priv"])
        status, body = _act(boot, record, jws)
        assert status == 200, body
        assert body["connection"]["enabled"] is False and body["verb"] == "disable"
        assert _rows(boot)["alpha"]["enabled"] is False
        status, body = _act(boot, record, jws)
        assert (status, body["error"]) == (403, "grant_replayed")

    def test_enable_turns_it_back_on(self, boot):
        off = _record("disable")
        assert _act(boot, off, _mint(_claims(off), boot["priv"]))[0] == 200
        on = _record("enable")
        status, body = _act(boot, on, _mint(_claims(on), boot["priv"]))
        assert status == 200 and body["connection"]["enabled"] is True

    def test_delete_removes_the_row_and_the_value(self, boot):
        record = _record("delete", "beta")
        status, body = _act(boot, record, _mint(_claims(record), boot["priv"]))
        assert status == 200 and body["deleted"] is True
        assert "beta" not in _rows(boot)
        assert len(boot["vault"].data) == 1, "the value went with the row; alpha's stays"
        assert "alpha" in _rows(boot), "only the named row goes"

    def test_a_grant_signed_by_another_key_is_refused(self, boot, other_keypair):
        record = _record()
        status, body = _act(boot, record, _mint(_claims(record), other_keypair[0]))
        assert (status, body["error"]) == (403, "grant_signature_invalid")
        assert _rows(boot)["alpha"]["enabled"] is True

    @pytest.mark.parametrize("over", [
        {"aud": ["another-bootloader"]},
        {"exp": int(time.time()) - 10, "iat": int(time.time()) - 100},
        {"nbf": int(time.time()) + 600},
    ], ids=["wrong-audience", "expired", "not-yet-valid"])
    def test_a_grant_outside_its_audience_or_window_is_refused_at_the_signature(self, boot, over):
        record = _record() if "exp" not in over else _record(not_after=over["exp"])
        status, body = _act(boot, record, _mint(_claims(record, **over), boot["priv"]))
        assert (status, body["error"]) == (403, "grant_signature_invalid")
        assert _rows(boot)["alpha"]["enabled"] is True

    @pytest.mark.parametrize("over, name", [
        ({"max_uses": None}, "not_single_use"),
        ({"max_uses": 2}, "not_single_use"),
        ({"cap_allow_actions": ["connections:disable", "connections:delete"]}, "action_not_admitted"),
        ({"cap_allow_actions": ["secret:rotate"]}, "action_not_admitted"),
        ({"cap_deny_actions": ["connections:delete"]}, "action_not_admitted"),
        ({"cap_groups": ["darwin:secret-reads"]}, "groups_not_admitted"),
        ({"cap_allow_actions": ["connections:delete"]}, "tuple_mismatch"),
        ({"purpose": None}, "purpose_mismatch"),
        ({"scope_services": ["ServiceB"]}, "scope_service_denied"),
        ({"scope_services": [SERVICE, "ServiceB"]}, "scope_service_denied"),
        ({"scope_repos": ["any"]}, "scope_not_admitted"),
        ({"scope_payload_sha256": "0" * 64}, "payload_mismatch"),
        ({"iat": None}, "window_exceeds_ceiling"),
    ])
    def test_each_broken_field_is_refused_by_name_and_the_grant_is_spent(self, boot, over, name):
        record = _record()
        if over.get("purpose", 1) is None:
            over["purpose"] = record.purpose()[:-1] + ("X" if record.purpose()[-1] != "X" else "Y")
        if over.get("iat", 1) is None:
            over["iat"] = record.not_after - ACT_WINDOW_SECONDS - 1
        claims = _claims(record, **over)
        jws = _mint(claims, boot["priv"])
        status, body = _act(boot, record, jws)
        assert (status, body["error"]) == (403, name), body
        assert _rows(boot)["alpha"]["enabled"] is True
        assert boot["state"].is_revoked(claims.jti), "a refused grant is dead too"
        assert _act(boot, record, jws)[1]["error"] == "grant_replayed"

    def test_a_record_that_differs_from_the_signed_one_is_refused(self, boot):
        signed = _record("disable", "alpha")
        jws = _mint(_claims(signed), boot["priv"])
        swapped = _record("disable", "beta", not_after=signed.not_after)
        status, body = _act(boot, swapped, jws)
        assert (status, body["error"]) == (403, "payload_mismatch")
        rows = _rows(boot)
        assert rows["alpha"]["enabled"] is True and rows["beta"]["enabled"] is True

    @pytest.mark.parametrize("change", ["bootloader_id", "not_after"])
    def test_a_record_naming_another_bootloader_or_window_is_a_tuple_mismatch(self, boot, change):
        record = _record()
        claims = _claims(record)
        jws = _mint(claims, boot["priv"])
        d = record.to_dict()
        d[change] = "rb1-ffffffffffffffffffffffffffffffff" if change == "bootloader_id" else record.not_after - 1
        status, body = _act(boot, d, jws)
        assert (status, body["error"]) == (403, "tuple_mismatch")

    def test_an_unknown_key_acts_on_nothing_and_creates_nothing(self, boot):
        record = _record("enable", "gamma")
        status, body = _act(boot, record, _mint(_claims(record), boot["priv"]))
        assert (status, body["error"]) == (404, "connection_not_found")
        assert "gamma" not in _rows(boot)

    def test_an_operator_token_is_no_authority_here(self, boot):
        record = _record()
        status, _ = _http(f"{boot['base']}/v0.4/connections/act", {"record": record.to_dict()},
                          {"X-Recto-Operator-Token": OPERATOR_TOKEN})
        assert status == 400
        assert _rows(boot)["alpha"]["enabled"] is True

    def test_the_route_is_off_without_connections_and_refuses_without_an_operator_key(self, boot, tmp_path):
        # create_server writes the handler's class-level config, so these spawns run last in the test.
        base = boot["spawn"](connections_path=None)
        assert _http(f"{base}/v0.4/connections/act", {"jws": "x", "record": {}})[1]["error"] == "unknown_endpoint"
        base = boot["spawn"](capability_operator_pubkey=None)
        status, body = _http(f"{base}/v0.4/connections/act", {"jws": "x", "record": {}})
        assert (status, body["error"]) == (503, "operator_pubkey_not_configured")

    def test_the_log_names_the_act_and_never_the_value(self, boot, caplog):
        caplog.set_level(logging.INFO, logger="recto.bootloader.connections")
        record = _record("delete", "alpha")
        assert _act(boot, record, _mint(_claims(record), boot["priv"]))[0] == 200
        bad = _record("disable", "beta")
        _act(boot, bad, _mint(_claims(bad, max_uses=None), boot["priv"]))
        text = caplog.text
        assert "connections act DONE" in text and "'delete'" in text and "'alpha'" in text
        assert "connections act REFUSED not_single_use" in text
        assert VALUE not in text


# -- the request route ------------------------------------------------------------------------------------------------

class TestTheRequestRoute:
    def _request(self, boot, claims: CapabilityClaims, record: ActRecord | dict | None, **extra: Any):
        body: dict[str, Any] = {"phone_id": boot["phone_id"], "claims": asdict(claims), "operation_description": "t"}
        if record is not None:
            body["connections_act"] = record.to_dict() if isinstance(record, ActRecord) else record
        body.update(extra)
        return _http(f"{boot['base']}/v0.4/capability/request", body, AGENT_HDR)

    def _queued(self, boot) -> int:
        return len(boot["state"].list_pending_for_phone(boot["phone_id"]))

    def test_a_matching_request_is_carded(self, boot):
        record = _record()
        status, body = self._request(boot, _claims(record), record)
        assert status == 201, body
        assert self._queued(boot) == 1

    def test_a_grant_window_to_restamp_is_refused(self, boot):
        record = _record()
        status, body = self._request(boot, _claims(record), record, grant_ttl_seconds=120)
        assert (status, body["error"]) == (403, "grant_ttl_not_admitted")
        assert self._queued(boot) == 0

    def test_a_connections_request_without_its_record_is_refused(self, boot):
        status, body = self._request(boot, _claims(_record()), None)
        assert (status, body["error"]) == (403, "act_record_required")
        assert self._queued(boot) == 0

    def test_a_record_on_another_action_is_refused(self, boot):
        record = _record()
        status, body = self._request(boot, _claims(record, cap_allow_actions=["page:update"]), record)
        assert (status, body["error"]) == (403, "action_not_admitted")

    def test_a_purpose_that_is_not_the_records_rendering_is_refused_before_the_card(self, boot):
        record = _record("delete", "alpha")
        lie = _claims(record, purpose=record.purpose().replace("alpha", "beta"))
        status, body = self._request(boot, lie, record)
        assert (status, body["error"]) == (403, "purpose_mismatch")
        assert self._queued(boot) == 0

    def test_a_purpose_longer_than_the_card_shows_is_refused(self, boot):
        d = {**_record().to_dict(), "service": "S" * 200}
        status, body = self._request(boot, _claims(_record()), d)
        assert (status, body["error"]) == (403, "purpose_too_long")

    def test_a_closed_window_is_refused(self, boot):
        record = _record(not_after=int(time.time()) - 1)
        status, body = self._request(boot, _claims(record, iat=record.not_after - 60), record)
        assert (status, body["error"]) == (403, "expired")


# -- the sample manifest ----------------------------------------------------------------------------------------------

def test_the_sample_manifest_carries_the_three_acts_inside_tier_two():
    from recto.capability.manifest import load_manifest
    from recto.capability.types import TIER_WEIGHT_CEILINGS
    from recto.connections.act_record import ACT_ACTIONS
    m = load_manifest(Path(__file__).parent.parent / "recto" / "capability" / "manifest_v1.json")
    for action in ACT_ACTIONS.values():
        assert action in m.actions, f"a consumer forking the sample would see {action} refused by name"
        assert TIER_WEIGHT_CEILINGS[1] < m.actions[action].count <= TIER_WEIGHT_CEILINGS[2]
    assert m.actions["connections:enable"].count < m.actions["connections:disable"].count < m.actions["connections:delete"].count
    assert not any(a.startswith("connections:") for g in m.groups.values() for a in g.actions), "no group carries an act"
