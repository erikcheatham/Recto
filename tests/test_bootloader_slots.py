"""THE SLOTS (2026-09-21, hard rule 14.4) -- two phones, not a list.

A bootloader holds a PRIMARY and a RECOVERY phone_ref. Pairing into an occupied slot is a
replacement question: the registry answers 409 slot_occupied with the occupant's model and
last-seen so the phone can ask the operator; the answer is the incoming IDENTITY key's
signature over `recto-slot-replace-v1|{slot}|{occupant ref}|{incoming pubkey}`; the occupant
is revoked in the same act the incoming key is recorded.

RED-BUILDS (the brief's): a third key cannot pair without displacing one; a displaced key's
queue reads empty (here: the displaced key is unknown to the registry at all -- stronger).
POSITIVE CONTROLS: two keys fill two slots; the same key re-pairing into its own slot is not
a replacement (P1's merge, unchanged); a claim by the wrong key, or over the wrong occupant,
is refused and displaces nobody.
"""

from __future__ import annotations

import base64
import json
import threading
import time
from pathlib import Path
from typing import Any
from urllib import request as urlrequest
from urllib.error import HTTPError

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from recto.bootloader.server import (
    POLL_SIG_HEADER,
    POLL_SIG_PREFIX,
    POLL_SIG_TS_HEADER,
    ChallengeStore,
    create_server,
    poll_key_delegation_payload,
    slot_replace_payload,
)
from recto.bootloader.state import PendingRequest, StateStore, phone_ref_of


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _key() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return key, _b64u(pub)


def _http(method: str, url: str, body: dict[str, Any] | None = None,
          headers: dict[str, str] | None = None) -> tuple[int, dict[str, Any]]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urlrequest.Request(url, data=data, headers={"Content-Type": "application/json", **(headers or {})},
                             method=method)
    try:
        with urlrequest.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8") or "{}")
    except HTTPError as exc:
        raw = exc.read().decode("utf-8")
        try:
            return exc.code, json.loads(raw or "{}")
        except json.JSONDecodeError:
            return exc.code, {"raw": raw}


@pytest.fixture
def ctx(tmp_path: Path):
    state = StateStore(state_dir=tmp_path)
    challenges = ChallengeStore(state=state)
    server = create_server(
        bind_host="127.0.0.1", bind_port=0, state=state, bootloader_id="slots-test",
        challenges=challenges, ssl_context=None, signed_poll_mode="required",
    )
    host, port = server.server_address
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield {"base_url": f"http://{host}:{port}", "state": state, "challenges": challenges}
    finally:
        server.shutdown()


class Phone:
    """An identity key + a delegated poll key, able to register into a slot."""

    def __init__(self, label: str):
        self.label = label
        self.identity, self.pub = _key()
        self.poll, self.poll_pub = _key()
        self.ref = phone_ref_of(self.pub)

    def register(self, ctx, slot: str = "primary", *, replace: str | None = None,
                 replace_signer: Ed25519PrivateKey | None = None,
                 challenge: str | None = None) -> tuple[int, dict[str, Any]]:
        if challenge is None:
            code, _ = ctx["challenges"].issue_pairing_code()
            status, chal = _http("GET", f"{ctx['base_url']}/v0.4/registration_challenge?code={code}")
            assert status == 200, chal
            challenge = chal["challenge_b64u"]
        self.last_challenge = challenge
        body: dict[str, Any] = {
            "device_label": self.label,
            "public_key_b64u": self.pub,
            "supported_algorithms": ["ed25519"],
            "v0_4_protocol": 1,
            "slot": slot,
            "registration_proof": {
                "challenge": challenge,
                "signature_b64u": _b64u(self.identity.sign(challenge.encode("ascii"))),
            },
            "poll_public_key_b64u": self.poll_pub,
            "poll_key_delegation_b64u": _b64u(self.identity.sign(
                poll_key_delegation_payload(self.pub, self.poll_pub))),
        }
        if replace is not None:
            signer = replace_signer or self.identity
            body["slot_replace_b64u"] = _b64u(signer.sign(slot_replace_payload(slot, replace, self.pub)))
        return _http("POST", f"{ctx['base_url']}/v0.4/register", body)

    def read_pending(self, ctx) -> tuple[int, dict[str, Any]]:
        path = "/v0.4/pending"
        ts = int(time.time())
        sig = self.poll.sign(f"{POLL_SIG_PREFIX}|{self.ref}|{ts}|{path}".encode("ascii"))
        return _http("GET", f"{ctx['base_url']}{path}?phone_id={self.ref}",
                     headers={POLL_SIG_HEADER: _b64u(sig), POLL_SIG_TS_HEADER: str(ts)})


def _queue_card(ctx, phone_ref: str) -> None:
    """A card in the occupant's queue, seeded through the store (the shape of the
    request is not what this suite tests; that it is GONE after displacement is)."""
    ctx["state"].add_pending(PendingRequest.new(
        kind="secret.read", service="svc", secret="key", phone_id=phone_ref,
        operation_description="slots test", payload_hash_b64u="AAAA",
        child_pid=1, child_argv0="test",
    ))


# --------------------------------------------------------------------------
# positive controls
# --------------------------------------------------------------------------

def test_two_keys_fill_the_two_slots(ctx):
    a, b = Phone("pixel"), Phone("iphone")
    s1, r1 = a.register(ctx, "primary")
    s2, r2 = b.register(ctx, "recovery")
    assert (s1, s2) == (201, 201), (r1, r2)
    assert r1["slot"] == "primary" and r2["slot"] == "recovery"
    assert {p.slot for p in ctx["state"].list_phones()} == {"primary", "recovery"}


def test_the_same_key_re_pairing_into_its_own_slot_is_not_a_replacement(ctx):
    a = Phone("pixel")
    assert a.register(ctx)[0] == 201
    status, body = a.register(ctx)  # unpair + re-pair, or a store re-verify
    assert status == 201, body
    assert "displaced_phone_ref" not in body
    assert len(ctx["state"].list_phones()) == 1


def test_an_unknown_slot_is_refused(ctx):
    status, body = Phone("pixel").register(ctx, "tertiary")
    assert status >= 400, body


# --------------------------------------------------------------------------
# RED-BUILD 1: a third key cannot pair without displacing one
# --------------------------------------------------------------------------

def test_a_third_key_cannot_pair_without_displacing_one(ctx):
    """RED-BUILD: drop the occupancy check and a third phone quietly joins a list."""
    a, b, c = Phone("pixel"), Phone("iphone"), Phone("stranger")
    assert a.register(ctx, "primary")[0] == 201
    assert b.register(ctx, "recovery")[0] == 201

    for slot in ("primary", "recovery"):
        status, body = c.register(ctx, slot)
        assert status == 409, body
        assert body["error"] == "slot_occupied"
        assert body["slot"] == slot
    assert len(ctx["state"].list_phones()) == 2, "a third key is in the registry"
    assert ctx["state"].get_phone(c.ref) is None


def test_the_replacement_question_names_the_occupant(ctx):
    a, c = Phone("pixel 9 pro"), Phone("pixel 10")
    assert a.register(ctx, "primary")[0] == 201
    status, body = c.register(ctx, "primary")
    assert status == 409
    occ = body["occupant"]
    assert occ["phone_ref"] == a.ref
    assert occ["device_label"] == "pixel 9 pro"
    assert isinstance(occ["last_seen_unix"], int)


# --------------------------------------------------------------------------
# RED-BUILD 2: the answer displaces, in the same act; the displaced key reads nothing
# --------------------------------------------------------------------------

def test_a_signed_replacement_displaces_the_occupant_in_the_same_act(ctx):
    a, c = Phone("pixel 9 pro"), Phone("pixel 10")
    assert a.register(ctx, "primary")[0] == 201
    _queue_card(ctx, a.ref)
    assert a.read_pending(ctx)[1]["requests"], "the occupant had a card before displacement"

    # ONE pairing code: the question (409) leaves the challenge intact and the
    # answer rides the same one. A second code would mean the operator's
    # authority was spent on the question rather than the displacement.
    status, body = c.register(ctx, "primary")
    assert status == 409, body
    status, body = c.register(ctx, "primary", replace=a.ref, challenge=c.last_challenge)
    assert status == 201, body
    assert body["displaced_phone_ref"] == a.ref
    assert body["slot"] == "primary"

    phones = ctx["state"].list_phones()
    assert [p.phone_id for p in phones] == [c.ref], "two keys hold one slot, or the occupant survived"

    # RED-BUILD: the displaced key's queue reads EMPTY -- here, the displaced
    # key is not a phone this registry knows at all.
    status, body = a.read_pending(ctx)
    assert status != 200, body
    assert not body.get("requests")
    assert ctx["state"].list_pending_for_phone(a.ref) == []


def test_a_replacement_signed_by_the_wrong_key_displaces_nobody(ctx):
    a, c = Phone("pixel"), Phone("stranger")
    stranger_signer, _ = _key()
    assert a.register(ctx, "primary")[0] == 201
    status, body = c.register(ctx, "primary", replace=a.ref, replace_signer=stranger_signer)
    assert status >= 400, body
    assert [p.phone_id for p in ctx["state"].list_phones()] == [a.ref]


def test_a_replacement_over_the_wrong_occupant_displaces_nobody(ctx):
    a, b, c = Phone("pixel"), Phone("iphone"), Phone("stranger")
    assert a.register(ctx, "primary")[0] == 201
    assert b.register(ctx, "recovery")[0] == 201
    # claims to replace b, but into a's slot: the payload names the wrong occupant
    status, body = c.register(ctx, "primary", replace=b.ref)
    assert status >= 400, body
    assert {p.phone_id for p in ctx["state"].list_phones()} == {a.ref, b.ref}


def test_manage_phones_rows_carry_the_slot(ctx):
    a, b = Phone("pixel"), Phone("iphone")
    assert a.register(ctx, "primary")[0] == 201
    assert b.register(ctx, "recovery")[0] == 201
    path = "/v0.4/manage/phones"
    ts = int(time.time())
    sig = a.poll.sign(f"{POLL_SIG_PREFIX}|{a.ref}|{ts}|{path}".encode("ascii"))
    status, body = _http("GET", f"{ctx['base_url']}{path}?phone_id={a.ref}",
                         headers={POLL_SIG_HEADER: _b64u(sig), POLL_SIG_TS_HEADER: str(ts)})
    assert status == 200, body
    assert [(r["phone_ref"], r["slot"]) for r in body["phones"]] == [(b.ref, "recovery")]
