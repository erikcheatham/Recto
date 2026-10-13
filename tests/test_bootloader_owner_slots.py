"""THE OWNER SLOTS (hard rule 14.4, amended) -- a code is not enough to become an owner.

The two slots are the business owner's phones. Before this suite a pairing code was the only
authority for an owner slot, and the code was optional: a challenge fetched with NO code bought
the same owner challenge a code buys, the slot question named the occupant to anyone who asked,
and the replace claim was signed by the INCOMING key. A stranger who reached /v0.4 could put a key
it made itself into either slot, displace the owner's phones, and keep them off.

THE SHAPE THESE TESTS PIN:
  - three challenge kinds: PLAIN (no code; revoke only), OWNER (an owner code), MEMBER (a member
    code). A plain challenge never registers. The slot question comes only after the challenge,
    the proof and the poll delegation verify.
  - GENESIS: while owner genesis is open, an owner code alone enrolls the first owner. Once
    it is closed, an owner key enters an owner slot only with the approval of an owner phone
    it does not displace (or, with no other owner, the occupant's approval of its own replacement):
    pass 1 raises a card on the approver naming the incoming key's ref, the operator approves on
    that phone, pass 2 with a fresh code enrolls. The approval binds the key, the slot, the
    approver and the occupant. A slot two keys contend for is refused for both.
  - the same key re-pairs into the slot it holds by code alone; a member key never enters an owner
    slot; a member revokes only itself and lists no business phone; the last owner phone is never
    revoked (the host reset is the path for a lost sole phone).
  - the push-token update never re-inserts a removed phone; the slot claim is atomic.
  - only a flagged agent mints owner codes; wrong codes are limited per public client.
  - the host CLI: owner-slots (read-only) and owner-reset (refused while the server holds the store).

RED-BUILDS: run against the server before this change, the tests of the owner approval flow fail
there. A POSITIVE CONTROL that needs nothing new (the genesis enrollment, the 64-byte P-256 key)
passes there too, as do two limiter tests a server with no limiter meets, three guards the old
code meets by its own shape (the cross-revoke race, a same-key re-pair spending its challenge, and
an empty --expect, refused there as an unknown command), and the startup-code cases with genesis
open (the old runner and example print a code on every start).
"""

from __future__ import annotations

import base64
import errno
import http.client
import io
import json
import logging
import os
import subprocess
import sys
import threading
import time
import types
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

from recto.bootloader.server import BootloaderError, ChallengeStore, create_server, poll_key_delegation_payload
from recto.bootloader.state import MEMBER_SLOT, PhoneRegistration, StateStore

from tests.test_bootloader_slots import Phone, _http

REPO = Path(__file__).resolve().parents[1]
AGENT_ID = "consumer-agent"
AGENT_TOKEN = "consumer-token-fixture"
BRIDGE_ID = "console-bridge"
BRIDGE_TOKEN = "bridge-token-fixture"
CONSUMER = "https://consumer.example"


def _start(state_dir: Path, **kw: Any):
    state = StateStore(state_dir=state_dir)
    challenges = ChallengeStore(state=state)
    server = create_server(
        bind_host="127.0.0.1", bind_port=0, state=state, bootloader_id="owner-slots-test",
        challenges=challenges, ssl_context=None, signed_poll_mode=kw.pop("signed_poll_mode", "advisory"),
        capability_agent_tokens={AGENT_ID: AGENT_TOKEN, BRIDGE_ID: BRIDGE_TOKEN}, **kw,
    )
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, {"base_url": f"http://{host}:{port}", "state": state, "challenges": challenges,
                            "server": server}


def _stop(server, thread) -> None:
    server.shutdown()
    server.server_close()
    thread.join(timeout=5.0)


@contextmanager
def serving(state_dir: Path, **kw: Any):
    server, thread, c = _start(state_dir, **kw)
    try:
        yield c
    finally:
        _stop(server, thread)


@pytest.fixture
def ctx(tmp_path):
    with serving(tmp_path) as c:
        yield c


def _grouped(ref: str) -> str:
    h = ref[len("pk_"):]
    return "pk_" + " ".join(h[i:i + 4] for i in range(0, len(h), 4))


def _plain_challenge(ctx, query: str = "") -> str:
    status, chal = _http("GET", f"{ctx['base_url']}/v0.4/registration_challenge{query}")
    assert status == 200, chal
    return chal["challenge_b64u"]


def _owner_cards(cards: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [c for c in cards if c.get("kind") == "single_sign" and str(c.get("secret", "")).startswith("owner-slot:")]


def _signed_cards(ctx, phone: Phone) -> list[dict[str, Any]]:
    status, body = phone.read_pending(ctx)
    assert status == 200, body
    return body.get("requests", [])


def _approve(ctx, approver: Phone, card: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    raw = card["context"]["payload_hash_b64u"]
    digest = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    sig = base64.urlsafe_b64encode(approver.identity.sign(digest)).decode("ascii").rstrip("=")
    return _http("POST", f"{ctx['base_url']}/v0.4/respond/{card['request_id']}",
                 {"decision": "approved", "signature_b64u": sig})


def _enroll_genesis(ctx, phone: Phone, slot: str = "primary") -> None:
    status, body = phone.register(ctx, slot)
    assert status == 201, body


def _enroll_approved(ctx, phone: Phone, slot: str, approver: Phone, occupant: Phone | None = None) -> None:
    """Both passes, through the approver's signed queue."""
    status, body = phone.register(ctx, slot, replace=occupant.ref if occupant else None)
    if status == 409:
        status, body = phone.register(ctx, slot, replace=occupant.ref if occupant else body["occupant"]["phone_ref"],
                                      challenge=phone.last_challenge)
    assert status == 403 and body.get("error") == "owner_approval_required", body
    cards = _owner_cards(_signed_cards(ctx, approver))
    assert len(cards) == 1, cards
    status, resolved = _approve(ctx, approver, cards[0])
    assert status == 200, resolved
    status, body = phone.register(ctx, slot, replace=occupant.ref if occupant else None)
    assert status == 201, body


def _seed_owner(ctx, phone: Phone, slot: str) -> None:
    """An owner phone put in its slot through the store, not the HTTP flow - so a test whose subject is not the
    enrollment reds on its own guard on a server without the approval flow."""
    ctx["state"].register_phone(PhoneRegistration.new(
        device_label=phone.label, public_key_b64u=phone.pub, supported_algorithms=("ed25519",),
        poll_public_key_b64u=phone.poll_pub, slot=slot))


def _holders(ctx) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for p in ctx["state"].list_phones():
        out.setdefault(p.slot, []).append(p.phone_id)
    return out


def _revoke(ctx, revoker: Phone, target_ref: str) -> tuple[int, dict[str, Any]]:
    challenge = _plain_challenge(ctx)
    sig = base64.urlsafe_b64encode(revoker.identity.sign(f"{challenge}:{target_ref}".encode("ascii"))).decode(
        "ascii").rstrip("=")
    return _http("POST", f"{ctx['base_url']}/v0.4/manage/phones/revoke", {
        "revoker_phone_id": revoker.ref, "target_phone_id": target_ref,
        "challenge_b64u": challenge, "signature_b64u": sig})


def _member_challenge(ctx, user_id: str) -> str:
    status, minted = _http("POST", f"{ctx['base_url']}/v0.4/pairing/code",
                           {"member_of": {"consumer": CONSUMER, "user_id": user_id}},
                           headers={"X-Recto-Agent-Id": AGENT_ID, "X-Recto-Agent-Token": AGENT_TOKEN})
    assert status == 200, minted
    return _plain_challenge(ctx, f"?code={minted['code']}")


# --------------------------------------------------------------------------
# A challenge without a code never registers; nothing about the occupant before the checks
# --------------------------------------------------------------------------

def test_a_codeless_challenge_never_registers_an_owner_on_an_empty_bootloader(ctx) -> None:
    stranger = Phone("stranger")
    status, body = stranger.register(ctx, "primary", challenge=_plain_challenge(ctx))
    assert status == 400, body
    assert ctx["state"].list_phones() == []


def test_an_empty_code_parameter_buys_no_owner_challenge(ctx) -> None:
    stranger = Phone("stranger")
    status, body = stranger.register(ctx, "recovery", challenge=_plain_challenge(ctx, "?code="))
    assert status == 400, body
    assert ctx["state"].list_phones() == []


def test_a_codeless_challenge_never_displaces_an_owner_nor_learns_who_it_is(ctx) -> None:
    owner = Phone("owner")
    _enroll_genesis(ctx, owner)
    stranger = Phone("stranger")
    status, body = stranger.register(ctx, "primary", challenge=_plain_challenge(ctx))
    assert status == 400, body
    assert "occupant" not in body and owner.ref not in str(body)
    status, body = stranger.register(ctx, "primary", replace=owner.ref, challenge=_plain_challenge(ctx))
    assert status == 400, body
    assert _holders(ctx) == {"primary": [owner.ref]}


def test_a_made_up_challenge_learns_nothing_about_the_occupant(ctx) -> None:
    owner = Phone("owner")
    _enroll_genesis(ctx, owner)
    stranger = Phone("stranger")
    status, body = stranger.register(ctx, "primary", challenge="bm90LWEtY2hhbGxlbmdl")
    assert status == 400, body
    assert "occupant" not in body and owner.ref not in str(body)


# --------------------------------------------------------------------------
# Genesis, then the other owner phone's approval
# --------------------------------------------------------------------------

def test_genesis_the_first_owner_enrolls_by_code_alone(ctx) -> None:
    """POSITIVE CONTROL."""
    owner = Phone("owner")
    _enroll_genesis(ctx, owner, "primary")
    assert _holders(ctx) == {"primary": [owner.ref]}


def test_a_second_owner_needs_the_other_phones_approval(ctx) -> None:
    owner = Phone("owner")
    _enroll_genesis(ctx, owner)
    newcomer = Phone("newcomer")
    status, body = newcomer.register(ctx, "recovery")
    assert status == 403, body
    assert body.get("error") == "owner_approval_required"
    assert body.get("phone_ref") == newcomer.ref
    assert body.get("detail", "").startswith(f"This phone is {_grouped(newcomer.ref)}"), body
    assert _holders(ctx) == {"primary": [owner.ref]}


def test_the_card_names_the_same_ref_and_only_a_signed_read_sees_it(ctx) -> None:
    owner = Phone("owner")
    _enroll_genesis(ctx, owner)
    newcomer = Phone("newcomer")
    assert newcomer.register(ctx, "recovery")[0] == 403
    cards = _owner_cards(_signed_cards(ctx, owner))
    assert len(cards) == 1, cards
    text = cards[0]["context"]["operation_description"]
    assert text.startswith(_grouped(newcomer.ref)), cards[0]
    assert newcomer.label not in text
    assert "The slot is empty." in text and "REMOVES" not in text, text
    status, unsigned = _http("GET", f"{ctx['base_url']}/v0.4/pending?phone_id={owner.ref}")
    assert status == 200, unsigned
    assert _owner_cards(unsigned.get("requests", [])) == [], "an unsigned read served the owner-enroll card"


def test_two_passes_enroll_the_approved_key(ctx) -> None:
    owner = Phone("owner")
    _enroll_genesis(ctx, owner)
    newcomer = Phone("newcomer")
    _enroll_approved(ctx, newcomer, "recovery", approver=owner)
    assert _holders(ctx) == {"primary": [owner.ref], "recovery": [newcomer.ref]}


def test_a_respond_that_does_not_verify_leaves_the_card(ctx) -> None:
    owner = Phone("owner")
    _enroll_genesis(ctx, owner)
    newcomer = Phone("newcomer")
    assert newcomer.register(ctx, "recovery")[0] == 403
    card = _owner_cards(_signed_cards(ctx, owner))[0]
    status, _ = _http("POST", f"{ctx['base_url']}/v0.4/respond/{card['request_id']}",
                      {"decision": "approved", "signature_b64u": "AAAA"})
    assert status != 200
    status, _ = _http("POST", f"{ctx['base_url']}/v0.4/respond/{card['request_id']}",
                      {"decision": "denied", "reason": "not me"})
    assert [c["request_id"] for c in _owner_cards(_signed_cards(ctx, owner))] == [card["request_id"]]
    assert _approve(ctx, owner, card)[0] == 200
    assert newcomer.register(ctx, "recovery")[0] == 201


def test_an_approval_for_the_empty_slot_never_displaces_the_owner(ctx) -> None:
    owner = Phone("owner")
    _enroll_genesis(ctx, owner)
    newcomer = Phone("newcomer")
    assert newcomer.register(ctx, "recovery")[0] == 403
    assert _approve(ctx, owner, _owner_cards(_signed_cards(ctx, owner))[0])[0] == 200
    # approved for the empty recovery slot, never for primary (which would displace the owner)
    status, body = newcomer.register(ctx, "primary", replace=owner.ref)
    assert status == 403 and body.get("error") == "owner_approval_required", body
    assert _holders(ctx) == {"primary": [owner.ref]}
    assert newcomer.register(ctx, "recovery")[0] == 201


def test_the_approval_is_bound_to_the_slot(ctx) -> None:
    """Seeded: an approval on file for the PRIMARY slot, same key, same occupant and approver - never spent on the
    recovery slot."""
    owner, second, newcomer = Phone("owner"), Phone("second"), Phone("newcomer")
    _enroll_genesis(ctx, owner)
    _seed_owner(ctx, second, "recovery")
    now = int(time.time())
    ctx["state"].put_owner_enroll({
        "request_id": str(uuid.uuid4()), "cards": {}, "incoming_pubkey": newcomer.pub, "incoming_ref": newcomer.ref,
        "slot": "primary", "approver_refs": [owner.ref], "occupant_ref": second.ref, "created_unix": now,
        "not_after": now, "state": "approved", "approved_by": owner.ref, "approved_until": now + 600,
        "expires_at_unix": now + 600,
    })
    status, body = newcomer.register(ctx, "recovery", replace=second.ref)
    assert status == 403 and body.get("error") == "owner_approval_required", body
    assert _holders(ctx) == {"primary": [owner.ref], "recovery": [second.ref]}


def test_an_approval_for_an_empty_slot_never_displaces_a_later_occupant(ctx) -> None:
    owner, newcomer, later = Phone("owner"), Phone("newcomer"), Phone("later")
    _enroll_genesis(ctx, owner)
    assert newcomer.register(ctx, "recovery")[0] == 403
    assert _approve(ctx, owner, _owner_cards(_signed_cards(ctx, owner))[0])[0] == 200
    _seed_owner(ctx, later, "recovery")            # the slot fills before the second pass
    status, body = newcomer.register(ctx, "recovery", replace=later.ref)
    assert status == 403 and body.get("error") == "owner_approval_required", body
    assert _holders(ctx) == {"primary": [owner.ref], "recovery": [later.ref]}


def test_an_approval_given_after_the_occupant_changed_is_refused(ctx) -> None:
    owner, second, newcomer = Phone("owner"), Phone("second"), Phone("newcomer")
    _enroll_genesis(ctx, owner)
    _seed_owner(ctx, second, "recovery")
    assert newcomer.register(ctx, "recovery", replace=second.ref)[0] == 403
    card = _owner_cards(_signed_cards(ctx, owner))[0]
    ctx["state"].revoke_phone(second.ref)          # the occupant the card names goes before the approval
    status, body = _approve(ctx, owner, card)
    assert status == 409 and body.get("error") == "owner_enroll_closed", body


def test_an_approval_for_one_key_never_enrolls_another(ctx) -> None:
    owner = Phone("owner")
    _enroll_genesis(ctx, owner)
    newcomer, other = Phone("newcomer"), Phone("other")
    assert newcomer.register(ctx, "recovery")[0] == 403
    assert _approve(ctx, owner, _owner_cards(_signed_cards(ctx, owner))[0])[0] == 200
    status, body = other.register(ctx, "recovery")
    assert status == 403, body
    assert _holders(ctx) == {"primary": [owner.ref]}


def test_an_approval_dies_with_its_approver(ctx) -> None:
    owner, second = Phone("owner"), Phone("second")
    _enroll_genesis(ctx, owner)
    _enroll_approved(ctx, second, "recovery", approver=owner)
    newcomer = Phone("newcomer")
    status, body = newcomer.register(ctx, "recovery", replace=second.ref)
    assert status == 403, body                      # the owner (primary) approves replacing the recovery phone
    assert "removes the old phone" not in body["detail"], body
    card = _owner_cards(_signed_cards(ctx, owner))[0]
    text = card["context"]["operation_description"]
    assert f"it replaces {_grouped(second.ref)} in that slot." in text and "REMOVES" not in text, text
    assert _owner_cards(_signed_cards(ctx, second)) == [], "the phone being displaced was asked to approve"
    assert _approve(ctx, owner, card)[0] == 200
    ctx["state"].revoke_phone(owner.ref)            # the approver is gone before the second pass
    status, body = newcomer.register(ctx, "recovery", replace=second.ref)
    assert status == 403, body
    assert _holders(ctx) == {"recovery": [second.ref]}


def test_an_approval_dies_when_the_occupant_changes(ctx) -> None:
    owner, second = Phone("owner"), Phone("second")
    _enroll_genesis(ctx, owner)
    _enroll_approved(ctx, second, "recovery", approver=owner)
    newcomer = Phone("newcomer")
    assert newcomer.register(ctx, "recovery", replace=second.ref)[0] == 403
    assert _approve(ctx, owner, _owner_cards(_signed_cards(ctx, owner))[0])[0] == 200
    ctx["state"].revoke_phone(second.ref)           # the occupant the approval named is gone before the second pass
    status, body = newcomer.register(ctx, "recovery")
    assert status == 403, body
    assert _holders(ctx) == {"primary": [owner.ref]}


def test_a_contested_slot_refuses_both_keys_and_withdraws_the_cards(ctx) -> None:
    owner = Phone("owner")
    _enroll_genesis(ctx, owner)
    newcomer, other = Phone("newcomer"), Phone("other")
    assert newcomer.register(ctx, "recovery")[0] == 403
    withdrawn = _owner_cards(_signed_cards(ctx, owner))
    assert len(withdrawn) == 1, withdrawn
    status, body = other.register(ctx, "recovery")
    assert status == 403 and body.get("error") == "owner_slot_contested", body
    detail = body.get("detail", "")
    assert detail.startswith(f"This phone is {_grouped(other.ref)}"), body
    assert "ONE phone" in detail and "15 minutes have passed since the last try from EITHER phone" in detail, body
    assert abs(body.get("reopens_at_unix", 0) - (int(time.time()) + 15 * 60 + 1)) <= 5, body
    assert _owner_cards(_signed_cards(ctx, owner)) == [], "a contested slot left a card to approve"
    status, body = _approve(ctx, owner, withdrawn[0])
    assert status == 400 and "not found or expired" in body.get("detail", ""), body
    # EITHER key's next ask inside the window is contested - the first asker's too.
    for phone in (newcomer, other, newcomer):
        status, body = phone.register(ctx, "recovery")
        assert status == 403 and body.get("error") == "owner_slot_contested", (phone.label, body)
    assert _owner_cards(_signed_cards(ctx, owner)) == []
    assert _holders(ctx) == {"primary": [owner.ref]}


def test_a_rival_ask_after_the_approval_still_refuses_both(ctx) -> None:
    owner = Phone("owner")
    _enroll_genesis(ctx, owner)
    newcomer, other = Phone("newcomer"), Phone("other")
    assert newcomer.register(ctx, "recovery")[0] == 403
    assert _approve(ctx, owner, _owner_cards(_signed_cards(ctx, owner))[0])[0] == 200
    assert other.register(ctx, "recovery")[1].get("error") == "owner_slot_contested"
    status, body = newcomer.register(ctx, "recovery")
    assert status == 403 and body.get("error") == "owner_slot_contested", body
    assert _owner_cards(_signed_cards(ctx, owner)) == []
    assert _holders(ctx) == {"primary": [owner.ref]}


def test_the_contest_ends_fifteen_minutes_after_the_rivals_ask(ctx, monkeypatch) -> None:
    owner = Phone("owner")
    _enroll_genesis(ctx, owner)
    newcomer, other = Phone("newcomer"), Phone("other")
    assert newcomer.register(ctx, "recovery")[0] == 403
    assert other.register(ctx, "recovery")[1].get("error") == "owner_slot_contested"
    real, offset = time.time, [0.0]
    monkeypatch.setattr(time, "time", lambda: real() + offset[0])
    offset[0] = 15 * 60 - 30
    status, body = newcomer.register(ctx, "recovery")
    assert status == 403 and body.get("error") == "owner_slot_contested", body
    offset[0] = 15 * 60 + 30
    status, body = newcomer.register(ctx, "recovery")
    assert status == 403 and body.get("error") == "owner_approval_required", body
    assert len(_owner_cards(_signed_cards(ctx, owner))) == 1


def test_the_contest_window_runs_from_the_other_phones_last_ask(ctx, monkeypatch) -> None:
    """Each phone's LAST ask counts for 15 minutes against the other: a phone that retries 15 minutes after its own
    refusal is still refused while the other phone asked since; alone, it asks again once the other's window ends."""
    owner = Phone("owner")
    _enroll_genesis(ctx, owner)
    b, c = Phone("b"), Phone("c")
    real, offset = time.time, [0.0]
    monkeypatch.setattr(time, "time", lambda: real() + offset[0])
    assert b.register(ctx, "recovery")[1].get("error") == "owner_approval_required"
    offset[0] = 10
    assert c.register(ctx, "recovery")[1].get("error") == "owner_slot_contested"
    offset[0] = 70
    assert b.register(ctx, "recovery")[1].get("error") == "owner_slot_contested"
    offset[0] = 10 + 15 * 60 + 1                      # C, 15 minutes after its OWN refusal: B asked at 70
    assert c.register(ctx, "recovery")[1].get("error") == "owner_slot_contested"
    offset[0] = 70 + 15 * 60 + 30                     # C alone, past B's last ask
    status, body = c.register(ctx, "recovery")
    assert status == 403 and body.get("error") == "owner_approval_required", body
    assert len(_owner_cards(_signed_cards(ctx, owner))) == 1


def test_an_approval_expires(ctx, monkeypatch) -> None:
    monkeypatch.setattr(ctx["server"].RequestHandlerClass.config, "owner_approval_ttl_seconds", 1)
    owner = Phone("owner")
    _enroll_genesis(ctx, owner)
    newcomer = Phone("newcomer")
    assert newcomer.register(ctx, "recovery")[0] == 403
    assert _approve(ctx, owner, _owner_cards(_signed_cards(ctx, owner))[0])[0] == 200
    time.sleep(2.2)
    status, body = newcomer.register(ctx, "recovery")
    assert status == 403, body
    assert _holders(ctx) == {"primary": [owner.ref]}


def test_the_sole_owner_approves_its_own_replacement(ctx) -> None:
    """The upgrade with the old phone in hand: no other owner, so the occupant approves - and both the 403 and the
    card say that approving removes the approving phone."""
    owner = Phone("old")
    _enroll_genesis(ctx, owner)
    newer = Phone("new")
    status, body = newer.register(ctx, "primary", replace=owner.ref)
    assert status == 403 and body.get("error") == "owner_approval_required", body
    assert body["detail"].startswith(
        f"This phone is {_grouped(newer.ref)}. Approve that id on the phone now in the primary slot "
        f"({_grouped(owner.ref)}), then pair again with a new code within 15 minutes - that pairing removes the old "
        "phone."), body
    assert "host reset" in body["detail"]
    cards = _owner_cards(_signed_cards(ctx, owner))
    assert len(cards) == 1, cards
    text = cards[0]["context"]["operation_description"]
    assert (f"If it pairs again within 15 minutes it takes the slot and {_grouped(owner.ref)} - THIS phone - is "
            "removed. Keep this phone until the new one shows paired.") in text, text
    assert _approve(ctx, owner, cards[0])[0] == 200
    assert _holders(ctx) == {"primary": [owner.ref]}, "approving removed the old phone before the new one paired"
    status, body = newer.register(ctx, "primary", replace=owner.ref)
    assert status == 201 and body.get("displaced_phone_ref") == owner.ref, body
    assert _holders(ctx) == {"primary": [newer.ref]}


def test_a_deny_is_refused_and_the_card_says_to_leave_it(ctx) -> None:
    owner = Phone("owner")
    _enroll_genesis(ctx, owner)
    newcomer = Phone("newcomer")
    assert newcomer.register(ctx, "recovery")[0] == 403
    card = _owner_cards(_signed_cards(ctx, owner))[0]
    text = card["context"]["operation_description"]
    assert "Leave this card - it expires in 5 minutes; Deny cannot remove it." in text, text
    status, body = _http("POST", f"{ctx['base_url']}/v0.4/respond/{card['request_id']}", {"decision": "denied"})
    assert status == 409 and body.get("error") == "owner_enroll_not_denied_unsigned", body
    assert "leave it" in body.get("detail", ""), body
    assert [c["request_id"] for c in _owner_cards(_signed_cards(ctx, owner))] == [card["request_id"]]


def test_a_lapsed_second_pass_leaves_the_approval_for_the_next(ctx, monkeypatch) -> None:
    owner = Phone("owner")
    _enroll_genesis(ctx, owner)
    newcomer = Phone("newcomer")
    assert newcomer.register(ctx, "recovery")[0] == 403
    assert _approve(ctx, owner, _owner_cards(_signed_cards(ctx, owner))[0])[0] == 200
    real = ctx["challenges"].consume_owner_challenge
    monkeypatch.setattr(ctx["challenges"], "consume_owner_challenge", lambda c: False)   # the challenge lapses mid-pass
    status, body = newcomer.register(ctx, "recovery")
    assert status == 400, body
    monkeypatch.setattr(ctx["challenges"], "consume_owner_challenge", real)
    status, body = newcomer.register(ctx, "recovery")
    assert status == 201, body


def test_genesis_never_reopens_once_an_owner_existed(ctx) -> None:
    owner = Phone("owner")
    _enroll_genesis(ctx, owner)
    ctx["state"].revoke_phone(owner.ref)          # the phone is gone, the store says it had an owner
    late = Phone("late")
    status, body = late.register(ctx, "primary")
    assert status == 403, body
    assert ctx["state"].list_phones() == []


def test_an_absent_marker_on_a_store_with_phones_is_decided_closed(tmp_path) -> None:
    seeded = StateStore(state_dir=tmp_path)
    member = Phone("member")
    seeded.register_phone(PhoneRegistration.new(device_label="m", public_key_b64u=member.pub,
                                                supported_algorithms=("ed25519",),
                                                poll_public_key_b64u=member.poll_pub, slot=MEMBER_SLOT))
    with serving(tmp_path) as c:
        late = Phone("late")
        status, body = late.register(c, "primary")
        assert status == 403, body
        assert {p.slot for p in c["state"].list_phones()} == {MEMBER_SLOT}


def test_a_same_key_re_pair_needs_only_the_code_and_keeps_its_slot(ctx) -> None:
    owner = Phone("owner")
    _enroll_genesis(ctx, owner)
    second = Phone("second")
    _enroll_approved(ctx, second, "recovery", approver=owner)
    status, body = second.register(ctx, "primary")   # the phone forgot its slot ('unpair, keep vault')
    assert status == 201, body
    assert body.get("slot") == "recovery"
    assert owner.register(ctx, "primary")[0] == 201
    assert _holders(ctx) == {"primary": [owner.ref], "recovery": [second.ref]}


# --------------------------------------------------------------------------
# The member plane and the revoke plane
# --------------------------------------------------------------------------

def test_a_member_key_never_moves_into_an_owner_slot(ctx) -> None:
    owner = Phone("owner")
    _enroll_genesis(ctx, owner)
    member = Phone("member")
    assert member.register(ctx, "primary", challenge=_member_challenge(ctx, "u1"))[0] == 201
    status, body = member.register(ctx, "recovery")
    assert status in (400, 403), body
    assert "member" in str(body).lower()
    assert _owner_cards(_signed_cards(ctx, owner)) == []
    assert _holders(ctx) == {"primary": [owner.ref], MEMBER_SLOT: [member.ref]}


def test_a_member_revokes_only_itself_and_lists_no_business_phone(ctx) -> None:
    owner, second = Phone("owner"), Phone("second")
    _enroll_genesis(ctx, owner)
    _seed_owner(ctx, second, "recovery")            # two owners: the last-owner guard is not what refuses
    member = Phone("member")
    assert member.register(ctx, "primary", challenge=_member_challenge(ctx, "u1"))[0] == 201
    status, body = _revoke(ctx, member, second.ref)
    assert status == 403 and body.get("error") == "revoke_plane", body
    assert _holders(ctx)["recovery"] == [second.ref]
    path = "/v0.4/manage/phones"
    ts = int(time.time())
    from recto.bootloader.server import POLL_SIG_HEADER, POLL_SIG_PREFIX, POLL_SIG_TS_HEADER
    sig = member.poll.sign(f"{POLL_SIG_PREFIX}|{member.ref}|{ts}|{path}".encode("ascii"))
    status, listed = _http("GET", f"{ctx['base_url']}{path}?phone_id={member.ref}", headers={
        POLL_SIG_HEADER: base64.urlsafe_b64encode(sig).decode("ascii").rstrip("="), POLL_SIG_TS_HEADER: str(ts)})
    assert status == 200 and listed.get("phones") == [], listed
    assert _revoke(ctx, member, member.ref)[0] == 200


def test_a_member_never_revokes_another_member(ctx) -> None:
    owner = Phone("owner")
    _enroll_genesis(ctx, owner)
    m1, m2 = Phone("m1"), Phone("m2")
    assert m1.register(ctx, "primary", challenge=_member_challenge(ctx, "u1"))[0] == 201
    assert m2.register(ctx, "primary", challenge=_member_challenge(ctx, "u2"))[0] == 201
    status, body = _revoke(ctx, m1, m2.ref)
    assert status == 403 and body.get("error") == "revoke_plane", body
    assert sorted(_holders(ctx)[MEMBER_SLOT]) == sorted([m1.ref, m2.ref])


def test_the_last_owner_phone_is_never_revoked(ctx) -> None:
    owner = Phone("owner")
    _enroll_genesis(ctx, owner)
    status, body = _revoke(ctx, owner, owner.ref)
    assert status == 403 and body.get("error") == "last_owner", body
    detail = body.get("detail", "")
    assert "owner-reset --slot <slot> --confirm <phone_ref> --reopen-genesis" in detail, body
    assert ("To move to a new phone: pair it with an owner code, approve its card here, and pair it again - that "
            "removes this one.") in detail and len(detail) <= 300, (len(detail), detail)
    assert _holders(ctx) == {"primary": [owner.ref]}


def test_a_slot_holder_revokes_the_other_owner_and_a_member(ctx) -> None:
    """POSITIVE CONTROL: the codeless lane still serves revoke."""
    owner = Phone("owner")
    _enroll_genesis(ctx, owner)
    second = Phone("second")
    _enroll_approved(ctx, second, "recovery", approver=owner)
    member = Phone("member")
    assert member.register(ctx, "primary", challenge=_member_challenge(ctx, "u1"))[0] == 201
    assert _revoke(ctx, owner, member.ref)[0] == 200
    assert _revoke(ctx, owner, second.ref)[0] == 200
    assert _holders(ctx) == {"primary": [owner.ref]}


def test_manage_phones_needs_a_signed_read_in_advisory(ctx) -> None:
    owner = Phone("owner")
    _enroll_genesis(ctx, owner)
    status, body = _http("GET", f"{ctx['base_url']}/v0.4/manage/phones?phone_id={owner.ref}")
    assert status == 401, body


# --------------------------------------------------------------------------
# Atomicity
# --------------------------------------------------------------------------

def test_the_push_token_update_never_re_inserts_a_removed_phone(ctx) -> None:
    owner = Phone("owner")
    _enroll_genesis(ctx, owner)
    second = Phone("second")
    _seed_owner(ctx, second, "recovery")
    stale = ctx["state"].get_phone(second.ref)
    assert _revoke(ctx, owner, second.ref)[0] == 200
    real_get = ctx["state"].get_phone
    ctx["state"].get_phone = lambda pid: stale if pid == second.ref else real_get(pid)   # read before the revoke
    try:
        status, body = _http("POST", f"{ctx['base_url']}/v0.4/manage/push_token",
                             {"phone_id": second.ref, "push_token": "tok", "push_platform": "fcm"})
    finally:
        ctx["state"].get_phone = real_get
    assert status >= 400, body
    assert second.ref not in [p.phone_id for p in ctx["state"].list_phones()]


def test_two_registrations_into_one_slot_leave_one_phone(ctx) -> None:
    barrier = threading.Barrier(2)
    real_list = ctx["state"].list_phones
    calls = {"n": 0}

    def paced():
        rows = real_list()
        calls["n"] += 1
        if calls["n"] <= 2:
            try:
                barrier.wait(timeout=0.5)
            except threading.BrokenBarrierError:
                pass
        return rows

    ctx["state"].list_phones = paced
    a, b = Phone("a"), Phone("b")
    results: list[int] = []
    threads = [threading.Thread(target=lambda p=p: results.append(p.register(ctx, "primary")[0])) for p in (a, b)]
    try:
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=20)
    finally:
        ctx["state"].list_phones = real_list
    assert len(_holders(ctx).get("primary", [])) == 1, (results, _holders(ctx))
    assert sorted(results) == [201, 409], results


# --------------------------------------------------------------------------
# Owner codes
# --------------------------------------------------------------------------

def test_owner_codes_are_minted_only_by_a_flagged_agent(tmp_path) -> None:
    with serving(tmp_path, owner_code_minters={BRIDGE_ID}) as c:
        status, body = _http("POST", f"{c['base_url']}/v0.4/pairing/code", {},
                             headers={"X-Recto-Agent-Id": AGENT_ID, "X-Recto-Agent-Token": AGENT_TOKEN})
        assert status == 403 and body.get("error") == "owner_code_mint_not_allowed", body
        status, body = _http("POST", f"{c['base_url']}/v0.4/pairing/code", {},
                             headers={"X-Recto-Agent-Id": BRIDGE_ID, "X-Recto-Agent-Token": BRIDGE_TOKEN})
        assert status == 200, body
        status, body = _http("POST", f"{c['base_url']}/v0.4/pairing/code",
                             {"member_of": {"consumer": CONSUMER, "user_id": "u"}},
                             headers={"X-Recto-Agent-Id": AGENT_ID, "X-Recto-Agent-Token": AGENT_TOKEN})
        assert status == 200, body


def _code_get(ctx, code: str, ip: str | None) -> tuple[int, dict[str, Any]]:
    return _http("GET", f"{ctx['base_url']}/v0.4/registration_challenge?code={code}",
                 headers={"CF-Connecting-IP": ip} if ip else None)


def _wrong(ctx, good: set[str]) -> str:
    n = 0
    while f"{n:06d}" in good:
        n += 1
    return f"{n:06d}"


def test_wrong_codes_are_limited_per_public_client_and_never_spend_a_good_code(ctx) -> None:
    good, _ = ctx["challenges"].issue_pairing_code()
    for _ in range(5):
        assert _code_get(ctx, _wrong(ctx, {good}), "203.0.113.5")[0] == 400
    status, body = _code_get(ctx, good, "203.0.113.5")
    assert status == 429, body
    assert _code_get(ctx, good, "198.51.100.7")[0] == 200, "the refused attempt spent the good code"


def test_a_request_without_the_client_header_is_never_locked(ctx) -> None:
    good, _ = ctx["challenges"].issue_pairing_code()
    for _ in range(12):
        assert _code_get(ctx, _wrong(ctx, {good}), None)[0] == 400
    assert _code_get(ctx, good, None)[0] == 200


def test_a_spent_code_sent_again_is_not_counted(ctx) -> None:
    spent, _ = ctx["challenges"].issue_pairing_code()
    assert _code_get(ctx, spent, "192.0.2.9")[0] == 200
    for _ in range(6):
        status, body = _code_get(ctx, spent, "192.0.2.9")
        assert status == 400, body
    fresh, _ = ctx["challenges"].issue_pairing_code()
    assert _code_get(ctx, fresh, "192.0.2.9")[0] == 200


# --------------------------------------------------------------------------
# The host CLI
# --------------------------------------------------------------------------

def _cli(*argv: str) -> tuple[int, str]:
    from recto.cli import main
    out, err = io.StringIO(), io.StringIO()
    rc = main(list(argv), stdout=out, stderr=err)
    return rc, out.getvalue() + err.getvalue()


def test_owner_reset_refuses_while_the_server_holds_the_store(tmp_path) -> None:
    with serving(tmp_path) as c:
        owner = Phone("owner")
        _enroll_genesis(c, owner)
        rc, text = _cli("bootloader", "owner-reset", "--state-dir", str(tmp_path), "--slot", "primary",
                        "--confirm", owner.ref)
        assert rc != 0 and "stop the bootloader" in text.lower(), text
        assert [p.phone_id for p in c["state"].list_phones()] == [owner.ref]


def test_owner_reset_reopens_genesis_only_when_no_owner_remains(tmp_path) -> None:
    owner, second = Phone("owner"), Phone("second")
    with serving(tmp_path) as c:
        _enroll_genesis(c, owner)
        _enroll_approved(c, second, "recovery", approver=owner)
    rc, text = _cli("bootloader", "owner-reset", "--state-dir", str(tmp_path), "--slot", "recovery",
                    "--confirm", second.ref, "--reopen-genesis")
    assert rc != 0, text
    rc, _ = _cli("bootloader", "owner-slots", "--state-dir", str(tmp_path), "--expect", f"{owner.ref},{second.ref}")
    assert rc == 0, "a refused reset removed a phone"


def test_owner_slots_and_the_reset_reopen_genesis_for_a_lost_sole_phone(tmp_path) -> None:
    owner = Phone("lost")
    with serving(tmp_path) as c:
        _enroll_genesis(c, owner)
    rc, text = _cli("bootloader", "owner-slots", "--state-dir", str(tmp_path), "--expect", owner.ref)
    assert rc == 0 and owner.ref in text, text
    rc, text = _cli("bootloader", "owner-slots", "--state-dir", str(tmp_path), "--expect", "pk_0000000000000000")
    assert rc != 0, text
    rc, text = _cli("bootloader", "owner-reset", "--state-dir", str(tmp_path), "--slot", "primary",
                    "--confirm", owner.ref, "--reopen-genesis")
    assert rc == 0 and owner.ref in text, text
    with serving(tmp_path) as c:
        replacement = Phone("replacement")
        _enroll_genesis(c, replacement)
        assert _holders(c) == {"primary": [replacement.ref]}


# --------------------------------------------------------------------------
# One key, one spelling (hard rule 14.3)
# --------------------------------------------------------------------------

_B64U = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _respelled(pub: str) -> str:
    """The same bytes with the last character's unused low bit set - a second spelling of one key."""
    return pub[:-1] + _B64U[_B64U.index(pub[-1]) ^ 1]


def _decoded(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def test_a_key_registers_only_in_its_one_spelling(ctx) -> None:
    owner = Phone("owner")
    canonical = owner.pub
    for spelling in (canonical + "=", _respelled(canonical)):
        assert spelling != canonical and _decoded(spelling) == _decoded(canonical)
        owner.pub = spelling
        status, body = owner.register(ctx, "primary")
        assert status == 400 and "unpadded base64url" in str(body), (spelling, body)
    assert ctx["state"].list_phones() == []
    owner.pub = canonical
    _enroll_genesis(ctx, owner)


def test_a_member_key_re_spelled_is_still_refused_an_owner_slot(ctx) -> None:
    owner = Phone("owner")
    _enroll_genesis(ctx, owner)
    member = Phone("member")
    assert member.register(ctx, "primary", challenge=_member_challenge(ctx, "u1"))[0] == 201
    canonical = member.pub
    for spelling in (canonical + "=", _respelled(canonical)):
        member.pub = spelling
        status, body = member.register(ctx, "recovery")
        assert status == 400, (spelling, body)
    member.pub = canonical
    status, body = member.register(ctx, "recovery")
    assert status == 403 and body.get("error") == "member_key_refused", body
    assert _owner_cards(_signed_cards(ctx, owner)) == []
    assert _holders(ctx) == {"primary": [owner.ref], MEMBER_SLOT: [member.ref]}


def test_a_legacy_row_in_another_spelling_is_still_the_same_key(ctx) -> None:
    """A row stored before the spelling rule answers to its ref: the canonical spelling of a member key held under a
    padded one is still that member key."""
    owner = Phone("owner")
    _enroll_genesis(ctx, owner)
    member = Phone("member")
    ctx["state"].register_phone(PhoneRegistration.new(device_label="legacy", public_key_b64u=member.pub + "=",
                                                      supported_algorithms=("ed25519",),
                                                      poll_public_key_b64u=member.poll_pub, slot=MEMBER_SLOT))
    status, body = member.register(ctx, "recovery")
    assert status == 403 and body.get("error") == "member_key_refused", body
    assert _owner_cards(_signed_cards(ctx, owner)) == []


class _P256Signer:
    """A P-256 key the way both shipped phones send it: 64 bytes X||Y, raw r||s signatures."""

    def __init__(self) -> None:
        from cryptography.hazmat.primitives.asymmetric import ec
        self._key = ec.generate_private_key(ec.SECP256R1())
        n = self._key.public_key().public_numbers()
        self.raw = n.x.to_bytes(32, "big") + n.y.to_bytes(32, "big")

    def sign(self, data: bytes) -> bytes:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        r, s = decode_dss_signature(self._key.sign(data, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _register_p256(ctx, signer: _P256Signer, pub: str, poll_pub: str, slot: str) -> tuple[int, dict[str, Any]]:
    code, _ = ctx["challenges"].issue_pairing_code()
    challenge = _plain_challenge(ctx, f"?code={code}")
    return _http("POST", f"{ctx['base_url']}/v0.4/register", {
        "device_label": "p256", "public_key_b64u": pub, "supported_algorithms": ["ecdsa-p256"], "v0_4_protocol": 1,
        "slot": slot,
        "registration_proof": {"challenge": challenge, "signature_b64u": _b64(signer.sign(challenge.encode("ascii")))},
        "poll_public_key_b64u": poll_pub,
        "poll_key_delegation_b64u": _b64(signer.sign(poll_key_delegation_payload(pub, poll_pub))),
    })


def test_a_p256_key_registers_as_its_64_bytes(ctx) -> None:
    """POSITIVE CONTROL: the form both shipped phones send (iOS and Android strip the 0x04 prefix)."""
    ident, poll = _P256Signer(), _P256Signer()
    status, body = _register_p256(ctx, ident, _b64(ident.raw), _b64(poll.raw), "primary")
    assert status == 201, body


def test_a_p256_key_never_registers_in_its_sec1_spelling(ctx) -> None:
    """0x04||X||Y is a second spelling of the same key - a second phone_ref for one key."""
    ident, poll = _P256Signer(), _P256Signer()
    status, body = _register_p256(ctx, ident, _b64(b"\x04" + ident.raw), _b64(poll.raw), "primary")
    assert status == 400 and "unpadded base64url" in str(body), body
    status, body = _register_p256(ctx, ident, _b64(ident.raw), _b64(b"\x04" + poll.raw), "primary")
    assert status == 400 and "poll_public_key_b64u" in str(body), body
    assert ctx["state"].list_phones() == []


def test_a_poll_key_that_re_spells_the_identity_key_is_refused(ctx) -> None:
    phone = Phone("phone")
    for spelling in (phone.pub + "=", _respelled(phone.pub)):
        phone.poll_pub = spelling
        status, body = phone.register(ctx, "primary")
        assert status == 400 and "poll_public_key_b64u" in str(body), (spelling, body)
    assert ctx["state"].list_phones() == []


def test_a_key_of_no_decodable_length_is_refused_not_an_error(ctx) -> None:
    phone = Phone("phone")
    for spelling in ("A" * 45, "A" * 85):
        phone.pub = spelling
        status, body = phone.register(ctx, "primary")
        assert status == 400 and "unpadded base64url" in str(body), (spelling, body)
    assert ctx["state"].list_phones() == []


# --------------------------------------------------------------------------
# The request log, the plain lane, wrong codes
# --------------------------------------------------------------------------

@pytest.mark.parametrize("query", ["code={c}&x=1", "CODE={c}&x=1", "c%6Fde={c}&x=1", "Co%64e={c}&x=1",
                                   "code+={c}&x=1", "code%00={c}&x=1", "x=1;code={c}"])
def test_the_request_log_never_prints_a_pairing_code(ctx, capsys, query) -> None:
    good, _ = ctx["challenges"].issue_pairing_code()
    _http("GET", f"{ctx['base_url']}/v0.4/registration_challenge?" + query.format(c=good))
    out = capsys.readouterr().out
    assert good not in out, out
    assert "=***" in out and "x=1" in out, out


def test_a_codeless_flood_never_evicts_a_phones_revoke_challenge(ctx) -> None:
    owner, second = Phone("owner"), Phone("second")
    _enroll_genesis(ctx, owner)
    _enroll_approved(ctx, second, "recovery", approver=owner)
    challenge = _plain_challenge(ctx)
    for _ in range(1100):
        ctx["challenges"].issue_challenge()
    sig = _b64(owner.identity.sign(f"{challenge}:{second.ref}".encode("ascii")))
    status, body = _http("POST", f"{ctx['base_url']}/v0.4/manage/phones/revoke", {
        "revoker_phone_id": owner.ref, "target_phone_id": second.ref, "challenge_b64u": challenge,
        "signature_b64u": sig})
    assert status == 200, body


def test_many_public_clients_never_lock_out_everyone(ctx, caplog) -> None:
    good, _ = ctx["challenges"].issue_pairing_code()
    for n in range(25):
        for _ in range(4):
            assert _code_get(ctx, _wrong(ctx, {good}), f"198.18.0.{n + 1}")[0] == 400
    assert _code_get(ctx, good, "203.0.113.200")[0] == 200, "a hundred strangers' guesses locked out a good code"
    assert any("someone may be guessing codes" in r.getMessage() for r in caplog.records)


def test_an_ipv6_client_is_counted_per_64(ctx) -> None:
    good, _ = ctx["challenges"].issue_pairing_code()
    for n in range(5):
        assert _code_get(ctx, _wrong(ctx, {good}), f"2001:db8:1:2::{n + 1}")[0] == 400
    assert _code_get(ctx, good, "2001:db8:1:2:ffff::99")[0] == 429
    assert _code_get(ctx, good, "2001:db8:1:3::1")[0] == 200


# --------------------------------------------------------------------------
# Two owners revoking each other
# --------------------------------------------------------------------------

def test_two_owners_revoking_each_other_leave_one(ctx) -> None:
    a, b = Phone("a"), Phone("b")
    _enroll_genesis(ctx, a)
    _seed_owner(ctx, b, "recovery")
    barrier = threading.Barrier(2)
    real_list = ctx["state"].list_phones
    calls = {"n": 0}

    def paced():
        rows = real_list()
        calls["n"] += 1
        if calls["n"] <= 2:
            try:
                barrier.wait(timeout=2.0)
            except threading.BrokenBarrierError:
                pass
        return rows

    results: list[int] = []
    threads = [threading.Thread(target=lambda r=r, t=t: results.append(_revoke(ctx, r, t.ref)[0]))
               for r, t in ((a, b), (b, a))]
    ctx["state"].list_phones = paced
    try:
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=20)
    finally:
        ctx["state"].list_phones = real_list
    owners = [p.phone_id for p in ctx["state"].list_phones() if p.slot in ("primary", "recovery")]
    assert len(owners) == 1, (results, owners)


# --------------------------------------------------------------------------
# The host CLI: reopening genesis, the last owner, another process
# --------------------------------------------------------------------------

def test_owner_reset_reopens_genesis_alone_on_a_store_with_no_owner(tmp_path) -> None:
    owner = Phone("owner")
    with serving(tmp_path) as c:
        _enroll_genesis(c, owner)
        c["state"].revoke_phone(owner.ref)            # the store had an owner and holds none now; genesis is closed
        status, body = Phone("late").register(c, "primary")
        assert status == 403 and body.get("error") == "no_owner_can_approve", body
    rc, text = _cli("bootloader", "owner-reset", "--state-dir", str(tmp_path), "--reopen-genesis")
    assert rc == 0 and "reopened" in text, text
    with serving(tmp_path) as c:
        replacement = Phone("replacement")
        _enroll_genesis(c, replacement)
        assert _holders(c) == {"primary": [replacement.ref]}


def test_owner_reset_reopen_alone_is_refused_while_an_owner_remains(tmp_path) -> None:
    owner = Phone("owner")
    with serving(tmp_path) as c:
        _enroll_genesis(c, owner)
    rc, text = _cli("bootloader", "owner-reset", "--state-dir", str(tmp_path), "--reopen-genesis")
    assert rc != 0 and owner.ref in text, text
    with serving(tmp_path) as c:
        assert Phone("late").register(c, "recovery")[0] == 403
        assert _holders(c) == {"primary": [owner.ref]}


def test_owner_reset_refuses_the_last_owner_without_reopen(tmp_path) -> None:
    owner = Phone("owner")
    with serving(tmp_path) as c:
        _enroll_genesis(c, owner)
    rc, text = _cli("bootloader", "owner-reset", "--state-dir", str(tmp_path), "--slot", "primary",
                    "--confirm", owner.ref)
    assert rc != 0 and "--reopen-genesis" in text, text
    rc, text = _cli("bootloader", "owner-slots", "--state-dir", str(tmp_path), "--expect", owner.ref)
    assert rc == 0, text


def test_owner_reset_takes_slot_and_confirm_together(tmp_path) -> None:
    owner = Phone("owner")
    with serving(tmp_path) as c:
        _enroll_genesis(c, owner)
    for argv, said in ((("--slot", "primary"), "go together"), (("--confirm", owner.ref), "go together"),
                       (("--slot", "primary", "--reopen-genesis"), "go together"), ((), "give --reopen-genesis alone")):
        rc, text = _cli("bootloader", "owner-reset", "--state-dir", str(tmp_path), *argv)
        assert rc != 0 and said in text and "None" not in text, (argv, text)
    rc, text = _cli("bootloader", "owner-slots", "--state-dir", str(tmp_path), "--expect", owner.ref)
    assert rc == 0, text


def _child_env() -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO) + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def test_the_host_cli_in_another_process_is_refused_while_the_server_holds_the_store(tmp_path) -> None:
    owner, second = Phone("owner"), Phone("second")
    with serving(tmp_path) as c:
        _enroll_genesis(c, owner)
        _enroll_approved(c, second, "recovery", approver=owner)
        proc = subprocess.run(
            [sys.executable, "-c", "import sys; from recto.cli import main; sys.exit(main(sys.argv[1:]))",
             "bootloader", "owner-reset", "--state-dir", str(tmp_path), "--slot", "recovery", "--confirm", second.ref],
            capture_output=True, text=True, env=_child_env(), cwd=str(REPO), timeout=120)
        assert proc.returncode != 0 and "stop the bootloader" in (proc.stdout + proc.stderr).lower(), proc
        assert _holders(c) == {"primary": [owner.ref], "recovery": [second.ref]}


def test_a_server_will_not_start_on_a_store_another_process_holds(tmp_path) -> None:
    holder = subprocess.Popen(
        [sys.executable, "-c",
         "import sys; from pathlib import Path; from recto.bootloader.owner_slots import acquire_store_lock; "
         "lock = acquire_store_lock(Path(sys.argv[1])); print('held' if lock else 'none', flush=True); sys.stdin.read()",
         str(tmp_path)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, env=_child_env(), cwd=str(REPO))
    try:
        assert holder.stdout.readline().strip() == "held"
        with pytest.raises(BootloaderError):
            _start(tmp_path)
    finally:
        holder.stdin.close()
        holder.wait(timeout=30)
    with serving(tmp_path) as c:
        _enroll_genesis(c, Phone("owner"))


def test_a_filesystem_that_cannot_lock_is_an_error_not_a_held_lock(tmp_path, monkeypatch) -> None:
    from recto.bootloader import owner_slots

    def no_locks(*_a: Any) -> None:
        raise OSError(errno.ENOLCK, "no locks available")

    if os.name == "nt":
        import msvcrt
        monkeypatch.setattr(msvcrt, "locking", no_locks)
    else:
        import fcntl
        monkeypatch.setattr(fcntl, "flock", no_locks)
    with pytest.raises(OSError):
        owner_slots._os_lock(tmp_path)


# --------------------------------------------------------------------------
# The runner's flag and the example
# --------------------------------------------------------------------------

def test_the_runner_reads_the_owner_mint_flag_strictly() -> None:
    examples = REPO / "examples"
    if str(examples) not in sys.path:
        sys.path.insert(0, str(examples))
    from run_bootloader_consumer import _owner_code_minters
    assert _owner_code_minters([{"agent_id": "bridge", "may_mint_owner_codes": True}, {"agent_id": "svc"},
                                {"agent_id": "other", "may_mint_owner_codes": False}]) == {"bridge"}
    with pytest.raises(ValueError, match="'svc'"):
        _owner_code_minters([{"agent_id": "svc", "may_mint_owner_codes": "true"}])


def test_the_example_flags_only_the_operators_own_agent() -> None:
    data = json.loads((REPO / "examples" / "agents.json.example").read_text(encoding="utf-8"))
    flagged = [a["agent_id"] for a in data["agents"] if a.get("may_mint_owner_codes") is True]
    assert flagged == ["operator-console"], flagged
    assert "app" not in next(a for a in data["agents"] if a["agent_id"] == "operator-console")


# --------------------------------------------------------------------------
# the legacy spelling on the member path; the approval's other pins
# --------------------------------------------------------------------------

@pytest.mark.parametrize("respell", ["padded", "low-bit"])
def test_a_legacy_owner_row_keeps_its_slot_when_its_phone_scans_a_member_code(ctx, respell) -> None:
    owner = Phone("owner")
    stored = owner.pub + "=" if respell == "padded" else _respelled(owner.pub)
    ctx["state"].register_phone(PhoneRegistration.new(device_label="legacy", public_key_b64u=stored,
                                                      supported_algorithms=("ed25519",),
                                                      poll_public_key_b64u=owner.poll_pub, slot="primary"))
    ctx["state"].set_owner_genesis("closed")
    status, body = owner.register(ctx, "primary", challenge=_member_challenge(ctx, "u1"))
    assert status == 201 and body.get("slot") == "primary", body
    assert _holders(ctx) == {"primary": [owner.ref]}
    assert [p.public_key_b64u for p in ctx["state"].list_phones()] == [owner.pub]


def test_an_approval_withdraws_the_other_approvers_card(ctx) -> None:
    """A registry from before the slots can hold two owner phones in one slot: both are asked, one answers."""
    a, b, newcomer = Phone("a"), Phone("b"), Phone("newcomer")
    _seed_owner(ctx, a, "primary")
    _seed_owner(ctx, b, "primary")
    ctx["state"].set_owner_genesis("closed")
    assert newcomer.register(ctx, "recovery")[0] == 403
    assert len(_owner_cards(_signed_cards(ctx, b))) == 1
    assert _approve(ctx, a, _owner_cards(_signed_cards(ctx, a))[0])[0] == 200
    assert _owner_cards(_signed_cards(ctx, b)) == [], "the other approver's card stayed after the approval"


def test_a_card_taken_off_the_queue_is_replaced_once(ctx) -> None:
    owner, newcomer = Phone("owner"), Phone("newcomer")
    _enroll_genesis(ctx, owner)
    assert newcomer.register(ctx, "recovery")[0] == 403
    first = _owner_cards(_signed_cards(ctx, owner))[0]
    ctx["state"].take_pending(first["request_id"])
    assert newcomer.register(ctx, "recovery")[0] == 403
    cards = _owner_cards(_signed_cards(ctx, owner))
    assert len(cards) == 1 and cards[0]["request_id"] != first["request_id"], cards
    assert newcomer.register(ctx, "recovery")[0] == 403
    assert [c["request_id"] for c in _owner_cards(_signed_cards(ctx, owner))] == [cards[0]["request_id"]]


def test_a_same_key_re_pair_spends_its_challenge(ctx) -> None:
    owner = Phone("owner")
    _enroll_genesis(ctx, owner)
    assert owner.register(ctx, "primary")[0] == 201
    status, body = owner.register(ctx, "primary", challenge=owner.last_challenge)
    assert status == 400, body


def test_a_spent_approval_is_refused_and_enrolls_nothing(ctx, monkeypatch) -> None:
    owner, newcomer = Phone("owner"), Phone("newcomer")
    _enroll_genesis(ctx, owner)
    assert newcomer.register(ctx, "recovery")[0] == 403
    assert _approve(ctx, owner, _owner_cards(_signed_cards(ctx, owner))[0])[0] == 200
    monkeypatch.setattr(ctx["state"], "delete_owner_enroll", lambda request_id: None)   # spent elsewhere meanwhile
    status, body = newcomer.register(ctx, "recovery")
    assert status == 400 and "already spent" in str(body), body
    assert _holders(ctx) == {"primary": [owner.ref]}


def test_a_displacement_that_fails_to_write_leaves_the_old_phone(ctx, monkeypatch) -> None:
    owner, newer = Phone("old"), Phone("new")
    _enroll_genesis(ctx, owner)
    assert newer.register(ctx, "primary", replace=owner.ref)[0] == 403
    assert _approve(ctx, owner, _owner_cards(_signed_cards(ctx, owner))[0])[0] == 200
    real = ctx["state"]._atomic_write

    def no_phones_json(path, body):
        if Path(path).name == "phones.json":
            raise OSError(28, "no space left on device")
        return real(path, body)

    monkeypatch.setattr(ctx["state"], "_atomic_write", no_phones_json)
    status, _ = newer.register(ctx, "primary", replace=owner.ref)
    assert status >= 500
    monkeypatch.undo()
    assert _holders(ctx) == {"primary": [owner.ref]}
    fresh = StateStore(state_dir=ctx["state"].state_dir)
    assert [p.phone_id for p in fresh.list_phones() if p.slot == "primary"] == [owner.ref]


# --------------------------------------------------------------------------
# genesis at startup
# --------------------------------------------------------------------------

def test_a_store_with_a_session_and_no_phone_is_decided_closed(tmp_path) -> None:
    from tests.test_state_postgres import _session
    seeded = StateStore(state_dir=tmp_path)
    seeded.put_session(_session())
    with serving(tmp_path) as c:
        assert c["state"].get_owner_genesis() == "closed"
        status, body = Phone("late").register(c, "primary")
        assert status == 403 and body.get("error") == "no_owner_can_approve", body


def test_the_genesis_decision_is_made_under_the_registry_lock(tmp_path) -> None:
    state = StateStore(state_dir=tmp_path)
    depth, seen = [0], []
    real_lock, real_get, real_set = state.registry_lock, state.get_owner_genesis, state.set_owner_genesis

    @contextmanager
    def counted():
        with real_lock():
            depth[0] += 1
            try:
                yield
            finally:
                depth[0] -= 1

    def get():
        seen.append(("get", depth[0]))
        return real_get()

    def set_(value):
        seen.append(("set", depth[0]))
        return real_set(value)

    state.registry_lock, state.get_owner_genesis, state.set_owner_genesis = counted, get, set_
    server = create_server(bind_host="127.0.0.1", bind_port=0, state=state, bootloader_id="lock-test",
                           challenges=ChallengeStore(state=state), ssl_context=None)
    server.server_close()
    decided = seen[:[k for k, _ in seen].index("set") + 1]
    assert decided and all(d > 0 for _, d in decided), seen


def test_a_member_only_store_is_decided_closed_and_the_reset_reopens_it(tmp_path) -> None:
    member = Phone("member")
    seeded = StateStore(state_dir=tmp_path)
    seeded.register_phone(PhoneRegistration.new(device_label="m", public_key_b64u=member.pub,
                                                supported_algorithms=("ed25519",),
                                                poll_public_key_b64u=member.poll_pub, slot=MEMBER_SLOT))
    with serving(tmp_path) as c:
        status, body = Phone("late").register(c, "primary")
        assert status == 403 and body.get("error") == "no_owner_can_approve", body
    rc, text = _cli("bootloader", "owner-reset", "--state-dir", str(tmp_path), "--reopen-genesis")
    assert rc == 0, text
    with serving(tmp_path) as c:
        first = Phone("first")
        _enroll_genesis(c, first)
        assert _holders(c) == {"primary": [first.ref], MEMBER_SLOT: [member.ref]}


# --------------------------------------------------------------------------
# the client header, the exposure budget, mapped addresses, the limiter's cost and its alert
# --------------------------------------------------------------------------

def _code_get_raw(ctx, code: str, header_values: list[str]) -> int:
    host, port = ctx["base_url"].split("//")[1].split(":")
    conn = http.client.HTTPConnection(host, int(port), timeout=10)
    try:
        conn.putrequest("GET", f"/v0.4/registration_challenge?code={code}")
        for value in header_values:
            conn.putheader("CF-Connecting-IP", value)
        conn.endheaders()
        resp = conn.getresponse()
        resp.read()
        return resp.status
    finally:
        conn.close()


def test_an_empty_or_blank_client_header_is_counted(ctx) -> None:
    good, _ = ctx["challenges"].issue_pairing_code()
    for value in ("", " ", "", "  ", ""):
        assert _code_get_raw(ctx, _wrong(ctx, {good}), [value]) == 400
    assert _code_get_raw(ctx, good, [" "]) == 429
    assert _code_get(ctx, good, "203.0.113.50")[0] == 200


def test_a_repeated_client_header_is_counted(ctx) -> None:
    good, _ = ctx["challenges"].issue_pairing_code()
    for n in range(5):
        assert _code_get_raw(ctx, _wrong(ctx, {good}), [f"203.0.113.{n + 1}", "198.51.100.1"]) == 400
    assert _code_get_raw(ctx, good, ["203.0.113.99", "198.51.100.99"]) == 429
    assert _code_get(ctx, good, "203.0.113.50")[0] == 200


def test_a_code_exposed_to_too_many_public_guesses_is_burned(ctx, monkeypatch, caplog) -> None:
    from recto.bootloader import owner_slots
    monkeypatch.setattr(owner_slots, "CODE_PUBLIC_EXPOSURE_BUDGET", 10)
    private_route, _ = ctx["challenges"].issue_pairing_code()
    exposed, _ = ctx["challenges"].issue_pairing_code()
    elsewhere, _ = ctx["state"].issue_pairing_code()        # minted where this server's limiter did not see it
    live = {private_route, exposed, elsewhere}
    for n in range(10):
        assert _code_get(ctx, _wrong(ctx, live), f"198.18.1.{n + 1}")[0] == 400
    assert _code_get(ctx, private_route, None)[0] == 200, "the private route lost a code to public guessing"
    for code in (exposed, elsewhere):
        status, body = _code_get(ctx, code, "203.0.113.77")
        assert status == 400 and "exposed to too many wrong guesses" in str(body), body
        assert _code_get(ctx, code, None)[0] == 400, "a burned code still redeemed"
        for _ in range(owner_slots.WRONG_CODE_LIMIT + 1):   # a phone re-sending its burned code is never counted
            status, body = _code_get(ctx, code, "203.0.113.77")
            assert status == 400 and "already used" in str(body), body
    burned = [r for r in caplog.records if r.name == "recto.bootloader.codes" and r.getMessage().startswith("burned ")]
    assert len(burned) == 2, [r.getMessage() for r in caplog.records]
    fresh, _ = ctx["challenges"].issue_pairing_code()
    assert _code_get(ctx, fresh, "203.0.113.77")[0] == 200


def test_an_ipv4_mapped_client_is_its_ipv4_address(ctx) -> None:
    good, _ = ctx["challenges"].issue_pairing_code()
    for _ in range(5):
        assert _code_get(ctx, _wrong(ctx, {good}), "::ffff:198.51.100.7")[0] == 400
    assert _code_get(ctx, good, "198.51.100.7")[0] == 429
    assert _code_get(ctx, good, "::ffff:203.0.113.5")[0] == 200


def test_the_limiter_buckets() -> None:
    from recto.bootloader.owner_slots import CodeAttemptLimiter
    b = CodeAttemptLimiter.bucket
    assert b("::ffff:198.51.100.7") == b("198.51.100.7") == "198.51.100.7"
    assert b("64:ff9b::c633:6407") == "198.51.100.7"
    assert b("2001:db8:1:2::1") == b("2001:db8:1:2:ffff::9") == "2001:db8:1:2::/64"
    assert b("2001:db8:1:3::1") != b("2001:db8:1:2::1")
    assert b(" Not-An-IP ") == "not-an-ip"
    assert b("203.0.113.5:443") == "203.0.113.5:443"


def _fake_clock(monkeypatch, start: float = 1_000_000.0) -> list[float]:
    now = [start]
    monkeypatch.setattr(time, "time", lambda: now[0])
    return now


def test_the_limiter_stays_cheap_under_many_clients(monkeypatch) -> None:
    from recto.bootloader.owner_slots import CodeAttemptLimiter
    _fake_clock(monkeypatch)
    limiter = CodeAttemptLimiter()
    logging.getLogger("recto.bootloader.codes").disabled = True
    try:
        t0 = time.perf_counter()
        for n in range(20_000):
            limiter.record_failure(f"198.{18 + n // 65536}.{(n // 256) % 256}.{n % 256}")
            limiter.blocked("203.0.113.1")
        elapsed = time.perf_counter() - t0
    finally:
        logging.getLogger("recto.bootloader.codes").disabled = False
    assert elapsed < 5.0, f"20,000 failures took {elapsed:.1f} s - the limiter's cost grows with its size"


def test_the_guessing_alert_reports_the_real_count_at_most_once_a_minute(monkeypatch, caplog) -> None:
    from recto.bootloader.owner_slots import CodeAttemptLimiter
    now = _fake_clock(monkeypatch)
    limiter = CodeAttemptLimiter()
    with caplog.at_level(logging.WARNING, logger="recto.bootloader.codes"):
        for n in range(3000):
            limiter.record_failure(f"198.18.{n // 256}.{n % 256}")
        alerts = [r.getMessage() for r in caplog.records if "guessing" in r.getMessage()]
        assert len(alerts) == 1 and alerts[0].startswith("100 "), alerts
        now[0] += 61
        limiter.record_failure("198.19.9.9")
        alerts = [r.getMessage() for r in caplog.records if "guessing" in r.getMessage()]
        assert len(alerts) == 2 and alerts[1].startswith("3001 "), alerts
        caplog.clear()
        for n in range(1200):                         # a steady stream for three hours, one failure every 9 s
            now[0] += 9
            limiter.record_failure(f"198.19.{n // 256}.{n % 256}")
        alerts = [r for r in caplog.records if "guessing" in r.getMessage()]
        assert len(alerts) <= 3 * 60 + 1, len(alerts)
        caplog.clear()
        now[0] += 15 * 60 + 1                         # the window empties: one more failure is no alarm
        limiter.record_failure("198.19.9.10")
        assert not [r for r in caplog.records if "guessing" in r.getMessage()], caplog.records


def test_refusals_are_reported_once_a_minute_and_never_counted(monkeypatch, caplog) -> None:
    from recto.bootloader.owner_slots import CodeAttemptLimiter
    now = _fake_clock(monkeypatch)
    limiter = CodeAttemptLimiter()
    with caplog.at_level(logging.WARNING, logger="recto.bootloader.codes"):
        for _ in range(200):
            limiter.record_refusal()
        lines = [r.getMessage() for r in caplog.records if "refused by the wrong-code limit" in r.getMessage()]
        assert lines == ["1 requests refused by the wrong-code limit since the last report"], lines
        now[0] += 61
        limiter.record_refusal()
        lines = [r.getMessage() for r in caplog.records if "refused by the wrong-code limit" in r.getMessage()]
        assert len(lines) == 2 and lines[1].startswith("200 "), lines
    assert limiter._total == 0 and not limiter._counts and not limiter._events


def test_a_blocked_client_stays_blocked_while_others_come_and_go(monkeypatch) -> None:
    from recto.bootloader.owner_slots import CodeAttemptLimiter
    now = _fake_clock(monkeypatch)
    limiter = CodeAttemptLimiter()
    logging.getLogger("recto.bootloader.codes").disabled = True
    try:
        for _ in range(5):
            limiter.record_failure("198.51.100.7")
        for n in range(10_000):
            now[0] += 0.08
            limiter.record_failure(f"198.18.{n // 256}.{n % 256}")
        assert now[0] - 1_000_000.0 == pytest.approx(800, abs=1)
        assert limiter.blocked("198.51.100.7")
        now[0] = 1_000_000.0 + 15 * 60 + 1
        assert not limiter.blocked("198.51.100.7")
    finally:
        logging.getLogger("recto.bootloader.codes").disabled = False


# --------------------------------------------------------------------------
# the host CLI - refs as printed, unreadable stores, unlockable dirs, the Postgres arm's refusals
# --------------------------------------------------------------------------

def test_owner_reset_and_owner_slots_take_the_grouped_ref(tmp_path) -> None:
    owner, second = Phone("owner"), Phone("second")
    with serving(tmp_path) as c:
        _enroll_genesis(c, owner)
        _seed_owner(c, second, "recovery")
    rc, text = _cli("bootloader", "owner-slots", "--state-dir", str(tmp_path), "--expect",
                    f"{_grouped(owner.ref)},{_grouped(second.ref)}")
    assert rc == 0, text
    sole = tmp_path / "sole"
    lost = Phone("lost")
    with serving(sole) as c:
        _enroll_genesis(c, lost)
    rc, text = _cli("bootloader", "owner-reset", "--state-dir", str(sole), "--slot", "primary",
                    "--confirm", _grouped(Phone("stranger").ref), "--reopen-genesis")
    assert rc != 0, text
    rc, text = _cli("bootloader", "owner-reset", "--state-dir", str(sole), "--slot", "primary",
                    "--confirm", _grouped(lost.ref), "--reopen-genesis")
    assert rc == 0 and f"removed {lost.ref} " in text, text


def test_owner_reset_refuses_the_right_phone_named_in_the_wrong_slot(tmp_path) -> None:
    owner, second = Phone("owner"), Phone("second")
    with serving(tmp_path) as c:
        _enroll_genesis(c, owner)
        _seed_owner(c, second, "recovery")
    rc, text = _cli("bootloader", "owner-reset", "--state-dir", str(tmp_path), "--slot", "primary",
                    "--confirm", second.ref)
    assert rc != 0 and "does not hold" in text, text
    rc, text = _cli("bootloader", "owner-slots", "--state-dir", str(tmp_path), "--expect", f"{owner.ref},{second.ref}")
    assert rc == 0, text


def test_an_unreadable_marker_is_a_named_refusal(tmp_path) -> None:
    owner = Phone("owner")
    with serving(tmp_path) as c:
        _enroll_genesis(c, owner)
    (tmp_path / "owner_genesis.json").write_text(json.dumps({"state": "ajar"}), encoding="utf-8")
    for argv in (("owner-slots",), ("owner-reset", "--reopen-genesis")):
        rc, text = _cli("bootloader", *argv, "--state-dir", str(tmp_path))
        assert rc == 1 and "cannot be read" in text and "a bootloader holds" not in text, (argv, text)
        assert "owner_genesis.json" in text and "repaired by hand" in text, (argv, text)


def test_a_refused_reset_releases_the_store_lock_it_took(tmp_path, monkeypatch) -> None:
    from recto.bootloader import owner_slots
    with serving(tmp_path) as c:
        _enroll_genesis(c, Phone("owner"))
    (tmp_path / "owner_genesis.json").write_text(json.dumps({"state": "ajar"}), encoding="utf-8")
    real_acquire, taken = owner_slots.acquire_store_lock, []

    def keep(state_dir):
        lock = real_acquire(state_dir)
        taken.append(lock)   # the reference outlives the call: a lock the CLI forgot to release stays held
        return lock

    monkeypatch.setattr(owner_slots, "acquire_store_lock", keep)
    rc, text = _cli("bootloader", "owner-reset", "--reopen-genesis", "--state-dir", str(tmp_path))
    assert rc == 1 and "cannot be read" in text, text
    assert len(taken) == 1 and taken[0] is not None
    again = real_acquire(tmp_path)
    assert again is not None, "the refused reset kept the store lock"
    again.release()


def _no_locks(monkeypatch) -> None:
    def refuse(*_a: Any) -> None:
        raise OSError(errno.ENOLCK, "no locks available")

    if os.name == "nt":
        import msvcrt
        monkeypatch.setattr(msvcrt, "locking", refuse)
    else:
        import fcntl
        monkeypatch.setattr(fcntl, "flock", refuse)


def test_a_dir_that_cannot_be_locked_is_named_by_the_server_and_the_cli(tmp_path, monkeypatch) -> None:
    owner = Phone("owner")
    with serving(tmp_path) as c:
        _enroll_genesis(c, owner)
    _no_locks(monkeypatch)
    with pytest.raises(BootloaderError, match="cannot take the store lock"):
        _start(tmp_path)
    rc, text = _cli("bootloader", "owner-reset", "--state-dir", str(tmp_path), "--slot", "primary",
                    "--confirm", owner.ref, "--reopen-genesis")
    assert rc == 1 and "nothing changed" in text, text


def test_the_postgres_arm_refuses_by_name_without_a_database(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("RECTO_STATE_BACKEND", "postgres")
    monkeypatch.setenv("RECTO_POSTGRES_DSN", "postgresql://nobody@127.0.0.1:1/never-dialled")
    monkeypatch.setenv("RECTO_POSTGRES_SCHEMA", "Bad-Schema")
    rc, text = _cli("bootloader", "owner-slots")
    assert rc == 1 and "lowercase identifier" in text and "never-dialled" not in text, text
    monkeypatch.setenv("RECTO_POSTGRES_SCHEMA", "recto_bootloader")
    monkeypatch.setitem(sys.modules, "psycopg", None)
    rc, text = _cli("bootloader", "owner-reset", "--reopen-genesis")
    assert rc == 1 and "needs the postgres extra" in text and "never-dialled" not in text, text


# --------------------------------------------------------------------------
# the runner's flag reaches the server; its texts agree with the server
# --------------------------------------------------------------------------

def test_the_runner_hands_the_flagged_agents_to_the_server(monkeypatch, tmp_path, capsys) -> None:
    from tests.test_capability_consumer_actions import _launcher_kwargs
    rc, kw = _launcher_kwargs(monkeypatch, tmp_path, [
        {"agent_id": "a", "token_env": "POLICY_TEST_TOKEN_A", "may_mint_owner_codes": True},
        {"agent_id": "b", "token_env": "POLICY_TEST_TOKEN_B"},
    ])
    assert rc is None and kw["owner_code_minters"] == {"a"}, (rc, kw)
    for value in ("true", 1, 0, None):
        rc, kw = _launcher_kwargs(monkeypatch, tmp_path, [
            {"agent_id": "a", "token_env": "POLICY_TEST_TOKEN_A", "may_mint_owner_codes": value},
        ])
        assert rc == 2 and kw is None, value
        assert "may_mint_owner_codes must be true or false" in capsys.readouterr().err, value
    rc, kw = _launcher_kwargs(monkeypatch, tmp_path, [
        {"agent_id": "a", "token_env": "POLICY_TEST_TOKEN_A", "may_mint_owner_codes": False},
    ])
    assert rc is None and kw["owner_code_minters"] == set(), (rc, kw)


def test_the_single_agent_flag_is_strict(monkeypatch) -> None:
    examples = REPO / "examples"
    if str(examples) not in sys.path:
        sys.path.insert(0, str(examples))
    from run_bootloader_consumer import _env_owner_mint_flag
    for raw, want in (("1", True), ("", False), ("0", False)):
        monkeypatch.setenv("RECTO_AGENT_MAY_MINT_OWNER_CODES", raw)
        assert _env_owner_mint_flag() is want, raw
    for raw in ("true", "yes"):
        monkeypatch.setenv("RECTO_AGENT_MAY_MINT_OWNER_CODES", raw)
        with pytest.raises(SystemExit) as exited:
            _env_owner_mint_flag()
        assert exited.value.code == 2


def test_the_quiet_banner_never_sends_the_operator_to_a_403(monkeypatch, tmp_path, capsys) -> None:
    from unittest import mock

    import tests.test_capability_consumer_actions as tcca
    import run_bootloader_consumer as rbc

    def fake_create_server(**kwargs: Any) -> Any:
        stub = mock.MagicMock()
        stub.server_address = ("127.0.0.1", 0)
        stub.serve_forever.side_effect = KeyboardInterrupt
        return stub

    agents = [{"agent_id": "a", "token_env": "POLICY_TEST_TOKEN_A"}]
    rc, _ = tcca._launcher_kwargs(monkeypatch, tmp_path, agents)   # sets the environment; stops at create_server
    monkeypatch.setenv("RECTO_BOOTLOADER_QUIET", "1")
    monkeypatch.setattr(rbc, "create_server", fake_create_server)
    capsys.readouterr()
    assert rbc.main() == 0
    out = capsys.readouterr().out
    assert "WARNING: no agent may mint OWNER pairing codes" in out and "RECTO_AGENT_MAY_MINT_OWNER_CODES=1" in out, out
    assert "MEMBER codes only" in out, out
    assert "Mint codes on demand via POST /v0.4/pairing/code (operator-trusted" not in out, out


# --------------------------------------------------------------------------
# the fallback ChallengeStore keeps owner and member codes apart too
# --------------------------------------------------------------------------

def test_the_fallback_challenge_store_never_mints_a_code_twice(monkeypatch) -> None:
    import secrets
    draws = iter([1, 1, 2, 3, 3, 4])
    monkeypatch.setattr(secrets, "randbelow", lambda n: next(draws))
    store = ChallengeStore()
    assert store.issue_member_pairing_code()[0] == "000001"
    assert store.issue_pairing_code()[0] == "000002", "an owner code drawn equal to a live member code"
    assert store.issue_pairing_code()[0] == "000003"
    assert store.issue_member_pairing_code()[0] == "000004", "a member code drawn equal to a live owner code"


# --------------------------------------------------------------------------
# the exposure budget on every store and both kinds; its cost; its clock
# --------------------------------------------------------------------------

def _mint(ctx, agent_id: str, token: str, body: dict[str, Any]) -> str:
    status, minted = _http("POST", f"{ctx['base_url']}/v0.4/pairing/code", body,
                           headers={"X-Recto-Agent-Id": agent_id, "X-Recto-Agent-Token": token})
    assert status == 200, minted
    return minted["code"]


def _mint_member_code(ctx, user_id: str) -> str:
    return _mint(ctx, AGENT_ID, AGENT_TOKEN, {"member_of": {"consumer": CONSUMER, "user_id": user_id}})


def test_a_server_built_without_a_challenge_store_stamps_its_codes(tmp_path, monkeypatch) -> None:
    from recto.bootloader import owner_slots
    from recto.bootloader.server import BootloaderHandler
    monkeypatch.setattr(owner_slots, "CODE_PUBLIC_EXPOSURE_BUDGET", 10)
    state = StateStore(state_dir=tmp_path)
    server = create_server(bind_host="127.0.0.1", bind_port=0, state=state, bootloader_id="default-store",
                           ssl_context=None, capability_agent_tokens={AGENT_ID: AGENT_TOKEN, BRIDGE_ID: BRIDGE_TOKEN},
                           owner_code_minters={BRIDGE_ID})
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    c = {"base_url": f"http://{host}:{port}", "state": state, "challenges": BootloaderHandler.config.challenges}
    try:
        assert c["challenges"].code_minted is not None, "the server's own store mints unstamped codes"
        before = _mint(c, BRIDGE_ID, BRIDGE_TOKEN, {})
        for n in range(10):
            assert _code_get(c, _wrong(c, {before}), f"198.18.2.{n + 1}")[0] == 400
        fresh_owner = _mint(c, BRIDGE_ID, BRIDGE_TOKEN, {})
        fresh_member = _mint_member_code(c, "u-fresh")
        assert _code_get(c, fresh_owner, "203.0.113.80")[0] == 200, "a fresh owner code was burned"
        assert _code_get(c, fresh_member, "203.0.113.81")[0] == 200, "a fresh member code was burned"
        status, body = _code_get(c, before, "203.0.113.82")
        assert status == 400 and "exposed to too many wrong guesses" in str(body), body
    finally:
        _stop(server, thread)


def test_an_exposed_member_code_is_burned_and_a_fresh_one_redeems(ctx, monkeypatch) -> None:
    from recto.bootloader import owner_slots
    monkeypatch.setattr(owner_slots, "CODE_PUBLIC_EXPOSURE_BUDGET", 10)
    private_route = _mint_member_code(ctx, "u1")
    exposed = _mint_member_code(ctx, "u2")
    live = {private_route, exposed}
    for n in range(10):
        assert _code_get(ctx, _wrong(ctx, live), f"198.18.1.{n + 1}")[0] == 400
    assert _code_get(ctx, private_route, None)[0] == 200
    status, body = _code_get(ctx, exposed, "203.0.113.77")
    assert status == 400 and "exposed to too many wrong guesses" in str(body), body
    assert _code_get(ctx, exposed, None)[0] == 400, "a burned member code still redeemed"
    for _ in range(owner_slots.WRONG_CODE_LIMIT + 1):
        status, body = _code_get(ctx, exposed, "203.0.113.78")
        assert status == 400 and "already used" in str(body), body
    fresh = _mint_member_code(ctx, "u3")
    assert _code_get(ctx, fresh, "203.0.113.78")[0] == 200


def test_a_public_wrong_guess_over_the_budget_costs_two_consumes(ctx, monkeypatch) -> None:
    from recto.bootloader import owner_slots
    monkeypatch.setattr(owner_slots, "CODE_PUBLIC_EXPOSURE_BUDGET", 10)
    good, _ = ctx["challenges"].issue_pairing_code()
    for n in range(10):
        assert _code_get(ctx, _wrong(ctx, {good}), f"198.18.3.{n + 1}")[0] == 400
    calls: list[str] = []
    for name in ("consume_pairing_code", "consume_member_pairing_code"):
        real = getattr(ctx["challenges"], name)
        monkeypatch.setattr(ctx["challenges"], name,
                            lambda code, real=real, name=name: (calls.append(name), real(code))[1])
    assert _code_get(ctx, _wrong(ctx, {good}), "198.18.3.99")[0] == 400
    assert calls == ["consume_pairing_code", "consume_member_pairing_code"], calls


def test_a_mint_stamps_under_the_limiters_lock() -> None:
    from recto.bootloader.owner_slots import CodeAttemptLimiter
    limiter = CodeAttemptLimiter()
    owned: list[bool] = []
    real = limiter._trim
    limiter._trim = lambda now: (owned.append(limiter.lock._is_owned()), real(now))[1]
    store = ChallengeStore()
    store.code_minted = limiter.stamp
    store.issue_pairing_code()
    store.issue_member_pairing_code()
    assert owned and all(owned), owned


def _quiet_codes():
    return logging.getLogger("recto.bootloader.codes")


def test_the_exposure_clock(monkeypatch) -> None:
    """The stamp, the hour of marks, the mark interval and the spent memory, on a fake clock."""
    from recto.bootloader import owner_slots
    from recto.bootloader.owner_slots import CODE_MAX_TTL_SECONDS, SPENT_CODE_MEMORY_SECONDS, CodeAttemptLimiter
    monkeypatch.setattr(owner_slots, "CODE_PUBLIC_EXPOSURE_BUDGET", 10)
    _quiet_codes().disabled = True
    try:
        # (a) a stamped code counts from its stamp, for its whole life
        now = _fake_clock(monkeypatch, 1_000_000.0)
        lim = CodeAttemptLimiter()
        lim.stamp("111111")
        for n in range(10):
            lim.record_failure(f"198.18.6.{n}")
        lim.stamp("222222")
        now[0] = 1_000_000.0 + CODE_MAX_TTL_SECONDS - 1
        assert lim.exposed("111111") and not lim.exposed("222222")
        # (b) an unstamped code counts failures spread over 50 minutes
        now = _fake_clock(monkeypatch, 2_000_000.0)
        lim = CodeAttemptLimiter()
        for n in range(10):
            lim.record_failure(f"198.18.8.{n}")
            now[0] += 300
        assert lim.exposed("333333")
        # (c) failures older than the hour (and its minute) no longer count
        now = _fake_clock(monkeypatch, 3_000_000.0)
        lim = CodeAttemptLimiter()
        for n in range(10):
            lim.record_failure(f"198.18.10.{n}")
        now[0] += CODE_MAX_TTL_SECONDS + 61
        assert not lim.exposed("444444")
        # (d) the spent memory, both sides
        now = _fake_clock(monkeypatch, 4_000_000.0)
        lim = CodeAttemptLimiter()
        lim.record_spent("555555")
        now[0] += SPENT_CODE_MEMORY_SECONDS - 1
        assert lim.was_spent("555555")
        now[0] += 2
        assert not lim.was_spent("555555")
        # (e) the mark interval: a lone early failure, then a burst; the burst still counts after the first mark ages
        now = _fake_clock(monkeypatch, 5_000_000.0)
        lim = CodeAttemptLimiter()
        lim.record_failure("198.18.12.1")
        now[0] += 3000
        for n in range(10):
            lim.record_failure(f"198.18.13.{n}")
        now[0] = 5_000_000.0 + CODE_MAX_TTL_SECONDS + 61
        assert lim.exposed("666666")
        # (f) stamps are forgotten after their code's life
        now = _fake_clock(monkeypatch, 6_000_000.0)
        lim = CodeAttemptLimiter()
        lim.stamp("777777")
        now[0] += CODE_MAX_TTL_SECONDS + 61
        lim.was_spent("x")
        assert "777777" not in lim._stamps and not lim._stamp_order
        # (g) a code stamped again keeps its newer stamp when the older one's time comes
        now = _fake_clock(monkeypatch, 7_000_000.0)
        lim = CodeAttemptLimiter()
        lim.stamp("888888")
        now[0] += 70
        for n in range(10):
            lim.record_failure(f"198.18.14.{n}")
        now[0] += 30
        lim.stamp("888888")
        now[0] = 7_000_000.0 + CODE_MAX_TTL_SECONDS + 61
        assert not lim.exposed("888888")
        # (h) a stamp follows the code's own expiry
        now = _fake_clock(monkeypatch, 8_000_000.0)
        lim = CodeAttemptLimiter()
        lim.stamp("999999", expires_at=8_000_000.0 + 2 * CODE_MAX_TTL_SECONDS)
        for n in range(10):
            lim.record_failure(f"198.18.16.{n}")
        now[0] += 2 * CODE_MAX_TTL_SECONDS - 10
        lim.was_spent("x")                            # any call trims
        assert "999999" in lim._stamps and lim.exposed("999999"), "the stamp ended before its code"
        now[0] = 8_000_000.0 + 2 * CODE_MAX_TTL_SECONDS + 61
        lim.was_spent("x")
        assert "999999" not in lim._stamps, "the stamp outlived its code"
        # (i) the ChallengeStore hands the code's expiry to the stamp
        now = _fake_clock(monkeypatch, 10_000_000.0)
        lim = CodeAttemptLimiter()
        store = ChallengeStore()
        store.code_minted = lim.stamp
        long_code, _ = store.issue_pairing_code(ttl_seconds=2 * CODE_MAX_TTL_SECONDS)
        for n in range(10):
            lim.record_failure(f"198.18.22.{n}")
        now[0] += 2 * CODE_MAX_TTL_SECONDS - 10
        assert lim.exposed(long_code), "a long-lived code's stamp ended before the code"
        # (j) a short stamp behind a long one still leaves when it is due
        now = _fake_clock(monkeypatch, 11_000_000.0)
        lim = CodeAttemptLimiter()
        lim.stamp("121212", expires_at=11_000_000.0 + 2 * CODE_MAX_TTL_SECONDS)
        lim.stamp("343434", expires_at=11_000_000.0 + 60)
        now[0] += 121
        lim.was_spent("x")
        assert "343434" not in lim._stamps and "121212" in lim._stamps
    finally:
        _quiet_codes().disabled = False


def test_an_unstamped_code_is_counted_to_the_minute_at_the_end_of_its_life(monkeypatch) -> None:
    """A code minted elsewhere 59 s after a mark, a burst inside that mark's minute and a fresh mark at 61 s: checked
    near the end of the code's hour, every failure it lived through still counts."""
    from recto.bootloader import owner_slots
    from recto.bootloader.owner_slots import CodeAttemptLimiter
    monkeypatch.setattr(owner_slots, "CODE_PUBLIC_EXPOSURE_BUDGET", 1000)
    _quiet_codes().disabled = True
    try:
        now = _fake_clock(monkeypatch, 12_000_000.0)
        lim = CodeAttemptLimiter()
        lim.record_failure("198.18.24.1")                 # the mark at 0
        for n in range(1500):                          # the code is minted at 59; the burst follows within the minute
            now[0] = 12_000_059.5 + n * 0.0006
            lim.record_failure(f"198.19.{20 + n // 250}.{n % 250 + 1}")
        now[0] = 12_000_061.0
        lim.record_failure("198.18.24.2")                 # the next mark
        now[0] = 12_000_000.0 + 3659
        assert lim.exposed("565656")
    finally:
        _quiet_codes().disabled = False


def test_an_unstamped_code_is_never_counted_looser_at_the_hour_edge(monkeypatch) -> None:
    """A code minted elsewhere a second after a mark, with a burst inside that mark's minute, still reads exposed at
    the end of a full hour."""
    from recto.bootloader import owner_slots
    from recto.bootloader.owner_slots import CodeAttemptLimiter
    monkeypatch.setattr(owner_slots, "CODE_PUBLIC_EXPOSURE_BUDGET", 1000)
    _quiet_codes().disabled = True
    try:
        now = _fake_clock(monkeypatch, 9_000_000.0)
        lim = CodeAttemptLimiter()
        lim.record_failure("198.18.18.1")
        for n in range(1500):
            now[0] = 9_000_001.5 + n * 0.038
            lim.record_failure(f"198.19.{10 + n // 250}.{n % 250 + 1}")
        now[0] = 9_000_000.0 + 3600.5
        assert lim.exposed("123123")
    finally:
        _quiet_codes().disabled = False


# --------------------------------------------------------------------------
# the contest's reopen time, exactly
# --------------------------------------------------------------------------

def _whole_second_clock(monkeypatch) -> tuple[float, list[float]]:
    base = float(int(time.time()))
    offset = [0.0]
    monkeypatch.setattr(time, "time", lambda: base + offset[0])
    return base, offset


def test_reopens_at_is_a_second_by_which_no_pending_rival_counts(ctx, monkeypatch) -> None:
    """For a pending rival the value is one second late (its record is gone at created + 900): never early."""
    owner = Phone("owner")
    _enroll_genesis(ctx, owner)
    b, c = Phone("b"), Phone("c")
    base, offset = _whole_second_clock(monkeypatch)
    assert b.register(ctx, "recovery")[1].get("error") == "owner_approval_required"
    offset[0] = 600
    status, body = c.register(ctx, "recovery")
    assert body.get("error") == "owner_slot_contested" and body.get("reopens_at_unix") == base + 901, body
    offset[0] = 901
    status, body = c.register(ctx, "recovery")
    assert status == 403 and body.get("error") == "owner_approval_required", body


def test_reopens_at_holds_after_an_approval(ctx, monkeypatch) -> None:
    owner = Phone("owner")
    _enroll_genesis(ctx, owner)
    b, c = Phone("b"), Phone("c")
    base, offset = _whole_second_clock(monkeypatch)
    offset[0] = 100
    assert b.register(ctx, "recovery")[1].get("error") == "owner_approval_required"
    offset[0] = 200
    assert _approve(ctx, owner, _owner_cards(_signed_cards(ctx, owner))[0])[0] == 200
    offset[0] = 300
    status, body = c.register(ctx, "recovery")
    assert body.get("error") == "owner_slot_contested" and body.get("reopens_at_unix") == base + 1001, body
    offset[0] = 1000
    assert c.register(ctx, "recovery")[1].get("error") == "owner_slot_contested"
    offset[0] = 1001
    status, body = c.register(ctx, "recovery")
    assert body.get("error") != "owner_slot_contested", body


# --------------------------------------------------------------------------
# writes that land, writes that fail
# --------------------------------------------------------------------------

@pytest.mark.parametrize("fail_at", [1, 2, 3, 4])
def test_a_displacement_never_leaves_the_slot_empty_whichever_write_fails(ctx, monkeypatch, fail_at) -> None:
    """Pass 2 of a sole-owner replacement with the Nth store write failing (4: past the writes a displacement makes):
    the slot holds exactly one key, in memory and on disk."""
    owner, newer = Phone("old"), Phone("new")
    _enroll_genesis(ctx, owner)
    assert newer.register(ctx, "primary", replace=owner.ref)[0] == 403
    assert _approve(ctx, owner, _owner_cards(_signed_cards(ctx, owner))[0])[0] == 200
    real, calls = ctx["state"]._atomic_write, [0]

    def failing(path, body):
        calls[0] += 1
        if calls[0] == fail_at:
            raise OSError(28, "no space left on device")
        return real(path, body)

    monkeypatch.setattr(ctx["state"], "_atomic_write", failing)
    newer.register(ctx, "primary", replace=owner.ref)
    monkeypatch.undo()
    in_memory = [p.phone_id for p in ctx["state"].list_phones() if p.slot == "primary"]
    on_disk = [p.phone_id for p in StateStore(state_dir=ctx["state"].state_dir).list_phones() if p.slot == "primary"]
    assert in_memory in ([owner.ref], [newer.ref]) and on_disk == in_memory, (in_memory, on_disk)


def test_a_revoke_that_landed_answers_200_when_the_sessions_file_fails(ctx, monkeypatch) -> None:
    owner, second = Phone("owner"), Phone("second")
    _enroll_genesis(ctx, owner)
    _seed_owner(ctx, second, "recovery")
    real = ctx["state"]._atomic_write

    def failing(path, body):
        if Path(path).name == "sessions.json":
            raise OSError(28, "no space left on device")
        return real(path, body)

    monkeypatch.setattr(ctx["state"], "_atomic_write", failing)
    status, body = _revoke(ctx, owner, second.ref)
    assert status == 200, body
    monkeypatch.undo()
    assert second.ref not in [p.phone_id for p in StateStore(state_dir=ctx["state"].state_dir).list_phones()]


def test_an_approval_does_not_survive_a_restart(tmp_path) -> None:
    """Approvals live in memory: after a restart, pass 2 raises a new card - each pass needs its own code."""
    owner, newcomer = Phone("owner"), Phone("newcomer")
    with serving(tmp_path) as c:
        _enroll_genesis(c, owner)
        assert newcomer.register(c, "recovery")[0] == 403
        assert _approve(c, owner, _owner_cards(_signed_cards(c, owner))[0])[0] == 200
    with serving(tmp_path) as c:
        status, body = newcomer.register(c, "recovery")
        assert status == 403 and body.get("error") == "owner_approval_required", body
        assert len(_owner_cards(_signed_cards(c, owner))) == 1
        assert _holders(c) == {"primary": [owner.ref]}


# --------------------------------------------------------------------------
# the host CLI says what landed; names the file; refuses an empty --expect; hints by count
# --------------------------------------------------------------------------

def test_owner_reset_names_a_store_that_fails_to_write(tmp_path) -> None:
    owner = Phone("lost")
    with serving(tmp_path) as c:
        _enroll_genesis(c, owner)
    (tmp_path / "owner_genesis.json.tmp").mkdir()
    rc, text = _cli("bootloader", "owner-reset", "--state-dir", str(tmp_path), "--slot", "primary",
                    "--confirm", owner.ref, "--reopen-genesis")
    assert rc == 1 and "the store failed" in text and "nothing changed" in text and "Traceback" not in text, text
    (tmp_path / "owner_genesis.json.tmp").rmdir()
    rc, text = _cli("bootloader", "owner-slots", "--state-dir", str(tmp_path), "--expect", owner.ref)
    assert rc == 0, text


def test_owner_reset_says_what_landed_when_the_reopen_fails(tmp_path, monkeypatch) -> None:
    owner = Phone("lost")
    with serving(tmp_path) as c:
        _enroll_genesis(c, owner)
    real = StateStore.set_owner_genesis

    def failing(self, value):
        if value == "open":
            raise OSError(28, "no space left on device")
        return real(self, value)

    monkeypatch.setattr(StateStore, "set_owner_genesis", failing)
    rc, text = _cli("bootloader", "owner-reset", "--state-dir", str(tmp_path), "--slot", "primary",
                    "--confirm", owner.ref, "--reopen-genesis")
    assert rc == 1 and f"removed {owner.ref} from the primary slot" in text, text
    assert "`recto bootloader owner-reset --reopen-genesis` alone" in text, text
    monkeypatch.undo()
    fresh = StateStore(state_dir=tmp_path)
    assert [p for p in fresh.list_phones() if p.slot in ("primary", "recovery")] == []
    assert fresh.get_owner_genesis() == "closed"


def test_owner_reset_names_a_registry_lock_that_will_not_come(monkeypatch) -> None:
    import recto.cli as cli_module
    from recto.bootloader.state import RegistryLockUnavailable
    closed: list[bool] = []

    class Busy:
        def registry_lock(self):
            raise RegistryLockUnavailable("held by another instance")

        def close(self):
            closed.append(True)

    monkeypatch.setattr(cli_module, "_open_owner_store", lambda args, write: (Busy(), None))
    rc, text = _cli("bootloader", "owner-reset", "--reopen-genesis")
    assert rc == 1 and "RegistryLockUnavailable" in text and "nothing changed" in text, text
    assert closed == [True]


def test_an_unreadable_phones_file_is_named_and_the_marker_is_not_blamed(tmp_path) -> None:
    with serving(tmp_path) as c:
        _enroll_genesis(c, Phone("owner"))
    (tmp_path / "phones.json").write_text("{not json", encoding="utf-8")
    for argv in (("owner-slots",), ("owner-reset", "--reopen-genesis")):
        rc, text = _cli("bootloader", *argv, "--state-dir", str(tmp_path))
        assert rc == 1 and "cannot be read" in text and "phones.json" in text, (argv, text)
        assert "owner_genesis.json is repaired" not in text, (argv, text)


def test_an_empty_expect_item_is_refused(tmp_path) -> None:
    with serving(tmp_path):
        pass                                          # a registry with no owner, genesis open
    for expect in ("", ",", " , "):
        rc, text = _cli("bootloader", "owner-slots", "--state-dir", str(tmp_path), "--expect", expect)
        assert rc == 2 and "exactly" not in text, (expect, text)
    owner = Phone("owner")
    with serving(tmp_path) as c:
        _enroll_genesis(c, owner)
    for expect in (f"{owner.ref},", f",{owner.ref}"):
        rc, text = _cli("bootloader", "owner-slots", "--state-dir", str(tmp_path), "--expect", expect)
        assert rc == 2 and "exactly" not in text, (expect, text)


def test_the_reopen_hint_matches_the_owners_left(tmp_path) -> None:
    owner, second = Phone("owner"), Phone("second")
    with serving(tmp_path) as c:
        _enroll_genesis(c, owner)
    rc, text = _cli("bootloader", "owner-reset", "--state-dir", str(tmp_path), "--reopen-genesis")
    assert rc == 1 and f"--slot primary --confirm {owner.ref} --reopen-genesis" in text, text
    with serving(tmp_path) as c:
        _seed_owner(c, second, "recovery")
    rc, text = _cli("bootloader", "owner-reset", "--state-dir", str(tmp_path), "--reopen-genesis")
    assert rc == 1 and "revoke all but one from an owner phone in hand" in text, text
    assert "to remove it:" not in text, text
    assert StateStore(state_dir=tmp_path).get_owner_genesis() == "closed"


def test_owner_reset_refuses_a_phone_that_is_not_the_last_owner(tmp_path) -> None:
    """Ruled 2026-10-13: a lost non-sole phone is revoked over the network by another owner phone, 1-of-N."""
    owner, second = Phone("owner"), Phone("second")
    with serving(tmp_path) as c:
        _enroll_genesis(c, owner)
        _seed_owner(c, second, "recovery")
    for extra in ((), ("--reopen-genesis",)):
        rc, text = _cli("bootloader", "owner-reset", "--state-dir", str(tmp_path), "--slot", "recovery",
                        "--confirm", second.ref, *extra)
        assert rc == 1 and "is not the last owner phone" in text and "over the network" in text, (extra, text)
    rc, text = _cli("bootloader", "owner-slots", "--state-dir", str(tmp_path), "--expect", f"{owner.ref},{second.ref}")
    assert rc == 0, text


def test_a_state_dir_that_cannot_hold_a_lock_is_unavailable_not_held(tmp_path) -> None:
    from recto.bootloader.owner_slots import StoreLockUnavailable, _os_lock
    a_file = tmp_path / "not-a-dir"
    a_file.write_text("x", encoding="utf-8")
    with pytest.raises(StoreLockUnavailable):
        _os_lock(a_file)
    lock_is_a_dir = tmp_path / "d"
    (lock_is_a_dir / "bootloader.lock").mkdir(parents=True)
    with pytest.raises(StoreLockUnavailable):
        _os_lock(lock_is_a_dir)


# --------------------------------------------------------------------------
# the Postgres arm of the host CLI, on a stand-in driver (no database needed)
# --------------------------------------------------------------------------

_SENTINEL = "SENTINEL-PASSWORD"


def _fake_psycopg(monkeypatch, connect) -> types.ModuleType:
    import recto.bootloader.state_postgres  # noqa: F401 - imported before the stand-in, so it keeps its own names

    fake = types.ModuleType("psycopg")

    class Error(Exception):
        sqlstate = None

    class OperationalError(Error):
        sqlstate = "08006"

    class ProgrammingError(Error):
        sqlstate = "42501"

    for cls in (Error, OperationalError, ProgrammingError):
        cls.__module__ = "psycopg"
    fake.Error, fake.OperationalError, fake.ProgrammingError = Error, OperationalError, ProgrammingError
    fake.connect = lambda dsn, **kw: connect(fake)
    monkeypatch.setitem(sys.modules, "psycopg", fake)
    monkeypatch.setenv("RECTO_STATE_BACKEND", "postgres")
    monkeypatch.setenv("RECTO_POSTGRES_DSN", f"postgresql://user:{_SENTINEL}@db.invalid/recto")
    monkeypatch.setenv("RECTO_POSTGRES_SCHEMA", "recto_bootloader")
    return fake


class _Probe:
    def __init__(self, found: str | None = "recto_bootloader.phones", raises: Exception | None = None) -> None:
        self.found, self.raises = found, raises

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, *_a):
        if self.raises is not None:
            raise self.raises
        return types.SimpleNamespace(fetchone=lambda: (self.found,))


def _stub_store(monkeypatch, *, genesis="closed", raise_on: str | None = None, error: Exception | None = None):
    import recto.bootloader.state_postgres as spg
    made: list[Any] = []

    class Stub:
        def __init__(self, dsn, schema):
            if raise_on == "init":
                raise error
            self.closed = False
            made.append(self)

        def get_owner_genesis(self):
            if raise_on == "genesis":
                raise error
            return genesis

        def list_phones(self):
            self.listed = getattr(self, "listed", 0) + 1
            if raise_on == "list" or (raise_on == "list-again" and self.listed > 1):
                raise error
            return []

        def registry_lock(self):
            if raise_on == "lock":
                raise error
            return __import__("contextlib").nullcontext()

        def close(self):
            self.closed = True

    monkeypatch.setattr(spg, "PostgresStateStore", Stub)
    return made


def test_the_postgres_arm_names_an_unreachable_database_without_the_dsn(monkeypatch) -> None:
    _fake_psycopg(monkeypatch, lambda fake: (_ for _ in ()).throw(
        fake.OperationalError(f"connection to db.invalid failed: password {_SENTINEL} rejected")))
    rc, text = _cli("bootloader", "owner-slots")
    assert rc == 1 and "cannot reach the database: OperationalError 08006" in text, text
    assert _SENTINEL not in text and "db.invalid" not in text, text


def test_the_postgres_arm_names_a_refused_probe(monkeypatch) -> None:
    fake = _fake_psycopg(monkeypatch, lambda fake: _Probe(raises=fake.ProgrammingError(f"denied for {_SENTINEL}")))
    rc, text = _cli("bootloader", "owner-slots")
    assert rc == 1 and "the database refused the registry probe: ProgrammingError 42501" in text, text
    assert _SENTINEL not in text and fake is sys.modules["psycopg"]


def test_the_postgres_arm_refuses_a_schema_with_no_registry(monkeypatch) -> None:
    _fake_psycopg(monkeypatch, lambda fake: _Probe(found=None))
    made = _stub_store(monkeypatch)
    rc, text = _cli("bootloader", "owner-reset", "--reopen-genesis")
    assert rc == 1 and "no bootloader registry in schema 'recto_bootloader'" in text, text
    assert made == [], "the store (and its DDL) was built for a schema with no registry"


def test_the_postgres_arm_names_a_bad_marker_row_and_closes_the_store(monkeypatch) -> None:
    _fake_psycopg(monkeypatch, lambda fake: _Probe())
    made = _stub_store(monkeypatch, raise_on="genesis",
                       error=ValueError("registry_meta owner_genesis holds 'ajar'; expected one of ('open', 'closed')"))
    rc, text = _cli("bootloader", "owner-slots")
    assert rc == 1 and "cannot be read" in text and "'ajar'" in text and "repaired by hand" in text, text
    assert len(made) == 1 and made[0].closed


def test_the_postgres_arm_names_a_store_that_fails_to_open_by_type_only(monkeypatch) -> None:
    class PoolTimeout(Exception):
        pass

    PoolTimeout.__module__ = "psycopg_pool"
    _fake_psycopg(monkeypatch, lambda fake: _Probe())
    _stub_store(monkeypatch, raise_on="init", error=PoolTimeout(f"couldn't get a connection to {_SENTINEL}"))
    rc, text = _cli("bootloader", "owner-slots")
    assert rc == 1 and "cannot be read: the database refused (PoolTimeout)" in text, text
    assert _SENTINEL not in text and "repaired by hand" not in text, text


def test_the_postgres_arm_lists_a_populated_schema_and_closes_it(monkeypatch) -> None:
    _fake_psycopg(monkeypatch, lambda fake: _Probe())
    made = _stub_store(monkeypatch)
    rc, text = _cli("bootloader", "owner-slots")
    assert rc == 0 and "owner genesis: closed" in text and "(no owner phone)" in text, text
    assert len(made) == 1 and made[0].closed


def test_the_postgres_arm_names_a_registry_lock_failure_in_owner_reset(monkeypatch) -> None:
    from recto.bootloader.state import RegistryLockUnavailable
    _fake_psycopg(monkeypatch, lambda fake: _Probe())
    made = _stub_store(monkeypatch, raise_on="lock", error=RegistryLockUnavailable("not granted within 30 s"))
    rc, text = _cli("bootloader", "owner-reset", "--reopen-genesis")
    assert rc == 1 and "the store failed (RegistryLockUnavailable" in text and "nothing changed" in text, text
    assert "may still have landed" not in text, "no write ran, yet the text says one may have landed"
    assert len(made) == 1 and made[0].closed


def test_a_postgres_store_that_fails_to_open_closes_its_pool(monkeypatch) -> None:
    import recto.bootloader.state_postgres as spg
    pools: list[Any] = []

    class FakePool:
        def __init__(self, *_a, **_k):
            self.closed = False
            pools.append(self)

        def wait(self, timeout=None):
            raise RuntimeError("no server")

        def close(self):
            self.closed = True

    monkeypatch.setattr(spg, "_IMPORT_ERROR", None)
    monkeypatch.setattr(spg, "ConnectionPool", FakePool)
    with pytest.raises(RuntimeError):
        spg.PostgresStateStore("postgresql://nobody@db.invalid/x", schema="recto_bootloader")
    assert len(pools) == 1 and pools[0].closed


# --------------------------------------------------------------------------
# the runner - the single-agent flag, the no-agent banner, a held state dir
# --------------------------------------------------------------------------

def _runner_env(monkeypatch, tmp_path, **extra: str):
    import tests.test_capability_consumer_actions  # noqa: F401 - puts examples/ on sys.path
    import run_bootloader_consumer as rbc
    for name in [k for k in os.environ if k.startswith("RECTO_")]:
        monkeypatch.delenv(name)
    monkeypatch.setenv("RECTO_BOOTLOADER_ID", "runner-test")
    monkeypatch.setenv("RECTO_BIND_HOST", "127.0.0.1")
    monkeypatch.setenv("RECTO_STATE_DIR", str(tmp_path / "state"))
    for key, value in extra.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(rbc, "_configure_logging", lambda: 20)
    return rbc


def test_the_single_agent_flag_reaches_the_server(monkeypatch, tmp_path) -> None:
    import tests.test_capability_consumer_actions as tcca
    rbc = _runner_env(monkeypatch, tmp_path, RECTO_AGENT_ID="solo", RECTO_AGENT_TOKEN="c" * 64,
                      RECTO_AGENT_MAY_MINT_OWNER_CODES="1")

    def fake_create_server(**kwargs: Any) -> None:
        raise tcca._CreateServerCalled(kwargs)

    monkeypatch.setattr(rbc, "create_server", fake_create_server)
    with pytest.raises(tcca._CreateServerCalled) as reached:
        rbc.main()
    assert reached.value.kwargs["owner_code_minters"] == {"solo"}


def test_the_quiet_banner_with_no_agent_names_the_404(monkeypatch, tmp_path, capsys) -> None:
    from unittest import mock
    rbc = _runner_env(monkeypatch, tmp_path, RECTO_BOOTLOADER_QUIET="1")

    def fake_create_server(**kwargs: Any) -> Any:
        stub = mock.MagicMock()
        stub.server_address = ("127.0.0.1", 0)
        stub.serve_forever.side_effect = KeyboardInterrupt
        return stub

    monkeypatch.setattr(rbc, "create_server", fake_create_server)
    capsys.readouterr()
    assert rbc.main() == 0
    out = capsys.readouterr().out
    assert "No agent is registered, so POST /v0.4/pairing/code answers 404" in out, out
    assert "MEMBER codes only" not in out, out


def test_the_runner_refuses_a_held_state_dir_by_name(monkeypatch, tmp_path, capsys) -> None:
    from recto.bootloader.owner_slots import acquire_store_lock
    rbc = _runner_env(monkeypatch, tmp_path, RECTO_BOOTLOADER_QUIET="1", RECTO_BIND_PORT="0")
    held = acquire_store_lock(tmp_path / "state")
    assert held is not None
    outcome: dict[str, Any] = {}

    def run() -> None:
        outcome["rc"] = rbc.main()

    try:
        capsys.readouterr()
        runner = threading.Thread(target=run, daemon=True)   # a regression that serves would never return
        runner.start()
        runner.join(timeout=10)
        assert not runner.is_alive(), "the runner started serving on a held state dir"
        assert outcome.get("rc") == 2, outcome
        err = capsys.readouterr().err
        assert "ERROR: another process holds" in err and "owner-reset" in err and "Traceback" not in err, err
    finally:
        held.release()


# --------------------------------------------------------------------------
# a registry lock that will not come is named - 503 on the wire, a refusal at startup
# --------------------------------------------------------------------------

def test_a_busy_registry_lock_answers_503(ctx, monkeypatch, capsys) -> None:
    from recto.bootloader.state import RegistryLockUnavailable
    owner = Phone("owner")
    _enroll_genesis(ctx, owner)

    def busy():
        raise RegistryLockUnavailable("not granted within 30 s - another instance holds it")

    monkeypatch.setattr(ctx["state"], "registry_lock", busy)
    capsys.readouterr()
    status, body = Phone("newcomer").register(ctx, "recovery")
    assert status == 503 and body.get("error") == "registry_busy", body
    assert "[bootloader] registry lock unavailable on /v0.4/register" in capsys.readouterr().out
    assert _holders(ctx) == {"primary": [owner.ref]}


def test_a_busy_registry_lock_on_a_read_answers_503_and_says_so(ctx, monkeypatch, capsys) -> None:
    from recto.bootloader.server import BootloaderHandler
    from recto.bootloader.state import RegistryLockUnavailable

    def busy(self):
        raise RegistryLockUnavailable("not granted within 30 s - another instance holds it")

    monkeypatch.setattr(BootloaderHandler, "_handle_clusters_list", busy)
    capsys.readouterr()
    status, body = _http("GET", f"{ctx['base_url']}/v0.5/clusters")
    assert status == 503 and body.get("error") == "registry_busy", body
    assert "[bootloader] registry lock unavailable on /v0.5/clusters" in capsys.readouterr().out


def test_no_store_read_follows_the_startup_guard(tmp_path, monkeypatch, caplog) -> None:
    """A read after the guarded block could raise past it and keep the socket and the store lock (a database read
    fails on its own); the startup lines log the value read under the guard."""
    state = StateStore(state_dir=tmp_path)
    real_lock, real_read, released = state.registry_lock, state.get_owner_genesis, [0]

    @contextmanager
    def counting_lock():
        with real_lock():
            yield
        released[0] += 1

    def read_under_the_lock_only():
        if released[0]:
            raise OSError(104, "connection reset by peer")
        return real_read()

    monkeypatch.setattr(state, "registry_lock", counting_lock)
    monkeypatch.setattr(state, "get_owner_genesis", read_under_the_lock_only)
    with caplog.at_level(logging.INFO, logger="recto.bootloader.slots"):
        server = create_server(bind_host="127.0.0.1", bind_port=0, state=state, bootloader_id="one-read",
                               challenges=ChallengeStore(state=state), ssl_context=None)
    server.server_close()
    said = [r.getMessage() for r in caplog.records if r.name == "recto.bootloader.slots"]
    assert said[:2] == ["owner genesis: open; owner-code minters: none",
                        "owner genesis is OPEN: the next owner pairing code alone enrolls the first owner phone - pair "
                        "it now, over the operator's own route"], said
    _assert_store_lock_free(tmp_path)


def test_a_busy_registry_lock_at_startup_is_a_named_refusal(tmp_path, monkeypatch) -> None:
    from recto.bootloader.state import RegistryLockUnavailable
    state = StateStore(state_dir=tmp_path)

    def busy():
        raise RegistryLockUnavailable("not granted within 30 s")

    monkeypatch.setattr(state, "registry_lock", busy)
    with pytest.raises(BootloaderError, match="cannot decide the owner genesis marker"):
        create_server(bind_host="127.0.0.1", bind_port=0, state=state, bootloader_id="busy",
                      challenges=ChallengeStore(state=state), ssl_context=None)
    monkeypatch.undo()
    _assert_store_lock_free(tmp_path)


def _assert_store_lock_free(state_dir: Path) -> None:
    """Servers share their hold within one process, so only the host CLI's lock sees a hold a refused start leaked."""
    from recto.bootloader.owner_slots import acquire_store_lock
    lock = acquire_store_lock(state_dir)
    assert lock is not None, "a refused start kept its hold on the state dir"
    lock.release()


def test_a_refused_start_lets_go_of_the_state_dir(tmp_path) -> None:
    state = StateStore(state_dir=tmp_path)
    with pytest.raises(ValueError, match="signed_poll_mode"):
        create_server(bind_host="127.0.0.1", bind_port=0, state=state, bootloader_id="bad-mode",
                      challenges=ChallengeStore(state=state), ssl_context=None, signed_poll_mode="sometimes")
    _assert_store_lock_free(tmp_path)
    with serving(tmp_path) as c:
        _enroll_genesis(c, Phone("owner"))


def test_owner_slots_names_a_store_that_fails_after_it_opened(tmp_path, monkeypatch) -> None:
    with serving(tmp_path) as c:
        _enroll_genesis(c, Phone("owner"))

    def broken(self):
        raise OSError(5, "input/output error")

    monkeypatch.setattr(StateStore, "list_phones", broken)
    rc, text = _cli("bootloader", "owner-slots", "--state-dir", str(tmp_path))
    assert rc == 1 and "the store failed" in text and "nothing changed" in text and "Traceback" not in text, text


# --------------------------------------------------------------------------
# the refusal path is never counted; every refused start lets go; the CLI's remaining branches
# --------------------------------------------------------------------------

def test_a_refused_request_is_never_counted_as_a_failure(ctx, monkeypatch, caplog) -> None:
    from recto.bootloader import owner_slots
    from recto.bootloader.server import BootloaderHandler
    monkeypatch.setattr(owner_slots, "CODE_PUBLIC_EXPOSURE_BUDGET", 10)
    good, _ = ctx["challenges"].issue_pairing_code()
    assert _code_get(ctx, ctx["challenges"].issue_pairing_code()[0], "198.51.100.8")[0] == 200
    for _ in range(5):
        assert _code_get(ctx, _wrong(ctx, {good}), "203.0.113.5")[0] == 400
    assert not [r for r in caplog.records if "refused by the wrong-code limit" in r.getMessage()], caplog.records
    limiter = BootloaderHandler.config.code_limiter
    with caplog.at_level(logging.WARNING, logger="recto.bootloader.codes"):
        for _ in range(10):
            status, body = _code_get(ctx, good, "203.0.113.5")
            assert status == 429 and body.get("error") == "too_many_wrong_codes", body
    assert limiter._total == 5 and limiter._counts == {"203.0.113.5": 5}, (limiter._total, limiter._counts)
    lines = [r.getMessage() for r in caplog.records if "refused by the wrong-code limit" in r.getMessage()]
    assert lines == ["1 requests refused by the wrong-code limit since the last report"], lines
    assert _code_get(ctx, good, "198.51.100.7")[0] == 200


def test_every_named_refusal_at_startup_lets_go_of_the_state_dir(tmp_path, monkeypatch) -> None:
    import recto.capability.signing as signing

    def start(**kw: Any) -> None:
        state = StateStore(state_dir=tmp_path)
        if kw.pop("seal", False):
            state.put_operator_pubkey(bytes(range(64)))
        create_server(bind_host="127.0.0.1", bind_port=0, state=state, bootloader_id="refused",
                      challenges=ChallengeStore(state=state), ssl_context=None, **kw)

    with pytest.raises(BootloaderError, match="REFUSING TO START"):
        start(seal=True, capability_operator_pubkey=bytes(range(1, 65)))
    _assert_store_lock_free(tmp_path)
    with pytest.raises(ValueError, match="32 bytes"):
        start(devices_pair_signing_key=b"\x07" * 31)
    _assert_store_lock_free(tmp_path)

    def no_signer() -> None:
        raise RuntimeError("the signing extra is not installed")

    monkeypatch.setattr(signing, "require_signing", no_signer)
    with pytest.raises(RuntimeError, match="signing extra"):
        start(devices_pair_signing_key=b"\x07" * 32)
    _assert_store_lock_free(tmp_path)


@pytest.mark.parametrize("genesis", ["closed", "absent"])
def test_owner_reset_says_the_marker_landed_when_the_removal_fails(tmp_path, monkeypatch, genesis) -> None:
    from recto.bootloader import owner_slots
    owner = Phone("lost")
    with serving(tmp_path) as c:
        _enroll_genesis(c, owner)
    if genesis == "absent":
        (tmp_path / "owner_genesis.json").unlink()        # a registry from before the marker
    (tmp_path / "phones.json.tmp").mkdir()                # the removal's write fails for real
    real_acquire, taken = owner_slots.acquire_store_lock, []

    def keep(state_dir):
        lock = real_acquire(state_dir)
        taken.append(lock)
        return lock

    monkeypatch.setattr(owner_slots, "acquire_store_lock", keep)
    rc, text = _cli("bootloader", "owner-reset", "--state-dir", str(tmp_path), "--slot", "primary",
                    "--confirm", owner.ref, "--reopen-genesis")
    assert rc == 1 and "nothing removed (the genesis marker was written CLOSED)" in text, text
    assert "Traceback" not in text and "may still have landed" not in text, text
    again = real_acquire(tmp_path)
    assert again is not None, "the failed reset kept the store lock"
    again.release()
    (tmp_path / "phones.json.tmp").rmdir()
    fresh = StateStore(state_dir=tmp_path)
    assert [p.phone_id for p in fresh.list_phones()] == [owner.ref]
    assert fresh.get_owner_genesis() == "closed"


def test_a_wrong_confirm_on_a_store_with_no_owner_names_the_reopen(tmp_path) -> None:
    with serving(tmp_path):
        pass
    rc, text = _cli("bootloader", "owner-reset", "--state-dir", str(tmp_path), "--slot", "primary",
                    "--confirm", "pk_0000000000000000")
    assert rc == 1 and "no owner phone remains: `--reopen-genesis` alone reopens enrollment" in text, text


@pytest.mark.parametrize("name", ["phones.json", "sessions.json", "owner_genesis.json", "revocations.json"])
def test_the_cli_names_the_corrupt_file_and_blames_the_marker_only_for_itself(tmp_path, name) -> None:
    with serving(tmp_path) as c:
        _enroll_genesis(c, Phone("owner"))
    (tmp_path / name).write_text("{not json", encoding="utf-8")
    rc, text = _cli("bootloader", "owner-slots", "--state-dir", str(tmp_path))
    assert rc == 1 and "cannot be read" in text and name in text, text
    assert ("repaired by hand" in text) == (name == "owner_genesis.json"), text


def test_the_postgres_arm_names_a_malformed_phones_row_without_blaming_the_marker(monkeypatch) -> None:
    _fake_psycopg(monkeypatch, lambda fake: _Probe())
    made = _stub_store(monkeypatch, raise_on="list", error=TypeError("unexpected field 'no_such_field'"))
    rc, text = _cli("bootloader", "owner-slots")
    assert rc == 1 and "a row in recto_bootloader.phones is malformed" in text, text
    assert "repaired by hand" not in text and "database refused" not in text, text
    assert len(made) == 1 and made[0].closed


def test_the_postgres_arm_names_a_database_error_reading_the_phones(monkeypatch) -> None:
    fake = _fake_psycopg(monkeypatch, lambda fake: _Probe())
    made = _stub_store(monkeypatch, raise_on="list",
                       error=fake.OperationalError(f"server db.invalid closed the connection ({_SENTINEL})"))
    rc, text = _cli("bootloader", "owner-slots")
    assert rc == 1 and "the database refused (OperationalError 08006)" in text, text
    assert _SENTINEL not in text and "db.invalid" not in text and made[0].closed, text


def test_the_postgres_arm_names_a_failure_after_the_store_opened(monkeypatch) -> None:
    fake = _fake_psycopg(monkeypatch, lambda fake: _Probe())
    made = _stub_store(monkeypatch, raise_on="list-again",
                       error=fake.OperationalError(f"server db.invalid went away ({_SENTINEL})"))
    rc, text = _cli("bootloader", "owner-slots")
    assert rc == 1 and "the store failed (OperationalError 08006)" in text, text
    assert _SENTINEL not in text and "db.invalid" not in text and made[0].closed, text


def test_a_postgres_store_whose_ddl_fails_closes_its_pool(monkeypatch) -> None:
    import recto.bootloader.state_postgres as spg
    pools: list[Any] = []

    class FakePool:
        def __init__(self, *_a, **_k):
            self.closed = False
            pools.append(self)

        def wait(self, timeout=None):
            return None

        def close(self):
            self.closed = True

    def ddl_fails(self):
        raise RuntimeError("permission denied for schema")

    monkeypatch.setattr(spg, "_IMPORT_ERROR", None)
    monkeypatch.setattr(spg, "ConnectionPool", FakePool)
    monkeypatch.setattr(spg.PostgresStateStore, "_ensure_schema", ddl_fails)
    with pytest.raises(RuntimeError, match="permission denied"):
        spg.PostgresStateStore("postgresql://nobody@db.invalid/x", schema="recto_bootloader")
    assert len(pools) == 1 and pools[0].closed


# --------------------------------------------------------------------------
# the Postgres registry lock on a stand-in pool - its one deadline, its refusal, its re-entrancy
# --------------------------------------------------------------------------

class _LockConn:
    def __init__(self, pool: "_LockPool") -> None:
        self.pool = pool
        self.info = types.SimpleNamespace(server_version=160000)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.pool.ended.append("rollback" if exc_type else "commit")
        return False

    def execute(self, sql, params=None):
        self.pool.statements.append(sql)
        if "pg_advisory_xact_lock" in sql and self.pool.busy:
            error = RuntimeError("canceling statement due to lock timeout")
            error.sqlstate = "55P03"
            raise error
        return types.SimpleNamespace(fetchone=lambda: (None,))


class _LockPool:
    def __init__(self, *_a, **_k) -> None:
        self.busy = False
        self.out = 0
        self.statements: list[str] = []
        self.ended: list[str] = []

    def wait(self, timeout=None):
        return None

    def close(self):
        return None

    @contextmanager
    def connection(self):
        conn = _LockConn(self)
        self.out += 1
        try:
            with conn:                                # psycopg_pool's own shape: the body inside `with conn:`
                yield conn
        finally:
            self.out -= 1


def _stand_in_store(monkeypatch):
    import recto.bootloader.state_postgres as spg
    monkeypatch.setattr(spg, "_IMPORT_ERROR", None)
    monkeypatch.setattr(spg, "ConnectionPool", _LockPool)
    monkeypatch.setattr(spg.PostgresStateStore, "_ensure_schema", lambda self: None)
    return spg, spg.PostgresStateStore("postgresql://nobody@db.invalid/x", schema="recto_bootloader")


def test_a_postgres_lock_whose_release_fails_is_logged_and_the_act_stands(monkeypatch, caplog) -> None:
    spg, store = _stand_in_store(monkeypatch)

    def release_fails(self, exc_type, exc, tb):
        self.pool.ended.append("rollback" if exc_type else "failed commit")
        if exc_type is None:
            raise RuntimeError("server closed the connection unexpectedly")
        return False

    monkeypatch.setattr(_LockConn, "__exit__", release_fails)
    with caplog.at_level(logging.ERROR, logger="recto.bootloader.state"):
        with store.registry_lock():
            pass
    said = [r.getMessage() for r in caplog.records if r.name == "recto.bootloader.state"]
    assert any("ending the lock's transaction failed" in m for m in said), said
    assert store._pool.ended == ["failed commit"] and store._pool.out == 0 and store._registry_depth == 0
    assert _rlock_free_from_another_thread(store)


def test_the_postgres_registry_lock_bounds_and_names_its_wait(monkeypatch) -> None:
    from recto.bootloader.state import RegistryLockUnavailable
    spg, store = _stand_in_store(monkeypatch)
    pool = store._pool
    with store.registry_lock():
        with store.registry_lock():                   # nested: one hold, one set of statements
            pass
    assert pool.statements.count("SELECT pg_advisory_xact_lock(%s)") == 1, pool.statements
    lock_at = pool.statements.index("SELECT pg_advisory_xact_lock(%s)")
    timeout_sets = [s for s in pool.statements[:lock_at] if s.startswith("SET LOCAL lock_timeout = '")]
    assert len(timeout_sets) == 1 and timeout_sets[0].endswith("ms'"), pool.statements
    assert int(timeout_sets[0].split("'")[1][:-2]) >= 1
    assert "SET LOCAL statement_timeout = 0" in pool.statements[:lock_at], pool.statements
    assert "SET LOCAL idle_in_transaction_session_timeout = 0" in pool.statements[:lock_at], pool.statements
    assert "SET LOCAL transaction_timeout = 0" not in pool.statements, "a setting PG16 does not know was sent"
    assert pool.ended == ["commit"] and pool.out == 0
    pool.busy, pool.ended = True, []
    with pytest.raises(RegistryLockUnavailable, match="not granted"):
        with store.registry_lock():
            pass
    assert pool.ended == ["rollback"] and pool.out == 0 and store._registry_depth == 0
    assert _rlock_free_from_another_thread(store)


def test_the_postgres_registry_lock_refuses_a_thread_queued_past_the_deadline(monkeypatch) -> None:
    from recto.bootloader.state import RegistryLockUnavailable
    spg, store = _stand_in_store(monkeypatch)
    monkeypatch.setattr(spg, "REGISTRY_LOCK_WAIT_SECONDS", 0.5)
    holding, release = threading.Event(), threading.Event()

    def hold() -> None:
        with store.registry_lock():
            holding.set()
            release.wait(10)

    holder = threading.Thread(target=hold, daemon=True)
    holder.start()
    assert holding.wait(5)
    outcome: dict = {}

    def queue() -> None:
        t0 = time.monotonic()
        try:
            with store.registry_lock():
                outcome["granted"] = True
        except RegistryLockUnavailable:
            outcome["refused_after"] = time.monotonic() - t0

    waiter = threading.Thread(target=queue, daemon=True)
    waiter.start()
    waiter.join(timeout=5)
    release.set()
    holder.join(timeout=5)
    assert not waiter.is_alive() and "refused_after" in outcome, outcome
    assert 0.4 <= outcome["refused_after"] < spg.REGISTRY_LOCK_WAIT_SECONDS + 0.4, outcome
    assert not holder.is_alive() and _rlock_free_from_another_thread(store) and store._registry_depth == 0


def test_the_postgres_registry_lock_never_sends_a_zero_lock_timeout(monkeypatch) -> None:
    from recto.bootloader.state import RegistryLockUnavailable
    spg, store = _stand_in_store(monkeypatch)
    monkeypatch.setattr(spg, "REGISTRY_LOCK_WAIT_SECONDS", 0.0001)
    with pytest.raises(RegistryLockUnavailable):
        with store.registry_lock():
            pass
    assert not any(s.startswith("SET LOCAL lock_timeout") for s in store._pool.statements), store._pool.statements
    assert store._pool.out == 0 and _rlock_free_from_another_thread(store)


# --------------------------------------------------------------------------
# the stateless ChallengeStore under concurrent mints and redemptions
# --------------------------------------------------------------------------

@pytest.mark.parametrize("purge", ["issue_member_pairing_code", "issue_pairing_code", "issue_challenge",
                                   "consume_challenge", "consume_owner_challenge", "consume_member_challenge"])
def test_a_stateless_store_never_redeems_a_code_twice_under_a_concurrent_purge(purge) -> None:
    """The overlap made certain: the purging thread stops inside its rebuild of the code dict while a redemption runs.
    With the store's lock the redemption waits for the rebuild; without it, the rebuild writes the redeemed code back."""
    store = ChallengeStore()
    code, _ = store.issue_pairing_code()
    in_purge, go_on = threading.Event(), threading.Event()
    purger: dict[str, Any] = {}

    class Slow(dict):
        def items(self):
            snapshot = list(super().items())
            if threading.current_thread() is purger.get("thread"):
                in_purge.set()
                go_on.wait(5)
            return snapshot

    store._pairing_codes = Slow(store._pairing_codes)
    errors: list[BaseException] = []
    results: list[bool] = []

    def run_purge() -> None:
        try:
            method = getattr(store, purge)
            method("nope") if purge.startswith("consume") else method()
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    def redeem() -> None:
        try:
            results.append(store.consume_pairing_code(code))
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    thread = threading.Thread(target=run_purge, daemon=True)
    purger["thread"] = thread
    thread.start()
    assert in_purge.wait(5)
    redeemer = threading.Thread(target=redeem, daemon=True)
    redeemer.start()
    redeemer.join(0.5)
    go_on.set()
    thread.join(5)
    redeemer.join(5)
    assert errors == [] and results == [True], (errors, results)
    assert store.consume_pairing_code(code) is False, "a redeemed code came back"


# --------------------------------------------------------------------------
# The registry lock's bounds, the CLI's Postgres refusals, the signing-key refusals
# --------------------------------------------------------------------------

def _rlock_free_from_another_thread(store) -> bool:
    """A re-entrant lock re-acquires on its owner thread whatever it holds: only another thread sees a leak."""
    got: list[bool] = []

    def probe() -> None:
        ok = store._registry_rlock.acquire(blocking=False)
        got.append(ok)
        if ok:
            store._registry_rlock.release()

    thread = threading.Thread(target=probe)
    thread.start()
    thread.join(5)
    return got == [True]


def test_the_database_wait_is_what_is_left_of_the_one_deadline(monkeypatch) -> None:
    spg, store = _stand_in_store(monkeypatch)
    monkeypatch.setattr(spg, "REGISTRY_LOCK_WAIT_SECONDS", 0.5)
    clock = [0.0]
    monkeypatch.setattr(spg, "time", types.SimpleNamespace(monotonic=lambda: clock[0], time=time.time))
    real, calls = store._registry_rlock, []

    class Slow:
        def acquire(self, blocking=True, timeout=-1):
            calls.append((blocking, timeout))
            clock[0] += 0.25                          # a quarter second spent waiting in this process
            return real.acquire(blocking, timeout)

        def release(self):
            real.release()

    store._registry_rlock = Slow()
    with store.registry_lock():
        pass
    assert "SET LOCAL lock_timeout = '250ms'" in store._pool.statements, store._pool.statements
    assert calls and calls[0][0] is True and 0 < calls[0][1] <= 0.5, calls


def test_the_postgres_registry_lock_lifts_the_transaction_cutoff_on_pg17(monkeypatch) -> None:
    spg, store = _stand_in_store(monkeypatch)
    real_connection = store._pool.connection

    @contextmanager
    def pg17():
        with real_connection() as conn:
            conn.info = types.SimpleNamespace(server_version=170000)
            yield conn

    store._pool.connection = pg17
    with store.registry_lock():
        pass
    lock_at = store._pool.statements.index("SELECT pg_advisory_xact_lock(%s)")
    assert "SET LOCAL transaction_timeout = 0" in store._pool.statements[:lock_at], store._pool.statements


def test_the_postgres_arm_names_a_database_error_reading_the_marker_and_closes_the_store(monkeypatch) -> None:
    fake = _fake_psycopg(monkeypatch, lambda fake: _Probe())
    made = _stub_store(monkeypatch, raise_on="genesis",
                       error=fake.OperationalError(f"server db.invalid went away ({_SENTINEL})"))
    rc, text = _cli("bootloader", "owner-slots")
    assert rc == 1 and "the database refused (OperationalError 08006)" in text, text
    assert "repaired by hand" not in text and _SENTINEL not in text, text
    assert len(made) == 1 and made[0].closed


def test_a_postgres_write_that_failed_may_have_landed_and_the_text_says_so(monkeypatch) -> None:
    import recto.bootloader.state_postgres as spg
    fake = _fake_psycopg(monkeypatch, lambda fake: _Probe())
    made = _stub_store(monkeypatch, genesis="closed")
    stub = spg.PostgresStateStore

    def failing_write(self, value):
        raise fake.OperationalError(f"server db.invalid closed the connection ({_SENTINEL})")

    monkeypatch.setattr(stub, "set_owner_genesis", failing_write, raising=False)
    rc, text = _cli("bootloader", "owner-reset", "--reopen-genesis")
    assert rc == 1 and "nothing changed (on Postgres the failed write may still have landed)" in text, text
    assert _SENTINEL not in text and made[0].closed, text


def test_an_invalid_signing_key_lets_go_of_the_state_dir(tmp_path) -> None:
    state = StateStore(state_dir=tmp_path)
    with pytest.raises(ValueError):
        create_server(bind_host="127.0.0.1", bind_port=0, state=state, bootloader_id="bad-key",
                      challenges=ChallengeStore(state=state), ssl_context=None, devices_pair_signing_key=b"\x00" * 32)
    _assert_store_lock_free(tmp_path)


@pytest.mark.parametrize("fails", ["closed", "revoke", "reopen"])
def test_the_postgres_slot_path_says_what_may_have_landed(monkeypatch, fails) -> None:
    """The Postgres arm's slot path: every failure after a write began carries the 'may still have landed' clause,
    and a failed final reopen never claims genesis stays closed."""
    import recto.bootloader.state_postgres as spg
    fake = _fake_psycopg(monkeypatch, lambda fake: _Probe())
    owner = Phone("owner")
    row = PhoneRegistration.new(device_label="owner", public_key_b64u=owner.pub, supported_algorithms=("ed25519",),
                                poll_public_key_b64u=owner.poll_pub, slot="primary")
    made: list[Any] = []

    class OneOwner:
        def __init__(self, dsn, schema):
            self.closed = False
            made.append(self)

        def get_owner_genesis(self):
            return "closed"

        def list_phones(self):
            return [row]

        def registry_lock(self):
            return __import__("contextlib").nullcontext()

        def set_owner_genesis(self, value):
            if (fails, value) in (("closed", "closed"), ("reopen", "open")):
                raise fake.OperationalError(f"server db.invalid closed the connection ({_SENTINEL})")

        def revoke_phone(self, phone_id):
            if fails == "revoke":
                raise fake.OperationalError(f"server db.invalid closed the connection ({_SENTINEL})")
            return True

        def list_owner_enrolls(self):
            return []

        def close(self):
            self.closed = True

    monkeypatch.setattr(spg, "PostgresStateStore", OneOwner)
    rc, text = _cli("bootloader", "owner-reset", "--slot", "primary", "--confirm", owner.ref, "--reopen-genesis")
    assert rc == 1 and "(on Postgres the failed write may still have landed)" in text, text
    assert "the store failed (OperationalError 08006)" in text, text
    expected = {"closed": "nothing changed", "revoke": "nothing removed (the genesis marker was written CLOSED)",
                "reopen": f"{owner.ref} was removed from the primary slot, but genesis could not be reopened - run"}
    assert expected[fails] in text and "stays CLOSED" not in text, text
    assert _SENTINEL not in text and "db.invalid" not in text and made[0].closed, text


def test_stamps_leave_when_they_are_due_whatever_order_they_came_in(monkeypatch) -> None:
    from recto.bootloader.owner_slots import CodeAttemptLimiter
    now = _fake_clock(monkeypatch, 13_000_000.0)
    lim = CodeAttemptLimiter()
    for code, life in (("100010", 10), ("100030", 30), ("100020", 20), ("100040", 40)):
        lim.stamp(code, expires_at=13_000_000.0 + life)    # each stamp is forgotten at its expiry + 60
    now[0] = 13_000_000.0 + 85                             # due: 70 and 80; not yet: 90 and 100
    lim.was_spent("x")
    assert sorted(lim._stamps) == ["100030", "100040"], sorted(lim._stamps)


# --------------------------------------------------------------------------
# The genesis marker beside an owner phone (a close that did not land)
# --------------------------------------------------------------------------

def _force_open(state_dir: Path) -> None:
    (state_dir / "owner_genesis.json").write_text(json.dumps({"state": "open"}), encoding="utf-8")


def test_owner_slots_exits_1_while_genesis_is_open_beside_an_owner(tmp_path) -> None:
    owner = Phone("owner")
    with serving(tmp_path) as c:
        _enroll_genesis(c, owner)
    _force_open(tmp_path)
    rc, text = _cli("bootloader", "owner-slots", "--state-dir", str(tmp_path), "--expect", owner.ref)
    assert rc == 1 and "!! owner genesis is OPEN while an owner slot is held" in text, text


def test_a_start_closes_genesis_left_open_beside_an_owner(tmp_path, caplog) -> None:
    owner = Phone("owner")
    with serving(tmp_path) as c:
        _enroll_genesis(c, owner)
    _force_open(tmp_path)
    caplog.clear()                                       # only the second start's lines
    with caplog.at_level(logging.DEBUG):
        with serving(tmp_path) as c:
            assert c["state"].get_owner_genesis() == "closed"
            status, body = Phone("stranger").register(c, "recovery")
            assert status == 403 and body.get("error") == "owner_approval_required", body
    repaired = [r.getMessage() for r in caplog.records if r.name == "recto.bootloader.slots"]
    assert "owner genesis was open beside an owner phone - closed" in repaired, repaired
    assert "owner genesis: closed; owner-code minters: none" in repaired, repaired
    assert not any("owner genesis is OPEN" in m for m in repaired), repaired
    rc, text = _cli("bootloader", "owner-slots", "--state-dir", str(tmp_path), "--expect", owner.ref)
    assert rc == 0 and "owner genesis: closed" in text, text


def test_an_open_genesis_is_logged_as_a_warning_at_startup(tmp_path, caplog) -> None:
    with caplog.at_level(logging.WARNING, logger="recto.bootloader.slots"):
        with serving(tmp_path):
            pass
    assert any("owner genesis is OPEN" in r.getMessage() for r in caplog.records)


def test_the_bootloader_logs_each_owner_slot_act(tmp_path, caplog) -> None:
    """The bootloader is a server its operator runs: it logs each owner-slot act (the phone app logs nothing)."""
    owner, second, newcomer, other = Phone("owner"), Phone("second"), Phone("newcomer"), Phone("other")
    with caplog.at_level(logging.WARNING, logger="recto.bootloader.slots"):
        with serving(tmp_path) as c:
            _enroll_genesis(c, owner)
            _enroll_approved(c, second, "recovery", approver=owner)
            assert newcomer.register(c, "recovery", replace=second.ref)[0] == 403
            assert _approve(c, owner, _owner_cards(_signed_cards(c, owner))[0])[0] == 200
            assert newcomer.register(c, "recovery", replace=second.ref)[0] == 201
            assert other.register(c, "recovery", replace=newcomer.ref)[0] == 403
            card = _owner_cards(_signed_cards(c, owner))[0]
            assert _approve(c, Phone("impostor"), card)[0] == 400       # a signature by the wrong key approves nothing
            third = Phone("third")
            assert third.register(c, "recovery", replace=newcomer.ref)[1].get("error") == "owner_slot_contested"
    lines = [r.getMessage() for r in caplog.records if r.name == "recto.bootloader.slots"]
    displaced = [m for m in lines if " displaced " in m]
    assert len(displaced) == 1 and displaced[0].endswith(f"(approved by {owner.ref})"), displaced
    assert len([m for m in lines if m.startswith("owner enroll approved:")]) == 2, lines
    assert any(m.startswith("owner genesis: slot=primary enrolled phone_id=" + owner.ref) for m in lines), lines
    assert any(m.startswith("owner enroll requested: slot=recovery phone_id=" + newcomer.ref) for m in lines), lines
    assert any(m.startswith(f"owner enroll approved: slot=recovery phone_id={newcomer.ref} by {owner.ref}")
               for m in lines), lines
    assert any(m.startswith(f"slot=recovery displaced phone_id={second.ref} by phone_id={newcomer.ref}")
               for m in lines), lines
    assert any(m.startswith(f"owner enroll: slot=recovery phone_id={newcomer.ref} approved by {owner.ref}")
               for m in lines), lines
    assert any("contested by phone_id=" in m and m.endswith("- refused") for m in lines), lines


# --------------------------------------------------------------------------
# The last owner with a member present; two members' lists
# --------------------------------------------------------------------------

def test_the_last_owner_is_never_revoked_while_a_member_exists(ctx) -> None:
    owner, member = Phone("owner"), Phone("member")
    _enroll_genesis(ctx, owner)
    assert member.register(ctx, "primary", challenge=_member_challenge(ctx, "u1"))[0] == 201
    status, body = _revoke(ctx, owner, owner.ref)
    assert status == 403 and body.get("error") == "last_owner", body
    assert _holders(ctx) == {"primary": [owner.ref], MEMBER_SLOT: [member.ref]}


def _signed_list(ctx, phone: Phone, path: str = "/v0.4/manage/phones"):
    from recto.bootloader.server import POLL_SIG_HEADER, POLL_SIG_PREFIX, POLL_SIG_TS_HEADER
    ts = int(time.time())
    sig = phone.poll.sign(f"{POLL_SIG_PREFIX}|{phone.ref}|{ts}|{path}".encode("ascii"))
    return _http("GET", f"{ctx['base_url']}{path}?phone_id={phone.ref}",
                 headers={POLL_SIG_HEADER: _b64(sig), POLL_SIG_TS_HEADER: str(ts)})


def test_a_member_lists_no_other_member(ctx) -> None:
    owner, m1, m2 = Phone("owner"), Phone("m1"), Phone("m2")
    _enroll_genesis(ctx, owner)
    assert m1.register(ctx, "primary", challenge=_member_challenge(ctx, "u1"))[0] == 201
    assert m2.register(ctx, "primary", challenge=_member_challenge(ctx, "u2"))[0] == 201
    status, body = _signed_list(ctx, m1)
    assert status == 200 and body.get("phones") == [], body


# --------------------------------------------------------------------------
# Both signed-read gates against forged headers (advisory mode)
# --------------------------------------------------------------------------

def _forged_headers(phone: Phone, path: str, forgery: str) -> dict[str, str]:
    from recto.bootloader.server import POLL_SIG_HEADER, POLL_SIG_PREFIX, POLL_SIG_TS_HEADER
    ts = int(time.time())
    if forgery == "zero-signature":
        return {POLL_SIG_HEADER: _b64(b"\x00" * 64), POLL_SIG_TS_HEADER: str(ts)}
    if forgery == "identity-key":
        sig = phone.identity.sign(f"{POLL_SIG_PREFIX}|{phone.ref}|{ts}|{path}".encode("ascii"))
        return {POLL_SIG_HEADER: _b64(sig), POLL_SIG_TS_HEADER: str(ts)}
    if forgery == "stale":
        old = ts - 3600
        sig = phone.poll.sign(f"{POLL_SIG_PREFIX}|{phone.ref}|{old}|{path}".encode("ascii"))
        return {POLL_SIG_HEADER: _b64(sig), POLL_SIG_TS_HEADER: str(old)}
    other = "/v0.4/pending" if path == "/v0.4/manage/phones" else "/v0.4/manage/phones"
    sig = phone.poll.sign(f"{POLL_SIG_PREFIX}|{phone.ref}|{ts}|{other}".encode("ascii"))
    return {POLL_SIG_HEADER: _b64(sig), POLL_SIG_TS_HEADER: str(ts)}


@pytest.mark.parametrize("forgery", ["zero-signature", "identity-key", "stale", "wrong-path"])
def test_a_forged_read_gets_neither_the_list_nor_an_owner_card(ctx, forgery) -> None:
    owner, newcomer = Phone("owner"), Phone("newcomer")
    _enroll_genesis(ctx, owner)
    assert newcomer.register(ctx, "recovery")[0] == 403          # an owner card waits on the owner's queue
    assert len(_owner_cards(_signed_cards(ctx, owner))) == 1
    status, body = _http("GET", f"{ctx['base_url']}/v0.4/manage/phones?phone_id={owner.ref}",
                         headers=_forged_headers(owner, "/v0.4/manage/phones", forgery))
    assert status == 401 and body.get("error") == "poll_signature_invalid", body
    status, body = _http("GET", f"{ctx['base_url']}/v0.4/pending?phone_id={owner.ref}",
                         headers=_forged_headers(owner, "/v0.4/pending", forgery))
    assert status == 200 and _owner_cards(body.get("requests", [])) == [], body


# --------------------------------------------------------------------------
# The ruled approver set at pass 2
# --------------------------------------------------------------------------

def test_a_self_approval_stops_counting_once_a_second_owner_joins(ctx) -> None:
    """The sole owner P approves its own replacement by N; R then joins in recovery. The rules now name R as the
    approver for replacing P, so N's next pass raises a card on R's queue - P's earlier approval is spent nowhere."""
    p, n, r = Phone("p"), Phone("n"), Phone("r")
    _enroll_genesis(ctx, p)
    assert n.register(ctx, "primary", replace=p.ref)[0] == 403
    assert _approve(ctx, p, _owner_cards(_signed_cards(ctx, p))[0])[0] == 200
    _enroll_approved(ctx, r, "recovery", approver=p)
    status, body = n.register(ctx, "primary", replace=p.ref)
    assert status == 403 and body.get("error") == "owner_approval_required", body
    assert len(_owner_cards(_signed_cards(ctx, r))) == 1
    assert _owner_cards(_signed_cards(ctx, p)) == []
    assert _holders(ctx) == {"primary": [p.ref], "recovery": [r.ref]}


# --------------------------------------------------------------------------
# The startup code only while genesis is open
# --------------------------------------------------------------------------

@pytest.mark.parametrize("genesis", ["open", "closed"])
def test_the_startup_code_is_printed_only_while_genesis_is_open(monkeypatch, tmp_path, capsys, genesis) -> None:
    from unittest import mock
    rbc = _runner_env(monkeypatch, tmp_path)
    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "owner_genesis.json").write_text(json.dumps({"state": genesis}), encoding="utf-8")

    def fake_create_server(**kwargs: Any) -> Any:
        stub = mock.MagicMock()
        stub.server_address = ("127.0.0.1", 0)
        stub.serve_forever.side_effect = KeyboardInterrupt
        return stub

    monkeypatch.setattr(rbc, "create_server", fake_create_server)
    capsys.readouterr()
    assert rbc.main() == 0
    out = capsys.readouterr().out
    if genesis == "open":
        assert "PAIRING CODE:" in out, out
    else:
        assert "PAIRING CODE:" not in out and "owner genesis is closed" in out, out


# --------------------------------------------------------------------------
# A removed phone's approvals die with it, even when its key pairs again
# --------------------------------------------------------------------------

def test_an_approval_given_by_a_revoked_owner_never_revives_when_its_key_pairs_again(ctx) -> None:
    p, r, n = Phone("p"), Phone("r"), Phone("n")
    _enroll_genesis(ctx, p)
    _enroll_approved(ctx, r, "recovery", approver=p)
    assert n.register(ctx, "recovery", replace=r.ref)[0] == 403
    assert _approve(ctx, p, _owner_cards(_signed_cards(ctx, p))[0])[0] == 200
    assert _revoke(ctx, r, p.ref)[0] == 200                 # the operator cancels P's approval the only way there is
    _enroll_approved(ctx, p, "primary", approver=r)          # P's key comes back
    status, body = n.register(ctx, "recovery", replace=r.ref)
    assert status == 403 and body.get("error") == "owner_approval_required", body
    assert _holders(ctx) == {"primary": [p.ref], "recovery": [r.ref]}


def test_an_approval_naming_a_revoked_occupant_never_revives_when_its_key_pairs_again(ctx, monkeypatch) -> None:
    p, r, n = Phone("p"), Phone("r"), Phone("n")
    _enroll_genesis(ctx, p)
    _enroll_approved(ctx, r, "recovery", approver=p)
    base, offset = _whole_second_clock(monkeypatch)
    assert n.register(ctx, "recovery", replace=r.ref)[0] == 403
    offset[0] = 200
    assert _approve(ctx, p, _owner_cards(_signed_cards(ctx, p))[0])[0] == 200
    offset[0] = 250
    assert _revoke(ctx, p, r.ref)[0] == 200
    offset[0] = 15 * 60 + 30                                 # past the contest window: R may ask again
    _enroll_approved(ctx, r, "recovery", approver=p)
    offset[0] = 15 * 60 + 60                                 # N's approval would still be inside its 15 minutes
    status, body = n.register(ctx, "recovery", replace=r.ref)
    assert status == 403 and body.get("error") == "owner_approval_required", body
    assert _holders(ctx) == {"primary": [p.ref], "recovery": [r.ref]}


# --------------------------------------------------------------------------
# A failing startup marker write leaves no socket or store lock behind
# --------------------------------------------------------------------------

@pytest.mark.parametrize("store", ["fresh", "open-beside-an-owner"])
def test_a_failing_genesis_write_at_startup_lets_go_of_the_state_dir(tmp_path, monkeypatch, store) -> None:
    if store == "open-beside-an-owner":
        with serving(tmp_path) as c:
            _enroll_genesis(c, Phone("owner"))
        _force_open(tmp_path)
    state = StateStore(state_dir=tmp_path)

    def failing(value):
        raise OSError(28, "no space left on device")

    monkeypatch.setattr(state, "set_owner_genesis", failing)
    with pytest.raises(OSError):
        create_server(bind_host="127.0.0.1", bind_port=0, state=state, bootloader_id="write-fails",
                      challenges=ChallengeStore(state=state), ssl_context=None)
    _assert_store_lock_free(tmp_path)


# --------------------------------------------------------------------------
# The startup code under the real create_server: the runner and the example
# --------------------------------------------------------------------------

def _seed_state_dir(state_dir: Path, marker: str, phone: str | None) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    seeded = StateStore(state_dir=state_dir)
    if phone is not None:
        who = Phone("seeded")
        seeded.register_phone(PhoneRegistration.new(device_label="seeded", public_key_b64u=who.pub,
                                                    supported_algorithms=("ed25519",),
                                                    poll_public_key_b64u=who.poll_pub, slot=phone))
    if marker != "absent":
        (state_dir / "owner_genesis.json").write_text(json.dumps({"state": marker}), encoding="utf-8")


def _wrap_real_create_server(module, monkeypatch) -> list[Any]:
    real, made = module.create_server, []

    def wrapped(**kwargs: Any) -> Any:
        server = real(**kwargs)
        made.append(server)

        def stop(*_a: Any, **_k: Any) -> None:
            raise KeyboardInterrupt

        server.serve_forever = stop
        server.shutdown = lambda: None                # shutdown() would wait for a loop that never ran
        return server

    monkeypatch.setattr(module, "create_server", wrapped)
    return made


_STARTUP_CASES = [
    ("open", None, "code"), ("absent", None, "code"), ("closed", None, "no-owner"),
    ("open", "primary", "owner"), ("absent", "primary", "owner"), ("absent", "recovery", "owner"),
    ("closed", MEMBER_SLOT, "no-owner"),
]


def _assert_startup(out: str, expect: str) -> None:
    if expect == "code":
        assert "PAIRING CODE:" in out, out
        return
    assert "PAIRING CODE:" not in out and "owner genesis is closed" in out, out
    if expect == "owner":
        assert "an owner phone is enrolled" in out and "no owner phone is enrolled" not in out, out
    else:
        assert "no owner phone is enrolled" in out, out


@pytest.mark.parametrize("marker,phone,expect", _STARTUP_CASES)
def test_the_runner_prints_a_startup_code_only_while_genesis_is_open(monkeypatch, tmp_path, capsys,
                                                                    marker, phone, expect) -> None:
    rbc = _runner_env(monkeypatch, tmp_path, RECTO_BIND_PORT="0")
    _seed_state_dir(tmp_path / "state", marker, phone)
    made = _wrap_real_create_server(rbc, monkeypatch)
    try:
        capsys.readouterr()
        assert rbc.main() == 0
        out = capsys.readouterr().out
    finally:
        for server in made:
            server.server_close()
    _assert_startup(out, expect)
    if (marker, phone) == ("open", "primary"):
        assert StateStore(state_dir=tmp_path / "state").get_owner_genesis() == "closed"


@pytest.mark.parametrize("marker,phone,expect", [("open", None, "code"), ("closed", "primary", "owner"),
                                                  ("closed", None, "no-owner")])
def test_the_example_prints_a_startup_code_only_while_genesis_is_open(monkeypatch, tmp_path, capsys,
                                                                     marker, phone, expect) -> None:
    import tests.test_capability_consumer_actions  # noqa: F401 - puts examples/ on sys.path
    import run_bootloader_example as ex
    monkeypatch.setenv("MYSERVICE_AGENT_TOKEN", "e" * 64)
    monkeypatch.setattr(ex, "STATE_DIR", tmp_path / "state")
    monkeypatch.setattr(ex, "BIND_HOST", "127.0.0.1")
    monkeypatch.setattr(ex, "BIND_PORT", 0)
    _seed_state_dir(tmp_path / "state", marker, phone)
    made = _wrap_real_create_server(ex, monkeypatch)
    try:
        capsys.readouterr()
        ex.main()
        out = capsys.readouterr().out
    finally:
        for server in made:
            server.server_close()
    _assert_startup(out, expect)


# --------------------------------------------------------------------------
# Every owner phone lost: the explicit host path (ruled 2026-10-13)
# --------------------------------------------------------------------------

def _two_owners_and_a_member(state_dir: Path) -> tuple[Phone, Phone, Phone]:
    owner, second, member = Phone("owner"), Phone("second"), Phone("member")
    with serving(state_dir) as c:
        _enroll_genesis(c, owner)
        _seed_owner(c, second, "recovery")
        assert member.register(c, "primary", challenge=_member_challenge(c, "u1"))[0] == 201
    return owner, second, member


def test_every_owner_lost_removes_them_all_and_reopens_genesis(tmp_path) -> None:
    owner, second, member = _two_owners_and_a_member(tmp_path)
    rc, text = _cli("bootloader", "owner-reset", "--state-dir", str(tmp_path), "--every-owner-lost",
                    "--confirm", f"{_grouped(owner.ref)},{second.ref}", "--reopen-genesis")
    assert rc == 0, text
    assert f"removed {owner.ref} from the primary slot" in text and f"removed {second.ref} from the recovery slot" in text
    assert "owner genesis reopened" in text, text
    fresh = StateStore(state_dir=tmp_path)
    assert [p.phone_id for p in fresh.list_phones()] == [member.ref], "a member phone was touched"
    assert fresh.get_owner_genesis() == "open"
    with serving(tmp_path) as c:
        replacement = Phone("replacement")
        _enroll_genesis(c, replacement)
        assert _holders(c) == {"primary": [replacement.ref], MEMBER_SLOT: [member.ref]}


@pytest.mark.parametrize("case", ["one-missing", "a-stranger-added", "a-duplicate", "a-repeat", "no-reopen",
                                  "with-slot", "no-confirm", "an-empty-item"])
def test_every_owner_lost_refuses_anything_but_the_exact_owner_set(tmp_path, case) -> None:
    owner, second, _ = _two_owners_and_a_member(tmp_path)
    stranger = Phone("stranger")
    argv = {
        "one-missing": ["--confirm", owner.ref, "--reopen-genesis"],
        "a-stranger-added": ["--confirm", f"{owner.ref},{second.ref},{stranger.ref}", "--reopen-genesis"],
        "a-duplicate": ["--confirm", f"{owner.ref},{owner.ref}", "--reopen-genesis"],
        "a-repeat": ["--confirm", f"{owner.ref},{second.ref},{owner.ref}", "--reopen-genesis"],
        "no-reopen": ["--confirm", f"{owner.ref},{second.ref}"],
        "with-slot": ["--slot", "primary", "--confirm", f"{owner.ref},{second.ref}", "--reopen-genesis"],
        "no-confirm": ["--reopen-genesis"],
        "an-empty-item": ["--confirm", f"{owner.ref},,{second.ref}", "--reopen-genesis"],
    }[case]
    said = {
        "one-missing": "must name every owner phone the slots hold, exactly",
        "a-stranger-added": "must name every owner phone the slots hold, exactly",
        "a-duplicate": "must name every owner phone the slots hold, exactly",
        "a-repeat": "must name every owner phone the slots hold, exactly",
        "no-reopen": "needs --reopen-genesis",
        "with-slot": "takes no --slot",
        "no-confirm": "needs --confirm",
        "an-empty-item": "empty item",
    }[case]
    rc, text = _cli("bootloader", "owner-reset", "--state-dir", str(tmp_path), "--every-owner-lost", *argv)
    assert rc == 1 and said in text and "nothing removed" in text, (case, text)
    rc, text = _cli("bootloader", "owner-slots", "--state-dir", str(tmp_path), "--expect", f"{owner.ref},{second.ref}")
    assert rc == 0 and "owner genesis: closed" in text, text


def test_every_owner_lost_on_a_store_with_no_owner_names_the_reopen(tmp_path) -> None:
    with serving(tmp_path):
        pass
    rc, text = _cli("bootloader", "owner-reset", "--state-dir", str(tmp_path), "--every-owner-lost",
                    "--confirm", "pk_0000000000000000", "--reopen-genesis")
    assert rc == 1 and "no owner phone remains" in text, text


def test_every_owner_lost_says_what_landed_when_a_removal_fails(tmp_path) -> None:
    owner, second, _ = _two_owners_and_a_member(tmp_path)
    (tmp_path / "phones.json.tmp").mkdir()
    rc, text = _cli("bootloader", "owner-reset", "--state-dir", str(tmp_path), "--every-owner-lost",
                    "--confirm", f"{owner.ref},{second.ref}", "--reopen-genesis")
    assert rc == 1 and "nothing removed (the genesis marker was written CLOSED)" in text, text
    (tmp_path / "phones.json.tmp").rmdir()
    fresh = StateStore(state_dir=tmp_path)
    assert sorted(p.phone_id for p in fresh.list_phones() if p.slot in ("primary", "recovery")) == sorted(
        [owner.ref, second.ref])
    assert fresh.get_owner_genesis() == "closed"


def test_a_single_named_owner_is_still_refused_beside_the_all_lost_path(tmp_path) -> None:
    owner, second, _ = _two_owners_and_a_member(tmp_path)
    rc, text = _cli("bootloader", "owner-reset", "--state-dir", str(tmp_path), "--slot", "recovery",
                    "--confirm", second.ref, "--reopen-genesis")
    assert rc == 1 and "is not the last owner phone" in text and "--every-owner-lost" in text, text


def test_an_approval_given_by_a_displaced_owner_never_revives_when_its_key_pairs_again(ctx) -> None:
    p, r, x, n = Phone("p"), Phone("r"), Phone("x"), Phone("n")
    _enroll_genesis(ctx, p)
    _enroll_approved(ctx, r, "recovery", approver=p)
    assert x.register(ctx, "primary", replace=p.ref)[0] == 403              # R is the approver for replacing P
    assert _approve(ctx, r, _owner_cards(_signed_cards(ctx, r))[0])[0] == 200
    _enroll_approved(ctx, n, "recovery", approver=p, occupant=r)             # N displaces R
    _enroll_approved(ctx, r, "recovery", approver=p, occupant=n)             # R's key comes back, displacing N
    status, body = x.register(ctx, "primary", replace=p.ref)
    assert status == 403 and body.get("error") == "owner_approval_required", body
    assert _holders(ctx) == {"primary": [p.ref], "recovery": [r.ref]}


# --------------------------------------------------------------------------
# A removal that landed is answered as landed; a midway failure names the phone still held
# --------------------------------------------------------------------------

def test_a_revoke_that_landed_answers_200_when_pending_json_cannot_be_written(tmp_path, caplog) -> None:
    p, r, n = Phone("p"), Phone("r"), Phone("n")
    with serving(tmp_path) as c:
        _enroll_genesis(c, p)
        _enroll_approved(c, r, "recovery", approver=p)
        assert n.register(c, "recovery", replace=r.ref)[0] == 403        # N's card, naming R, waits on P's queue
        assert len(_owner_cards(_signed_cards(c, p))) == 1
        (tmp_path / "pending.json.tmp").mkdir()                           # pending.json can no longer be written
        try:
            status, body = _revoke(c, p, r.ref)
        finally:
            (tmp_path / "pending.json.tmp").rmdir()
        assert status == 200, (status, body)
        assert _holders(c) == {"primary": [p.ref]}
        assert _owner_cards(_signed_cards(c, p)) == [], "the card naming the removed phone is still offered"
    said = [r.getMessage() for r in caplog.records if r.name == "recto.bootloader.state"]
    assert any(m.startswith("pending.json not written after withdrawing an owner card") for m in said), said


def test_a_removal_that_withdraws_a_card_warns_of_no_failed_write(ctx, caplog) -> None:
    p, r, n = Phone("p"), Phone("r"), Phone("n")
    _enroll_genesis(ctx, p)
    _enroll_approved(ctx, r, "recovery", approver=p)
    assert n.register(ctx, "recovery", replace=r.ref)[0] == 403            # N's card, naming R, waits on P's queue
    assert len(_owner_cards(_signed_cards(ctx, p))) == 1
    assert _revoke(ctx, p, r.ref)[0] == 200
    assert _owner_cards(_signed_cards(ctx, p)) == [], "the card naming the removed phone is still offered"
    assert not [x for x in caplog.records if x.name == "recto.bootloader.state"], "a write that landed was warned"


def test_every_owner_lost_writes_closed_before_the_first_removal(tmp_path) -> None:
    owner, second, _ = _two_owners_and_a_member(tmp_path)
    _force_open(tmp_path)                                  # a close that did not land: the assertion below can bite
    (tmp_path / "phones.json.tmp").mkdir()                 # the first removal fails
    try:
        rc, text = _cli("bootloader", "owner-reset", "--state-dir", str(tmp_path), "--every-owner-lost",
                        "--confirm", f"{owner.ref},{second.ref}", "--reopen-genesis")
    finally:
        (tmp_path / "phones.json.tmp").rmdir()
    assert rc == 1 and "nothing removed (the genesis marker was written CLOSED)" in text, text
    assert StateStore(state_dir=tmp_path).get_owner_genesis() == "closed"


def test_every_owner_lost_names_the_phone_still_held_when_a_later_removal_fails(tmp_path, monkeypatch) -> None:
    owner, second, member = _two_owners_and_a_member(tmp_path)
    real, calls = StateStore._write_phones, [0]

    def second_write_fails(self, phones):
        calls[0] += 1
        if calls[0] == 2:
            raise OSError(28, "no space left on device")
        return real(self, phones)

    monkeypatch.setattr(StateStore, "_write_phones", second_write_fails)
    rc, text = _cli("bootloader", "owner-reset", "--state-dir", str(tmp_path), "--every-owner-lost",
                    "--confirm", f"{owner.ref},{second.ref}", "--reopen-genesis")
    monkeypatch.setattr(StateStore, "_write_phones", real)
    gone = [x for x in (owner, second) if f"removed {x.ref} from the" in text]
    assert rc == 1 and len(gone) == 1, text
    held = second if gone[0] is owner else owner
    slot = "recovery" if held is second else "primary"
    assert f"{gone[0].ref} was removed from the" in text and f"{held.ref} was NOT removed from the {slot} slot" in text
    assert "genesis stays CLOSED" in text and f"--every-owner-lost --confirm {held.ref} --reopen-genesis" in text
    assert "could not be reopened" not in text and "may still have landed" not in text, text
    assert "refused first" not in text and "no longer shows" not in text, "a Postgres clause on the file store"
    fresh = StateStore(state_dir=tmp_path)
    assert sorted(x.phone_id for x in fresh.list_phones()) == sorted([held.ref, member.ref])
    assert fresh.get_owner_genesis() == "closed"
    rc, text = _cli("bootloader", "owner-reset", "--state-dir", str(tmp_path), "--every-owner-lost",
                    "--confirm", held.ref, "--reopen-genesis")
    assert rc == 0 and StateStore(state_dir=tmp_path).get_owner_genesis() == "open", text


# --------------------------------------------------------------------------
# The host CLI's Postgres arm: every write under registry_lock, and the void reaches the records
# --------------------------------------------------------------------------

def _recording_pg_store(monkeypatch, fake, phones, enrolls, pending, *, fail_revoke_at: int | None = None,
                        fail_put: bool = False, fail_take: bool = False):
    import recto.bootloader.state_postgres as spg
    writes: list[tuple[str, bool]] = []
    made: list[Any] = []

    class Recording:
        def __init__(self, dsn, schema):
            self.depth, self.genesis, self.revokes, self.closed = 0, "closed", 0, False
            made.append(self)

        @contextmanager
        def registry_lock(self):
            self.depth += 1
            try:
                yield
            finally:
                self.depth -= 1

        def _wrote(self, what):
            writes.append((what, self.depth > 0))

        def get_owner_genesis(self):
            return self.genesis

        def set_owner_genesis(self, value):
            self._wrote(f"genesis={value}")
            self.genesis = value

        def list_phones(self):
            return list(phones.values())

        def revoke_phone(self, phone_id):
            self.revokes += 1
            if self.revokes == fail_revoke_at:
                raise fake.OperationalError(f"server db.invalid closed the connection ({_SENTINEL})")
            self._wrote(f"revoke {phone_id}")
            return phones.pop(phone_id, None) is not None

        def list_owner_enrolls(self):
            return [dict(r) for r in enrolls.values()]

        def put_owner_enroll(self, rec):
            if fail_put:
                raise fake.OperationalError(f"server db.invalid closed the connection ({_SENTINEL})")
            self._wrote(f"put {rec['request_id']}={rec['state']}")
            enrolls[rec["request_id"]] = dict(rec)

        def take_pending(self, card_id):
            if fail_take:
                raise fake.OperationalError(f"server db.invalid closed the connection ({_SENTINEL})")
            self._wrote(f"take {card_id}")
            return pending.pop(card_id, None)

        def close(self):
            self.closed = True

    monkeypatch.setattr(spg, "PostgresStateStore", Recording)
    return writes, made


def _pg_owners_and_records(owners: tuple[str, ...]):
    regs = [PhoneRegistration.new(device_label=slot, public_key_b64u=who.pub, supported_algorithms=("ed25519",),
                                  poll_public_key_b64u=who.poll_pub, slot=slot)
            for slot, who in [(s, Phone(f"{s}-{i}")) for i, s in enumerate((*owners, MEMBER_SLOT))]]
    phones = {r.phone_id: r for r in regs}
    first, last = regs[0].phone_id, regs[len(owners) - 1].phone_id
    record = {"created_unix": 1, "expires_at_unix": 2**40, "slot": "recovery"}
    enrolls = {
        "approved": {**record, "request_id": "approved", "state": "approved", "approved_by": first,
                     "occupant_ref": None, "cards": {}},
        "naming": {**record, "request_id": "naming", "state": "pending", "approved_by": None, "occupant_ref": last,
                   "cards": {"c-naming": first}},
        "other": {**record, "request_id": "other", "state": "pending", "approved_by": None, "occupant_ref": "x",
                  "cards": {"c-other": "x"}},
    }
    pending = {"c-naming": object(), "c-other": object()}
    return regs, phones, enrolls, pending


@pytest.mark.parametrize("path", ["every-owner-lost", "the-last-owner"])
def test_the_postgres_reset_voids_the_removed_phones_records_under_the_registry_lock(monkeypatch, path) -> None:
    fake = _fake_psycopg(monkeypatch, lambda fake: _Probe())
    owners = ("primary", "recovery") if path == "every-owner-lost" else ("primary",)
    regs, phones, enrolls, pending = _pg_owners_and_records(owners)
    writes, made = _recording_pg_store(monkeypatch, fake, phones, enrolls, pending)
    if path == "every-owner-lost":
        argv = ["--every-owner-lost", "--confirm", ",".join(r.phone_id for r in regs[:2]), "--reopen-genesis"]
    else:
        argv = ["--slot", "primary", "--confirm", regs[0].phone_id, "--reopen-genesis"]
    rc, text = _cli("bootloader", "owner-reset", *argv)
    assert rc == 0, text
    assert writes and all(locked for _, locked in writes), writes
    assert writes[0][0] == "genesis=closed" and writes[-1][0] == "genesis=open", writes
    assert list(phones) == [regs[-1].phone_id], "a member phone was touched"
    assert enrolls["approved"]["state"] == "refused" and enrolls["naming"]["state"] == "refused"
    assert enrolls["other"]["state"] == "pending" and list(pending) == ["c-other"], (enrolls, pending)
    done = [w for w, _ in writes]
    assert done.index("put naming=refused") < done.index("take c-naming"), done
    assert made[0].closed


def test_the_postgres_all_lost_path_names_the_phone_still_held_when_a_later_removal_fails(monkeypatch) -> None:
    fake = _fake_psycopg(monkeypatch, lambda fake: _Probe())
    regs, phones, enrolls, pending = _pg_owners_and_records(("primary", "recovery"))
    _recording_pg_store(monkeypatch, fake, phones, enrolls, pending, fail_revoke_at=2)
    rc, text = _cli("bootloader", "owner-reset", "--every-owner-lost", "--confirm",
                    ",".join(r.phone_id for r in regs[:2]), "--reopen-genesis")
    assert rc == 1 and f"{regs[0].phone_id} was removed from the primary slot" in text, text
    assert (f"{regs[1].phone_id} was NOT removed from the recovery slot (on Postgres the failed write may still "
            f"have landed); any approval or request naming {regs[1].phone_id} was refused first; genesis stays CLOSED"
            f" - to finish, run `recto bootloader owner-reset --every-owner-lost --confirm {regs[1].phone_id} "
            "--reopen-genesis` against the same store (if `owner-slots` no longer shows "
            f"{regs[1].phone_id}, leave it out; if no owner phone remains, run `--reopen-genesis` alone)") in text, text
    assert "could not be reopened" not in text and _SENTINEL not in text, text


@pytest.mark.parametrize("path", ["every-owner-lost", "the-last-owner"])
def test_a_postgres_void_that_fails_leaves_the_phone_held(monkeypatch, path) -> None:
    fake = _fake_psycopg(monkeypatch, lambda fake: _Probe())
    owners = ("primary", "recovery") if path == "every-owner-lost" else ("primary",)
    regs, phones, enrolls, pending = _pg_owners_and_records(owners)
    writes, _ = _recording_pg_store(monkeypatch, fake, phones, enrolls, pending, fail_put=True)
    if path == "every-owner-lost":
        argv = ["--every-owner-lost", "--confirm", ",".join(r.phone_id for r in regs[:2]), "--reopen-genesis"]
    else:
        argv = ["--slot", "primary", "--confirm", regs[0].phone_id, "--reopen-genesis"]
    rc, text = _cli("bootloader", "owner-reset", *argv)
    assert rc == 1 and "nothing removed (the genesis marker was written CLOSED)" in text, text
    assert [w for w, _ in writes] == ["genesis=closed"], writes
    assert len(phones) == len(regs), "a phone was removed before its approvals were withdrawn"


def test_every_owner_lost_says_the_reopen_failed_when_only_the_reopen_failed(tmp_path, monkeypatch) -> None:
    owner, second, member = _two_owners_and_a_member(tmp_path)
    real = StateStore.set_owner_genesis

    def open_fails(self, value):
        if value == "open":
            raise OSError(28, "no space left on device")
        return real(self, value)

    monkeypatch.setattr(StateStore, "set_owner_genesis", open_fails)
    rc, text = _cli("bootloader", "owner-reset", "--state-dir", str(tmp_path), "--every-owner-lost",
                    "--confirm", f"{owner.ref},{second.ref}", "--reopen-genesis")
    monkeypatch.setattr(StateStore, "set_owner_genesis", real)
    assert rc == 1 and f"{owner.ref} was removed from the primary slot" in text, text
    assert f"{second.ref} was removed from the recovery slot" in text, text
    assert "but genesis could not be reopened and stays CLOSED" in text and "NOT removed" not in text, text
    fresh = StateStore(state_dir=tmp_path)
    assert [x.phone_id for x in fresh.list_phones()] == [member.ref] and fresh.get_owner_genesis() == "closed"
    rc, text = _cli("bootloader", "owner-reset", "--state-dir", str(tmp_path), "--reopen-genesis")
    assert rc == 0 and StateStore(state_dir=tmp_path).get_owner_genesis() == "open", text


def test_the_postgres_all_lost_path_names_every_owner_phone_still_held(monkeypatch) -> None:
    """A registry from before the slot rule can hold two phones in one slot: a midway failure names them all."""
    fake = _fake_psycopg(monkeypatch, lambda fake: _Probe())
    regs, phones, enrolls, pending = _pg_owners_and_records(("primary", "primary", "recovery"))
    _recording_pg_store(monkeypatch, fake, phones, enrolls, pending, fail_revoke_at=2)
    rc, text = _cli("bootloader", "owner-reset", "--every-owner-lost", "--confirm",
                    ",".join(r.phone_id for r in regs[:3]), "--reopen-genesis")
    owners = [r.phone_id for r in regs[:3]]
    gone = [ref for ref in owners if f"{ref} was removed from the" in text]
    assert rc == 1 and len(gone) == 1, text
    still = [ref for ref in owners if ref not in gone]
    assert f"--every-owner-lost --confirm {','.join(still)} --reopen-genesis" in text, text
    assert sorted(phones) == sorted([*still, regs[-1].phone_id])


@pytest.mark.parametrize("path", ["every-owner-lost", "the-last-owner"])
def test_a_postgres_card_withdrawal_that_fails_is_named_and_leaves_the_phone_held(monkeypatch, path) -> None:
    fake = _fake_psycopg(monkeypatch, lambda fake: _Probe())
    owners = ("primary", "recovery") if path == "every-owner-lost" else ("primary",)
    regs, phones, enrolls, pending = _pg_owners_and_records(owners)
    _recording_pg_store(monkeypatch, fake, phones, enrolls, pending, fail_take=True)
    if path == "every-owner-lost":
        argv = ["--every-owner-lost", "--confirm", ",".join(r.phone_id for r in regs[:2]), "--reopen-genesis"]
    else:
        argv = ["--slot", "primary", "--confirm", regs[0].phone_id, "--reopen-genesis"]
    rc, text = _cli("bootloader", "owner-reset", *argv)
    last = regs[len(owners) - 1].phone_id                      # the phone the card-bearing record names
    assert rc == 1 and "the store failed (OperationalError 08006)" in text, text
    assert f"{last} was NOT removed: refusing its approvals failed, and some may already be refused" in text, text
    assert "may still have landed" not in text, "the removal never ran, yet the text hedges it"
    assert enrolls["naming"]["state"] == "refused", "the record was not refused before its card was withdrawn"
    assert last in phones and regs[-1].phone_id in phones
    if path == "every-owner-lost":
        assert f"{regs[0].phone_id} was removed from the primary slot" in text and regs[0].phone_id not in phones
        assert f"--every-owner-lost --confirm {last} --reopen-genesis" in text, text
        assert "no longer shows" not in text, "a removal that never ran is hedged as maybe landed"
    else:
        assert "nothing removed (the genesis marker was written CLOSED)" in text, text


def test_the_finishing_command_names_a_key_held_by_two_legacy_records_once(monkeypatch) -> None:
    """A store from before one spelling per key can hold two records of one key under uuid phone_ids; its ref names
    both, so the command printed after a midway failure names it once - and that command is the one the path takes."""
    from dataclasses import replace
    fake = _fake_psycopg(monkeypatch, lambda fake: _Probe())
    b, a, member = Phone("b"), Phone("a"), Phone("member")

    def reg(phone: Phone, slot: str) -> PhoneRegistration:
        return PhoneRegistration.new(device_label=phone.label, public_key_b64u=phone.pub,
                                     supported_algorithms=("ed25519",), poll_public_key_b64u=phone.poll_pub, slot=slot)

    rows = [reg(b, "primary"), replace(reg(a, "recovery"), phone_id=str(uuid.uuid4())),
            replace(reg(a, "recovery"), phone_id=str(uuid.uuid4())), reg(member, MEMBER_SLOT)]
    phones = {r.phone_id: r for r in rows}
    _recording_pg_store(monkeypatch, fake, phones, {}, {}, fail_revoke_at=2)
    rc, text = _cli("bootloader", "owner-reset", "--every-owner-lost", "--confirm", f"{b.ref},{a.ref}",
                    "--reopen-genesis")
    assert rc == 1 and f"{b.ref} was removed from the primary slot" in text, text
    assert f"--every-owner-lost --confirm {a.ref} --reopen-genesis" in text and f"{a.ref},{a.ref}" not in text, text
    _recording_pg_store(monkeypatch, fake, phones, {}, {})
    rc, text = _cli("bootloader", "owner-reset", "--every-owner-lost", "--confirm", a.ref, "--reopen-genesis")
    assert rc == 0 and list(phones) == [rows[-1].phone_id], text


def test_the_all_lost_refusal_lists_a_key_two_legacy_records_hold_once(monkeypatch) -> None:
    from dataclasses import replace
    fake = _fake_psycopg(monkeypatch, lambda fake: _Probe())
    b, a, member = Phone("b"), Phone("a"), Phone("member")

    def reg(phone: Phone, slot: str) -> PhoneRegistration:
        return PhoneRegistration.new(device_label=phone.label, public_key_b64u=phone.pub,
                                     supported_algorithms=("ed25519",), poll_public_key_b64u=phone.poll_pub, slot=slot)

    rows = [reg(b, "primary"), replace(reg(a, "recovery"), phone_id=str(uuid.uuid4())),
            replace(reg(a, "recovery"), phone_id=str(uuid.uuid4())), reg(member, MEMBER_SLOT)]
    phones = {r.phone_id: r for r in rows}
    _recording_pg_store(monkeypatch, fake, phones, {}, {})
    rc, text = _cli("bootloader", "owner-reset", "--every-owner-lost", "--confirm", b.ref, "--reopen-genesis")
    assert rc == 1 and f"they hold {sorted([a.ref, b.ref])}" in text, text
    _recording_pg_store(monkeypatch, fake, phones, {}, {})
    rc, text = _cli("bootloader", "owner-reset", "--every-owner-lost", "--confirm", ",".join(sorted([a.ref, b.ref])),
                    "--reopen-genesis")
    assert rc == 0 and list(phones) == [rows[-1].phone_id], text

