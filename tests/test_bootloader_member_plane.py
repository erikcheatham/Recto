"""THE MEMBER PLANE (2026-09-30) -- members pair to the business one plane DOWN, never into its slots.

The bootloader's two slots (hard rule 14.4) are the BUSINESS owner's phones. A consumer (a
downstream service that pairs its own users through this bootloader) mints codes for its MEMBERS
through ``/v0.4/pairing/code`` with its agent token. Today that code is indistinguishable from the
owner's: a member's fresh phone registers into ``primary`` by default, meets the owner's phone
there (409 slot_occupied), and the REPLACE answer -- signed by the member's OWN incoming key --
revokes the owner's phone. That is a plane crossing: a member's code must never carry the
authority to read, fill or displace a business slot.

THE SHAPE THESE TESTS PIN: a consumer mints a
MEMBER code by naming who it is for -- ``{"member_of": {"consumer": <base url>, "user_id": <id>}}``
on ``/v0.4/pairing/code``; a registration on a member code lands in the member plane (no slot,
bound to that consumer user) and never answers 409 slot_occupied.

RED-BUILDS (both failed on the server before the member plane, 409 slot_occupied; a probe showed the
REPLACE answer displacing the owner):
  - a member registration never displaces the owner, even with a REPLACE signed by its own key;
  - a member registration lands beside the slots, and the owner's slot still holds the owner.
POSITIVE CONTROL: the owner's own code still fills the business slots exactly as 14.4 says.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from recto.bootloader.server import ChallengeStore, create_server
from recto.bootloader.state import SLOTS, StateStore

from tests.test_bootloader_slots import Phone, _http

AGENT_ID = "consumer-agent"
AGENT_TOKEN = "agent-token-fixture"
CONSUMER = "https://consumer.example"


@pytest.fixture
def ctx(tmp_path):
    import threading

    state = StateStore(state_dir=tmp_path)
    challenges = ChallengeStore(state=state)
    server = create_server(
        bind_host="127.0.0.1", bind_port=0, state=state, bootloader_id="member-plane-test",
        challenges=challenges, ssl_context=None, signed_poll_mode="required",
        capability_agent_tokens={AGENT_ID: AGENT_TOKEN},
    )
    host, port = server.server_address
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield {"base_url": f"http://{host}:{port}", "state": state, "challenges": challenges}
    finally:
        server.shutdown()


def _member_challenge(ctx, user_id: str) -> str:
    """A consumer mints a MEMBER code for one of its users, then the phone asks for its challenge."""
    status, minted = _http(
        "POST", f"{ctx['base_url']}/v0.4/pairing/code",
        {"member_of": {"consumer": CONSUMER, "user_id": user_id}},
        headers={"X-Recto-Agent-Id": AGENT_ID, "X-Recto-Agent-Token": AGENT_TOKEN},
    )
    assert status == 200, minted
    status, chal = _http("GET", f"{ctx['base_url']}/v0.4/registration_challenge?code={minted['code']}")
    assert status == 200, chal
    return chal["challenge_b64u"]


def _business_slot_holders(ctx) -> dict[str, str]:
    return {p.slot: p.phone_id for p in ctx["state"].list_phones() if p.slot in SLOTS}


def test_the_owners_code_still_fills_the_business_slots(ctx) -> None:
    """POSITIVE CONTROL: 14.4 unchanged for the business owner."""
    owner = Phone("owner pixel")
    status, body = owner.register(ctx, "primary")
    assert status in (200, 201), body
    assert _business_slot_holders(ctx) == {"primary": owner.ref}


def test_a_member_registration_never_displaces_the_owner(ctx) -> None:
    """The member plane: no 409 for a member code, and no REPLACE of the owner even when the member signs one."""
    owner = Phone("owner pixel")
    assert owner.register(ctx, "primary")[0] in (200, 201)

    member = Phone("member phone")
    challenge = _member_challenge(ctx, user_id="member-1")
    first, first_body = member.register(ctx, "primary", challenge=challenge)
    assert first != 409, f"a member code must never reach the business slot question: {first_body}"

    # even a replace the member signs itself must displace nobody
    member.register(ctx, "primary", replace=owner.ref, challenge=challenge)
    assert _business_slot_holders(ctx).get("primary") == owner.ref, "the owner's phone left its slot for a member"


def test_a_member_registration_lands_beside_the_slots_bound_to_its_user(ctx) -> None:
    """The member plane: the member phone registers, outside SLOTS, and the owner's slot is untouched."""
    owner = Phone("owner pixel")
    assert owner.register(ctx, "primary")[0] in (200, 201)

    member = Phone("member phone")
    status, body = member.register(ctx, challenge=_member_challenge(ctx, user_id="member-1"))
    assert status in (200, 201), body

    record = ctx["state"].get_phone(member.ref)
    assert record is not None, "the member phone has no registration"
    assert record.slot not in SLOTS, f"a member took a business slot: {record.slot!r}"
    assert _business_slot_holders(ctx) == {"primary": owner.ref}


def test_the_owners_phone_scanning_a_member_code_keeps_its_slot(ctx) -> None:
    """A member code can never DEMOTE a business key: re-registering the owner's own key through it keeps primary."""
    owner = Phone("owner pixel")
    assert owner.register(ctx, "primary")[0] in (200, 201)
    status, body = owner.register(ctx, challenge=_member_challenge(ctx, user_id="member-1"))
    assert status in (200, 201), body
    assert _business_slot_holders(ctx) == {"primary": owner.ref}


def test_a_member_code_answers_no_slot_question_by_name(ctx) -> None:
    """The replace claim on a member challenge is refused BY NAME, and the challenge displaces nobody."""
    owner = Phone("owner pixel")
    assert owner.register(ctx, "primary")[0] in (200, 201)
    member = Phone("member phone")
    status, body = member.register(ctx, "primary", replace=owner.ref, challenge=_member_challenge(ctx, user_id="member-1"))
    assert status == 400 and "answers no slot question" in json.dumps(body), (status, body)
    assert ctx["state"].get_phone(owner.ref) is not None
