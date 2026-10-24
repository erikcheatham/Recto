"""Hard rule 14.7, end to end: the passphrase AND one owner device for every top-plane act, on a running bootloader.

Each test runs a real bootloader, a chain whose first device entered under the passphrase alone (entry 0 the
passphrase, entry 1 the recovery phone under the passphrase alone), phones that answer their
cards with their own identity keys, and the HOST verbs (recto.top_plane_cli) with the passphrase injected where the
real CLI reads a hidden prompt. The host computes every digest itself from the chain it replays.

Each test pins a route, a verb or a chain op of the top plane: a phone's approval alone never seats a phone once the
plane is sealed.
"""

from __future__ import annotations

import base64
import io
import json
import time
import types
from pathlib import Path

import pytest

from recto import top_plane_cli as tp
from recto.bootloader.genesis_chain import entries_from_records, replay_state, signing_bytes
from recto.bootloader.server import BootloaderHandler, create_server
from recto.profile.passphrase_member import derive_passphrase_member, passphrase_member_pubkey

from tests.test_bootloader_owner_slots import _approve, _enroll_approved, _enroll_genesis, _signed_cards, serving
from tests.test_bootloader_slots import Phone, _http

PHRASE = "correct horse battery staple ridge lantern copper meadow"
_PP_PUB = None


def _op_key() -> bytes:
    """A real operator key: 64 bytes X||Y on secp256k1."""
    from cryptography.hazmat.primitives.asymmetric import ec
    nums = ec.generate_private_key(ec.SECP256K1()).public_key().public_numbers()
    return nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")


def _fresh_meta(**over) -> str:
    from recto.bootloader.genesis_chain import canonical_meta
    meta = {"nonce": "n" * 32, "not_after": int(time.time()) + 600}
    meta.update(over)
    return canonical_meta(meta)


def _pp_pub() -> bytes:
    global _PP_PUB
    if _PP_PUB is None:
        _PP_PUB = passphrase_member_pubkey(PHRASE)
    return _PP_PUB


def _raw(phone: Phone) -> bytes:
    return base64.urlsafe_b64decode(phone.pub + "=" * (-len(phone.pub) % 4))


def _seed_chain(state, recovery: Phone) -> None:
    """A chain whose first device entered under the passphrase alone: entry 0 the passphrase (unsigned), entry 1
    the recovery phone under the passphrase alone."""
    state.append_genesis_chain_entry({"seq": 0, "op": "add", "kind": "passphrase", "pubkey": _pp_pub().hex(),
                                      "algorithm": "ed25519", "prev": None, "signatures": []})
    cs = state.genesis_chain_state()
    raw = signing_bytes(seq=1, op="add", kind="recovery-phone", pubkey=_raw(recovery), algorithm="ed25519",
                        prev=cs.tip_hash)
    sig = derive_passphrase_member(PHRASE).sign(raw)
    state.append_genesis_chain_entry({"seq": 1, "op": "add", "kind": "recovery-phone", "pubkey": _raw(recovery).hex(),
                                      "algorithm": "ed25519", "prev": cs.tip_hash,
                                      "signatures": [base64.urlsafe_b64encode(sig).decode().rstrip("=")]})


def _args(ctx, **kw):
    ns = types.SimpleNamespace(bootloader_url=ctx["base_url"], request=None, slot=None, slot_list=[],
                               every_owner_lost=False, confirm=None, window_seconds=2, arm=None, complete=None,
                               public_key=None, algorithm="ed25519", pubkey_hex=None)
    for k, v in kw.items():
        setattr(ns, k, v)
    return ns


def _host(verb, ctx, *, phrase=PHRASE, answer="SIGN", **kw):
    out, err = io.StringIO(), io.StringIO()
    rc = verb(_args(ctx, **kw), out=out, err=err, read_passphrase=lambda _l: phrase, confirm=lambda _q: answer)
    return rc, out.getvalue(), err.getvalue()


def _arm(ctx, iid: str, slot: str = "primary") -> dict:
    rc, out, err = _host(tp.reset_arm, ctx, arm=iid, slot=slot)
    assert rc == 0, err
    return json.loads(next(line for line in out.splitlines() if line.strip().startswith("{")))


def _top_cards(ctx, phone: Phone) -> list[dict]:
    return [c for c in _signed_cards(ctx, phone) if str(c.get("secret", "")).startswith("top-plane:")]


def _chain(ctx):
    status, body = _http("GET", f"{ctx['base_url']}/v0.4/genesis/chain")
    assert status == 200, body
    return replay_state(entries_from_records(body["records"])), body


@pytest.fixture
def plane(tmp_path):
    """A running bootloader: R (recovery, the sealed device) and P (primary, an owner not yet a member), the chain
    seeded, the id SEALED by the passphrase + R."""
    op_key = _op_key()
    with serving(tmp_path, signed_poll_mode="advisory", capability_operator_pubkey=op_key) as ctx:
        ctx["op_key"] = op_key
        BootloaderHandler.config.owner_reset_window_seconds = 2
        r, p = Phone("recovery"), Phone("primary")
        _enroll_genesis(ctx, r, "recovery")
        _enroll_approved(ctx, p, "primary", approver=r)
        _seed_chain(ctx["state"], r)
        rc, out, err = _host(tp.seal_id, ctx)
        assert rc == 0, err
        cards = _top_cards(ctx, r)
        assert len(cards) == 1
        status, body = _approve(ctx, r, cards[0])
        assert status == 200 and body.get("appended"), body
        ctx.update(r=r, p=p, tmp=tmp_path)
        yield ctx
        BootloaderHandler.config.owner_reset_window_seconds = 72 * 3600


class TestRule14_7TheTopPlaneNeedsThePassphraseAndADevice:

    def test_the_id_is_sealed_by_the_passphrase_and_a_device(self, plane) -> None:
        cs, body = _chain(plane)
        assert cs.sealed_id == body["bootloader_id"] and cs.length == 3

    def test_slot_replacement_with_the_phone_approval_alone_is_refused(self, plane) -> None:
        """Once the plane is sealed, a phone's approval alone never seats a phone in a slot."""
        n = Phone("newphone")
        status, body = n.register(plane, "primary")
        assert status == 409
        status, body = n.register(plane, "primary", replace=plane["p"].ref, challenge=n.last_challenge)
        assert status == 403 and body["error"] == "owner_approval_required", body
        cards = [c for c in _signed_cards(plane, plane["r"]) if str(c.get("secret", "")).startswith("owner-slot:")]
        assert _approve(plane, plane["r"], cards[0])[0] == 200
        status, body = n.register(plane, "primary", replace=plane["p"].ref)
        assert status == 403 and body["error"] == "owner_passphrase_required", body
        assert plane["state"].get_phone(n.ref) is None

    def test_slot_replacement_with_the_phone_and_the_passphrase_lands_and_swaps_the_device_member(self, plane) -> None:
        n = Phone("newphone")
        assert n.register(plane, "primary")[0] == 409
        n.register(plane, "primary", replace=plane["p"].ref, challenge=n.last_challenge)
        cards = [c for c in _signed_cards(plane, plane["r"]) if str(c.get("secret", "")).startswith("owner-slot:")]
        assert _approve(plane, plane["r"], cards[0])[0] == 200
        rc, out, err = _host(tp.approve_enroll, plane)
        assert rc == 0, err
        assert n.ref in out  # the host showed the incoming ref it signed for
        status, body = n.register(plane, "primary", replace=plane["p"].ref)
        assert status == 201, body
        cs, _ = _chain(plane)
        assert cs.members["primary-phone"].pubkey == _raw(n)
        assert plane["state"].get_phone(plane["p"].ref) is None

    def test_re_pairing_into_ones_own_slot_needs_no_passphrase(self, plane) -> None:
        status, body = plane["r"].register(plane, "recovery")
        assert status == 201, body

    def test_adding_the_primary_phone_as_a_device_member_leaves_the_bootloader_id_unchanged(self, plane) -> None:
        before = _chain(plane)[0].sealed_id
        rc, _, err = _host(tp.add_device, plane, slot="primary", public_key=plane["p"].pub)
        assert rc == 0, err
        assert _approve(plane, plane["r"], _top_cards(plane, plane["r"])[0])[0] == 200
        cs, body = _chain(plane)
        assert "primary-phone" in cs.members and cs.sealed_id == before == body["bootloader_id"]

    def test_operator_key_rotation_with_the_passphrase_and_a_device_lands_and_the_old_key_stops_verifying(
            self, plane) -> None:
        new_key = _op_key()
        rc, _, err = _host(tp.rotate_operator, plane, pubkey_hex=new_key.hex())
        assert rc == 0, err
        assert _approve(plane, plane["r"], _top_cards(plane, plane["r"])[0])[0] == 200
        cs, _ = _chain(plane)
        assert cs.operator_pubkey == new_key
        assert plane["state"].get_operator_pubkey() == new_key
        assert BootloaderHandler.config.capability_operator_pubkey == new_key

    def test_operator_key_rotation_without_the_passphrase_is_refused(self, plane) -> None:
        cs, _ = _chain(plane)
        draft = {"op": "rotate-operator", "kind": "operator", "value_hex": _op_key().hex(), "algorithm": "none",
                 "seq": cs.length, "prev": cs.tip_hash, "meta": _fresh_meta()}
        status, body = _http("POST", f"{plane['base_url']}/v0.4/top-plane/open",
                             {"draft": draft, "passphrase_signature_b64u": "AAAA"})
        assert status == 403 and body["error"] == "top_plane_passphrase_invalid", body
        assert _top_cards(plane, plane["r"]) == []

    def test_a_wrong_phrase_signs_nothing_and_opens_nothing(self, plane) -> None:
        rc, _, err = _host(tp.rotate_operator, plane, pubkey_hex=_op_key().hex(),
                           phrase=PHRASE.replace("meadow", "meadows"))
        assert rc == 1 and "not the sealed passphrase" in err
        assert _top_cards(plane, plane["r"]) == []

    def test_declining_at_the_confirmation_reads_no_passphrase(self, plane) -> None:
        asked = []
        out, err = io.StringIO(), io.StringIO()
        rc = tp.rotate_operator(_args(plane, pubkey_hex=_op_key().hex()), out=out, err=err,
                                read_passphrase=lambda _l: asked.append(1) or PHRASE, confirm=lambda _q: "no")
        assert rc == 1 and asked == []

    def test_a_start_whose_id_differs_from_the_chains_sealed_id_is_refused(self, plane) -> None:
        with pytest.raises(RuntimeError, match="differs from the id SEALED"):
            create_server(bind_host="127.0.0.1", bind_port=0, state=plane["state"],
                          bootloader_id="rb1-00000000000000000000000000000000",
                          challenges=plane["challenges"], ssl_context=None)


class TestRule14_7TheOwnerResetWindow:

    def _start(self, plane, *, lost=None, slot="primary", window=2):
        if window != 2:
            BootloaderHandler.config.owner_reset_window_seconds = window
        rc, out, err = _host(tp.reset_start, plane, slot_list=[slot], confirm=lost or plane["p"].ref,
                             window_seconds=window)
        assert rc == 0, err
        return json.loads(out.strip().splitlines()[-1])["intent_id"]

    def test_an_owner_reset_starts_a_window_and_cards_every_owner_phone(self, plane) -> None:
        self._start(plane)
        assert len(_top_cards(plane, plane["r"])) == 1 and len(_top_cards(plane, plane["p"])) == 1

    def test_a_phone_named_as_lost_may_still_cancel_the_reset(self, plane) -> None:
        iid = self._start(plane)
        status, body = _approve(plane, plane["p"], _top_cards(plane, plane["p"])[0])  # P is the phone named lost
        assert status == 200 and body.get("cancelled"), body
        assert plane["state"].is_revoked("ownerreset:" + iid)

    def test_a_cancelled_reset_never_completes(self, plane) -> None:
        iid = self._start(plane)
        _approve(plane, plane["r"], _top_cards(plane, plane["r"])[0])
        time.sleep(2.2)
        rc, _, err = _host(tp.reset_arm, plane, arm=iid, slot="primary")
        assert rc == 1 and "owner_reset_cancelled" in err, err

    def test_a_reset_completed_before_the_window_is_refused(self, plane) -> None:
        iid = self._start(plane, window=1800)
        rc, _, err = _host(tp.reset_arm, plane, arm=iid, slot="primary")
        assert rc == 1 and "owner_reset_early" in err, err

    def test_a_cancel_signed_by_a_non_owner_is_refused(self, plane) -> None:
        self._start(plane)
        card = _top_cards(plane, plane["r"])[0]
        stranger = Phone("stranger")
        status, _ = _approve(plane, stranger, card)
        assert status != 200
        assert all(r.get("state") == "waiting" for r in plane["state"].list_top_plane_records()
                   if r.get("type") == "reset")
        # a refused answer takes no card: every owner phone can still cancel
        assert len(_top_cards(plane, plane["r"])) == 1 and len(_top_cards(plane, plane["p"])) == 1

    def test_the_cancel_cards_live_until_the_window_ends(self, plane) -> None:
        """A reset's cancel card lives as long as its window, never an act card's five minutes."""
        BootloaderHandler.config.owner_reset_window_seconds = 1800
        rc, out, err = _host(tp.reset_start, plane, slot_list=["primary"], confirm=plane["p"].ref,
                             window_seconds=1800)
        assert rc == 0, err
        not_before = json.loads(out.strip().splitlines()[-1])["not_before"]
        for phone in (plane["r"], plane["p"]):
            pending = plane["state"].list_pending_for_phone(phone.ref)
            card = next(c for c in pending if str(c.secret).startswith("top-plane:"))
            assert card.expires_at_unix >= not_before - 60

    def test_arming_without_the_passphrase_is_refused(self, plane) -> None:
        """The intent id is in every owner card; it arms nothing alone."""
        iid = self._start(plane)
        time.sleep(2.2)
        status, body = _http("POST", f"{plane['base_url']}/v0.4/owner/reset/arm", {"intent_id": iid})
        assert status == 400 and "code" not in body, body
        status, body = _http("POST", f"{plane['base_url']}/v0.4/owner/reset/arm",
                             {"arm": {"intent_id": iid, "slot": "primary", "nonce": "n1"},
                              "passphrase_signature_b64u": "AAAA"})
        assert status == 403 and body["error"] == "top_plane_passphrase_invalid" and "code" not in body, body

    def test_a_live_code_is_never_replaced(self, plane) -> None:
        iid = self._start(plane)
        time.sleep(2.2)
        _arm(plane, iid)
        rc, _, err = _host(tp.reset_arm, plane, arm=iid, slot="primary")
        assert rc == 1 and "owner_reset_armed" in err, err

    def test_the_challenge_is_never_served_while_armed(self, plane) -> None:
        """Only the code holder gets the registration challenge."""
        iid = self._start(plane)
        time.sleep(2.2)
        armed = _arm(plane, iid)
        _http("GET", f"{plane['base_url']}/v0.4/registration_challenge?code={armed['code']}")
        status, body = _http("GET", f"{plane['base_url']}/v0.4/owner/reset?intent_id={iid}")
        # one opaque state while waiting or armed: no timing oracle for the burn
        assert status == 200 and body["state"] == "open" and body["challenge"] is None, body

    def test_wrong_codes_burn_a_live_arm_code(self, plane) -> None:
        iid = self._start(plane)
        time.sleep(2.2)
        armed = _arm(plane, iid)
        for i in range(5):
            wrong = f"{(int(armed['code']) + 1 + i) % 1000000:06d}"
            _http("GET", f"{plane['base_url']}/v0.4/registration_challenge?code={wrong}",
                  headers={"CF-Connecting-IP": f"198.51.100.{i + 1}"})
        status, _ = _http("GET", f"{plane['base_url']}/v0.4/registration_challenge?code={armed['code']}")
        assert status != 200

    def test_private_route_typos_never_burn_a_live_code(self, plane) -> None:
        """Only the PUBLIC edge counts: a private-route or loopback pairer's typos never burn the operator's reset."""
        iid = self._start(plane)
        time.sleep(2.2)
        armed = _arm(plane, iid)
        for i in range(8):
            wrong = f"{(int(armed['code']) + 1 + i) % 1000000:06d}"
            _http("GET", f"{plane['base_url']}/v0.4/registration_challenge?code={wrong}")
        status, chal = _http("GET", f"{plane['base_url']}/v0.4/registration_challenge?code={armed['code']}")
        assert status == 200 and chal["challenge_b64u"].startswith("recto-reset-v1:"), chal

    def test_no_owner_phone_is_revoked_by_another_while_a_reset_is_open(self, plane) -> None:
        """Every owner phone keeps its cancel until the reset completes or is cancelled."""
        self._start(plane)
        status, chal = _http("GET", f"{plane['base_url']}/v0.4/registration_challenge")
        challenge = chal["challenge_b64u"]
        sig = base64.urlsafe_b64encode(plane["r"].identity.sign(f"{challenge}:{plane['p'].ref}".encode())).decode()
        status, body = _http("POST", f"{plane['base_url']}/v0.4/manage/phones/revoke", {
            "revoker_phone_id": plane["r"].ref, "target_phone_id": plane["p"].ref, "challenge_b64u": challenge,
            "signature_b64u": sig.rstrip("=")})
        assert status == 409 and body["error"] == "owner_reset_open", body
        assert plane["state"].get_phone(plane["p"].ref) is not None

    def test_a_window_shorter_than_the_bootloaders_is_refused(self, plane) -> None:
        BootloaderHandler.config.owner_reset_window_seconds = 3600
        rc, _, err = _host(tp.reset_start, plane, slot_list=["primary"], confirm=plane["p"].ref, window_seconds=60)
        assert rc == 1 and "owner_reset_window_short" in err

    def test_the_reset_completes_after_the_window_and_seats_the_fresh_device(self, plane) -> None:
        iid = self._start(plane)
        time.sleep(2.2)
        armed = _arm(plane, iid)
        fresh = Phone("fresh")
        status, chal = _http("GET", f"{plane['base_url']}/v0.4/registration_challenge?code={armed['code']}")
        assert status == 200 and chal["challenge_b64u"].startswith("recto-reset-v1:" + iid), chal
        status, body = fresh.register(plane, "primary", challenge=chal["challenge_b64u"])
        assert status == 202 and body["status"] == "reset_pending_completion", body
        rc, out, err = _host(tp.reset_complete, plane, complete=iid)
        assert rc == 0, err
        assert fresh.ref in out
        cs, _ = _chain(plane)
        assert cs.members["primary-phone"].pubkey == _raw(fresh) and iid in cs.resets
        assert plane["state"].get_phone(plane["p"].ref) is None
        assert plane["state"].get_phone(fresh.ref).slot == "primary"

    def test_the_direct_host_reset_is_refused_once_sealed(self, plane, tmp_path) -> None:
        from recto.cli import main

        plane["server"].shutdown()
        plane["server"].server_close()
        out, err = io.StringIO(), io.StringIO()
        rc = main(["bootloader", "owner-reset", "--state-dir", str(plane["tmp"]), "--slot", "primary", "--confirm",
                   plane["p"].ref], stdout=out, stderr=err)
        assert rc == 1 and "top plane is SEALED" in err.getvalue(), err.getvalue()


class TestRule14_7TheSealHolds:

    def test_a_truncated_chain_refuses_after_the_seal(self, plane) -> None:
        """Cutting the chain back to its pre-seal entries is a tamper signal, never 'unsealed'."""
        path = Path(plane["tmp"]) / "genesis_members.json"
        body = json.loads(path.read_text(encoding="utf-8"))
        body["chain"] = body["chain"][:2]
        path.write_text(json.dumps(body), encoding="utf-8")
        status, out = _http("GET", f"{plane['base_url']}/v0.4/genesis/chain")
        assert status == 503 and out["error"] == "genesis_chain_unreadable", out
        n = Phone("newphone")
        assert n.register(plane, "primary")[0] == 409
        status, out = n.register(plane, "primary", replace=plane["p"].ref, challenge=n.last_challenge)
        assert status == 503 and out["error"] == "genesis_chain_unreadable", out
        with pytest.raises(RuntimeError, match="does not replay"):
            create_server(bind_host="127.0.0.1", bind_port=0, state=plane["state"], bootloader_id="x",
                          challenges=plane["challenges"], ssl_context=None)

    def test_the_anchor_refuses_a_start_whose_chain_is_not_sealed_with_the_expected_id(self, plane) -> None:
        """The anchor (RECTO_EXPECT_SEALED_ID), set outside the state dir: with the mark deleted and the chain cut
        back, the start refuses."""
        sealed = _chain(plane)[0].sealed_id
        with pytest.raises(RuntimeError, match="RECTO_EXPECT_SEALED_ID"):
            create_server(bind_host="127.0.0.1", bind_port=0, state=plane["state"], bootloader_id="x",
                          challenges=plane["challenges"], ssl_context=None, expect_sealed_id="rb1-not-this-one")
        tmp = Path(plane["tmp"])
        (tmp / "genesis_seal_mark.json").unlink()
        body = json.loads((tmp / "genesis_members.json").read_text(encoding="utf-8"))
        body["chain"] = body["chain"][:2]
        (tmp / "genesis_members.json").write_text(json.dumps(body), encoding="utf-8")
        with pytest.raises(RuntimeError, match="not sealed"):
            create_server(bind_host="127.0.0.1", bind_port=0, state=plane["state"], bootloader_id="x",
                          challenges=plane["challenges"], ssl_context=None, expect_sealed_id=sealed)

    def test_the_anchor_refuses_every_act_at_runtime(self, plane) -> None:
        sealed = _chain(plane)[0].sealed_id
        BootloaderHandler.config.expect_sealed_id = sealed
        try:
            tmp = Path(plane["tmp"])
            (tmp / "genesis_seal_mark.json").unlink()
            body = json.loads((tmp / "genesis_members.json").read_text(encoding="utf-8"))
            body["chain"] = body["chain"][:2]
            (tmp / "genesis_members.json").write_text(json.dumps(body), encoding="utf-8")
            status, out = _http("GET", f"{plane['base_url']}/v0.4/genesis/chain")
            assert status == 503 and "RECTO_EXPECT_SEALED_ID" in out["detail"], out
        finally:
            BootloaderHandler.config.expect_sealed_id = None

    def test_open_seats_owner_devices_only(self, plane) -> None:
        """An act cannot seat a non-device co-signer."""
        cs, _ = _chain(plane)
        draft = {"op": "add", "kind": "other", "value_hex": bytes(32).hex(), "algorithm": "ed25519",
                 "seq": cs.length, "prev": cs.tip_hash, "meta": None}
        status, body = _http("POST", f"{plane['base_url']}/v0.4/top-plane/open",
                             {"draft": draft, "passphrase_signature_b64u": "AAAA"})
        assert status == 400 and body["error"] == "top_plane_kind_refused", body

    def test_owner_genesis_never_seats_a_phone_by_code_alone_once_sealed(self, plane) -> None:
        st = plane["state"]
        for ref in (plane["r"].ref, plane["p"].ref):
            st.revoke_phone(ref)
        st.set_owner_genesis("open")
        status, body = Phone("intruder").register(plane, "primary")
        assert status == 403 and body["error"] == "owner_genesis_sealed", body

    def test_an_act_card_past_its_expiry_appends_nothing(self, plane) -> None:
        rc, _, err = _host(tp.rotate_operator, plane, pubkey_hex=_op_key().hex())
        assert rc == 0, err
        rec = next(r for r in plane["state"].list_top_plane_records()
                   if r.get("type") == "act" and r["draft"]["op"] == "rotate-operator" and r["state"] == "pending")
        rec["expires_at_unix"] = int(time.time()) - 1
        plane["state"].put_top_plane_record(rec)
        card = _top_cards(plane, plane["r"])[0]
        status, body = _approve(plane, plane["r"], card)
        assert status == 410 and body["error"] == "top_plane_card_expired", body
        assert _chain(plane)[0].operator_pubkey is None


class TestRule14_7TheResetSurvives:

    def _start(self, plane, slots, lost, window=2):
        BootloaderHandler.config.owner_reset_window_seconds = window
        rc, out, err = _host(tp.reset_start, plane, slot_list=slots, every_owner_lost=len(slots) == 2,
                             confirm=",".join(lost), window_seconds=window)
        assert rc == 0, err
        return json.loads(out.strip().splitlines()[-1])["intent_id"]

    def _seat(self, plane, iid, slot, fresh):
        armed = _arm(plane, iid, slot)
        status, chal = _http("GET", f"{plane['base_url']}/v0.4/registration_challenge?code={armed['code']}")
        assert status == 200, chal
        status, body = fresh.register(plane, slot, challenge=chal["challenge_b64u"])
        assert status == 202, body
        rc, _, err = _host(tp.reset_complete, plane, complete=iid)
        assert rc == 0, err

    def test_a_restart_inside_the_window_cards_every_owner_phone_again(self, plane) -> None:
        """Pending cards are not reloaded, so the startup re-cards every open reset."""
        iid = self._start(plane, ["primary"], [plane["p"].ref], window=1800)
        from tests.test_bootloader_owner_slots import _start as _start_server, _stop
        plane["server"].shutdown()
        plane["server"].server_close()
        server, thread, ctx = _start_server(plane["tmp"], signed_poll_mode="advisory",
                                            capability_operator_pubkey=plane["op_key"])
        try:
            ctx.update(r=plane["r"], p=plane["p"])
            cards = _top_cards(ctx, plane["p"])
            assert len(cards) == 1 and len(_top_cards(ctx, plane["r"])) == 1
            status, body = _approve(ctx, plane["p"], cards[0])
            assert status == 200 and body.get("cancelled"), body
            assert ctx["state"].is_revoked("ownerreset:" + iid)
        finally:
            _stop(server, thread)

    def test_a_two_slot_reset_seats_both_slots(self, plane) -> None:
        """Every-owner-lost seats each of its slots once."""
        iid = self._start(plane, ["primary", "recovery"], [plane["p"].ref, plane["r"].ref])
        time.sleep(2.2)
        f1, f2 = Phone("fresh-primary"), Phone("fresh-recovery")
        self._seat(plane, iid, "primary", f1)
        self._seat(plane, iid, "recovery", f2)
        cs, _ = _chain(plane)
        assert cs.members["primary-phone"].pubkey == _raw(f1) and cs.members["recovery-phone"].pubkey == _raw(f2)
        rec = plane["state"].get_top_plane_record(iid)
        assert rec["state"] == "completed" and sorted(rec["completed_slots"]) == ["primary", "recovery"]

    def test_the_host_aborts_an_open_reset_and_a_new_one_may_start(self, plane) -> None:
        """A reset in any open state can be ended with the passphrase."""
        iid = self._start(plane, ["primary"], [plane["p"].ref], window=1800)
        rc, _, err = _host(tp.reset_abort, plane, abort=iid)
        assert rc == 0, err
        assert plane["state"].get_top_plane_record(iid)["state"] == "aborted"
        assert plane["state"].is_revoked("ownerreset:" + iid)
        assert _top_cards(plane, plane["r"]) == [] and _top_cards(plane, plane["p"]) == []
        self._start(plane, ["primary"], [plane["p"].ref], window=1800)

    def test_an_abort_without_the_passphrase_is_refused(self, plane) -> None:
        iid = self._start(plane, ["primary"], [plane["p"].ref], window=1800)
        status, body = _http("POST", f"{plane['base_url']}/v0.4/owner/reset/abort",
                             {"abort": {"intent_id": iid, "nonce": "n"}, "passphrase_signature_b64u": "AAAA"})
        assert status == 403 and body["error"] == "top_plane_passphrase_invalid", body


class TestRule14_7RevokingASealedDevice:
    """Revoking a sealed device member is a top-plane act (the passphrase and the revoking phone); non-members and
    self-revokes stay as they are (hard rule 14.7)."""

    def _revoke(self, plane, revoker, target):
        status, chal = _http("GET", f"{plane['base_url']}/v0.4/registration_challenge")
        challenge = chal["challenge_b64u"]
        sig = base64.urlsafe_b64encode(revoker.identity.sign(f"{challenge}:{target.ref}".encode())).decode()
        return _http("POST", f"{plane['base_url']}/v0.4/manage/phones/revoke", {
            "revoker_phone_id": revoker.ref, "target_phone_id": target.ref, "challenge_b64u": challenge,
            "signature_b64u": sig.rstrip("=")})

    def _seat_primary(self, plane):
        rc, _, err = _host(tp.add_device, plane, slot="primary", public_key=plane["p"].pub)
        assert rc == 0, err
        assert _approve(plane, plane["r"], _top_cards(plane, plane["r"])[0])[0] == 200

    def test_a_sibling_cannot_revoke_a_sealed_device(self, plane) -> None:
        self._seat_primary(plane)
        status, body = self._revoke(plane, plane["r"], plane["p"])
        assert status == 409 and body["error"] == "top_plane_revoke_required", body
        assert plane["state"].get_phone(plane["p"].ref) is not None

    def test_the_passphrase_and_the_revoking_device_remove_a_sealed_device(self, plane) -> None:
        self._seat_primary(plane)
        rc, _, err = _host(tp.remove_device, plane, slot="primary")
        assert rc == 0, err
        assert _top_cards(plane, plane["p"]) == []  # the phone removed never signs its own removal
        assert _approve(plane, plane["r"], _top_cards(plane, plane["r"])[0])[0] == 200
        cs, _ = _chain(plane)
        assert "primary-phone" not in cs.members
        assert plane["state"].get_phone(plane["p"].ref) is None

    def test_the_last_sealed_device_cannot_be_removed(self, plane) -> None:
        rc, _, err = _host(tp.remove_device, plane, slot="recovery")
        assert rc == 1 and "top_plane_no_device_phone" in err, err

    def test_a_phone_that_is_not_a_sealed_device_is_still_revoked_by_a_sibling(self, plane) -> None:
        status, body = self._revoke(plane, plane["r"], plane["p"])  # P holds the primary slot, not a device
        assert status == 200, body
        assert plane["state"].get_phone(plane["p"].ref) is None

    def test_a_sealed_device_still_revokes_itself(self, plane) -> None:
        self._seat_primary(plane)
        status, body = self._revoke(plane, plane["p"], plane["p"])
        assert status == 200, body


class TestEveryLegIsFreshAndBound:
    """Each signed leg is fresh, opens once and is bound to what it names; the seal's mark and the reset's phones
    hold."""

    def _rotate_draft(self, plane, **meta):
        cs, _ = _chain(plane)
        from recto.bootloader import top_plane as _top
        return _top.Draft(op="rotate-operator", kind="operator", value=_op_key(), algorithm="none", seq=cs.length,
                          prev=cs.tip_hash, meta=_fresh_meta(**meta)), cs

    def _signed_open(self, plane, draft):
        from recto.bootloader.genesis_chain import act_message
        msg = act_message(seq=draft.seq, op=draft.op, kind=draft.kind, pubkey=draft.value, algorithm=draft.algorithm,
                          prev=draft.prev, meta=draft.meta, sealed_id=_chain(plane)[0].sealed_id)
        sig = base64.urlsafe_b64encode(derive_passphrase_member(PHRASE).sign(msg)).decode().rstrip("=")
        return _http("POST", f"{plane['base_url']}/v0.4/top-plane/open",
                     {"draft": draft.as_wire(), "passphrase_signature_b64u": sig})

    def test_a_stored_passphrase_signature_opens_its_act_once(self, plane) -> None:
        draft, _ = self._rotate_draft(plane)
        assert self._signed_open(plane, draft)[0] == 200
        status, body = self._signed_open(plane, draft)  # the same (draft, signature) again
        assert status == 409 and body["error"] == "top_plane_draft_used", body

    def test_an_act_past_its_not_after_is_refused(self, plane) -> None:
        draft, _ = self._rotate_draft(plane, not_after=int(time.time()) - 1)
        status, body = self._signed_open(plane, draft)
        assert status == 400 and body["error"] == "top_plane_draft_stale", body

    def test_a_reset_not_armed_within_its_grace_expires(self, plane, monkeypatch) -> None:
        from recto.bootloader import top_plane as _top
        monkeypatch.setattr(_top, "RESET_ARM_GRACE_SECONDS", 1)
        rc, out, err = _host(tp.reset_start, plane, slot_list=["primary"], confirm=plane["p"].ref)
        iid = json.loads(out.strip().splitlines()[-1])["intent_id"]
        time.sleep(4.5)
        rc, _, err = _host(tp.reset_arm, plane, arm=iid, slot="primary")
        assert rc == 1 and "owner_reset_expired" in err, err
        rc, _, err = _host(tp.reset_start, plane, slot_list=["primary"], confirm=plane["p"].ref)
        assert rc == 0, err  # an expired reset never blocks a fresh start

    def test_a_mistyped_passphrase_prints_none_of_its_words(self, plane) -> None:
        typed = "correct horse, battery staple ridge lantern copper meadow 7"
        rc, out, err = _host(tp.rotate_operator, plane, pubkey_hex=_op_key().hex(), phrase=typed)
        assert rc == 1
        for word in ("correct", "horse", "battery", "lantern", "meadow", "7", ","):
            assert word not in err, (word, err)  # the refusal repeats none of the typed tokens
        for word in ("correct", "horse", "battery", "lantern", "meadow"):
            assert word not in out, (word, out)  # nor does anything shown before it

    def test_a_re_arm_kills_the_previous_codes_challenge(self, plane) -> None:
        rc, out, err = _host(tp.reset_start, plane, slot_list=["primary"], confirm=plane["p"].ref)
        iid = json.loads(out.strip().splitlines()[-1])["intent_id"]
        time.sleep(2.2)
        first = _arm(plane, iid)
        status, chal = _http("GET", f"{plane['base_url']}/v0.4/registration_challenge?code={first['code']}")
        rec = plane["state"].get_top_plane_record(iid)
        rec["code_expires_at"] = int(time.time()) - 1  # the first code lapses unused
        plane["state"].put_top_plane_record(rec)
        _arm(plane, iid)
        status, body = Phone("late").register(plane, "primary", challenge=chal["challenge_b64u"])
        assert status != 202, body

    def test_an_approval_from_before_the_seal_never_seats_after_it(self, tmp_path) -> None:
        with serving(tmp_path, signed_poll_mode="advisory", capability_operator_pubkey=_op_key()) as ctx:
            r, p, n = Phone("recovery"), Phone("primary"), Phone("newphone")
            _enroll_genesis(ctx, r, "recovery")
            _enroll_approved(ctx, p, "primary", approver=r)
            _seed_chain(ctx["state"], r)
            assert n.register(ctx, "primary")[0] == 409
            n.register(ctx, "primary", replace=p.ref, challenge=n.last_challenge)
            cards = [c for c in _signed_cards(ctx, r) if str(c.get("secret", "")).startswith("owner-slot:")]
            assert _approve(ctx, r, cards[0])[0] == 200  # approved while unsealed
            assert _host(tp.seal_id, ctx)[0] == 0
            assert _approve(ctx, r, _top_cards(ctx, r)[0])[0] == 200  # the seal appends
            status, body = n.register(ctx, "primary", replace=p.ref)
            assert status in (403, 409) and ctx["state"].get_phone(n.ref) is None, body

    def test_a_device_key_that_is_not_a_registered_owner_phone_is_refused(self, plane) -> None:
        stranger = Phone("stranger")
        rc, _, err = _host(tp.add_device, plane, slot="primary", public_key=stranger.pub)
        assert rc == 1 and "top_plane_device_unregistered" in err, err

    def test_add_device_says_what_it_replaces(self, plane) -> None:
        rc, out, _ = _host(tp.add_device, plane, slot="recovery", public_key=plane["r"].pub, answer="no")
        assert "REPLACES the sealed recovery-phone" in out

    def test_a_rotation_to_a_non_point_is_refused_before_signing(self, plane) -> None:
        rc, _, err = _host(tp.rotate_operator, plane, pubkey_hex=(bytes([0x11]) * 64).hex())
        assert rc == 2 and "not a secp256k1 point" in err

    def test_seal_id_refuses_an_id_that_is_not_derived(self, tmp_path) -> None:
        with serving(tmp_path, signed_poll_mode="advisory") as ctx:  # no operator key: a label id
            r = Phone("recovery")
            _enroll_genesis(ctx, r, "recovery")
            _seed_chain(ctx["state"], r)
            rc, _, err = _host(tp.seal_id, ctx)
            assert rc == 2 and "not a derived rb1- id" in err, err

    def test_a_sealed_chain_without_its_mark_refuses(self, plane) -> None:
        mark = Path(plane["tmp"]) / "genesis_seal_mark.json"
        mark.unlink()
        assert _http("GET", f"{plane['base_url']}/v0.4/genesis/chain")[0] == 503
        mark.write_text("{}", encoding="utf-8")
        assert _http("GET", f"{plane['base_url']}/v0.4/genesis/chain")[0] == 503

    def test_the_mark_advances_and_a_chain_cut_back_to_the_seal_refuses(self, plane) -> None:
        rc, _, err = _host(tp.rotate_operator, plane, pubkey_hex=_op_key().hex())
        assert rc == 0, err
        assert _approve(plane, plane["r"], _top_cards(plane, plane["r"])[0])[0] == 200
        mark = json.loads((Path(plane["tmp"]) / "genesis_seal_mark.json").read_text(encoding="utf-8"))
        assert mark["length"] == 4  # passphrase, recovery, seal, rotation
        path = Path(plane["tmp"]) / "genesis_members.json"
        body = json.loads(path.read_text(encoding="utf-8"))
        body["chain"] = body["chain"][:3]  # back to the seal entry, the mark kept
        path.write_text(json.dumps(body), encoding="utf-8")
        assert _http("GET", f"{plane['base_url']}/v0.4/genesis/chain")[0] == 503
        n = Phone("newphone")
        assert n.register(plane, "primary")[0] == 409
        assert n.register(plane, "primary", replace=plane["p"].ref, challenge=n.last_challenge)[0] == 503
        with pytest.raises(RuntimeError, match="does not replay"):
            create_server(bind_host="127.0.0.1", bind_port=0, state=plane["state"], bootloader_id="x",
                          challenges=plane["challenges"], ssl_context=None)

    def test_an_unsigned_read_serves_no_top_plane_card(self, plane) -> None:
        _host(tp.reset_start, plane, slot_list=["primary"], confirm=plane["p"].ref)
        status, body = _http("GET", f"{plane['base_url']}/v0.4/pending?phone_id={plane['r'].ref}")
        assert status == 200
        assert not any(str(c.get("secret", "")).startswith("top-plane:") for c in body.get("requests", [])), body

    def test_the_phones_named_lost_must_be_the_slots_owner_phones(self, plane) -> None:
        rc, _, err = _host(tp.reset_start, plane, slot_list=["primary"], confirm=plane["r"].ref)  # R holds recovery
        assert rc == 1 and "owner_reset_invalid" in err, err


class TestTheHostPassphrase:

    def test_the_passphrase_is_read_from_a_hidden_prompt_only(self, monkeypatch) -> None:
        import getpass

        from recto.cli import _prompt_passphrase, _top_plane_reader

        assert _top_plane_reader(getpass.getpass) is _prompt_passphrase
        monkeypatch.setattr("sys.stdin", io.StringIO(PHRASE + "\n"))  # not a TTY
        with pytest.raises(SystemExit, match="no terminal"):
            _prompt_passphrase("Passphrase (not echoed)")

    def test_nothing_of_the_passphrase_is_written_or_logged(self, plane, caplog) -> None:
        caplog.set_level("DEBUG")
        rc, out, err = _host(tp.rotate_operator, plane, pubkey_hex=_op_key().hex())
        assert rc == 0
        _approve(plane, plane["r"], _top_cards(plane, plane["r"])[0])
        words = PHRASE.split()
        for f in Path(plane["tmp"]).rglob("*"):
            if f.is_file() and f.suffix != ".lock":
                text = f.read_bytes()
                assert not any(w.encode() in text for w in ("lantern", "meadow", "copper")), f
        blob = out + err + caplog.text
        assert not any(w in blob for w in words[4:]), "a passphrase word reached the output or the log"
