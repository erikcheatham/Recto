"""Hard rule 14.7 under faults, races and restarts: a committed act finishes, an expired reset frees what it held,
every reset-record write holds the registry lock, each signed host leg is fresh and spent once, the seal's mark
settles, and nothing of a typed passphrase reaches a terminal.

Each test runs a real bootloader through the `plane` fixture of test_top_plane_e2e (a chain whose first device
entered under the passphrase alone, then sealed by the passphrase and that device).
"""

from __future__ import annotations

import base64
import io
import json
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import pytest

from recto import top_plane_cli as tp
from recto.bootloader import top_plane
from recto.bootloader.genesis_chain import act_message, canonical_meta
from recto.bootloader.server import BootloaderHandler, ChallengeStore, create_server
from recto.bootloader.state import PhoneRegistration, StateStore
from recto.profile.passphrase_member import derive_passphrase_member

from tests.test_bootloader_owner_slots import _approve, _enroll_approved, _enroll_genesis, _signed_cards, serving
from tests.test_bootloader_owner_slots import _start as _start_server
from tests.test_bootloader_owner_slots import _stop
from tests.test_bootloader_signed_polls import _denial_headers
from tests.test_bootloader_slots import Phone, _http
from tests.test_top_plane_e2e import (  # noqa: F401 - `plane` is the fixture
    PHRASE, _arm, _chain, _host, _op_key, _seed_chain, _top_cards, plane,
)

_PP = None


def _pp():
    global _PP
    if _PP is None:
        _PP = derive_passphrase_member(PHRASE)
    return _PP


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _sign_pp(message: bytes) -> str:
    return _b64u(_pp().sign(message))


def _leg(**over) -> dict:
    leg = {"nonce": "n" * 24, "not_after": int(time.time()) + 600}
    leg.update(over)
    return leg


def _one_shot(monkeypatch, obj, name, exc=None):
    """The next call of obj.name raises (a disk that fills once); later calls run as before."""
    orig = getattr(obj, name)
    fired: list[int] = []

    def faulty(*a, **k):
        if not fired:
            fired.append(1)
            raise exc or OSError("injected fault")
        return orig(*a, **k)

    monkeypatch.setattr(obj, name, faulty)
    return fired


@contextmanager
def _restarted(plane, *, from_vault: bool = False):
    """Stop the plane's bootloader and start a new one on the same state dir - with the plane's operator key, or
    (after a rotation reached the vault) with the vault's own."""
    plane["server"].shutdown()
    plane["server"].server_close()
    server, thread, ctx = _start_server(plane["tmp"], signed_poll_mode="advisory",
                                        capability_operator_pubkey=None if from_vault else plane["op_key"])
    ctx.update(r=plane["r"], p=plane["p"], tmp=plane["tmp"], op_key=plane["op_key"])
    try:
        yield ctx
    finally:
        _stop(server, thread)


def _start_reset(ctx, *, slots=("primary",), lost=None, window=2):
    BootloaderHandler.config.owner_reset_window_seconds = window
    rc, out, err = _host(tp.reset_start, ctx, slot_list=list(slots), every_owner_lost=len(slots) == 2,
                         confirm=",".join(lost or [ctx["p"].ref]), window_seconds=window)
    assert rc == 0, err
    return json.loads(out.strip().splitlines()[-1])["intent_id"]


def _post_start(ctx, *, slots=("primary",), lost=None, window=2):
    """Start a reset with the passphrase key already derived: the intent's window starts as it is posted."""
    BootloaderHandler.config.owner_reset_window_seconds = window
    cs, body = _chain(ctx)
    intent = top_plane.new_intent(bootloader_id=cs.sealed_id, slots=list(slots), lost=list(lost or [ctx["p"].ref]),
                                  window_seconds=window)
    status, out = _http("POST", f"{ctx['base_url']}/v0.4/owner/reset/start",
                        {"intent": intent,
                         "passphrase_signature_b64u": _sign_pp(top_plane.reset_intent_digest(intent))})
    assert status == 200, out
    return intent["intent_id"]


def _registered(ctx, *, slot="primary", lost=None):
    """A reset whose fresh device has answered its code: state 'registered'."""
    iid = _start_reset(ctx, slots=(slot,), lost=lost)
    time.sleep(2.2)
    armed = _arm(ctx, iid, slot)
    status, chal = _http("GET", f"{ctx['base_url']}/v0.4/registration_challenge?code={armed['code']}")
    assert status == 200, chal
    fresh = Phone("fresh")
    status, body = fresh.register(ctx, slot, challenge=chal["challenge_b64u"])
    assert status == 202, body
    return iid, fresh


def _revoke(ctx, revoker, target):
    status, chal = _http("GET", f"{ctx['base_url']}/v0.4/registration_challenge")
    challenge = chal["challenge_b64u"]
    sig = _b64u(revoker.identity.sign(f"{challenge}:{target.ref}".encode()))
    return _http("POST", f"{ctx['base_url']}/v0.4/manage/phones/revoke", {
        "revoker_phone_id": revoker.ref, "target_phone_id": target.ref, "challenge_b64u": challenge,
        "signature_b64u": sig})


def _seat_primary_device(ctx):
    rc, _, err = _host(tp.add_device, ctx, slot="primary", public_key=ctx["p"].pub)
    assert rc == 0, err
    assert _approve(ctx, ctx["r"], _top_cards(ctx, ctx["r"])[0])[0] == 200


def _signed_open(ctx, draft):
    cs = _chain(ctx)[0]
    msg = act_message(seq=draft.seq, op=draft.op, kind=draft.kind, pubkey=draft.value, algorithm=draft.algorithm,
                      prev=draft.prev, meta=draft.meta, sealed_id=cs.sealed_id)
    return _http("POST", f"{ctx['base_url']}/v0.4/top-plane/open",
                 {"draft": draft.as_wire(), "passphrase_signature_b64u": _sign_pp(msg)})


def _rotate_draft(ctx):
    cs = _chain(ctx)[0]
    return top_plane.Draft(op="rotate-operator", kind="operator", value=_op_key(), algorithm="none", seq=cs.length,
                           prev=cs.tip_hash, meta=canonical_meta(_leg(nonce="r" * 32)))


# --- a committed act finishes ---------------------------------------------------------------------------------------

class TestACommittedActFinishes:

    def test_a_fault_at_the_revoke_finishes_on_a_repeat_complete(self, plane, monkeypatch) -> None:
        iid, fresh = _registered(plane)
        fired = _one_shot(monkeypatch, plane["state"], "revoke_phone")
        rc, out, err = _host(tp.reset_complete, plane, complete=iid)
        assert fired and rc == 3 and "COMMITTED" in out and "REFUSED" not in err, (rc, out, err)
        rc, out, err = _host(tp.reset_complete, plane, complete=iid)
        assert rc == 0, err
        st = plane["state"]
        assert st.get_phone(plane["p"].ref) is None and st.get_phone(fresh.ref).slot == "primary"
        assert st.get_top_plane_record(iid)["state"] == "completed"
        status, body = _revoke(plane, plane["r"], fresh)  # no open reset holds the owner phones any longer
        assert body.get("error") != "owner_reset_open", body

    def test_a_fault_at_the_register_in_a_sole_phone_set_finishes_at_the_next_start(self, plane, monkeypatch) -> None:
        assert _revoke(plane, plane["r"], plane["p"])[0] == 200  # R is now the only owner phone
        iid, fresh = _registered(plane, slot="recovery", lost=[plane["r"].ref])
        fired = _one_shot(monkeypatch, plane["state"], "register_phone")
        rc, out, err = _host(tp.reset_complete, plane, complete=iid)
        assert fired and rc == 3 and "REFUSED" not in err, (rc, out, err)
        assert plane["state"].get_phone(plane["r"].ref) is not None  # the slot is never left empty
        with _restarted(plane) as ctx:
            st = ctx["state"]
            assert st.get_phone(fresh.ref).slot == "recovery" and st.get_phone(plane["r"].ref) is None
            assert st.get_top_plane_record(iid)["state"] == "completed"

    def test_a_fault_at_a_removals_revoke_finishes_at_the_next_start(self, plane, monkeypatch) -> None:
        _seat_primary_device(plane)
        rc, _, err = _host(tp.remove_device, plane, slot="primary")
        assert rc == 0, err
        fired = _one_shot(monkeypatch, plane["state"], "revoke_phone")
        status, body = _approve(plane, plane["r"], _top_cards(plane, plane["r"])[0])
        assert fired and status == 202 and body.get("appended") and body.get("finished") is False, body
        assert "primary-phone" not in _chain(plane)[0].members
        with _restarted(plane) as ctx:
            assert ctx["state"].get_phone(plane["p"].ref) is None
            assert all(r["state"] == "appended" for r in ctx["state"].list_top_plane_records()
                       if r.get("type") == "act" and r["draft"]["op"] == "remove")


# --- an expired reset frees what it held ----------------------------------------------------------------------------

class TestAnExpiredResetFrees:

    def test_a_registered_reset_past_its_bound_refuses_complete_and_frees_revokes_and_starts(
            self, plane, monkeypatch) -> None:
        iid, _ = _registered(plane)
        monkeypatch.setattr(top_plane, "RESET_ARM_GRACE_SECONDS", 1)
        rec = plane["state"].get_top_plane_record(iid)
        rec["code_expires_at"] = int(time.time()) - 5
        plane["state"].put_top_plane_record(rec)
        rc, _, err = _host(tp.reset_complete, plane, complete=iid)
        assert rc == 1 and "owner_reset_expired" in err and "not completed after its code" in err, err
        assert _revoke(plane, plane["r"], plane["p"])[0] == 200
        _start_reset(plane, slots=("recovery",), lost=[plane["r"].ref])

    def test_an_expired_waiting_reset_never_blocks_a_sibling_revoke(self, plane, monkeypatch) -> None:
        monkeypatch.setattr(top_plane, "RESET_ARM_GRACE_SECONDS", 1)
        _post_start(plane)
        time.sleep(4.5)
        status, body = _revoke(plane, plane["r"], plane["p"])
        assert status == 200, body


# --- every reset-record write holds the registry lock ---------------------------------------------------------------

class TestTheResetRecordIsWrittenUnderTheLock:

    def test_no_plaintext_challenge_is_on_disk_while_armed(self, plane) -> None:
        iid = _start_reset(plane)
        time.sleep(2.2)
        armed = _arm(plane, iid)
        status, chal = _http("GET", f"{plane['base_url']}/v0.4/registration_challenge?code={armed['code']}")
        assert status == 200
        text = (Path(plane["tmp"]) / "top_plane.json").read_text(encoding="utf-8")
        assert chal["challenge_b64u"] not in text

    def test_an_abort_inside_a_redemption_stays_aborted(self, plane, monkeypatch) -> None:
        iid = _start_reset(plane)
        time.sleep(2.2)
        armed = _arm(plane, iid)
        st = plane["state"]
        orig = BootloaderHandler._armed_reset_for_code

        def abort_lands_here(self, code):
            rec = orig(self, code)
            if rec is not None:  # the host's abort lands between the redemption's read and its write
                live = dict(st.get_top_plane_record(rec["id"]), state="aborted", code_hash=None)
                st.put_top_plane_record(live)
            return rec

        monkeypatch.setattr(BootloaderHandler, "_armed_reset_for_code", abort_lands_here)
        status, _ = _http("GET", f"{plane['base_url']}/v0.4/registration_challenge?code={armed['code']}")
        assert status != 200
        assert st.get_top_plane_record(iid)["state"] == "aborted"

    def test_every_reset_record_write_holds_the_registry_lock(self, plane, monkeypatch) -> None:
        st = plane["state"]
        orig = st.put_top_plane_record
        unlocked: list[str] = []

        def watched(record):
            if record.get("type") == "reset" and not st._registry_lock._is_owned():
                unlocked.append(record.get("state"))
            return orig(record)

        monkeypatch.setattr(st, "put_top_plane_record", watched)
        iid = _start_reset(plane)
        time.sleep(2.2)
        armed = _arm(plane, iid)
        wrong = f"{(int(armed['code']) + 1) % 1000000:06d}"
        _http("GET", f"{plane['base_url']}/v0.4/registration_challenge?code={wrong}",
              headers={"CF-Connecting-IP": "198.51.100.9"})
        status, chal = _http("GET", f"{plane['base_url']}/v0.4/registration_challenge?code={armed['code']}")
        assert status == 200, chal
        assert Phone("fresh").register(plane, "primary", challenge=chal["challenge_b64u"])[0] == 202
        rc, _, err = _host(tp.reset_complete, plane, complete=iid)
        assert rc == 0, err
        assert unlocked == [], unlocked


# --- a removal names its member -------------------------------------------------------------------------------------

class TestARemovalNamesItsMember:

    def test_a_removal_under_another_key_is_refused_at_open(self, plane) -> None:
        _seat_primary_device(plane)
        cs = _chain(plane)[0]
        stranger = Phone("stranger")
        draft = top_plane.Draft(op="remove", kind="primary-phone", value=base64.urlsafe_b64decode(
            stranger.pub + "=" * (-len(stranger.pub) % 4)), algorithm="ed25519", seq=cs.length, prev=cs.tip_hash,
            meta=canonical_meta(_leg(nonce="m" * 32)))
        status, body = _signed_open(plane, draft)
        assert status == 400 and body["error"] == "top_plane_remove_mismatch", body


# --- the seal holds the operator key --------------------------------------------------------------------------------

def _bootstrap(plane, key_hex: str, *, force: bool = True):
    from recto.cli import main

    plane["server"].shutdown()
    plane["server"].server_close()
    out, err = io.StringIO(), io.StringIO()
    argv = ["vault", "bootstrap", key_hex, "--state-dir", str(plane["tmp"])] + (["--force"] if force else [])
    return main(argv, stdout=out, stderr=err), out.getvalue(), err.getvalue()


class TestTheSealHoldsTheOperatorKey:

    def test_the_sealed_chain_records_the_operator_key(self, plane) -> None:
        cs = _chain(plane)[0]
        assert cs.sealed_operator_pubkey == plane["op_key"] and cs.current_operator_pubkey == plane["op_key"]

    def test_bootstrap_to_a_new_key_is_refused_once_sealed(self, plane) -> None:
        rc, _, err = _bootstrap(plane, _op_key().hex())
        assert rc == 1 and "SEALED" in err, err

    def test_bootstrap_to_the_chains_own_key_still_repairs(self, plane) -> None:
        rc, out, err = _bootstrap(plane, plane["op_key"].hex())
        assert rc == 0, err

    def test_a_swapped_vault_key_under_a_sealed_chain_refuses_the_start(self, plane) -> None:
        plane["server"].shutdown()
        plane["server"].server_close()
        state = StateStore(state_dir=Path(plane["tmp"]))
        state.put_operator_pubkey(_op_key())
        with pytest.raises(RuntimeError, match="GATE 5d: the operator key"):
            server = create_server(bind_host="127.0.0.1", bind_port=0, state=state, bootloader_id="x",
                                   challenges=ChallengeStore(state=state), ssl_context=None)
            server.server_close()

    def test_a_seal_recording_another_operator_key_is_refused_at_open(self, tmp_path) -> None:
        with serving(tmp_path, signed_poll_mode="advisory", capability_operator_pubkey=_op_key()) as ctx:
            r = Phone("recovery")
            _enroll_genesis(ctx, r, "recovery")
            _seed_chain(ctx["state"], r)
            cs, body = _chain(ctx)
            draft = top_plane.Draft(op="seal-id", kind="bootloader-id", value=body["bootloader_id"].encode(),
                                    algorithm="none", seq=cs.length, prev=cs.tip_hash,
                                    meta=canonical_meta(_leg(nonce="s" * 32, operator_pubkey=_op_key().hex(),
                                                             identity_members=[])))
            msg = act_message(seq=draft.seq, op=draft.op, kind=draft.kind, pubkey=draft.value,
                              algorithm=draft.algorithm, prev=draft.prev, meta=draft.meta,
                              sealed_id=body["bootloader_id"])
            status, out = _http("POST", f"{ctx['base_url']}/v0.4/top-plane/open",
                                {"draft": draft.as_wire(), "passphrase_signature_b64u": _sign_pp(msg)})
            assert status == 400 and out["error"] == "top_plane_seal_operator_mismatch", out


# --- each host leg is fresh and spent once --------------------------------------------------------------------------

def _post_arm(ctx, arm: dict):
    return _http("POST", f"{ctx['base_url']}/v0.4/owner/reset/arm",
                 {"arm": arm, "passphrase_signature_b64u": _sign_pp(top_plane.reset_arm_digest(arm))})


class TestEachHostLegIsSpentOnce:

    def test_an_early_arm_replayed_after_the_window_is_refused(self, plane) -> None:
        _pp()
        iid = _post_start(plane, window=3)
        arm = dict(_leg(nonce="a" * 24), intent_id=iid, slot="primary")
        status, body = _post_arm(plane, arm)
        assert status == 403 and body["error"] == "owner_reset_early", body
        time.sleep(3.2)
        status, body = _post_arm(plane, arm)
        assert status == 409 and "code" not in body, body

    def test_a_refused_armed_leg_replayed_after_the_code_expires_is_refused(self, plane) -> None:
        iid = _start_reset(plane)
        time.sleep(2.2)
        _arm(plane, iid)
        arm = dict(_leg(nonce="b" * 24), intent_id=iid, slot="primary")
        status, body = _post_arm(plane, arm)
        assert status == 409 and body["error"] == "owner_reset_armed", body
        rec = plane["state"].get_top_plane_record(iid)
        rec["code_expires_at"] = int(time.time()) - 1
        plane["state"].put_top_plane_record(rec)
        status, body = _post_arm(plane, arm)
        assert status == 409 and "code" not in body, body

    def test_an_arm_past_its_not_after_is_refused(self, plane) -> None:
        iid = _start_reset(plane)
        time.sleep(2.2)
        arm = dict(_leg(nonce="c" * 24, not_after=int(time.time()) - 1), intent_id=iid, slot="primary")
        status, body = _post_arm(plane, arm)
        assert status == 400 and "code" not in body, body


# --- the slot entry's passphrase leg is fresh -----------------------------------------------------------------------

def _approved_slot_entry(plane):
    """A slot entry for a new primary phone, approved by R and signed by the passphrase, waiting for its landing."""
    n = Phone("newphone")
    _slot_entry(plane, n)
    cards = [c for c in _signed_cards(plane, plane["r"]) if str(c.get("secret", "")).startswith("owner-slot:")]
    assert _approve(plane, plane["r"], cards[0])[0] == 200
    rc, _, err = _host(tp.approve_enroll, plane)
    assert rc == 0, err
    return n


def _slot_entry(plane, n):
    assert n.register(plane, "primary")[0] == 409
    n.register(plane, "primary", replace=plane["p"].ref, challenge=n.last_challenge)
    status, body = _http("GET", f"{plane['base_url']}/v0.4/owner/enroll/pending")
    assert status == 200 and len(body["pending"]) == 1, body
    return body["pending"][0]


def _entry_message(plane, wire: dict) -> bytes:
    d = top_plane.Draft.from_wire(wire)
    return act_message(seq=d.seq, op=d.op, kind=d.kind, pubkey=d.value, algorithm=d.algorithm, prev=d.prev,
                       meta=d.meta, sealed_id=_chain(plane)[0].sealed_id)


class TestTheSlotEntryLegIsFresh:

    def test_an_old_passphrase_signature_never_signs_a_new_identical_request(self, plane, monkeypatch) -> None:
        import types

        import recto.bootloader.server as server_module

        frozen = int(time.time())
        monkeypatch.setattr(server_module, "time", types.SimpleNamespace(
            time=lambda: frozen, gmtime=time.gmtime, strftime=time.strftime, sleep=time.sleep,
            monotonic=time.monotonic))
        n = Phone("newphone")
        first = _slot_entry(plane, n)
        old_sig = _sign_pp(_entry_message(plane, first["draft"]))
        st = plane["state"]
        rec = next(r for r in st.list_owner_enrolls() if r["request_id"] == first["request_id"])
        for card_id in rec.get("cards") or {}:
            st.take_pending(card_id)
        st.delete_owner_enroll(first["request_id"])
        second = _slot_entry(plane, n)
        assert json.loads(second["draft"]["meta"])["not_after"] == json.loads(first["draft"]["meta"])["not_after"]
        status, body = _http("POST", f"{plane['base_url']}/v0.4/owner/enroll/passphrase",
                             {"request_id": second["request_id"], "signature_b64u": old_sig})
        assert status == 403 and body["error"] == "top_plane_passphrase_invalid", body

    def test_a_slot_entry_leg_past_its_not_after_is_refused(self, plane) -> None:
        entry = _slot_entry(plane, Phone("newphone"))
        st = plane["state"]
        rec = next(r for r in st.list_owner_enrolls() if r["request_id"] == entry["request_id"])
        draft = dict(rec["top_plane"]["draft"], meta=canonical_meta({"nonce": "e" * 32, "not_after": 1}))
        rec = dict(rec, top_plane=dict(rec["top_plane"], draft=draft))
        st.put_owner_enroll(rec)
        status, body = _http("POST", f"{plane['base_url']}/v0.4/owner/enroll/passphrase",
                             {"request_id": entry["request_id"],
                              "signature_b64u": _sign_pp(_entry_message(plane, draft))})
        assert status == 400 and body["error"] == "top_plane_draft_stale", body


# --- the seal's mark settles ----------------------------------------------------------------------------------------

def _rotate(ctx) -> tuple[int, dict]:
    rc, _, err = _host(tp.rotate_operator, ctx, pubkey_hex=_op_key().hex())
    assert rc == 0, err
    return _approve(ctx, ctx["r"], _top_cards(ctx, ctx["r"])[0])


class TestTheSealMarkSettles:

    def test_two_faults_in_the_mark_window_leave_the_chain_readable(self, plane, monkeypatch) -> None:
        """Two appends each fail between the in-flight mark and the chain write; the chain stays readable and the
        next act appends."""
        st = plane["state"]
        orig = st._atomic_write
        faults = [1, 1]

        def chain_write_fails(path, body):
            if Path(path).name == "genesis_members.json" and faults:
                faults.pop()
                raise OSError("injected fault")
            return orig(path, body)

        monkeypatch.setattr(st, "_atomic_write", chain_write_fails)
        for _ in range(2):
            assert _rotate(plane)[0] != 200
        assert faults == []
        assert _http("GET", f"{plane['base_url']}/v0.4/genesis/chain")[0] == 200
        status, body = _rotate(plane)
        assert status == 200 and body.get("appended"), body

    def test_after_a_seals_failed_final_mark_write_a_cut_back_chain_refuses_after_a_restart(
            self, tmp_path, monkeypatch) -> None:
        op_key = _op_key()
        with serving(tmp_path, signed_poll_mode="advisory", capability_operator_pubkey=op_key) as ctx:
            r, p = Phone("recovery"), Phone("primary")
            _enroll_genesis(ctx, r, "recovery")
            _enroll_approved(ctx, p, "primary", approver=r)
            _seed_chain(ctx["state"], r)
            st = ctx["state"]
            orig = st._atomic_write
            faults = [1]

            def plain_mark_write_fails(path, body):
                if Path(path).name == "genesis_seal_mark.json" and "next" not in body and faults:
                    faults.pop()
                    raise OSError("injected fault")
                return orig(path, body)

            monkeypatch.setattr(st, "_atomic_write", plain_mark_write_fails)
            assert _host(tp.seal_id, ctx)[0] == 0
            assert _approve(ctx, r, _top_cards(ctx, r)[0])[0] == 200
            assert faults == []
            ctx["server"].shutdown()
            ctx["server"].server_close()
            server, thread, ctx2 = _start_server(tmp_path, signed_poll_mode="advisory",
                                                 capability_operator_pubkey=op_key)
            try:
                path = Path(tmp_path) / "genesis_members.json"
                body = json.loads(path.read_text(encoding="utf-8"))
                body["chain"] = body["chain"][:2]  # back to before the seal, the mark kept
                path.write_text(json.dumps(body), encoding="utf-8")
                assert _http("GET", f"{ctx2['base_url']}/v0.4/genesis/chain")[0] == 503
            finally:
                _stop(server, thread)


# --- an unreadable top-plane file -----------------------------------------------------------------------------------

class TestAnUnreadableTopPlaneFile:

    def test_an_ordinary_card_is_answered_and_a_top_plane_read_is_refused_by_name(self, plane) -> None:
        from recto.bootloader.state import PendingRequest

        card = PendingRequest.new(kind="single_sign", service="svc", secret="ordinary", phone_id=plane["r"].ref,
                                  operation_description="an ordinary sign request", payload_hash_b64u=_b64u(b"x" * 32),
                                  child_pid=0, child_argv0="(test)", ttl_seconds=300)
        plane["state"].add_pending(card)
        (Path(plane["tmp"]) / "top_plane.json").write_text("{not json", encoding="utf-8")
        path = f"/v0.4/respond/{card.request_id}"
        status, body = _http("POST", f"{plane['base_url']}{path}", {"decision": "denied", "reason": "test"},
                             headers=_denial_headers(plane["r"].poll, plane["r"].ref, path))
        assert status == 200, body
        status, body = _http("GET", f"{plane['base_url']}/v0.4/owner/reset?intent_id=reset-x")
        assert status == 503 and body["error"] == "top_plane_records_unreadable", body

    def test_a_new_owners_pairing_is_asked_the_slot_question_with_the_file_unreadable(self, plane) -> None:
        (Path(plane["tmp"]) / "top_plane.json").write_text("{not json", encoding="utf-8")
        status, body = Phone("newphone").register(plane, "primary")
        assert status == 409 and body["error"] == "slot_occupied", body


# --- the typed tokens stay off the terminal -------------------------------------------------------------------------

class TestTheTypedTokensStayOffTheTerminal:

    @pytest.mark.parametrize("typed", [
        "correct horse, battery staple ridge lantern copper meadow",
        "correct horse 41352 staple ridge lantern copper meadow",
        "41352 16655 23412 55163 34521 61245 12356 44321",
    ])
    def test_the_vault_passphrase_commands_print_no_typed_token(self, tmp_path, monkeypatch, typed) -> None:
        import builtins
        import types

        import recto.cli as cli

        args = types.SimpleNamespace(state_dir=str(tmp_path), force=False)
        monkeypatch.setattr(builtins, "input", lambda *a, **k: "SEAL")

        def run(fn, entries):
            q = list(entries)
            monkeypatch.setattr(cli, "_prompt_passphrase", lambda label: q.pop(0))
            out, err = io.StringIO(), io.StringIO()
            fn(args, out=out, err=err)
            return out.getvalue() + err.getvalue()

        shown = run(cli._cmd_vault_seal_passphrase, [typed, typed])
        assert run(cli._cmd_vault_seal_passphrase, [PHRASE, PHRASE])  # seal the real phrase
        shown += run(cli._cmd_vault_verify_passphrase, [typed])
        for token in ("horse,", "41352", "16655", "correct", "horse"):
            assert token not in shown, (token, shown)


# --- a backend with no genesis chain --------------------------------------------------------------------------------

class _NoChainStore(StateStore):
    def supports_genesis_chain(self) -> bool:
        return False


@contextmanager
def _no_chain_server(tmp_path, **kw):
    state = _NoChainStore(state_dir=Path(tmp_path))
    server = create_server(bind_host="127.0.0.1", bind_port=0, state=state, bootloader_id="no-chain",
                           challenges=ChallengeStore(state=state), ssl_context=None, **kw)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield {"base_url": f"http://{host}:{port}", "state": state, "server": server}
    finally:
        _stop(server, thread)


class TestABackendWithNoGenesisChain:

    def test_the_anchor_refuses_the_start(self, tmp_path) -> None:
        with pytest.raises(RuntimeError, match="no genesis chain"):
            with _no_chain_server(tmp_path, expect_sealed_id="rb1-expected"):
                pass

    def test_without_the_anchor_the_start_warns(self, tmp_path, caplog) -> None:
        caplog.set_level("WARNING")
        with _no_chain_server(tmp_path):
            pass
        assert "no genesis chain" in caplog.text

    def test_the_host_says_the_backend_has_no_genesis_chain(self, tmp_path) -> None:
        with _no_chain_server(tmp_path) as ctx:
            with pytest.raises(SystemExit, match="no genesis chain"):
                _host(tp.rotate_operator, ctx, pubkey_hex=_op_key().hex())


# --- the last-owner text, one open per act, restarts and the sealed id -----------------------------------------------

class TestRestartsOpensAndTheSealedId:

    def test_the_sealed_last_owner_refusal_names_the_owner_reset(self, plane) -> None:
        assert _revoke(plane, plane["r"], plane["p"])[0] == 200
        status, body = _revoke(plane, plane["r"], plane["r"])
        assert status == 403 and body["error"] == "last_owner" and "owner-reset --start" in body["detail"], body

    def test_concurrent_opens_of_one_act_card_the_devices_once(self, plane, monkeypatch) -> None:
        orig = BootloaderHandler._card_devices

        def slow(self, *a, **k):
            time.sleep(0.4)
            return orig(self, *a, **k)

        monkeypatch.setattr(BootloaderHandler, "_card_devices", slow)
        draft = _rotate_draft(plane)
        results: list[int] = []
        threads = [threading.Thread(target=lambda: results.append(_signed_open(plane, draft)[0])) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        assert sorted(results) == [200, 409], results
        assert len(_top_cards(plane, plane["r"])) == 1

    def test_a_re_arm_after_a_restart_needs_no_wait(self, plane) -> None:
        iid = _start_reset(plane)
        time.sleep(2.2)
        _arm(plane, iid)  # a live code, which the restart kills
        with _restarted(plane) as ctx:
            rc, _, err = _host(tp.reset_arm, ctx, arm=iid, slot="primary")
            assert rc == 0, err

    def test_a_cancel_on_a_card_held_before_a_restart_still_cancels(self, plane) -> None:
        iid = _start_reset(plane, window=1800)
        held = _top_cards(plane, plane["r"])[0]
        with _restarted(plane) as ctx:
            status, body = _approve(ctx, plane["r"], held)
            assert status == 200 and body.get("cancelled"), body
            assert ctx["state"].is_revoked("ownerreset:" + iid)

    def test_a_configured_rb1_label_is_never_sealed(self, tmp_path) -> None:
        state = StateStore(state_dir=Path(tmp_path))
        challenges = ChallengeStore(state=state)
        server = create_server(bind_host="127.0.0.1", bind_port=0, state=state, bootloader_id="rb1-configured-label",
                               challenges=challenges, ssl_context=None, signed_poll_mode="advisory")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        host, port = server.server_address
        ctx = {"base_url": f"http://{host}:{port}", "state": state, "challenges": challenges, "server": server}
        try:
            r = Phone("recovery")
            _enroll_genesis(ctx, r, "recovery")
            _seed_chain(state, r)
            cs, body = _chain(ctx)
            assert body["bootloader_id"] == "rb1-configured-label"
            draft = top_plane.Draft(op="seal-id", kind="bootloader-id", value=b"rb1-configured-label",
                                    algorithm="none", seq=cs.length, prev=cs.tip_hash,
                                    meta=canonical_meta(_leg(nonce="l" * 32, operator_pubkey=_op_key().hex(),
                                                             identity_members=[])))
            msg = act_message(seq=draft.seq, op=draft.op, kind=draft.kind, pubkey=draft.value,
                              algorithm=draft.algorithm, prev=draft.prev, meta=draft.meta,
                              sealed_id="rb1-configured-label")
            status, out = _http("POST", f"{ctx['base_url']}/v0.4/top-plane/open",
                                {"draft": draft.as_wire(), "passphrase_signature_b64u": _sign_pp(msg)})
            assert status == 403 and out["error"] == "top_plane_seal_not_derived", out
        finally:
            _stop(server, thread)


# --- the abort, the gate, the slots, the seal's voids and the named lost -------------------------------------------

class TestTheResetAndTheActGuards:

    def test_an_abort_ends_a_registered_reset(self, plane) -> None:
        iid, fresh = _registered(plane)
        rc, _, err = _host(tp.reset_abort, plane, abort=iid)
        assert rc == 0, err
        assert plane["state"].get_top_plane_record(iid)["state"] == "aborted"
        assert plane["state"].get_phone(fresh.ref) is None

    def test_a_revoke_waiting_on_the_lock_while_a_reset_starts_is_refused(self, plane, monkeypatch) -> None:
        orig = BootloaderHandler._card_devices
        result: list[tuple[int, dict]] = []
        waiter: list[threading.Thread] = []

        def revoke_meanwhile(self, *a, **k):
            if not waiter:  # the start holds the registry lock here; a revoke arrives and waits on it
                t = threading.Thread(target=lambda: result.append(_revoke(plane, plane["r"], plane["p"])))
                waiter.append(t)
                t.start()
                time.sleep(0.5)
            return orig(self, *a, **k)

        monkeypatch.setattr(BootloaderHandler, "_card_devices", revoke_meanwhile)
        _start_reset(plane, window=1800)
        waiter[0].join(timeout=30)
        status, body = result[0]
        assert status == 409 and body["error"] == "owner_reset_open", body
        assert plane["state"].get_phone(plane["p"].ref) is not None

    def test_a_failed_vault_write_keeps_the_new_key_running_and_refuses_the_next_start(
            self, plane, monkeypatch) -> None:
        def fails(_key):
            raise OSError("injected fault")

        monkeypatch.setattr(plane["state"], "put_operator_pubkey", fails)
        new_key = _op_key()
        rc, _, err = _host(tp.rotate_operator, plane, pubkey_hex=new_key.hex())
        assert rc == 0, err
        status, body = _approve(plane, plane["r"], _top_cards(plane, plane["r"])[0])
        assert status == 200 and body.get("appended"), body
        assert BootloaderHandler.config.capability_operator_pubkey == new_key
        plane["server"].shutdown()
        plane["server"].server_close()
        with pytest.raises(RuntimeError, match="GATE 5d: the operator key"):
            server = create_server(bind_host="127.0.0.1", bind_port=0, state=plane["state"], bootloader_id="x",
                                   challenges=plane["challenges"], ssl_context=None,
                                   capability_operator_pubkey=plane["op_key"])
            server.server_close()

    def test_the_gate_refuses_an_act_whose_passphrase_was_replaced_since_it_opened(self, plane) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        rc, _, err = _host(tp.rotate_operator, plane, pubkey_hex=_op_key().hex())
        assert rc == 0, err
        rotation_card = _top_cards(plane, plane["r"])[0]
        cs = _chain(plane)[0]
        new_pp = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
        replace = top_plane.Draft(op="add", kind="passphrase", value=new_pp, algorithm="ed25519", seq=cs.length,
                                  prev=cs.tip_hash, meta=canonical_meta(_leg(nonce="p" * 32)))
        assert _signed_open(plane, replace)[0] == 200
        replace_card = next(c for c in _top_cards(plane, plane["r"]) if c["request_id"] != rotation_card["request_id"])
        assert _approve(plane, plane["r"], replace_card)[0] == 200
        status, body = _approve(plane, plane["r"], rotation_card)
        assert status == 403 and body["error"] == "top_plane_gate_refused", body

    def test_arm_refuses_a_slot_the_reset_already_seated(self, plane) -> None:
        iid = _start_reset(plane, slots=("primary", "recovery"), lost=[plane["p"].ref, plane["r"].ref])
        time.sleep(2.2)
        armed = _arm(plane, iid, "primary")
        status, chal = _http("GET", f"{plane['base_url']}/v0.4/registration_challenge?code={armed['code']}")
        assert Phone("fresh-primary").register(plane, "primary", challenge=chal["challenge_b64u"])[0] == 202
        assert _host(tp.reset_complete, plane, complete=iid)[0] == 0
        rc, _, err = _host(tp.reset_arm, plane, arm=iid, slot="primary")
        assert rc == 1 and "owner_reset_invalid" in err, err

    def test_the_seal_voids_an_approval_given_before_it(self, tmp_path) -> None:
        with serving(tmp_path, signed_poll_mode="advisory", capability_operator_pubkey=_op_key()) as ctx:
            r, p, n = Phone("recovery"), Phone("primary"), Phone("newphone")
            _enroll_genesis(ctx, r, "recovery")
            _enroll_approved(ctx, p, "primary", approver=r)
            _seed_chain(ctx["state"], r)
            assert n.register(ctx, "primary")[0] == 409
            n.register(ctx, "primary", replace=p.ref, challenge=n.last_challenge)
            cards = [c for c in _signed_cards(ctx, r) if str(c.get("secret", "")).startswith("owner-slot:")]
            assert _approve(ctx, r, cards[0])[0] == 200
            assert _host(tp.seal_id, ctx)[0] == 0
            assert _approve(ctx, r, _top_cards(ctx, r)[0])[0] == 200
            assert [e for e in ctx["state"].list_owner_enrolls() if e.get("top_plane") is None] == []

    def test_a_sealed_bootloader_refuses_an_approval_without_its_passphrase_leg(self, tmp_path) -> None:
        with serving(tmp_path, signed_poll_mode="advisory", capability_operator_pubkey=_op_key()) as ctx:
            r, p, n = Phone("recovery"), Phone("primary"), Phone("newphone")
            _enroll_genesis(ctx, r, "recovery")
            _enroll_approved(ctx, p, "primary", approver=r)
            _seed_chain(ctx["state"], r)
            assert n.register(ctx, "primary")[0] == 409
            n.register(ctx, "primary", replace=p.ref, challenge=n.last_challenge)
            cards = [c for c in _signed_cards(ctx, r) if str(c.get("secret", "")).startswith("owner-slot:")]
            assert _approve(ctx, r, cards[0])[0] == 200
            survivor = next(e for e in ctx["state"].list_owner_enrolls() if e.get("state") == "approved")
            assert _host(tp.seal_id, ctx)[0] == 0
            assert _approve(ctx, r, _top_cards(ctx, r)[0])[0] == 200
            ctx["state"].put_owner_enroll(survivor)  # an approval from before the seal that the seal missed
            status, body = n.register(ctx, "primary", replace=p.ref)
            assert status == 403 and body["error"] == "owner_enroll_from_before_the_seal", body
            assert ctx["state"].get_phone(n.ref) is None

    def test_a_wrong_slot_and_a_wrong_algorithm_are_refused_at_open(self, plane) -> None:
        rc, _, err = _host(tp.add_device, plane, slot="recovery", public_key=plane["p"].pub)  # P holds primary
        assert rc == 1 and "top_plane_device_unregistered" in err, err
        rc, _, err = _host(tp.add_device, plane, slot="primary", public_key=plane["p"].pub, algorithm="ecdsa-p256")
        assert rc == 1 and "top_plane_device_unregistered" in err, err

    def test_the_sign_screen_shows_the_whole_operator_key(self, plane) -> None:
        new_key = _op_key()
        rc, out, _ = _host(tp.rotate_operator, plane, pubkey_hex=new_key.hex(), answer="no")
        assert new_key.hex() in out

    def test_completion_revokes_only_the_phones_named_lost(self, plane) -> None:
        x = Phone("extra")
        plane["state"].register_phone(PhoneRegistration.new(
            device_label="extra", public_key_b64u=x.pub, supported_algorithms=("ed25519",), push_token=None,
            push_platform=None, poll_public_key_b64u=x.poll_pub, slot="primary"))
        iid, fresh = _registered(plane, lost=[plane["p"].ref])
        assert _host(tp.reset_complete, plane, complete=iid)[0] == 0
        assert plane["state"].get_phone(plane["p"].ref) is None
        assert plane["state"].get_phone(x.ref) is not None


# --- the reset's own entry is the evidence ---------------------------------------------------------------------------

def _revoke_intent(st, iid: str) -> None:
    from recto.bootloader.state import RevocationEntry
    st.add_revocation(RevocationEntry(jti="ownerreset:" + iid, revoked_at_unix=int(time.time()),
                                      original_exp_unix=int(time.time()) + 86400, reason="test"))


def _both_slots_with_primary_seated(ctx):
    """An every-owner-lost reset whose primary slot is seated (a fresh phone on the chain), waiting for the recovery
    slot."""
    iid = _start_reset(ctx, slots=("primary", "recovery"), lost=[ctx["p"].ref, ctx["r"].ref])
    time.sleep(2.2)
    armed = _arm(ctx, iid, "primary")
    status, chal = _http("GET", f"{ctx['base_url']}/v0.4/registration_challenge?code={armed['code']}")
    assert status == 200, chal
    f1 = Phone("fresh-primary")
    assert f1.register(ctx, "primary", challenge=chal["challenge_b64u"])[0] == 202
    assert _host(tp.reset_complete, ctx, complete=iid)[0] == 0
    return iid, f1


def _seed_registered_under_a_members_key(ctx, iid: str, phone) -> None:
    """The recovery slot's record seeded 'registered' under a key that is the slot's CURRENT member, with no entry on
    the chain for it (as if registration had taken that key)."""
    st = ctx["state"]
    rec = dict(st.get_top_plane_record(iid))
    rec.update(state="registered", slot="recovery", challenge=f"recto-reset-v1:{iid}:seeded",
               code_expires_at=int(time.time()) + 600, fresh={
                   "public_key_b64u": phone.pub, "algorithm": "ed25519", "proof_b64u": "AAAA",
                   "poll_public_key_b64u": phone.poll_pub, "device_label": "seeded", "push_token": None,
                   "push_platform": None})
    st.put_top_plane_record(rec)


class TestTheResetsOwnEntryIsTheEvidence:

    def test_a_fresh_key_that_is_a_registered_phone_is_refused_at_registration(self, plane) -> None:
        iid, _ = _both_slots_with_primary_seated(plane)
        armed = _arm(plane, iid, "recovery")
        status, chal = _http("GET", f"{plane['base_url']}/v0.4/registration_challenge?code={armed['code']}")
        assert status == 200, chal
        status, body = plane["r"].register(plane, "recovery", challenge=chal["challenge_b64u"])  # the lost R itself
        assert status == 409 and body["error"] == "owner_reset_key_known", body
        assert plane["state"].get_top_plane_record(iid)["state"] == "armed"

    def test_an_abort_of_a_reset_with_no_entry_aborts_even_when_its_key_is_the_member(self, plane) -> None:
        iid, _ = _both_slots_with_primary_seated(plane)
        _seed_registered_under_a_members_key(plane, iid, plane["r"])
        rc, _, err = _host(tp.reset_abort, plane, abort=iid)
        assert rc == 0, err
        assert plane["state"].get_top_plane_record(iid)["state"] == "aborted"
        assert plane["state"].is_revoked("ownerreset:" + iid)
        assert plane["state"].get_phone(plane["r"].ref) is not None

    def test_a_restart_and_an_unsigned_complete_never_finish_a_reset_with_no_entry(self, plane) -> None:
        iid, _ = _both_slots_with_primary_seated(plane)
        _seed_registered_under_a_members_key(plane, iid, plane["r"])
        with _restarted(plane) as ctx:
            assert ctx["state"].get_top_plane_record(iid)["state"] == "registered"
            status, body = _http("POST", f"{ctx['base_url']}/v0.4/owner/reset/complete", {"intent_id": iid})
            assert status == 403 and body["error"] == "top_plane_passphrase_invalid", body
            assert ctx["state"].get_top_plane_record(iid)["state"] == "registered"

    def test_a_repeat_complete_after_the_member_changed_finishes_the_commit(self, plane, monkeypatch) -> None:
        iid, fresh = _registered(plane)
        _one_shot(monkeypatch, plane["state"], "register_phone")
        assert _host(tp.reset_complete, plane, complete=iid)[0] == 3
        rc, _, err = _host(tp.remove_device, plane, slot="primary")  # the fresh member removed before the repeat
        assert rc == 0, err
        assert _approve(plane, plane["r"], _top_cards(plane, plane["r"])[0])[0] == 200
        length = _chain(plane)[0].length
        rc, out, err = _host(tp.reset_complete, plane, complete=iid)
        assert rc == 0 and "REFUSED" not in err, (out, err)
        cs = _chain(plane)[0]
        assert cs.length == length and "primary-phone" not in cs.members  # no second append; the remove stands
        assert plane["state"].get_phone(plane["p"].ref) is None
        assert plane["state"].get_top_plane_record(iid)["state"] == "completed"
        assert plane["state"].get_phone(fresh.ref) is None  # the chain dropped it: never registered
        with _restarted(plane) as ctx:
            assert ctx["state"].get_phone(fresh.ref) is None

    def test_an_abort_with_a_second_fault_answers_the_committed_shape(self, plane, monkeypatch) -> None:
        iid, fresh = _registered(plane)
        _one_shot(monkeypatch, plane["state"], "register_phone")
        assert _host(tp.reset_complete, plane, complete=iid)[0] == 3
        _one_shot(monkeypatch, plane["state"], "register_phone")
        rc, out, err = _host(tp.reset_abort, plane, abort=iid)
        assert rc == 3 and "COMMITTED" in out and "500" not in err, (rc, out, err)
        rc, out, err = _host(tp.reset_complete, plane, complete=iid)
        assert rc == 0 and "nothing to sign" in out, (out, err)
        assert plane["state"].get_phone(fresh.ref).slot == "primary"

    def test_an_abort_of_a_committed_reset_finishes_it(self, plane, monkeypatch) -> None:
        iid, fresh = _registered(plane)
        _one_shot(monkeypatch, plane["state"], "revoke_phone")
        assert _host(tp.reset_complete, plane, complete=iid)[0] == 3
        rc, _, err = _host(tp.reset_abort, plane, abort=iid)
        assert rc == 1 and "owner_reset_committed" in err, err
        assert plane["state"].get_top_plane_record(iid)["state"] == "completed"
        assert plane["state"].get_phone(plane["p"].ref) is None


# --- a retried act finishes ------------------------------------------------------------------------------------------

class TestARetriedActFinishes:

    def test_a_fault_at_a_removals_revoke_then_a_second_approval_finishes_it(self, plane, monkeypatch) -> None:
        _seat_primary_device(plane)
        rc, _, err = _host(tp.remove_device, plane, slot="primary")
        assert rc == 0, err
        card = _top_cards(plane, plane["r"])[0]
        _one_shot(monkeypatch, plane["state"], "revoke_phone")
        assert _approve(plane, plane["r"], card)[0] == 202
        status, body = _approve(plane, plane["r"], card)  # the phone answers its card again
        assert status == 200 and body.get("appended"), body
        assert plane["state"].get_phone(plane["p"].ref) is None
        with _restarted(plane) as ctx:
            assert ctx["state"].get_phone(plane["p"].ref) is None
            assert all(r["state"] == "appended" for r in ctx["state"].list_top_plane_records()
                       if r.get("type") == "act" and r["draft"]["op"] == "remove")

    def test_the_start_finishes_only_the_act_whose_exact_entry_is_on_the_chain(self, plane) -> None:
        ka, kb = _op_key(), _op_key()
        assert _host(tp.rotate_operator, plane, pubkey_hex=ka.hex())[0] == 0
        first = _top_cards(plane, plane["r"])[0]
        assert _host(tp.rotate_operator, plane, pubkey_hex=kb.hex())[0] == 0  # the same seq: A is not appended
        second = next(c for c in _top_cards(plane, plane["r"]) if c["request_id"] != first["request_id"])
        assert _approve(plane, plane["r"], second)[0] == 200
        with _restarted(plane, from_vault=True) as ctx:
            assert ctx["state"].get_operator_pubkey() == kb
            assert BootloaderHandler.config.capability_operator_pubkey == kb

    def test_a_removal_revokes_the_removed_keys_own_phone(self, plane) -> None:
        x = Phone("second-primary")
        plane["state"].register_phone(PhoneRegistration.new(
            device_label="second", public_key_b64u=x.pub, supported_algorithms=("ed25519",), push_token=None,
            push_platform=None, poll_public_key_b64u=x.poll_pub, slot="primary"))
        rc, _, err = _host(tp.add_device, plane, slot="primary", public_key=x.pub)
        assert rc == 0, err
        assert _approve(plane, plane["r"], _top_cards(plane, plane["r"])[0])[0] == 200
        rc, _, err = _host(tp.remove_device, plane, slot="primary")
        assert rc == 0, err
        assert _approve(plane, plane["r"], _top_cards(plane, plane["r"])[0])[0] == 200
        assert plane["state"].get_phone(x.ref) is None and plane["state"].get_phone(plane["p"].ref) is not None


# --- the texts after a fault point at --complete ---------------------------------------------------------------------

class TestTheTextsAfterAFaultPointAtComplete:

    def test_the_fresh_phone_pairing_in_the_committed_window_is_pointed_at_complete(self, plane, monkeypatch) -> None:
        iid, fresh = _registered(plane)
        _one_shot(monkeypatch, plane["state"], "register_phone")
        assert _host(tp.reset_complete, plane, complete=iid)[0] == 3
        status, body = fresh.register(plane, "primary")
        assert status == 409 and body["error"] == "owner_reset_committed", body
        assert f"owner-reset --complete {iid}" in body["detail"], body

    def test_arming_the_next_slot_while_one_is_committed_points_at_complete(self, plane, monkeypatch) -> None:
        iid = _start_reset(plane, slots=("primary", "recovery"), lost=[plane["p"].ref, plane["r"].ref])
        time.sleep(2.2)
        armed = _arm(plane, iid, "primary")
        status, chal = _http("GET", f"{plane['base_url']}/v0.4/registration_challenge?code={armed['code']}")
        assert Phone("fresh-primary").register(plane, "primary", challenge=chal["challenge_b64u"])[0] == 202
        _one_shot(monkeypatch, plane["state"], "register_phone")
        assert _host(tp.reset_complete, plane, complete=iid)[0] == 3
        rc, _, err = _host(tp.reset_arm, plane, arm=iid, slot="recovery")
        assert rc == 1 and "owner_reset_state" in err and f"owner-reset --complete {iid}" in err, err


# --- a registered reset expires from its code ------------------------------------------------------------------------

class TestARegisteredResetExpiresFromItsCode:

    def test_a_registered_reset_expires_from_its_code_not_from_its_window(self, plane, monkeypatch) -> None:
        iid, fresh = _registered(plane)
        monkeypatch.setattr(top_plane, "RESET_ARM_GRACE_SECONDS", 20)
        rec = dict(plane["state"].get_top_plane_record(iid))
        now = int(time.time())
        rec["intent"] = dict(rec["intent"], not_before=now - 21)  # past its window's grace...
        rec["code_expires_at"] = now + 60  # ...but well inside its code's
        plane["state"].put_top_plane_record(rec)
        rc, _, err = _host(tp.reset_complete, plane, complete=iid)
        assert rc == 0, err
        assert plane["state"].get_phone(fresh.ref).slot == "primary"


# --- a stale copy written inside the lock loses ----------------------------------------------------------------------

def _hook_next_lock(monkeypatch, st):
    """Arm an action to run in this thread just before its next registry-lock acquisition (a writer that lands in the
    window between a pre-lock read and the lock)."""
    local = threading.local()
    orig = st.registry_lock

    @contextmanager
    def hooked():
        action = getattr(local, "action", None)
        if action is not None:
            local.action = None
            action()
        with orig():
            yield

    monkeypatch.setattr(st, "registry_lock", hooked)
    return local


def _edit_reset(st, iid, **changes):
    rec = dict(st.get_top_plane_record(iid))
    for k, v in changes.items():
        rec[k] = v(rec.get(k)) if callable(v) else v
    st.put_top_plane_record(rec)


def _armed_with_challenge(ctx):
    iid = _start_reset(ctx)
    time.sleep(2.2)
    armed = _arm(ctx, iid)
    status, chal = _http("GET", f"{ctx['base_url']}/v0.4/registration_challenge?code={armed['code']}")
    assert status == 200, chal
    return iid, chal["challenge_b64u"]


def _before_registrations_lock(monkeypatch, st, action):
    local = _hook_next_lock(monkeypatch, st)
    orig = BootloaderHandler._reset_for_challenge
    calls: list[int] = []

    def first_read_arms(self, challenge):
        found = orig(self, challenge)
        if not calls and found is not None:  # the registration's read before its lock
            calls.append(1)
            local.action = action
        return found

    monkeypatch.setattr(BootloaderHandler, "_reset_for_challenge", first_read_arms)


class TestAStaleCopyWrittenInsideTheLockLoses:

    def test_a_re_arm_before_registrations_lock_wins(self, plane, monkeypatch) -> None:
        iid, challenge = _armed_with_challenge(plane)
        st = plane["state"]
        _before_registrations_lock(monkeypatch, st, lambda: _edit_reset(
            st, iid, code_hash="re-armed", challenge_mac=None, code_expires_at=int(time.time()) + 600,
            arm_nonces=lambda n: list(n or []) + ["re-arm-nonce"]))
        status, body = Phone("fresh").register(plane, "primary", challenge=challenge)
        assert status == 400, body
        rec = st.get_top_plane_record(iid)
        assert rec["state"] == "armed" and rec["code_hash"] == "re-armed" and "re-arm-nonce" in rec["arm_nonces"]

    def test_an_abort_before_registrations_lock_stays_aborted(self, plane, monkeypatch) -> None:
        iid, challenge = _armed_with_challenge(plane)
        st = plane["state"]
        _before_registrations_lock(monkeypatch, st, lambda: _edit_reset(st, iid, state="aborted", code_hash=None))
        status, body = Phone("fresh").register(plane, "primary", challenge=challenge)
        assert status == 400, body
        assert st.get_top_plane_record(iid)["state"] == "aborted"

    def test_a_spent_nonce_survives_the_registration(self, plane, monkeypatch) -> None:
        iid, challenge = _armed_with_challenge(plane)
        st = plane["state"]
        _before_registrations_lock(monkeypatch, st, lambda: _edit_reset(
            st, iid, arm_nonces=lambda n: list(n or []) + ["spent-before-registration"]))
        assert Phone("fresh").register(plane, "primary", challenge=challenge)[0] == 202
        rec = st.get_top_plane_record(iid)
        assert rec["state"] == "registered" and "spent-before-registration" in rec["arm_nonces"]

    def test_a_spent_nonce_survives_the_redemption(self, plane, monkeypatch) -> None:
        iid = _start_reset(plane)
        time.sleep(2.2)
        armed = _arm(plane, iid)
        st = plane["state"]
        local = _hook_next_lock(monkeypatch, st)
        orig = BootloaderHandler._armed_reset_for_code

        def read_arms(self, code):
            found = orig(self, code)
            if found is not None:
                local.action = lambda: _edit_reset(st, iid, arm_nonces=lambda n: list(n or []) + ["spent-mid-redeem"])
            return found

        monkeypatch.setattr(BootloaderHandler, "_armed_reset_for_code", read_arms)
        status, _ = _http("GET", f"{plane['base_url']}/v0.4/registration_challenge?code={armed['code']}")
        assert status == 200
        assert "spent-mid-redeem" in st.get_top_plane_record(iid)["arm_nonces"]

    def test_a_spent_nonce_survives_the_wrong_code_count(self, plane, monkeypatch) -> None:
        iid = _start_reset(plane)
        time.sleep(2.2)
        armed = _arm(plane, iid)
        st = plane["state"]
        local = _hook_next_lock(monkeypatch, st)
        orig = BootloaderHandler._count_reset_code_failure

        def count_arms(self):
            local.action = lambda: _edit_reset(st, iid, arm_nonces=lambda n: list(n or []) + ["spent-mid-count"])
            return orig(self)

        monkeypatch.setattr(BootloaderHandler, "_count_reset_code_failure", count_arms)
        wrong = f"{(int(armed['code']) + 1) % 1000000:06d}"
        _http("GET", f"{plane['base_url']}/v0.4/registration_challenge?code={wrong}",
              headers={"CF-Connecting-IP": "198.51.100.7"})
        rec = st.get_top_plane_record(iid)
        assert "spent-mid-count" in rec["arm_nonces"] and int(rec["code_attempts"]) == 1


# --- each reset leg, the removal's algorithm, the seal key and the mark ----------------------------------------------

def _abort_leg(iid, **over):
    leg = dict(_leg(nonce="x" * 24), intent_id=iid)
    leg.update(over)
    return leg


def _post_abort(ctx, leg, sign_as=None):
    sig = _sign_pp(top_plane.reset_abort_digest(sign_as or leg))
    return _http("POST", f"{ctx['base_url']}/v0.4/owner/reset/abort", {"abort": leg, "passphrase_signature_b64u": sig})


class TestEachResetLegAndItsGuard:

    def test_a_revoked_intent_never_holds_the_owner_phones(self, plane) -> None:
        iid = _start_reset(plane, window=1800)
        _revoke_intent(plane["state"], iid)  # its record still reads 'waiting'
        status, body = _revoke(plane, plane["r"], plane["p"])
        assert status == 200, body

    def test_a_code_for_a_revoked_reset_is_never_redeemed(self, plane) -> None:
        iid = _start_reset(plane)
        time.sleep(2.2)
        armed = _arm(plane, iid)
        _revoke_intent(plane["state"], iid)  # its record still reads 'armed'
        status, _ = _http("GET", f"{plane['base_url']}/v0.4/registration_challenge?code={armed['code']}")
        assert status != 200

    def test_a_removal_under_the_members_key_but_another_algorithm_is_refused_at_open(self, plane) -> None:
        _seat_primary_device(plane)
        cs = _chain(plane)[0]
        draft = top_plane.Draft(op="remove", kind="primary-phone", value=bytes(cs.members["primary-phone"].pubkey),
                                algorithm="ecdsa-p256", seq=cs.length, prev=cs.tip_hash,
                                meta=canonical_meta(_leg(nonce="g" * 32)))
        status, body = _signed_open(plane, draft)
        assert status == 400 and body["error"] == "top_plane_remove_mismatch", body

    def test_bootstrap_after_a_rotation_re_seals_only_the_rotated_key(self, plane) -> None:
        new_key = _op_key()
        assert _host(tp.rotate_operator, plane, pubkey_hex=new_key.hex())[0] == 0
        assert _approve(plane, plane["r"], _top_cards(plane, plane["r"])[0])[0] == 200
        rc, _, err = _bootstrap(plane, plane["op_key"].hex())  # the seal's key, which the rotation replaced
        assert rc == 1 and "SEALED" in err, err
        from recto.cli import main
        out, err2 = io.StringIO(), io.StringIO()
        assert main(["vault", "bootstrap", new_key.hex(), "--state-dir", str(plane["tmp"]), "--force"],
                    stdout=out, stderr=err2) == 0, err2.getvalue()

    def test_the_repair_gate_5d_names_restores_the_start(self, plane, monkeypatch) -> None:
        import re

        from recto.cli import main

        def fails(_key):
            raise OSError("injected fault")

        monkeypatch.setattr(plane["state"], "put_operator_pubkey", fails)
        assert _host(tp.rotate_operator, plane, pubkey_hex=_op_key().hex())[0] == 0
        assert _approve(plane, plane["r"], _top_cards(plane, plane["r"])[0])[0] == 200
        monkeypatch.undo()
        plane["server"].shutdown()
        plane["server"].server_close()
        state = StateStore(state_dir=Path(plane["tmp"]))
        with pytest.raises(RuntimeError, match="GATE 5d") as refused:
            create_server(bind_host="127.0.0.1", bind_port=0, state=state, bootloader_id="x",
                          challenges=ChallengeStore(state=state), ssl_context=None).server_close()
        key_hex = re.search(r"bootstrap ([0-9a-f]{128}) --force", str(refused.value)).group(1)
        out, err = io.StringIO(), io.StringIO()
        assert main(["vault", "bootstrap", key_hex, "--state-dir", str(plane["tmp"]), "--force"],
                    stdout=out, stderr=err) == 0, err.getvalue()
        state = StateStore(state_dir=Path(plane["tmp"]))
        create_server(bind_host="127.0.0.1", bind_port=0, state=state, bootloader_id="x",
                      challenges=ChallengeStore(state=state), ssl_context=None).server_close()

    def test_an_abort_leg_is_spent_once(self, plane) -> None:
        iid = _start_reset(plane, window=1800)
        leg = _abort_leg(iid)
        assert _post_abort(plane, leg)[0] == 200
        status, body = _post_abort(plane, leg)
        assert status == 409 and body["error"] == "owner_reset_leg_used", body

    def test_an_abort_leg_past_its_not_after_is_refused(self, plane) -> None:
        iid = _start_reset(plane, window=1800)
        status, body = _post_abort(plane, _abort_leg(iid, not_after=int(time.time()) - 1))
        assert status == 400 and body["error"] == "owner_reset_leg_stale", body
        assert plane["state"].get_top_plane_record(iid)["state"] == "waiting"

    def test_not_after_is_inside_the_arm_and_abort_digests(self, plane) -> None:
        iid = _start_reset(plane)
        time.sleep(2.2)
        stale = int(time.time()) - 1
        arm = dict(_leg(nonce="d" * 24, not_after=stale), intent_id=iid, slot="primary")
        bumped = dict(arm, not_after=int(time.time()) + 600)
        status, body = _http("POST", f"{plane['base_url']}/v0.4/owner/reset/arm", {
            "arm": bumped, "passphrase_signature_b64u": _sign_pp(top_plane.reset_arm_digest(arm))})
        assert status == 403 and body["error"] == "top_plane_passphrase_invalid", body
        leg = _abort_leg(iid, nonce="e" * 24, not_after=stale)
        status, body = _post_abort(plane, dict(leg, not_after=int(time.time()) + 600), sign_as=leg)
        assert status == 403 and body["error"] == "top_plane_passphrase_invalid", body

    def test_a_slot_entry_leg_is_signed_once(self, plane) -> None:
        entry = _slot_entry(plane, Phone("newphone"))
        sig = _sign_pp(_entry_message(plane, entry["draft"]))
        body = {"request_id": entry["request_id"], "signature_b64u": sig}
        assert _http("POST", f"{plane['base_url']}/v0.4/owner/enroll/passphrase", body)[0] == 200
        status, out = _http("POST", f"{plane['base_url']}/v0.4/owner/enroll/passphrase", body)
        assert status == 409 and out["error"] == "top_plane_draft_used", out

    def test_the_mark_settles_to_the_side_the_chain_matches(self, plane, monkeypatch) -> None:
        st = plane["state"]
        orig = st._atomic_write
        faults = [1]

        def plain_mark_write_fails(path, body):
            if Path(path).name == "genesis_seal_mark.json" and "next" not in body and faults:
                faults.pop()
                raise OSError("injected fault")
            return orig(path, body)

        monkeypatch.setattr(st, "_atomic_write", plain_mark_write_fails)
        assert _rotate(plane)[0] == 200 and faults == []
        with _restarted(plane, from_vault=True) as ctx:
            path = Path(plane["tmp"]) / "genesis_members.json"
            body = json.loads(path.read_text(encoding="utf-8"))
            body["chain"] = body["chain"][:3]  # back to the seal, the settled mark kept
            path.write_text(json.dumps(body), encoding="utf-8")
            assert _http("GET", f"{ctx['base_url']}/v0.4/genesis/chain")[0] == 503

    def test_the_recarded_cards_are_pushed_after_a_restart(self, plane) -> None:
        class Recorder:
            def __init__(self):
                self.sent: list[str] = []

            def notify(self, phone, request_id):
                self.sent.append(request_id)

        _start_reset(plane, window=1800)
        held = {c["request_id"] for c in _top_cards(plane, plane["r"]) + _top_cards(plane, plane["p"])}
        plane["server"].shutdown()
        plane["server"].server_close()
        recorder = Recorder()
        server, thread, _ctx = _start_server(plane["tmp"], signed_poll_mode="advisory",
                                             capability_operator_pubkey=plane["op_key"], push_dispatcher=recorder)
        try:
            assert set(recorder.sent) == held, (recorder.sent, held)
        finally:
            _stop(server, thread)

    def test_a_non_ascii_reset_challenge_is_refused_by_name(self, plane) -> None:
        _armed_with_challenge(plane)  # a live reset challenge, so the lookup compares against its MAC
        stranger = Phone("stranger")
        status, body = _http("POST", f"{plane['base_url']}/v0.4/register", {
            "registration_proof": {"challenge": "recto-reset-v1:é", "signature_b64u": "AAAA"},
            "public_key_b64u": stranger.pub, "supported_algorithms": ["ed25519"], "v0_4_protocol": 1,
            "poll_public_key_b64u": stranger.poll_pub, "poll_key_delegation_b64u": "AAAA"})
        assert status == 400 and body.get("error") == "bootloader_error", (status, body)
        assert "challenge unknown or expired" in body.get("detail", ""), body

    def test_the_sealed_last_owner_text_stays_short(self, plane) -> None:
        assert _revoke(plane, plane["r"], plane["p"])[0] == 200
        _, body = _revoke(plane, plane["r"], plane["r"])
        assert body["error"] == "last_owner" and len(body["detail"]) <= 300, len(body["detail"])


# --- an effect applies only while the chain still holds it ---------------------------------------------------------

def _fault_on_appended(monkeypatch, st, op):
    """The next write of an act of `op` as 'appended' raises once (the act's effects ran, its record did not land)."""
    orig = st.put_top_plane_record
    fired: list[int] = []

    def faulty(record):
        if (not fired and record.get("type") == "act" and record.get("state") == "appended"
                and record["draft"]["op"] == op):
            fired.append(1)
            raise OSError("injected fault")
        return orig(record)

    monkeypatch.setattr(st, "put_top_plane_record", faulty)
    return fired


def _primary_phones(st):
    return sorted(p.phone_id for p in st.list_phones() if p.slot == "primary")


class TestAnEffectAppliesOnlyWhileTheChainHoldsIt:

    def test_a_second_reset_is_refused_while_a_committed_one_is_unfinished(self, plane, monkeypatch) -> None:
        first, f1 = _registered(plane)
        _one_shot(monkeypatch, plane["state"], "register_phone")
        assert _host(tp.reset_complete, plane, complete=first)[0] == 3  # committed, unfinished
        # past its bound with the grace untouched: a shortened grace would also expire the second reset under a
        # slow KDF
        _edit_reset(plane["state"], first,
                    code_expires_at=int(time.time()) - top_plane.RESET_ARM_GRACE_SECONDS - 5)
        rc, _, err = _host(tp.reset_start, plane, slot_list=["primary"], confirm=plane["p"].ref, window_seconds=2)
        assert rc == 1 and "owner_reset_committed" in err and f"--complete {first}" in err, err
        # the first finishes: its fresh phone seated, P revoked
        assert _host(tp.reset_complete, plane, complete=first)[0] == 0
        second, f2 = _registered(plane, lost=[f1.ref])
        assert _host(tp.reset_complete, plane, complete=second)[0] == 0
        assert _primary_phones(plane["state"]) == [f2.ref]
        with _restarted(plane) as ctx:
            assert _primary_phones(ctx["state"]) == [f2.ref]

    def test_a_slot_entry_inside_a_resets_window_is_refused(self, plane) -> None:
        n = _approved_slot_entry(plane)
        _start_reset(plane, window=1800)
        status, body = n.register(plane, "primary", replace=plane["p"].ref)  # the landing, inside the window
        assert status == 409 and body["error"] == "owner_reset_open", body
        assert plane["state"].get_phone(n.ref) is None

    def test_a_re_added_phone_keeps_its_phone_when_its_old_removal_finishes(self, plane, monkeypatch) -> None:
        _seat_primary_device(plane)
        rc, _, err = _host(tp.remove_device, plane, slot="primary")
        assert rc == 0, err
        removal_card = _top_cards(plane, plane["r"])[0]
        _one_shot(monkeypatch, plane["state"], "revoke_phone")
        assert _approve(plane, plane["r"], removal_card)[0] == 202  # P removed on the chain, still registered
        _seat_primary_device(plane)  # P added back
        status, body = _approve(plane, plane["r"], removal_card)  # the old card answered again
        assert status == 200, body
        assert plane["state"].get_phone(plane["p"].ref) is not None
        with _restarted(plane) as ctx:
            assert ctx["state"].get_phone(plane["p"].ref) is not None

    def test_a_superseded_rotation_never_sets_its_key_again(self, plane, monkeypatch) -> None:
        ka, kb = _op_key(), _op_key()
        assert _host(tp.rotate_operator, plane, pubkey_hex=ka.hex())[0] == 0
        card_a = _top_cards(plane, plane["r"])[0]
        _fault_on_appended(monkeypatch, plane["state"], "rotate-operator")
        assert _approve(plane, plane["r"], card_a)[0] == 202  # A on the chain, its record still 'pending'
        monkeypatch.undo()
        assert _host(tp.rotate_operator, plane, pubkey_hex=kb.hex())[0] == 0
        assert _approve(plane, plane["r"], _top_cards(plane, plane["r"])[0])[0] == 200  # B appended
        status, body = _approve(plane, plane["r"], card_a)  # A's old card answered again
        assert status == 200, body
        assert BootloaderHandler.config.capability_operator_pubkey == kb
        assert plane["state"].get_operator_pubkey() == kb
        with _restarted(plane, from_vault=True) as ctx:
            assert ctx["state"].get_operator_pubkey() == kb
            assert BootloaderHandler.config.capability_operator_pubkey == kb


# --- an unreadable chain refuses by name and changes nothing --------------------------------------------------------

def _fault_read_under_the_lock(monkeypatch, st):
    """The next chain read made while the registry lock is held raises once (the abort's read, never the host's
    chain GET)."""
    orig = st.read_genesis_chain
    fired: list[int] = []

    def faulty():
        if not fired and st._registry_lock._is_owned():
            fired.append(1)
            raise OSError("injected fault")
        return orig()

    monkeypatch.setattr(st, "read_genesis_chain", faulty)
    return fired


class TestAnUnreadableChainIsNeverNotCommitted:

    def test_an_abort_with_an_unreadable_chain_refuses_and_a_repeat_finishes(self, plane, monkeypatch) -> None:
        iid, fresh = _registered(plane)
        _one_shot(monkeypatch, plane["state"], "register_phone")
        assert _host(tp.reset_complete, plane, complete=iid)[0] == 3
        _fault_read_under_the_lock(monkeypatch, plane["state"])
        rc, _, err = _host(tp.reset_abort, plane, abort=iid)
        assert rc == 1 and "genesis_chain_unreadable" in err, err
        rec = plane["state"].get_top_plane_record(iid)
        assert rec["state"] == "registered" and rec["fresh"] and not plane["state"].is_revoked("ownerreset:" + iid)
        rc, out, err = _host(tp.reset_complete, plane, complete=iid)
        assert rc == 0, err
        assert plane["state"].get_phone(fresh.ref).slot == "primary"
        assert plane["state"].get_phone(plane["p"].ref) is None

    def test_a_retried_approval_with_an_unreadable_chain_refuses_and_a_later_one_finishes(
            self, plane, monkeypatch) -> None:
        _seat_primary_device(plane)
        rc, _, err = _host(tp.remove_device, plane, slot="primary")
        assert rc == 0, err
        card = _top_cards(plane, plane["r"])[0]
        _one_shot(monkeypatch, plane["state"], "revoke_phone")
        assert _approve(plane, plane["r"], card)[0] == 202
        _one_shot(monkeypatch, plane["state"], "read_genesis_chain")
        status, body = _approve(plane, plane["r"], card)
        assert status == 503 and body["error"] == "genesis_chain_unreadable", body
        assert all(r["state"] == "pending" for r in plane["state"].list_top_plane_records()
                   if r.get("type") == "act" and r["draft"]["op"] == "remove")
        status, body = _approve(plane, plane["r"], card)
        assert status == 200, body
        assert plane["state"].get_phone(plane["p"].ref) is None


# --- a known key is never fresh, and a committed act finishes past a refusal ----------------------------------------

class TestKnownKeysAndCommittedActs:

    def test_a_registered_owner_that_is_no_member_is_refused_as_a_fresh_key(self, plane) -> None:
        iid = _start_reset(plane, slots=("recovery",), lost=[plane["r"].ref])
        time.sleep(2.2)
        armed = _arm(plane, iid, "recovery")
        status, chal = _http("GET", f"{plane['base_url']}/v0.4/registration_challenge?code={armed['code']}")
        assert status == 200, chal
        status, body = plane["p"].register(plane, "recovery", challenge=chal["challenge_b64u"])  # P: no member
        assert status == 409 and body["error"] == "owner_reset_key_known", body
        assert plane["state"].get_top_plane_record(iid)["state"] == "armed"

    def test_a_sealed_member_with_no_phone_is_refused_as_a_fresh_key(self, plane) -> None:
        iid = _start_reset(plane, slots=("recovery",), lost=[plane["r"].ref])
        time.sleep(2.2)
        armed = _arm(plane, iid, "recovery")
        plane["state"].revoke_phone(plane["r"].ref)  # R's registration gone at the store; R is still sealed
        status, chal = _http("GET", f"{plane['base_url']}/v0.4/registration_challenge?code={armed['code']}")
        assert status == 200, chal
        status, body = plane["r"].register(plane, "recovery", challenge=chal["challenge_b64u"])
        assert status == 409 and body["error"] == "owner_reset_key_known", body

    def test_a_removal_left_refused_with_its_entry_on_the_chain_finishes_at_start(self, plane, monkeypatch) -> None:
        _seat_primary_device(plane)
        rc, _, err = _host(tp.remove_device, plane, slot="primary")
        assert rc == 0, err
        _one_shot(monkeypatch, plane["state"], "revoke_phone")
        assert _approve(plane, plane["r"], _top_cards(plane, plane["r"])[0])[0] == 202
        rec = next(r for r in plane["state"].list_top_plane_records()
                   if r.get("type") == "act" and r["draft"]["op"] == "remove")
        plane["state"].put_top_plane_record(dict(rec, state="refused"))
        with _restarted(plane) as ctx:
            assert ctx["state"].get_phone(plane["p"].ref) is None
            assert ctx["state"].get_top_plane_record(rec["id"])["state"] == "appended"

    def test_an_old_card_answered_after_the_passphrase_was_replaced_finishes_a_committed_removal(
            self, plane, monkeypatch) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        _seat_primary_device(plane)
        rc, _, err = _host(tp.remove_device, plane, slot="primary")
        assert rc == 0, err
        card = _top_cards(plane, plane["r"])[0]
        _one_shot(monkeypatch, plane["state"], "revoke_phone")
        assert _approve(plane, plane["r"], card)[0] == 202
        cs = _chain(plane)[0]
        replace = top_plane.Draft(op="add", kind="passphrase",
                                  value=Ed25519PrivateKey.generate().public_key().public_bytes_raw(),
                                  algorithm="ed25519", seq=cs.length, prev=cs.tip_hash,
                                  meta=canonical_meta(_leg(nonce="q" * 32)))
        assert _signed_open(plane, replace)[0] == 200
        replace_card = next(c for c in _top_cards(plane, plane["r"]) if c["request_id"] != card["request_id"])
        assert _approve(plane, plane["r"], replace_card)[0] == 200
        status, body = _approve(plane, plane["r"], card)
        assert status == 200, body
        assert plane["state"].get_phone(plane["p"].ref) is None
        with _restarted(plane) as ctx:
            assert ctx["state"].get_phone(plane["p"].ref) is None


# --- the pointers after a fault name only what is so ----------------------------------------------------------------

class TestThePointersNameOnlyWhatIsSo:

    def test_the_fresh_phone_of_a_reset_with_no_entry_gets_no_pointer(self, plane) -> None:
        iid, fresh = _registered(plane)  # registered, never completed
        status, body = fresh.register(plane, "primary")
        assert body.get("error") != "owner_reset_committed", body

    def test_arming_while_the_other_slot_is_registered_but_uncommitted_says_nothing_committed(self, plane) -> None:
        iid = _start_reset(plane, slots=("primary", "recovery"), lost=[plane["p"].ref, plane["r"].ref])
        time.sleep(2.2)
        armed = _arm(plane, iid, "primary")
        status, chal = _http("GET", f"{plane['base_url']}/v0.4/registration_challenge?code={armed['code']}")
        assert Phone("fresh-primary").register(plane, "primary", challenge=chal["challenge_b64u"])[0] == 202
        rc, _, err = _host(tp.reset_arm, plane, arm=iid, slot="recovery")
        assert rc == 1 and "owner_reset_state" in err and "committed" not in err, err

    def test_a_bystander_in_a_committed_window_gets_no_pointer(self, plane, monkeypatch) -> None:
        iid, fresh = _registered(plane)
        _one_shot(monkeypatch, plane["state"], "register_phone")
        assert _host(tp.reset_complete, plane, complete=iid)[0] == 3
        status, body = Phone("bystander").register(plane, "primary")
        assert body.get("error") != "owner_reset_committed", body


# --- a fault at the abort's nonce write answers by name -------------------------------------------------------------

class TestAFaultAtALegsNonceWrite:

    def test_a_fault_at_the_aborts_nonce_write_answers_by_name(self, plane, monkeypatch) -> None:
        iid, fresh = _registered(plane)
        _one_shot(monkeypatch, plane["state"], "register_phone")
        assert _host(tp.reset_complete, plane, complete=iid)[0] == 3
        _one_shot(monkeypatch, plane["state"], "put_top_plane_record")
        rc, _, err = _host(tp.reset_abort, plane, abort=iid)
        assert rc == 1 and "owner_reset_store_fault" in err and "500" not in err, err
        assert plane["state"].get_top_plane_record(iid)["state"] == "registered"
        assert _host(tp.reset_complete, plane, complete=iid)[0] == 0
        assert plane["state"].get_phone(fresh.ref).slot == "primary"


# --- a stale leg is spent, and no lock on a backend with no top plane ---------------------------------------------

class TestAStaleLegIsSpentAndANoChainCountTakesNoLock:

    def test_a_stale_arm_leg_replayed_is_refused_as_used(self, plane) -> None:
        iid = _start_reset(plane)
        time.sleep(2.2)
        arm = dict(_leg(nonce="s" * 24, not_after=int(time.time()) - 1), intent_id=iid, slot="primary")
        status, body = _post_arm(plane, arm)
        assert status == 400 and body["error"] == "owner_reset_leg_stale", body
        status, body = _post_arm(plane, arm)
        assert status == 409 and body["error"] == "owner_reset_leg_used", body

    def test_a_stale_abort_leg_replayed_is_refused_as_used(self, plane) -> None:
        iid = _start_reset(plane, window=1800)
        leg = _abort_leg(iid, nonce="t" * 24, not_after=int(time.time()) - 1)
        status, body = _post_abort(plane, leg)
        assert status == 400 and body["error"] == "owner_reset_leg_stale", body
        status, body = _post_abort(plane, leg)
        assert status == 409 and body["error"] == "owner_reset_leg_used", body

    def test_a_wrong_code_on_a_backend_with_no_top_plane_takes_no_registry_lock(self, tmp_path, monkeypatch) -> None:
        with _no_chain_server(tmp_path) as ctx:
            st = ctx["state"]
            taken: list[int] = []
            orig = st.registry_lock

            @contextmanager
            def counted():
                taken.append(1)
                with orig():
                    yield

            monkeypatch.setattr(st, "registry_lock", counted)
            _http("GET", f"{ctx['base_url']}/v0.4/registration_challenge?code=000000",
                  headers={"CF-Connecting-IP": "198.51.100.3"})
            assert taken == []


# --- a sealed id is served with the inputs that recompute it --------------------------------------------------------

def _v1_derive(operator: bytes, members: list[bytes]) -> str:
    """The phone's v1 rule (Recto.Shared/Services/BootloaderIdentity.cs Derive), written out independently: SHA-256
    over the version string, then each distinct key sorted bytewise, each prefixed by its 4-byte big-endian length;
    the first 128 bits as lowercase hex behind rb1-."""
    import hashlib

    h = hashlib.sha256(b"recto-bootloader-id-v1")
    for k in sorted({bytes(operator), *[bytes(m) for m in members]}):
        h.update(len(k).to_bytes(4, "big") + k)
    return "rb1-" + h.hexdigest()[:32]


def _identity_recomputes(ctx, phone, slot) -> None:
    status, body = phone.register(ctx, slot)
    assert status == 201, body
    ident = body.get("bootloader_identity")
    assert ident and ident["derivation"] == "recto-bootloader-id-v1", body
    unb = top_plane.unb64u
    derived = _v1_derive(unb(ident["operator_pubkey_b64u"]), [unb(m) for m in ident["member_pubkeys_b64u"]])
    assert derived == _chain(ctx)[0].sealed_id == body.get("bootloader_id", derived), (derived, body)


class TestASealedIdIsServedWithItsInputs:

    def test_after_a_rotation_and_a_restart_the_identity_recomputes_the_sealed_id(self, plane) -> None:
        assert _rotate(plane)[0] == 200
        with _restarted(plane, from_vault=True) as ctx:
            _identity_recomputes(ctx, plane["r"], "recovery")

    def test_after_a_recovery_member_change_and_a_restart_the_identity_recomputes_the_sealed_id(self, plane) -> None:
        n = Phone("new-recovery")
        plane["state"].register_phone(PhoneRegistration.new(
            device_label="new", public_key_b64u=n.pub, supported_algorithms=("ed25519",), push_token=None,
            push_platform=None, poll_public_key_b64u=n.poll_pub, slot="recovery"))
        rc, _, err = _host(tp.add_device, plane, slot="recovery", public_key=n.pub)
        assert rc == 0, err
        assert _approve(plane, plane["r"], _top_cards(plane, plane["r"])[0])[0] == 200
        assert _chain(plane)[0].members["recovery-phone"].pubkey != base64.urlsafe_b64decode(
            plane["r"].pub + "=" * (-len(plane["r"].pub) % 4))
        with _restarted(plane) as ctx:
            _identity_recomputes(ctx, n, "recovery")

    def test_a_seal_whose_identity_members_do_not_recompute_its_id_is_refused_at_open(self, tmp_path) -> None:
        with serving(tmp_path, signed_poll_mode="advisory", capability_operator_pubkey=_op_key()) as ctx:
            r = Phone("recovery")
            _enroll_genesis(ctx, r, "recovery")
            _seed_chain(ctx["state"], r)
            cs, body = _chain(ctx)
            stranger = top_plane.unb64u(Phone("stranger").pub).hex()
            draft = top_plane.Draft(op="seal-id", kind="bootloader-id", value=body["bootloader_id"].encode(),
                                    algorithm="none", seq=cs.length, prev=cs.tip_hash,
                                    meta=canonical_meta(_leg(nonce="i" * 32,
                                                             operator_pubkey=body["operator_pubkey_hex"],
                                                             identity_members=[stranger])))
            msg = act_message(seq=draft.seq, op=draft.op, kind=draft.kind, pubkey=draft.value,
                              algorithm=draft.algorithm, prev=draft.prev, meta=draft.meta,
                              sealed_id=body["bootloader_id"])
            status, out = _http("POST", f"{ctx['base_url']}/v0.4/top-plane/open",
                                {"draft": draft.as_wire(), "passphrase_signature_b64u": _sign_pp(msg)})
            assert status == 400 and out["error"] == "top_plane_seal_inputs_mismatch", out


# --- a call that appended answers committed, whatever the reads after it --------------------------------------------

def _reads_fail_after_the_append(monkeypatch, st):
    """Every chain read made after this call's own append raises (until disarmed): the call must finish from what its
    append returned, never from a read."""
    armed = {"on": False}
    orig_append, orig_read = st.append_genesis_chain_entry, st._read_chain_locked

    def append(record):
        out = orig_append(record)
        armed["on"] = True
        return out

    def read():
        if armed["on"]:
            raise OSError("injected fault")
        return orig_read()

    monkeypatch.setattr(st, "append_genesis_chain_entry", append)
    monkeypatch.setattr(st, "_read_chain_locked", read)
    return armed


class TestACallThatAppendedFinishesFromItsAppend:

    def test_a_complete_finishes_with_the_chain_unreadable_after_its_append(self, plane, monkeypatch) -> None:
        iid, fresh = _registered(plane)
        armed = _reads_fail_after_the_append(monkeypatch, plane["state"])
        rc, out, err = _host(tp.reset_complete, plane, complete=iid)
        armed["on"] = False
        assert rc == 0 and "nothing was changed" not in err, (out, err)
        assert plane["state"].get_phone(fresh.ref).slot == "primary"

    def test_a_removal_finishes_with_the_chain_unreadable_after_its_append(self, plane, monkeypatch) -> None:
        _seat_primary_device(plane)
        assert _host(tp.remove_device, plane, slot="primary")[0] == 0
        card = _top_cards(plane, plane["r"])[0]
        armed = _reads_fail_after_the_append(monkeypatch, plane["state"])
        status, body = _approve(plane, plane["r"], card)
        armed["on"] = False
        assert status == 200 and body.get("appended"), body
        assert plane["state"].get_phone(plane["p"].ref) is None

    def test_a_rotation_sets_its_key_with_the_chain_unreadable_after_its_append(self, plane, monkeypatch) -> None:
        key = _op_key()
        assert _host(tp.rotate_operator, plane, pubkey_hex=key.hex())[0] == 0
        card = _top_cards(plane, plane["r"])[0]
        armed = _reads_fail_after_the_append(monkeypatch, plane["state"])
        status, body = _approve(plane, plane["r"], card)
        armed["on"] = False
        assert status == 200, body
        assert BootloaderHandler.config.capability_operator_pubkey == key
        assert plane["state"].get_operator_pubkey() == key
        with _restarted(plane, from_vault=True) as ctx:  # no re-seal needed
            assert ctx["state"].get_operator_pubkey() == key


# --- a seal's recorded inputs and the id this process serves --------------------------------------------------------

def _unsealed_with_recovery(tmp_path, op_key):
    """A started bootloader with R and P owners and the chain seeded (unsealed); the caller stops it."""
    server, thread, ctx = _start_server(tmp_path, signed_poll_mode="advisory", capability_operator_pubkey=op_key)
    r, p = Phone("recovery"), Phone("primary")
    _enroll_genesis(ctx, r, "recovery")
    _enroll_approved(ctx, p, "primary", approver=r)
    _seed_chain(ctx["state"], r)
    ctx.update(r=r, p=p)
    return server, thread, ctx


class TestTheSealedIdAndItsServedInputs:

    def test_a_start_refuses_a_sealed_id_its_recorded_inputs_do_not_recompute(self, tmp_path) -> None:
        op_key = _op_key()
        server, thread, ctx = _unsealed_with_recovery(tmp_path, op_key)
        try:
            cs, body = _chain(ctx)
            stranger = top_plane.unb64u(Phone("stranger").pub).hex()
            draft = top_plane.Draft(op="seal-id", kind="bootloader-id", value=body["bootloader_id"].encode(),
                                    algorithm="none", seq=cs.length, prev=cs.tip_hash,
                                    meta=canonical_meta(_leg(nonce="w" * 32, operator_pubkey=op_key.hex(),
                                                             identity_members=[stranger])))
            msg = act_message(seq=draft.seq, op=draft.op, kind=draft.kind, pubkey=draft.value,
                              algorithm=draft.algorithm, prev=draft.prev, meta=draft.meta,
                              sealed_id=body["bootloader_id"])
            sigs = [_sign_pp(msg), _b64u(ctx["r"].identity.sign(msg))]
            ctx["state"].append_genesis_chain_entry(top_plane.record_of(draft, sigs))  # past the open's check
        finally:
            _stop(server, thread)
        state = StateStore(state_dir=Path(tmp_path))
        with pytest.raises(RuntimeError, match="do not recompute the sealed id"):
            create_server(bind_host="127.0.0.1", bind_port=0, state=state, bootloader_id="x",
                          challenges=ChallengeStore(state=state), ssl_context=None,
                          capability_operator_pubkey=op_key).server_close()

    def test_a_seal_card_answered_after_a_restart_that_changed_the_served_id_is_refused(self, tmp_path) -> None:
        op_key = _op_key()
        server, thread, ctx = _unsealed_with_recovery(tmp_path, op_key)
        try:
            assert _host(tp.seal_id, ctx)[0] == 0
            card = _top_cards(ctx, ctx["r"])[0]
            opened_id = _chain(ctx)[1]["bootloader_id"]
        finally:
            _stop(server, thread)
        server, thread, ctx2 = _start_server(tmp_path, signed_poll_mode="advisory", capability_operator_pubkey=op_key)
        try:
            assert _chain(ctx2)[1]["bootloader_id"] != opened_id  # the restart derives with the recovery member
            status, body = _approve(ctx2, ctx["r"], card)
            assert status == 409 and body["error"] == "top_plane_seal_mismatch", body
            assert _chain(ctx2)[0].sealed_id is None
            assert any(r.get("state") == "refused" and r["draft"]["op"] == "seal-id"
                       for r in ctx2["state"].list_top_plane_records() if r.get("type") == "act")
        finally:
            _stop(server, thread)


# --- the finish refuses by name, the start keeps going, and the evidence names its intent, slot and challenge --------

def _fault_chain_state_once(monkeypatch, st):
    """The next genesis_chain_state() raises once (the finish's read)."""
    return _one_shot(monkeypatch, st, "genesis_chain_state")


def _committed_unfinished(plane, monkeypatch):
    iid, fresh = _registered(plane)
    _one_shot(monkeypatch, plane["state"], "register_phone")
    assert _host(tp.reset_complete, plane, complete=iid)[0] == 3
    return iid, fresh


class TestTheFinishRefusesAndTheEvidenceHolds:

    def test_a_lost_phone_that_is_a_member_again_is_spared(self, plane, monkeypatch) -> None:
        iid, fresh = _committed_unfinished(plane, monkeypatch)
        _seat_primary_device(plane)  # P becomes the primary member again
        assert _host(tp.reset_complete, plane, complete=iid)[0] == 0
        assert plane["state"].get_phone(plane["p"].ref) is not None
        assert plane["state"].get_phone(fresh.ref) is None

    def test_a_read_failure_inside_the_finish_refuses_by_name_and_a_repeat_finishes(self, plane, monkeypatch) -> None:
        iid, fresh = _committed_unfinished(plane, monkeypatch)
        st = plane["state"]
        orig = st.genesis_chain_state
        calls: list[int] = []

        def nth_fails():
            calls.append(1)
            if len(calls) == 2:  # the evidence's read passes; the finish's read fails
                raise OSError("injected fault")
            return orig()

        monkeypatch.setattr(st, "genesis_chain_state", nth_fails)
        status, body = _http("POST", f"{plane['base_url']}/v0.4/owner/reset/complete", {"intent_id": iid})
        monkeypatch.setattr(st, "genesis_chain_state", orig)
        assert status == 503 and body["error"] == "genesis_chain_unreadable", body
        assert st.get_top_plane_record(iid)["state"] == "registered"
        assert _host(tp.reset_complete, plane, complete=iid)[0] == 0
        assert st.get_phone(fresh.ref).slot == "primary"

    def test_an_approval_refused_by_name_keeps_its_card(self, plane, monkeypatch) -> None:
        assert _host(tp.rotate_operator, plane, pubkey_hex=_op_key().hex())[0] == 0
        card = _top_cards(plane, plane["r"])[0]
        _one_shot(monkeypatch, plane["state"], "read_genesis_chain")
        status, body = _approve(plane, plane["r"], card)
        assert status == 503 and body["error"] == "genesis_chain_unreadable", body
        assert [c["request_id"] for c in _top_cards(plane, plane["r"])] == [card["request_id"]]

    def test_the_status_and_the_complete_refuse_by_name_on_an_unreadable_chain(self, plane, monkeypatch) -> None:
        iid, _ = _registered(plane)
        _one_shot(monkeypatch, plane["state"], "read_genesis_chain")
        status, body = _http("GET", f"{plane['base_url']}/v0.4/owner/reset?intent_id={iid}")
        assert status == 503 and body["error"] == "genesis_chain_unreadable", body
        _fault_read_under_the_lock(monkeypatch, plane["state"])
        status, body = _http("POST", f"{plane['base_url']}/v0.4/owner/reset/complete", {"intent_id": iid})
        assert status == 503 and body["error"] == "genesis_chain_unreadable", body

    def test_the_start_leaves_an_unapproved_removal_pending(self, plane) -> None:
        _seat_primary_device(plane)
        assert _host(tp.remove_device, plane, slot="primary")[0] == 0  # opened, never approved
        with _restarted(plane) as ctx:
            assert ctx["state"].get_phone(plane["p"].ref) is not None
            assert all(r["state"] == "pending" for r in ctx["state"].list_top_plane_records()
                       if r.get("type") == "act" and r["draft"]["op"] == "remove")

    def test_one_records_fault_at_the_start_never_stops_the_others(self, plane, monkeypatch) -> None:
        iid, fresh = _committed_unfinished(plane, monkeypatch)
        _one_shot(monkeypatch, StateStore, "register_phone")  # the restart's first registration faults
        with _restarted(plane) as ctx:
            assert ctx["state"].get_top_plane_record(iid)["state"] == "registered"  # skipped, the start ran
        with _restarted(plane) as ctx:
            assert ctx["state"].get_phone(fresh.ref).slot == "primary"  # and the next start finishes it

    def test_an_old_card_of_an_act_at_a_seq_another_act_took_is_refused(self, plane) -> None:
        assert _host(tp.rotate_operator, plane, pubkey_hex=_op_key().hex())[0] == 0
        first = _top_cards(plane, plane["r"])[0]
        assert _host(tp.rotate_operator, plane, pubkey_hex=_op_key().hex())[0] == 0
        second = next(c for c in _top_cards(plane, plane["r"]) if c["request_id"] != first["request_id"])
        assert _approve(plane, plane["r"], second)[0] == 200
        status, body = _approve(plane, plane["r"], first)
        assert status == 409 and body["error"] == "top_plane_chain_refused", body
        first_rec = next(r for r in plane["state"].list_top_plane_records()
                         if r.get("type") == "act" and first["request_id"] in (r.get("cards") or {}))
        assert plane["state"].get_top_plane_record(first_rec["id"])["state"] == "refused"
        with _restarted(plane, from_vault=True) as ctx:
            assert ctx["state"].get_top_plane_record(first_rec["id"])["state"] != "appended"

    @pytest.mark.parametrize("change", ["intent_id", "slot", "challenge"])
    def test_the_evidence_needs_this_intent_this_slot_and_this_challenge(self, plane, change) -> None:
        iid, fresh = _registered(plane)
        assert _host(tp.reset_complete, plane, complete=iid)[0] == 0  # an entry seats F under this intent and slot
        rec = dict(plane["state"].get_top_plane_record(iid))
        entry = next(r for r in plane["state"].read_genesis_chain() if r.get("op") == "reset")
        rec["challenge"] = json.loads(entry["meta"])["challenge"]  # the entry's own; only `change` differs
        other = dict(rec, state="registered", fresh={"public_key_b64u": fresh.pub, "algorithm": "ed25519",
                                                     "proof_b64u": "AAAA", "poll_public_key_b64u": fresh.poll_pub,
                                                     "device_label": "seeded", "push_token": None,
                                                     "push_platform": None},
                     slot="primary", challenge=rec["challenge"],
                     code_expires_at=int(time.time()) + 600)
        if change == "intent_id":
            other["id"] = "reset-another"
            other["intent"] = dict(rec["intent"], intent_id="reset-another")
        elif change == "slot":
            other["slot"] = "recovery"
        else:
            other["challenge"] = f"recto-reset-v1:{iid}:another"
        plane["state"].put_top_plane_record(other)
        status, body = _http("POST", f"{plane['base_url']}/v0.4/owner/reset/complete", {"intent_id": other["id"]})
        assert status == 403 and body["error"] == "top_plane_passphrase_invalid", body

    def test_the_arm_pointer_skips_an_unreadable_chain(self, plane, monkeypatch) -> None:
        iid = _start_reset(plane, slots=("primary", "recovery"), lost=[plane["p"].ref, plane["r"].ref])
        time.sleep(2.2)
        armed = _arm(plane, iid, "primary")
        status, chal = _http("GET", f"{plane['base_url']}/v0.4/registration_challenge?code={armed['code']}")
        assert Phone("fresh-primary").register(plane, "primary", challenge=chal["challenge_b64u"])[0] == 202
        _one_shot(monkeypatch, plane["state"], "register_phone")
        assert _host(tp.reset_complete, plane, complete=iid)[0] == 3
        _fault_read_under_the_lock(monkeypatch, plane["state"])
        rc, _, err = _host(tp.reset_arm, plane, arm=iid, slot="recovery")
        assert rc == 1 and "owner_reset_state" in err and "genesis_chain_unreadable" not in err, err

    def test_an_abort_refused_for_an_unreadable_chain_leaves_its_leg_unspent(self, plane, monkeypatch) -> None:
        iid = _start_reset(plane, window=1800)
        leg = _abort_leg(iid, nonce="u" * 24)
        _fault_read_under_the_lock(monkeypatch, plane["state"])
        status, body = _post_abort(plane, leg)
        assert status == 503 and body["error"] == "genesis_chain_unreadable", body
        status, body = _post_abort(plane, leg)  # the same leg, now that the chain reads
        assert status == 200 and body.get("aborted"), body


# --- a fresh device's late answer, after the reset's grace ---------------------------------------------------------

def _armed_and_redeemed(ctx, slot="primary", lost=None):
    """A reset armed with its code redeemed: the challenge the code bought is live for 300 s."""
    iid = _start_reset(ctx, slots=(slot,), lost=lost)
    time.sleep(2.2)
    armed = _arm(ctx, iid, slot)
    status, chal = _http("GET", f"{ctx['base_url']}/v0.4/registration_challenge?code={armed['code']}")
    assert status == 200, chal
    return iid, chal["challenge_b64u"]


def _past_its_grace(st, iid):
    """Move the reset's window back so it passed its grace while armed (as
    test_a_second_reset_is_refused_while_a_committed_one_is_unfinished moves code_expires_at)."""
    _edit_reset(st, iid, intent=lambda i: dict(i, not_before=int(time.time()) - top_plane.RESET_ARM_GRACE_SECONDS - 5))


def _open_resets(st):
    from recto.bootloader.server import reset_open_in
    return [r["id"] for r in st.list_top_plane_records() if reset_open_in(st, r)]


class TestALateAnswerAfterTheGraceIsRefused:

    def test_a_late_answer_beside_a_second_reset_is_refused_and_one_phone_ends_in_the_slot(self, plane) -> None:
        st = plane["state"]
        first, late_challenge = _armed_and_redeemed(plane)
        _past_its_grace(st, first)
        assert _open_resets(st) == []
        second = _start_reset(plane)  # admitted: the first is not open
        assert _open_resets(st) == [second]
        f1 = Phone("fresh-late")
        status, body = f1.register(plane, "primary", challenge=late_challenge)
        assert status == 400 and "passed its grace" in body.get("detail", ""), body
        rec = st.get_top_plane_record(first)
        assert rec["state"] == "armed" and first not in _open_resets(st)
        assert _host(tp.reset_complete, plane, complete=first)[0] != 0
        assert _open_resets(st) == [second]
        time.sleep(2.2)
        armed = _arm(plane, second)
        status, chal = _http("GET", f"{plane['base_url']}/v0.4/registration_challenge?code={armed['code']}")
        f2 = Phone("fresh-second")
        assert f2.register(plane, "primary", challenge=chal["challenge_b64u"])[0] == 202
        assert _host(tp.reset_complete, plane, complete=second)[0] == 0
        assert _primary_phones(st) == [f2.ref]
        assert _chain(plane)[0].members["primary-phone"].pubkey == top_plane.unb64u(f2.pub)

    def test_with_no_second_reset_the_late_answer_is_refused_and_a_new_start_is_admitted(self, plane) -> None:
        st = plane["state"]
        first, late_challenge = _armed_and_redeemed(plane)
        _past_its_grace(st, first)
        rc, _, err = _host(tp.reset_arm, plane, arm=first, slot="primary")
        assert rc == 1 and "owner_reset_expired" in err, err
        status, body = Phone("fresh-late").register(plane, "primary", challenge=late_challenge)
        assert status == 400 and "passed its grace" in body.get("detail", ""), body
        assert _primary_phones(st) == [plane["p"].ref]
        _start_reset(plane)


# --- the wrappers after a finish's own read, and the start after a faulted record -----------------------------------

class TestTheWrappersAndTheStartAfterAFault:

    def test_the_approvals_wrapper_refuses_by_name_when_the_finishs_read_fails(self, plane, monkeypatch) -> None:
        _seat_primary_device(plane)
        assert _host(tp.remove_device, plane, slot="primary")[0] == 0
        card = _top_cards(plane, plane["r"])[0]
        _one_shot(monkeypatch, plane["state"], "revoke_phone")
        assert _approve(plane, plane["r"], card)[0] == 202  # appended, unfinished
        _fault_chain_state_once(monkeypatch, plane["state"])  # the finish's own read
        status, body = _approve(plane, plane["r"], card)
        assert status == 503 and body["error"] == "genesis_chain_unreadable", body
        status, body = _approve(plane, plane["r"], card)
        assert status == 200, body
        assert plane["state"].get_phone(plane["p"].ref) is None

    def test_the_aborts_wrapper_refuses_by_name_and_says_the_leg_is_spent(self, plane, monkeypatch) -> None:
        iid, fresh = _committed_unfinished(plane, monkeypatch)
        st = plane["state"]
        orig = st.genesis_chain_state
        calls: list[int] = []

        def second_fails():
            calls.append(1)
            if len(calls) == 2:  # the first is require_sealed's; the second is the finish's
                raise OSError("injected fault")
            return orig()

        monkeypatch.setattr(st, "genesis_chain_state", second_fails)
        leg = _abort_leg(iid, nonce="v" * 24)
        status, body = _post_abort(plane, leg)
        monkeypatch.setattr(st, "genesis_chain_state", orig)
        assert status == 503 and body["error"] == "genesis_chain_unreadable", body
        assert "leg is spent" in body["detail"], body
        status, body = _post_abort(plane, leg)
        assert status == 409 and body["error"] == "owner_reset_leg_used", body
        assert _host(tp.reset_complete, plane, complete=iid)[0] == 0
        assert st.get_phone(fresh.ref).slot == "primary"

    def test_a_faulted_record_at_the_start_never_stops_the_records_after_it(self, plane, monkeypatch) -> None:
        key = _op_key()
        assert _host(tp.rotate_operator, plane, pubkey_hex=key.hex())[0] == 0
        _fault_on_appended(monkeypatch, plane["state"], "rotate-operator")
        assert _approve(plane, plane["r"], _top_cards(plane, plane["r"])[0])[0] == 202  # a committed act
        monkeypatch.undo()
        iid, fresh = _committed_unfinished(plane, monkeypatch)  # then a committed reset
        ids = [r["id"] for r in plane["state"].list_top_plane_records() if r.get("state") in ("pending", "registered")]
        assert ids == sorted(ids) and ids[0].startswith("act-") and ids[-1] == iid  # the act comes first
        orig = StateStore.put_top_plane_record
        fired: list[int] = []

        def act_finish_faults(self, record):
            if not fired and record.get("type") == "act" and record.get("state") == "appended":
                fired.append(1)
                raise OSError("injected fault")
            return orig(self, record)

        monkeypatch.setattr(StateStore, "put_top_plane_record", act_finish_faults)
        with _restarted(plane, from_vault=True) as ctx:
            assert fired == [1]
            assert ctx["state"].get_top_plane_record(iid)["state"] == "completed"
            assert ctx["state"].get_phone(fresh.ref).slot == "primary"


# --- the landing keeps the window's refusal, and a committed reset is always named ----------------------------------

class TestTheLandingAndTheStartNameWhatHoldsThem:

    def test_an_unreadable_window_refuses_the_landing_by_name_and_keeps_the_approval(self, plane, monkeypatch) -> None:
        n = _approved_slot_entry(plane)
        _start_reset(plane, window=1800)
        st = plane["state"]
        orig = st.list_top_plane_records

        def unreadable():
            raise top_plane.TopPlaneRefused("top_plane_records_unreadable", "unreadable (injected)", 503)

        monkeypatch.setattr(st, "list_top_plane_records", unreadable)
        status, body = n.register(plane, "primary", replace=plane["p"].ref)
        monkeypatch.setattr(st, "list_top_plane_records", orig)
        assert status == 503 and body["error"] == "top_plane_records_unreadable", body
        assert st.get_phone(n.ref) is None
        assert any(e.get("state") == "approved" for e in st.list_owner_enrolls())
        status, body = n.register(plane, "primary", replace=plane["p"].ref, challenge=n.last_challenge)
        assert status == 409 and body["error"] == "owner_reset_open", body

    def test_a_committed_reset_inside_its_bound_is_named_at_a_new_start(self, plane, monkeypatch) -> None:
        iid, _ = _committed_unfinished(plane, monkeypatch)  # still inside its bound: also open
        rc, _, err = _host(tp.reset_start, plane, slot_list=["recovery"], confirm=plane["r"].ref, window_seconds=2)
        assert rc == 1 and "owner_reset_committed" in err and f"--complete {iid}" in err, err


# --- only the top plane writes a reset's revocation -----------------------------------------------------------------

_CONSUMER = "http://127.0.0.1:9/consumer"
_OPERATOR_TOKEN = "o" * 48


def _sealed_plane_with_a_consumer(tmp_path):
    """A sealed bootloader (R the recovery device, P the primary owner) with a devices:pair consumer registered and an
    operator token for capability/revoke; the caller stops it."""
    op_key = _op_key()
    server, thread, ctx = _start_server(tmp_path, signed_poll_mode="advisory", capability_operator_pubkey=op_key,
                                        devices_pair_consumer_webhook_tokens={_CONSUMER: "tok"},
                                        capability_operator_token=_OPERATOR_TOKEN)
    r, p = Phone("recovery"), Phone("primary")
    _enroll_genesis(ctx, r, "recovery")
    _enroll_approved(ctx, p, "primary", approver=r)
    _seed_chain(ctx["state"], r)
    assert _host(tp.seal_id, ctx)[0] == 0
    assert _approve(ctx, r, _top_cards(ctx, r)[0])[0] == 200
    ctx.update(r=r, p=p, tmp=tmp_path, op_key=op_key)
    return server, thread, ctx


def _self_made_pair_grant(bootloader_id: str, jti: str) -> dict:
    """A devices:pair body whose grant a self-made key signs - the route takes no credential."""
    from recto.capability.pair_record import PAIR_ACTION, PairRecord
    from recto.capability.types import CapabilityClaims, CapabilityClause, CapabilityScope

    import tests.test_bootloader_devices_pair as dp

    priv, pub = dp._keypair()
    record = PairRecord(bootloader_id=bootloader_id, subject=dp._subject("anyone"), phone_pubkey=pub,
                        code=dp._VALID_CODE, not_after=int(time.time()) + 600)
    now = int(time.time())
    claims = CapabilityClaims(
        iss="phone:user:enclave", sub="user:anyone", aud=[bootloader_id, "consumer"], iat=now, nbf=now,
        exp=now + 300, jti=jti,
        cap=CapabilityClause(tier=0, registry_version=dp._MANIFEST_VERSION,
                             scope=CapabilityScope(payload_sha256=record.fingerprint(), pairing_code=record.code),
                             allow_actions=[PAIR_ACTION]),
        purpose="pair", max_uses=1,
    )
    return {"consumer_base_url": _CONSUMER, "record": record.to_dict(), "user_jws": dp._mint(claims, priv)}


class TestOnlyTheTopPlaneWritesAResetsRevocation:

    def test_a_pair_grant_and_a_capability_revoke_cannot_close_a_reset(self, tmp_path) -> None:
        server, thread, ctx = _sealed_plane_with_a_consumer(tmp_path)
        try:
            BootloaderHandler.config.owner_reset_window_seconds = 2
            iid = _start_reset(ctx)
            jti = top_plane.REVOKED_RESET_PREFIX + iid
            status, body = _http("POST", f"{ctx['base_url']}/v0.4/devices/pair",
                                 _self_made_pair_grant(_chain(ctx)[0].sealed_id, jti))
            assert status == 403 and body["error"] == "grant_jti_reserved", body
            assert not ctx["state"].is_revoked(jti)
            status, body = _http("POST", f"{ctx['base_url']}/v0.4/capability/revoke",
                                 {"jti": jti, "original_exp_unix": int(time.time()) + 3600},
                                 headers={"X-Recto-Operator-Token": _OPERATOR_TOKEN})
            assert status == 403 and body["error"] == "revoke_jti_reserved", body
            assert not ctx["state"].is_revoked(jti)
            time.sleep(2.2)
            rc, _, err = _host(tp.reset_arm, ctx, arm=iid, slot="primary")  # still open: it arms
            assert rc == 0, err
        finally:
            BootloaderHandler.config.owner_reset_window_seconds = 72 * 3600
            _stop(server, thread)


# --- the approval's wrapper after this answer's own append ----------------------------------------------------------

class TestTheApprovalAfterItsOwnAppend:

    def test_a_named_refusal_after_this_answers_append_answers_committed(self, plane, monkeypatch) -> None:
        _seat_primary_device(plane)
        assert _host(tp.remove_device, plane, slot="primary")[0] == 0
        card = _top_cards(plane, plane["r"])[0]
        st = plane["state"]
        orig = st.put_top_plane_record
        fired: list[int] = []

        def appended_write_refuses(record):
            if (not fired and record.get("type") == "act" and record.get("state") == "appended"
                    and record["draft"]["op"] == "remove"):
                fired.append(1)
                raise top_plane.TopPlaneRefused("top_plane_records_unreadable", "unreadable (injected)", 503)
            return orig(record)

        monkeypatch.setattr(st, "put_top_plane_record", appended_write_refuses)
        length = _chain(plane)[0].length
        status, body = _approve(plane, plane["r"], card)
        assert fired and status == 202 and body.get("appended") and body.get("finished") is False, body
        assert _chain(plane)[0].length == length + 1  # the entry is on the chain
        status, body = _approve(plane, plane["r"], card)
        assert status == 200, body
        assert st.get_phone(plane["p"].ref) is None


# --- the texts of a closed reset ------------------------------------------------------------------------------------

class TestAClosedResetSaysWhy:

    def test_a_live_code_of_a_reset_past_its_grace_is_told_the_reset_closed(self, plane) -> None:
        iid = _start_reset(plane)
        time.sleep(2.2)
        armed = _arm(plane, iid)
        _past_its_grace(plane["state"], iid)
        status, body = _http("GET", f"{plane['base_url']}/v0.4/registration_challenge?code={armed['code']}")
        assert status == 400 and "arms it again" not in body.get("detail", ""), body
        assert "closed" in body.get("detail", ""), body
        rc, _, err = _host(tp.reset_arm, plane, arm=iid, slot="primary")
        assert rc == 1 and "owner_reset_expired" in err, err

    def test_an_aborted_resets_arm_says_it_was_aborted_on_the_host(self, plane) -> None:
        iid = _start_reset(plane)
        assert _host(tp.reset_abort, plane, abort=iid)[0] == 0
        time.sleep(2.2)
        rc, _, err = _host(tp.reset_arm, plane, arm=iid, slot="primary")
        assert rc == 1 and "owner_reset_cancelled" in err and "aborted on the host" in err, err


# --- a caller's grant never spends a reset's jti --------------------------------------------------------------------

def _sealed_plane_with_connections(tmp_path):
    """A sealed bootloader (R the recovery device, P the primary owner) whose operator key signs connection acts,
    one connection ("alpha") stored; the caller stops it."""
    import tests.test_bootloader_connections_act as ca
    from tests.test_bootloader_owner_slots import AGENT_ID

    priv, op_key = ca._keypair()
    vault = ca._MemoryVault()
    server, thread, ctx = _start_server(tmp_path, signed_poll_mode="advisory", capability_operator_pubkey=op_key,
                                        capability_operator_token=_OPERATOR_TOKEN,
                                        connections_path=str(tmp_path / "connections.json"),
                                        connections_agent_services={AGENT_ID: ca.SERVICE},
                                        connections_secret_source_factory=vault.factory)
    r, p = Phone("recovery"), Phone("primary")
    _enroll_genesis(ctx, r, "recovery")
    _enroll_approved(ctx, p, "primary", approver=r)
    _seed_chain(ctx["state"], r)
    assert _host(tp.seal_id, ctx)[0] == 0
    assert _approve(ctx, r, _top_cards(ctx, r)[0])[0] == 200
    status, body = _http("POST", f"{ctx['base_url']}/v0.4/connections",
                         {"service": ca.SERVICE, "key": "alpha", "secret": ca.VALUE},
                         headers={"X-Recto-Operator-Token": _OPERATOR_TOKEN})
    assert status == 200, body
    ctx.update(r=r, p=p, tmp=tmp_path, op_priv=priv, bid=_chain(ctx)[0].sealed_id)
    return server, thread, ctx


def _act_claims(ctx, jti: str):
    import tests.test_bootloader_connections_act as ca

    record = ca._record("disable", bootloader_id=ctx["bid"])
    return record, ca._claims(record, aud=[ctx["bid"]], jti=jti)


class TestACallersGrantNeverSpendsAResetsJti:

    def test_an_operator_signed_act_grant_with_a_resets_jti_is_refused_before_its_spend(self, tmp_path) -> None:
        import tests.test_bootloader_connections_act as ca

        server, thread, ctx = _sealed_plane_with_connections(tmp_path)
        try:
            BootloaderHandler.config.owner_reset_window_seconds = 2
            iid = _start_reset(ctx)
            jti = top_plane.REVOKED_RESET_PREFIX + iid
            record, claims = _act_claims(ctx, jti)
            status, body = _http("POST", f"{ctx['base_url']}/v0.4/connections/act",
                                 {"jws": ca._mint(claims, ctx["op_priv"]), "record": record.to_dict()})
            assert status == 403 and body["error"] == "grant_jti_reserved", body
            assert not ctx["state"].is_revoked(jti)
            time.sleep(2.2)
            rc, _, err = _host(tp.reset_arm, ctx, arm=iid, slot="primary")  # still open: it arms
            assert rc == 0, err
        finally:
            BootloaderHandler.config.owner_reset_window_seconds = 72 * 3600
            _stop(server, thread)

    def test_a_capability_request_with_a_resets_jti_is_refused_and_never_carded(self, tmp_path) -> None:
        from dataclasses import asdict

        from tests.test_bootloader_owner_slots import AGENT_ID, AGENT_TOKEN

        server, thread, ctx = _sealed_plane_with_connections(tmp_path)
        try:
            iid = _start_reset(ctx)
            st = ctx["state"]
            before = {ph.ref: len(st.list_pending_for_phone(ph.ref)) for ph in (ctx["r"], ctx["p"])}
            record, claims = _act_claims(ctx, top_plane.REVOKED_RESET_PREFIX + iid)
            status, body = _http("POST", f"{ctx['base_url']}/v0.4/capability/request",
                                 {"phone_id": ctx["r"].ref, "claims": asdict(claims), "operation_description": "t",
                                  "connections_act": record.to_dict()},
                                 headers={"X-Recto-Agent-Id": AGENT_ID, "X-Recto-Agent-Token": AGENT_TOKEN})
            assert status == 403 and body["error"] == "claims_jti_reserved", body
            assert {ph.ref: len(st.list_pending_for_phone(ph.ref)) for ph in (ctx["r"], ctx["p"])} == before
        finally:
            _stop(server, thread)

    def test_every_route_that_spends_a_callers_jti_refuses_a_resets_first(self) -> None:
        """Each add_revocation in a handler method either builds its jti from a server prefix or sits after the
        reserved-prefix refusal in the same method."""
        import ast
        import inspect

        import recto.bootloader.server as srv

        tree = ast.parse(inspect.getsource(srv.BootloaderHandler))
        unguarded, writers = [], 0
        for fn in (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)):
            calls = [c for c in ast.walk(fn) if isinstance(c, ast.Call) and getattr(c.func, "attr", "") ==
                     "add_revocation"]
            guards = [c.lineno for c in ast.walk(fn) if isinstance(c, ast.Call) and getattr(c.func, "id", "") ==
                      "reserved_reset_jti"]
            for call in calls:
                writers += 1
                arg = call.args[0]
                jti = next((k.value for k in getattr(arg, "keywords", []) if k.arg == "jti"), None)
                if jti is not None and "PREFIX" in ast.unparse(jti):
                    continue
                if not any(g < call.lineno for g in guards):
                    unguarded.append(fn.name)
        assert writers >= 9 and not unguarded, (writers, unguarded)
