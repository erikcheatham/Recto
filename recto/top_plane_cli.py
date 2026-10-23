"""The HOST's side of the top plane (hard rule 14.7): `recto vault seal-id | rotate-operator | approve-enroll` and
`recto bootloader owner-reset --start | --arm | --complete`.

THE HOST NEVER SIGNS A DIGEST THE SERVER HANDS IT
-------------------------------------------------
A hijacked bootloader could show the operator one act and ask the passphrase to sign another. So every verb here:

  1. fetches the PUBLIC genesis chain and REPLAYS it locally (the tip, the length, the sealed id and the passphrase's
     public key are the replay's, not the server's summary);
  2. builds the act from what the operator named (or, for a slot entry, from the pending draft - and shows the
     incoming phone's ref to compare with the phone in hand);
  3. computes the 32-byte digest ITSELF and PRINTS every field it covers;
  4. asks for confirmation, and only then reads the passphrase at a hidden prompt (no TTY, no prompt: refused);
  5. signs once with the passphrase (a phrase that is not the sealed one refuses before signing) and posts the
     signature. The words and the key never leave this process and are never written or logged.

The passphrase is typed only at the bootloader host's own console session.
"""

from __future__ import annotations

import hashlib
import json
import os
import urllib.error
import urllib.request
from typing import Any, Callable, TextIO

from recto.bootloader import top_plane
from recto.bootloader.genesis_chain import ChainError, act_message, entries_from_records, replay_state
from recto.profile.passphrase_member import PassphraseMismatchError, WeakPassphraseError, sign_top_plane_act

ReadPassphrase = Callable[[str], str]
Confirm = Callable[[str], str]

DEFAULT_URL = "http://127.0.0.1:8765"


def bootloader_url(args: Any) -> str:
    return (getattr(args, "bootloader_url", None) or os.environ.get("RECTO_BOOTLOADER_URL") or DEFAULT_URL).rstrip("/")


def _http(method: str, url: str, body: dict[str, Any] | None = None) -> tuple[int, dict[str, Any]]:
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=20) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except ValueError:
            return e.code, {}


def _ref(raw: bytes) -> str:
    return "pk_" + hashlib.sha256(bytes(raw)).hexdigest()[:16]


def _fresh() -> dict[str, Any]:
    """{nonce, not_after}: a signed leg is usable once, within minutes."""
    import secrets as _secrets
    import time as _time

    return {"nonce": _secrets.token_hex(16), "not_after": int(_time.time()) + 600}


def _not_after(draft: top_plane.Draft) -> str:
    try:
        return str(int(json.loads(draft.meta or "")["not_after"]))
    except (ValueError, KeyError, TypeError):
        return "(none - the bootloader will refuse it)"


def _fresh_meta(**extra: Any) -> str:
    """{nonce, not_after} inside the act's digest: the passphrase's signature opens this act once, within minutes."""
    from recto.bootloader.genesis_chain import canonical_meta
    return canonical_meta({**_fresh(), **extra})


class _Chain:
    """The chain as THIS process replayed it."""

    def __init__(self, base: str) -> None:
        status, body = _http("GET", f"{base}/v0.4/genesis/chain")
        if status != 200:
            raise SystemExit(f"REFUSING: the bootloader did not return its chain (HTTP {status} {body.get('error')})")
        try:
            self.state = replay_state(entries_from_records(body.get("records") or []))
        except ChainError as exc:
            raise SystemExit(f"REFUSING: the chain the bootloader returned does not replay here ({exc})") from None
        self.served_id = body.get("bootloader_id")
        self.served_operator_hex = body.get("operator_pubkey_hex")
        self.served_identity_members = list(body.get("identity_members_hex") or [])
        if body.get("supports_genesis_chain") is False:
            raise SystemExit("REFUSING: this backend has no genesis chain, so it has no top plane (hard rule 14.7)")
        member = self.state.members.get("passphrase")
        if member is None:
            raise SystemExit("REFUSING: no passphrase is sealed in this chain")
        self.passphrase_pubkey = member.pubkey

    def message(self, draft: top_plane.Draft) -> bytes:
        sealed = draft.value.decode("ascii", "replace") if draft.op == "seal-id" else self.state.sealed_id
        return act_message(seq=draft.seq, op=draft.op, kind=draft.kind, pubkey=draft.value, algorithm=draft.algorithm,
                           prev=draft.prev, meta=draft.meta, sealed_id=sealed)


def _sign(chain: _Chain, message: bytes, lines: list[str], *, out: TextIO, err: TextIO,
          read_passphrase: ReadPassphrase, confirm: Confirm, declined: str | None = None) -> str | None:
    """Show the act, confirm, read the passphrase, sign. Returns the signature (b64u) or None (declined/refused)."""
    print("  THE ACT (computed on this host, not by the bootloader):", file=out)
    for line in lines:
        print(f"    {line}", file=out)
    print(f"    digest: {message.hex() if len(message) == 32 else hashlib.sha256(message).hexdigest()}", file=out)
    if confirm("  Type SIGN to sign this act with the passphrase: ").strip() != "SIGN":
        print("  Nothing signed.", file=out)
        if declined:
            print(f"  {declined}", file=out)
        return None
    phrase = read_passphrase("Passphrase (not echoed)")
    try:
        sig = sign_top_plane_act(phrase, message, sealed_pubkey=chain.passphrase_pubkey)
    except PassphraseMismatchError as exc:
        print(f"REFUSING: {exc}", file=err)
        return None
    except WeakPassphraseError:
        # A refusal here repeats none of the typed words.
        print("REFUSING: the words typed are not a well-formed passphrase (a word count or a character outside the "
              "word list) - nothing was signed. Type the words exactly as written down.", file=err)
        return None
    finally:
        del phrase
    return top_plane.b64u(sig)


def _post(base: str, path: str, body: dict[str, Any], *, out: TextIO, err: TextIO) -> int:
    status, resp = _http("POST", f"{base}{path}", body)
    if status == 202 and (resp.get("committed") or resp.get("appended")):
        print("  COMMITTED: the entry is on the chain; the registry work did not finish. It finishes when this is "
              "run again or at the bootloader's next start.", file=out)
        print(f"  {json.dumps(resp, sort_keys=True)}", file=out)
        return 3
    if status != 200:
        print(f"REFUSED by the bootloader: HTTP {status} {resp.get('error')}: {resp.get('detail')}", file=err)
        return 1
    print(f"  {json.dumps(resp, sort_keys=True)}", file=out)
    return 0


def seal_id(args: Any, *, out: TextIO, err: TextIO, read_passphrase: ReadPassphrase, confirm: Confirm) -> int:
    base = bootloader_url(args)
    chain = _Chain(base)
    if chain.state.sealed_id is not None:
        print(f"REFUSING: the id is already sealed ({chain.state.sealed_id})", file=err)
        return 2
    the_id = chain.served_id or ""
    if not the_id.startswith("rb1-"):
        print(f"REFUSING: the bootloader serves {the_id!r}, not a derived rb1- id - seal the operator key first; "
              "a configured label or a random id is never sealed", file=err)
        return 2
    op_hex = chain.served_operator_hex or ""
    if len(op_hex) != 128:
        print("REFUSING: the bootloader names no operator key; the seal records the key it holds", file=err)
        return 2
    draft = top_plane.Draft(op="seal-id", kind="bootloader-id", value=the_id.encode("ascii"), algorithm="none",
                            seq=chain.state.length, prev=chain.state.tip_hash,
                            meta=_fresh_meta(operator_pubkey=op_hex, identity_members=chain.served_identity_members))
    sig = _sign(chain, chain.message(draft), [
        f"SEAL the bootloader id: {the_id}", f"with the operator key: {op_hex}",
        f"and the identity members it was derived with: {', '.join(chain.served_identity_members) or 'none'}",
        f"its fingerprint (sha256): {hashlib.sha256(bytes.fromhex(op_hex)).hexdigest()[:32]}",
        f"chain entry: seq {draft.seq}, after {draft.prev}",
        "then a sealed device signs the same act on its card",
    ], out=out, err=err, read_passphrase=read_passphrase, confirm=confirm)
    if sig is None:
        return 1
    rc = _post(base, "/v0.4/top-plane/open", {"draft": draft.as_wire(), "passphrase_signature_b64u": sig},
               out=out, err=err)
    if rc == 0:
        print("  Approve the card on a sealed device phone now (5 minutes).", file=out)
    return rc


def add_device(args: Any, *, out: TextIO, err: TextIO, read_passphrase: ReadPassphrase, confirm: Confirm) -> int:
    """`recto vault add-device --slot primary --public-key <b64u> --algorithm ecdsa-p256`: seat an already-registered
    owner phone as a device member (the primary phone joining the set)."""
    base = bootloader_url(args)
    chain = _Chain(base)
    raw = top_plane.unb64u(args.public_key)
    kind = top_plane.SLOT_KIND[args.slot]
    draft = top_plane.Draft(op="add", kind=kind, value=raw, algorithm=args.algorithm,
                            seq=chain.state.length, prev=chain.state.tip_hash, meta=_fresh_meta())
    old = chain.state.members.get(kind)
    replaces = (f"it REPLACES the sealed {kind} {_ref(old.pubkey)}" if old is not None
                else f"no {kind} is sealed yet")
    sig = _sign(chain, chain.message(draft), [
        f"SEAT {_ref(raw)} as the {kind} device member ({args.algorithm})", replaces, f"chain entry: seq {draft.seq}",
        "compare the ref with the phone's own Pairing Details; the bootloader refuses a key that is not a registered "
        f"owner phone in the {args.slot} slot",
    ], out=out, err=err, read_passphrase=read_passphrase, confirm=confirm)
    if sig is None:
        return 1
    return _post(base, "/v0.4/top-plane/open", {"draft": draft.as_wire(), "passphrase_signature_b64u": sig},
                 out=out, err=err)


def remove_device(args: Any, *, out: TextIO, err: TextIO, read_passphrase: ReadPassphrase, confirm: Confirm) -> int:
    """`recto vault remove-device --slot X`: remove the sealed device member of a slot (and its phone from the
    registry) - the passphrase here, then ANOTHER sealed device approves the card (hard rule 14.7)."""
    base = bootloader_url(args)
    chain = _Chain(base)
    kind = top_plane.SLOT_KIND[args.slot]
    member = chain.state.members.get(kind)
    if member is None:
        print(f"REFUSING: no {kind} is sealed", file=err)
        return 2
    draft = top_plane.Draft(op="remove", kind=kind, value=bytes(member.pubkey), algorithm=member.algorithm,
                            seq=chain.state.length, prev=chain.state.tip_hash, meta=_fresh_meta())
    sig = _sign(chain, chain.message(draft), [
        f"REMOVE {_ref(member.pubkey)}, the sealed {kind}, and revoke its phone", f"chain entry: seq {draft.seq}",
        "another sealed device approves the card; the last device can never be removed (the reset is its path)",
    ], out=out, err=err, read_passphrase=read_passphrase, confirm=confirm)
    if sig is None:
        return 1
    return _post(base, "/v0.4/top-plane/open", {"draft": draft.as_wire(), "passphrase_signature_b64u": sig},
                 out=out, err=err)


def rotate_operator(args: Any, *, out: TextIO, err: TextIO, read_passphrase: ReadPassphrase, confirm: Confirm) -> int:
    base = bootloader_url(args)
    chain = _Chain(base)
    try:
        value = bytes.fromhex(args.pubkey_hex.strip().lower().removeprefix("0x").removeprefix("04")
                              if len(args.pubkey_hex.strip()) == 130 else args.pubkey_hex.strip())
    except ValueError:
        print("REFUSING: the operator key is hex", file=err)
        return 2
    from cryptography.hazmat.primitives.asymmetric import ec
    try:
        if len(value) != 64:
            raise ValueError
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), b"\x04" + value)
    except ValueError:
        print("REFUSING: the operator key is not a secp256k1 point (64 bytes X||Y, 128 hex)", file=err)
        return 2
    draft = top_plane.Draft(op="rotate-operator", kind="operator", value=value, algorithm="none",
                            seq=chain.state.length, prev=chain.state.tip_hash, meta=_fresh_meta())
    sig = _sign(chain, chain.message(draft), [
        f"ROTATE the operator key to {value.hex()}",
        f"its fingerprint (sha256): {hashlib.sha256(value).hexdigest()[:32]} - compare it with the key's owner",
        f"chain entry: seq {draft.seq}",
        "every capability signed by the OLD key stops verifying once a device signs",
    ], out=out, err=err, read_passphrase=read_passphrase, confirm=confirm)
    if sig is None:
        return 1
    return _post(base, "/v0.4/top-plane/open", {"draft": draft.as_wire(), "passphrase_signature_b64u": sig},
                 out=out, err=err)


def approve_enroll(args: Any, *, out: TextIO, err: TextIO, read_passphrase: ReadPassphrase, confirm: Confirm) -> int:
    base = bootloader_url(args)
    chain = _Chain(base)
    status, body = _http("GET", f"{base}/v0.4/owner/enroll/pending")
    if status != 200:
        print(f"REFUSING: HTTP {status} {body.get('error')}", file=err)
        return 1
    pending = [p for p in body.get("pending") or [] if not args.request or p["request_id"] == args.request]
    if len(pending) != 1:
        print(f"REFUSING: {len(pending)} open slot entries match; name one with --request:", file=err)
        for p in body.get("pending") or []:
            print(f"    {p['request_id']}  slot={p['slot']}  incoming={p['incoming_ref']}", file=err)
        return 2
    p = pending[0]
    draft = top_plane.Draft.from_wire(p["draft"])
    if _ref(draft.value) != p["incoming_ref"] or draft.kind != top_plane.SLOT_KIND.get(p["slot"]) or draft.op != "add":
        print("REFUSING: the pending draft does not describe the slot entry it is listed as", file=err)
        return 2
    sig = _sign(chain, chain.message(draft), [
        f"SEAT {_ref(draft.value)} in the {p['slot']} slot (as {draft.kind})",
        f"it replaces {p.get('occupant_ref') or 'nobody'}", f"chain entry: seq {draft.seq}",
        f"signable until unix {_not_after(draft)}", "compare the ref with the NEW phone in your hand",
    ], out=out, err=err, read_passphrase=read_passphrase, confirm=confirm)
    if sig is None:
        return 1
    return _post(base, "/v0.4/owner/enroll/passphrase", {"request_id": p["request_id"], "signature_b64u": sig},
                 out=out, err=err)


def reset_start(args: Any, *, out: TextIO, err: TextIO, read_passphrase: ReadPassphrase, confirm: Confirm) -> int:
    base = bootloader_url(args)
    chain = _Chain(base)
    if chain.state.sealed_id is None:
        print("REFUSING: the top plane is not sealed; this bootloader still uses the direct host reset", file=err)
        return 2
    slots = list(args.slot_list or [])
    if args.every_owner_lost:
        slots = ["primary", "recovery"]
    if not slots:
        print("REFUSING: name --slot (repeatable) or --every-owner-lost", file=err)
        return 2
    lost = [s.strip() for s in (args.confirm or "").split(",") if s.strip()]
    intent = top_plane.new_intent(bootloader_id=chain.state.sealed_id, slots=slots, lost=lost,
                                  window_seconds=int(args.window_seconds))
    digest = top_plane.reset_intent_digest(intent)
    sig = _sign(chain, digest, [
        f"START an owner reset of slot(s) {', '.join(intent['slots'])}",
        f"phones named lost: {', '.join(lost) or 'none'}",
        f"it completes no sooner than unix {intent['not_before']} ({int(args.window_seconds) // 3600} h)",
        "EVERY registered owner phone is carded and may cancel it",
    ], out=out, err=err, read_passphrase=read_passphrase, confirm=confirm)
    if sig is None:
        return 1
    return _post(base, "/v0.4/owner/reset/start", {"intent": intent, "passphrase_signature_b64u": sig},
                 out=out, err=err)


def reset_arm(args: Any, *, out: TextIO, err: TextIO, read_passphrase: ReadPassphrase, confirm: Confirm) -> int:
    """After the window: arm the reset for one slot - a PASSPHRASE act; the code comes back only to this signer."""
    base = bootloader_url(args)
    chain = _Chain(base)
    if not args.slot:
        print("REFUSING: name the --slot the fresh phone takes", file=err)
        return 2
    arm = {"intent_id": args.arm, "slot": args.slot, **_fresh()}
    sig = _sign(chain, top_plane.reset_arm_digest(arm), [
        f"ARM owner reset {args.arm} for the {args.slot} slot", "a one-time code (10 minutes) for the fresh phone",
    ], out=out, err=err, read_passphrase=read_passphrase, confirm=confirm)
    if sig is None:
        return 1
    rc = _post(base, "/v0.4/owner/reset/arm", {"arm": arm, "passphrase_signature_b64u": sig}, out=out, err=err)
    if rc == 0:
        print("  Pair the fresh phone with that code now (10 minutes), then run --complete.", file=out)
    return rc


def reset_abort(args: Any, *, out: TextIO, err: TextIO, read_passphrase: ReadPassphrase, confirm: Confirm) -> int:
    """End an open reset in any state - the passphrase; its cards go and it never completes."""
    base = bootloader_url(args)
    chain = _Chain(base)
    abort = {"intent_id": args.abort, **_fresh()}
    sig = _sign(chain, top_plane.reset_abort_digest(abort), [
        f"ABORT owner reset {args.abort}", "its cards are withdrawn; it never completes; a new reset may start",
    ], out=out, err=err, read_passphrase=read_passphrase, confirm=confirm)
    if sig is None:
        return 1
    return _post(base, "/v0.4/owner/reset/abort", {"abort": abort, "passphrase_signature_b64u": sig}, out=out, err=err)


def reset_complete(args: Any, *, out: TextIO, err: TextIO, read_passphrase: ReadPassphrase, confirm: Confirm) -> int:
    base = bootloader_url(args)
    chain = _Chain(base)
    status, rec = _http("GET", f"{base}/v0.4/owner/reset?intent_id={args.complete}")
    if status != 200 or rec.get("state") != "registered" or not rec.get("fresh"):
        shown = rec.get("state") or rec.get("error")
        print(f"REFUSING: the reset is not waiting for completion (HTTP {status} {shown})", file=err)
        return 2
    if rec.get("committed"):
        # The entry is already on the chain: finishing the registry needs no new signature, so none is asked.
        print(f"  The reset's entry for the {rec['slot']} slot is already on the chain; finishing it "
              "(nothing to sign).", file=out)
        return _post(base, "/v0.4/owner/reset/complete", {"intent_id": args.complete}, out=out, err=err)
    fresh = rec["fresh"]
    raw = top_plane.unb64u(fresh["public_key_b64u"])
    meta = top_plane.reset_meta({"intent": rec["intent"], "challenge": rec["challenge"]}, rec["slot"])
    draft = top_plane.Draft(op="reset", kind=top_plane.SLOT_KIND[rec["slot"]], value=raw,
                            algorithm=fresh["algorithm"], seq=chain.state.length, prev=chain.state.tip_hash, meta=meta)
    sig = _sign(chain, chain.message(draft), [
        f"COMPLETE owner reset {rec['intent']['intent_id']}: seat {_ref(raw)} in the {rec['slot']} slot",
        f"phones named lost: {', '.join(rec['intent']['lost']) or 'none'} (the slot's phones are removed)",
        f"chain entry: seq {draft.seq}", "compare the ref with the FRESH phone in your hand",
    ], out=out, err=err, read_passphrase=read_passphrase, confirm=confirm,
        declined=f"If that is not the phone in your hand, end this reset: owner-reset --abort {args.complete}")
    if sig is None:
        return 1
    return _post(base, "/v0.4/owner/reset/complete", {"intent_id": args.complete, "passphrase_signature_b64u": sig},
                 out=out, err=err)
