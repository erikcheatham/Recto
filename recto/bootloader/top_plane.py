"""THE TOP PLANE (hard rule 14.7) -- the bootloader's side of every act that needs the PASSPHRASE AND ONE
OWNER DEVICE.

EVERY ACT IS A CHAIN ENTRY
--------------------------
An act lands only by appending to the genesis chain, and the chain's own replay is the gate (genesis_chain): the
store refuses an entry that does not carry the passphrase's signature AND a device's. There is no second record of
authority, so no act can happen off the chain.

ONE MESSAGE: THE 32-BYTE DIGEST
-------------------------------
After the id is sealed, an entry is signed over `act_message(...)` -- 32 bytes with the sealed id inside. A phone's
card carries those 32 bytes and the phone signs them; the HOST computes the same 32 bytes ITSELF from the act's
fields (it never signs a digest a server supplies -- a hijacked server could show one act and ask for another), shows
the fields, and signs with the passphrase. The bootloader appends only when both signatures are over the SAME
digest, so a mismatched card fails closed.

THE TRANSITION
--------------
The rule binds from the SEAL: a bootloader whose chain has no `seal-id` entry keeps rule 14.4's slot approval as it
was and logs that the top plane is not sealed. Sealing is itself the first top-plane act (the passphrase + a device),
so the transition cannot be skipped by anyone who cannot already act.

THE OWNER RESET
---------------
The passphrase STARTS a reset; every registered owner phone - including the phones the reset names as lost - is
carded and may CANCEL it by signing; after the window (72 h) the host ARMS it, a fresh device
pairs with the armed code (its registration proof is its signature over a challenge bound to the intent), and the
host COMPLETES it with the passphrase over the reset entry's digest. A cancelled intent goes on the revocation list
and can never complete, even replayed later. The window and the cancels are this module's; the chain records what
was asked.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any

from recto.bootloader.genesis_chain import (
    DEVICE_KINDS, PASSPHRASE_KIND, ChainError, ChainState, act_message, canonical_meta,
)
from recto.bootloader.sessions import verify_signature

__all__ = [
    "ACT_CARD_TTL_SECONDS",
    "OWNER_RESET_WINDOW_SECONDS",
    "RESET_CHALLENGE_PREFIX",
    "SLOT_KIND",
    "TopPlaneRefused",
    "Draft",
    "chain_state",
    "device_kind_of",
    "device_member_phones",
    "describe",
    "draft_message",
    "record_of",
    "require_sealed",
    "act_freshness",
    "reset_abort_digest",
    "reset_expired",
    "reset_arm_digest",
    "reset_intent_digest",
    "verify_passphrase",
]

ACT_CARD_TTL_SECONDS = 300
OWNER_RESET_WINDOW_SECONDS = 72 * 3600
RESET_CHALLENGE_PREFIX = "recto-reset-v1:"
RESET_INTENT_DOMAIN = b"recto-owner-reset-intent-v1|"
SLOT_KIND = {"primary": "primary-phone", "recovery": "recovery-phone"}
REVOKED_RESET_PREFIX = "ownerreset:"


class TopPlaneRefused(Exception):
    """A named refusal: `name` is stable, `status` is the HTTP status, `detail` never carries a secret."""

    def __init__(self, name: str, detail: str, status: int = 403) -> None:
        super().__init__(f"{name}: {detail}")
        self.name, self.detail, self.status = name, detail, status


@dataclass(frozen=True)
class Draft:
    """An act as a chain entry before its signatures: everything the signers sign over."""

    op: str
    kind: str
    value: bytes
    algorithm: str
    seq: int
    prev: str | None
    meta: str | None = None

    def as_wire(self) -> dict[str, Any]:
        return {"op": self.op, "kind": self.kind, "value_hex": self.value.hex(), "algorithm": self.algorithm,
                "seq": self.seq, "prev": self.prev, "meta": self.meta}

    @classmethod
    def from_wire(cls, d: Any) -> "Draft":
        try:
            return cls(op=str(d["op"]), kind=str(d["kind"]), value=bytes.fromhex(d["value_hex"]),
                       algorithm=str(d["algorithm"]), seq=int(d["seq"]), prev=d.get("prev"), meta=d.get("meta"))
        except (KeyError, TypeError, ValueError) as exc:
            raise TopPlaneRefused("top_plane_draft_invalid", f"the act is not a well-formed draft ({exc})", 400) \
                from None


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode("ascii")


def _unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def chain_state(state: Any, expect_sealed_id: str | None = None) -> ChainState | None:
    """The chain's state, or None when this store has no chain. An unreadable chain is a REFUSAL, never 'nothing
    sealed'. THE ANCHOR (hard rule 14.7): when the operator set the expected sealed id outside the state dir, a chain
    that is not sealed with exactly that id refuses the same way, whatever the mark beside it says."""
    if not state.supports_genesis_chain():
        if expect_sealed_id:
            raise TopPlaneRefused("genesis_chain_unreadable",
                                  "a sealed id is expected but this store has no genesis chain", 503)
        return None
    try:
        cs = state.genesis_chain_state()
    except ChainError as exc:
        raise TopPlaneRefused("genesis_chain_unreadable",
                              f"the genesis chain does not replay ({exc}); nothing top-plane can run", 503) from None
    if expect_sealed_id and (cs is None or cs.sealed_id != expect_sealed_id):
        raise TopPlaneRefused("genesis_chain_unreadable",
                              f"the chain is not sealed with the expected id {expect_sealed_id!r} "
                              "(RECTO_EXPECT_SEALED_ID); nothing top-plane can run", 503)
    return cs


def require_sealed(state: Any, *, for_seal: bool = False, expect_sealed_id: str | None = None) -> ChainState:
    """The chain the act will append to. `for_seal`: the seal-id act itself (the id must NOT be sealed yet)."""
    cs = chain_state(state, expect_sealed_id)
    if cs is None:
        raise TopPlaneRefused("top_plane_unavailable", "this bootloader has no genesis chain", 404)
    if PASSPHRASE_KIND not in cs.members:
        raise TopPlaneRefused("top_plane_no_passphrase",
                              "no passphrase is sealed; the top plane needs it for every act")
    if not any(k in DEVICE_KINDS for k in cs.members):
        raise TopPlaneRefused("top_plane_no_device", "no owner device is sealed; the top plane needs one for every act")
    if for_seal:
        if cs.sealed_id is not None:
            raise TopPlaneRefused("top_plane_already_sealed", f"the bootloader id is sealed ({cs.sealed_id})", 409)
    elif cs.sealed_id is None:
        raise TopPlaneRefused("top_plane_unsealed",
                              "the bootloader id is not sealed yet; seal it first (`recto vault seal-id`)", 409)
    return cs


def draft_message(cs: ChainState, draft: Draft) -> bytes:
    """The 32 bytes the act is signed over. The draft must sit on the chain's tip."""
    if draft.seq != cs.length or draft.prev != cs.tip_hash:
        raise TopPlaneRefused("top_plane_chain_moved",
                              f"the act was drafted at seq {draft.seq}; the chain is at {cs.length} - draft it again",
                              409)
    sealed = draft.value.decode("ascii", "replace") if draft.op == "seal-id" else cs.sealed_id
    return act_message(seq=draft.seq, op=draft.op, kind=draft.kind, pubkey=draft.value, algorithm=draft.algorithm,
                       prev=draft.prev, meta=draft.meta, sealed_id=sealed)


def verify_passphrase(cs: ChainState, message: bytes, signature_b64u: Any) -> bool:
    member = cs.members.get(PASSPHRASE_KIND)
    if member is None or not isinstance(signature_b64u, str) or not signature_b64u:
        return False
    try:
        return verify_signature(payload=message, signature_b64u=signature_b64u, public_key_b64u=_b64u(member.pubkey),
                                algorithm=member.algorithm)
    except Exception:  # noqa: BLE001 - a malformed signature is a refusal
        return False


def device_kind_of(cs: ChainState, phone: Any) -> str | None:
    """The device member kind a registered phone IS (its identity key is that member's key), or None."""
    for kind, member in cs.members.items():
        if kind in DEVICE_KINDS and _b64u(member.pubkey) == getattr(phone, "public_key_b64u", None):
            return kind
    return None


def device_member_phones(state: Any, cs: ChainState) -> list[Any]:
    return [p for p in state.list_phones() if device_kind_of(cs, p) is not None]


def record_of(draft: Draft, signatures_b64u: list[str]) -> dict[str, Any]:
    rec = {"seq": draft.seq, "op": draft.op, "kind": draft.kind, "pubkey": draft.value.hex(),
           "algorithm": draft.algorithm, "prev": draft.prev, "signatures": list(signatures_b64u)}
    if draft.meta is not None:
        rec["meta"] = draft.meta
    return rec


ACT_FRESH_SECONDS = 900
RESET_ARM_GRACE_SECONDS = 24 * 3600


def act_freshness(draft: Draft) -> dict[str, Any]:
    """An opened act's {nonce, not_after}, read from its meta (inside the digest). Raises ValueError when absent,
    already past, or reaching further than ACT_FRESH_SECONDS: a passphrase signature over an act stays usable only
    while the act could still be carded."""
    try:
        meta = json.loads(draft.meta or "")
        nonce, not_after = str(meta["nonce"]), int(meta["not_after"])
    except (ValueError, KeyError, TypeError):
        raise ValueError("the act carries no {nonce, not_after} in its meta") from None
    now = int(time.time())
    if len(nonce) < 16 or not_after <= now or not_after > now + ACT_FRESH_SECONDS:
        raise ValueError(f"the act's not_after is past, or further than {ACT_FRESH_SECONDS} s ahead")
    return {"nonce": nonce, "not_after": not_after}


OPEN_RESET_STATES = ("waiting", "armed", "registered")


def reset_expired(rec: dict[str, Any], now: int | None = None) -> bool:
    """A reset expires RESET_ARM_GRACE_SECONDS after the moment it could last move: a reset waiting or armed, after
    its not_before; a reset whose fresh device registered, after that device's code lapsed. The passphrase alone never
    arms or completes it months later, with no card left to cancel it - the host aborts it or starts a new one (a
    reset whose entry is already on the chain is completed instead)."""
    now = int(time.time()) if now is None else now
    if rec.get("type") != "reset" or rec.get("state") not in OPEN_RESET_STATES:
        return False
    if rec["state"] == "registered":
        anchor = int(rec.get("code_expires_at") or rec["intent"]["not_before"])
    else:
        anchor = int(rec["intent"]["not_before"])
    return now > anchor + RESET_ARM_GRACE_SECONDS


def reset_is_open(rec: dict[str, Any], *, revoked: bool, now: int | None = None) -> bool:
    """THE ONE OPEN-RESET PREDICATE: a reset record in an open state, not expired, whose intent is not on the
    revocation list. Every reader of "is this reset open" reads this one: the start, the owner-revoke guard, the
    slot-entry guard, the code redemption, the wrong-code count, the fresh device's registration, the host's verbs
    and the restart re-card."""
    return (rec.get("type") == "reset" and rec.get("state") in OPEN_RESET_STATES and not revoked
            and not reset_expired(rec, now))


def describe(draft: Draft) -> str:
    """The act in words for the device card. Every field the digest covers that a person can check is named: the
    phone does not recompute the digest; the person checks the named fields."""
    if draft.op == "seal-id":
        what = f"SEAL this bootloader's id as {draft.value.decode('ascii', 'replace')}"
    elif draft.op == "rotate-operator":
        what = f"ROTATE the operator key to {draft.value.hex()[:16]}..."
    elif draft.op == "add" and draft.kind == PASSPHRASE_KIND:
        what = "REPLACE the recovery passphrase"
    elif draft.op == "add":
        what = f"SEAT {_ref_of(draft.value)} as the {draft.kind}"
    elif draft.op == "remove":
        what = f"REMOVE the {draft.kind} {_ref_of(draft.value)}"
    else:
        what = f"{draft.op} {draft.kind}"
    return (f"TOP-PLANE ACT, entry {draft.seq}: {what}. The passphrase has signed it on the host. Approve ONLY if you "
            f"started this at the host just now; it expires in {ACT_CARD_TTL_SECONDS // 60} minutes.")


def _ref_of(raw_key: bytes) -> str:
    return "pk_" + hashlib.sha256(bytes(raw_key)).hexdigest()[:16]


def reset_intent_digest(intent: dict[str, Any]) -> bytes:
    """The 32 bytes the passphrase signs to START a reset, and an owner phone signs to CANCEL it."""
    return hashlib.sha256(RESET_INTENT_DOMAIN + canonical_meta(intent).encode("utf-8")).digest()


RESET_ARM_DOMAIN = b"recto-owner-reset-arm-v1|"


def reset_arm_digest(arm: dict[str, Any]) -> bytes:
    """The 32 bytes the passphrase signs to ARM a reset after its window: the intent, the slot, a fresh nonce and a
    not_after (an arm is usable for minutes, once)."""
    return hashlib.sha256(RESET_ARM_DOMAIN + canonical_meta(arm).encode("utf-8")).digest()


RESET_ABORT_DOMAIN = b"recto-owner-reset-abort-v1|"


def reset_abort_digest(abort: dict[str, Any]) -> bytes:
    """The 32 bytes the passphrase signs to ABORT an open reset."""
    return hashlib.sha256(RESET_ABORT_DOMAIN + canonical_meta(abort).encode("utf-8")).digest()


def new_intent(*, bootloader_id: str, slots: list[str], lost: list[str], window_seconds: int,
               now: int | None = None) -> dict[str, Any]:
    now = int(time.time()) if now is None else now
    return {"intent_id": "reset-" + secrets.token_hex(8), "bootloader_id": bootloader_id, "slots": sorted(slots),
            "lost": sorted(lost), "not_before": now + int(window_seconds), "started_at": now}


def leg_freshness(leg: dict[str, Any], now: int | None = None) -> None:
    """A signed host leg's (an arm's, an abort's) {nonce, not_after}: raises ValueError when absent, past, or reaching
    further than ACT_FRESH_SECONDS ahead."""
    now = int(time.time()) if now is None else now
    try:
        nonce, not_after = str(leg["nonce"]), int(leg["not_after"])
    except (KeyError, TypeError, ValueError):
        raise ValueError("the leg carries no {nonce, not_after}") from None
    if len(nonce) < 16 or not_after <= now or not_after > now + ACT_FRESH_SECONDS:
        raise ValueError(f"the leg's not_after is past, or further than {ACT_FRESH_SECONDS} s ahead")


def reset_meta(record: dict[str, Any], slot: str) -> str:
    """What the reset entry carries for the record: the intent, the slot it seats and the bound challenge."""
    intent = record["intent"]
    return canonical_meta({"intent_id": intent["intent_id"], "slot": slot, "lost": intent["lost"],
                           "not_before": intent["not_before"], "challenge": record["challenge"]})


def unb64u(s: str) -> bytes:
    return _unb64u(s)


def b64u(raw: bytes) -> str:
    return _b64u(raw)
