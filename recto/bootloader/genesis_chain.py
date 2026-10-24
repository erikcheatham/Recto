"""GATE 5 -- the genesis membership chain.

WHY A CHAIN AND NOT A GUARD
---------------------------
`put_genesis_member` used to write whatever it was handed. The obvious fix is
to make the writer demand a signature -- and it would be **security theatre**,
because anyone who can call that function can also open `genesis_members.json`
in an editor. A code path cannot defend a file from someone who has the file.

So membership is a CHAIN, and the defence is DETECTION rather than refusal:

    entry N is signed by the set as it stood at entry N-1,
    and carries the hash of entry N-1.

Edit any entry and its hash stops matching the next `prev`. Append an entry
and it has no valid signatures. Remove one and the sequence breaks. **The file
can still be edited; it can no longer be edited WITHOUT THAT BEING VISIBLE.**

THRESHOLD: THE PASSPHRASE AND ONE DEVICE (hard rule 14.7)
--------------------------------------------------------
A set holding the PASSPHRASE changes only under the passphrase's signature AND the
signature of a sealed owner DEVICE (recovery-phone or primary-phone; no other kind
counts). The passphrase alone moves the roster ONLY while the chain
has NEVER held a device - that is how the first device enters, and it is exactly the
replay of a chain's opening entries. Once any device has been sealed:

  * the chain never falls back to the passphrase alone;
  * an entry that would leave ZERO devices is refused (a lost last device is the
    owner reset's job, window included - hard rule 14.4);
  * the passphrase is never removed, only replaced (an `add` of the passphrase kind,
    signed by the current passphrase and a device).

A chain with no passphrase member keeps the MAJORITY below for REPLAY only; the top
plane refuses every act there (genesis_authority.verify_top_plane).

THE MAJORITY (the legacy replay rule)
-------------------------------------
    k = (N // 2) + 1        N=1 -> 1    N=2 -> 2    N=3 -> 2    N=5 -> 3

Unanimity makes a single lost phone unrecoverable, and at N=2 a majority IS both
members, so a two-member majority cannot repair a lost phone either. The
passphrase-plus-one-device rule can: the passphrase and the SURVIVING device
replace a lost one, and no set of phones acts without the passphrase.

THE SEALED ID AND THE DIGEST FORM (hard rule 14.7)
--------------------------------------------------
A `seal-id` entry commits the bootloader id into the chain once (kind
`bootloader-id`, the id's ASCII bytes as its value, algorithm `none`, and in its
meta the operator key and the identity members the id was derived with - a seal
whose recorded inputs do not recompute its id is refused). On a fresh chain it follows the first device's
entry - the seal is itself signed by the passphrase and a device, so a device is
sealed first; on a chain that predates the rule it is appended when the operator
seals. From the seal-id entry on, every entry is signed
over the 32-byte DIGEST `sha256(signing_bytes)` with the sealed id inside the
signed bytes -- the same 32 bytes a phone signs on its card and the host's
passphrase signs, so one pair of signatures is both the act's authority and the
chain's. A chain spliced from another bootloader carries another id and does not
replay. Entries before the seal keep the raw signing-bytes form, so a chain's
opening entries replay unchanged.

THE OTHER TOP-PLANE ENTRIES
---------------------------
`rotate-operator` (kind `operator`, the new operator public key as its value,
algorithm `none`) records an operator-key rotation; the latest one is the key the
bootloader must hold. `reset` (kind: an owner device kind, the fresh device's key)
is the owner reset's completion: the passphrase over the digest AND the fresh key's
own signature over the registration challenge the reset bound (`meta.challenge`).
The 72-hour window and the cancels are the bootloader's to enforce -- the chain
cannot see time -- so the reset entry's `meta` carries what was asked (the intent
id, the slot, the phones named lost, not_before) for the record.

WHAT THE GENESIS ENTRY IS
-------------------------
Entry 0 is unsigned, because there is no prior set to sign it. That is not a
hole: it is the definition of genesis. Everything after it is anchored to it,
so tampering with entry 0 invalidates every signature that follows.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

from recto.bootloader.sessions import SUPPORTED_ALGORITHMS, verify_signature

__all__ = [
    "ChainError",
    "ChainEntry",
    "ChainState",
    "CHAIN_DOMAIN",
    "DEVICE_KINDS",
    "PASSPHRASE_KIND",
    "act_message",
    "build_entry",
    "entries_from_records",
    "entry_hash",
    "replay",
    "replay_state",
    "signing_bytes",
]

# Domain separation: these bytes are signed by an operator's genesis keys, and
# must never be confusable with any other payload those keys sign.
CHAIN_DOMAIN = "recto-genesis-chain-v1"

_ADD = "add"
_REMOVE = "remove"
_SEAL_ID = "seal-id"
_ROTATE = "rotate-operator"
_RESET = "reset"
_OPS = (_ADD, _REMOVE, _SEAL_ID, _ROTATE, _RESET)
_MEMBER_OPS = (_ADD, _REMOVE, _RESET)
_VALUE_ALGORITHM = "none"  # seal-id / rotate-operator carry a value, not a signer
_RESET_CHALLENGE_PREFIX = "recto-reset-v1:"

PASSPHRASE_KIND = "passphrase"
# The OWNER devices, one per slot - the ONLY members that count as the second leg, in the chain and at the gate
# (genesis_authority.verify_top_plane). Another sealed kind never co-signs a roster change and never stands in for a
# device, so no act can seat a non-device co-signer and then remove every real device.
DEVICE_KINDS = frozenset({"recovery-phone", "primary-phone"})
_SLOT_KIND = {"primary": "primary-phone", "recovery": "recovery-phone"}


class ChainError(Exception):
    """The chain does not verify. **Always a tamper/corruption signal, never a
    routine authorisation failure** -- callers must surface it as "unreadable",
    never as "nothing is sealed"."""


@dataclass(frozen=True, slots=True)
class ChainEntry:
    seq: int
    op: str
    kind: str
    pubkey: bytes
    algorithm: str
    prev: str | None
    signatures: tuple[bytes, ...] = ()
    meta: str | None = None  # canonical JSON, signed; None on entries that carry none (every pre-rule entry)

    def as_record(self) -> dict[str, Any]:
        rec = {
            "seq": self.seq,
            "op": self.op,
            "kind": self.kind,
            "pubkey": self.pubkey.hex(),
            "algorithm": self.algorithm,
            "prev": self.prev,
            "signatures": [_b64u(s) for s in self.signatures],
        }
        if self.meta is not None:
            rec["meta"] = self.meta
        return rec


@dataclass(frozen=True)
class ChainState:
    """What a whole chain says, after it replayed clean."""

    members: dict[str, ChainEntry]
    sealed_id: str | None
    operator_pubkey: bytes | None  # the latest rotate-operator's value, or None when the key was never rotated
    device_ever: bool
    tip_hash: str | None
    length: int
    resets: tuple[str, ...] = field(default_factory=tuple)  # intent ids of completed resets
    sealed_operator_pubkey: bytes | None = None  # the operator key the seal-id entry recorded

    @property
    def current_operator_pubkey(self) -> bytes | None:
        """The operator key the chain holds now: the latest rotation's, else the one the seal recorded."""
        return self.operator_pubkey if self.operator_pubkey is not None else self.sealed_operator_pubkey


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode("ascii")


def canonical_meta(meta: dict[str, Any]) -> str:
    return json.dumps(meta, sort_keys=True, separators=(",", ":"))


def signing_bytes(
    *, seq: int, op: str, kind: str, pubkey: bytes, algorithm: str, prev: str | None,
    meta: str | None = None, sealed_id: str | None = None,
) -> bytes:
    """The exact bytes an entry is anchored by. **Signatures are NOT part of the input**
    -- otherwise the second signer would be signing over the first signature
    and no two members could ever sign the same entry.

    `meta` and `sealed_id` join the canonical JSON only when present, so every
    entry written before them hashes and verifies exactly as it did.
    """
    body: dict[str, Any] = {
        "algorithm": algorithm,
        "kind": kind,
        "op": op,
        "prev": prev,
        "pubkey": bytes(pubkey).hex(),
        "seq": seq,
    }
    if meta is not None:
        body["meta"] = meta
    if sealed_id is not None:
        body["sealed_id"] = sealed_id
    return CHAIN_DOMAIN.encode("ascii") + b"\x00" + json.dumps(body, sort_keys=True, separators=(",", ":")).encode(
        "utf-8")


def act_message(
    *, seq: int, op: str, kind: str, pubkey: bytes, algorithm: str, prev: str | None,
    meta: str | None = None, sealed_id: str | None,
) -> bytes:
    """What the set signs for an entry. Before the seal: the raw signing bytes. From the seal-id entry on: the
    32-byte digest of the signing bytes with the sealed id inside them - the bytes a phone's card carries and the
    host's passphrase signs, so the act's signatures ARE the chain entry's."""
    raw = signing_bytes(seq=seq, op=op, kind=kind, pubkey=pubkey, algorithm=algorithm, prev=prev, meta=meta,
                        sealed_id=sealed_id)
    return raw if sealed_id is None else hashlib.sha256(raw).digest()


def entry_hash(entry: ChainEntry) -> str:
    """Hash of an entry's identity bytes (the sealed id excluded, so `prev` is the same whatever the seal).

    Signatures are excluded deliberately: an entry's identity is what it says,
    not who has countersigned it so far. Including them would change the hash
    as signatures arrived, so `prev` could not be computed until the last
    signer had finished.
    """
    return hashlib.sha256(
        signing_bytes(
            seq=entry.seq, op=entry.op, kind=entry.kind,
            pubkey=entry.pubkey, algorithm=entry.algorithm, prev=entry.prev, meta=entry.meta,
        )
    ).hexdigest()


def entries_from_records(records: Iterable[dict[str, Any]]) -> list[ChainEntry]:
    """The ONE reader from stored records to entries - every caller (the store's replay, its append guard, the CLI)
    reads through it, so a field added to the record cannot be read by one and dropped by another."""
    out: list[ChainEntry] = []
    for e in records:
        out.append(build_entry(
            seq=e["seq"], op=e["op"], kind=e["kind"], pubkey=bytes.fromhex(e["pubkey"]), algorithm=e["algorithm"],
            prev=e.get("prev"),
            signatures=[base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)) for s in (e.get("signatures") or [])],
            meta=e.get("meta"),
        ))
    return out


def build_entry(
    *, seq: int, op: str, kind: str, pubkey: bytes, algorithm: str,
    prev: str | None, signatures: Sequence[bytes] = (), meta: str | None = None,
) -> ChainEntry:
    if op not in _OPS:
        raise ChainError(f"unknown chain op {op!r}; expected one of {_OPS}")
    if op in (_SEAL_ID, _ROTATE):
        if algorithm != _VALUE_ALGORITHM:
            raise ChainError(f"entry {seq}: a {op} entry carries a value, so its algorithm is {_VALUE_ALGORITHM!r}")
    elif algorithm not in SUPPORTED_ALGORITHMS:
        raise ChainError(
            f"entry {seq} declares algorithm {algorithm!r}, which no verifier "
            f"supports; it could be written and never used"
        )
    if op in (_ADD, _RESET):
        # A member is a key the verifier can load under the algorithm it names - an Ed25519 key labelled ecdsa-p256 is
        # a member that can never sign, and a dead device must never satisfy the last-device guard.
        from recto.bootloader.state import validate_genesis_pubkey
        try:
            validate_genesis_pubkey(bytes(pubkey), algorithm)
        except ValueError as exc:
            raise ChainError(f"entry {seq}: {exc}") from None
    if op == _ROTATE:
        _require_secp256k1_point(bytes(pubkey), seq)
    return ChainEntry(
        seq=seq, op=op, kind=kind, pubkey=bytes(pubkey),
        algorithm=algorithm, prev=prev, signatures=tuple(bytes(s) for s in signatures), meta=meta,
    )


def _verifier_for(pubkey: bytes, algorithm: str):
    pk = _b64u(pubkey)

    def verify(sig: bytes, msg: bytes) -> bool:
        try:
            return verify_signature(
                payload=msg, signature_b64u=_b64u(sig),
                public_key_b64u=pk, algorithm=algorithm,
            )
        except Exception:
            return False

    return verify


def _message(entry: ChainEntry, sealed_id: str | None) -> bytes:
    return act_message(seq=entry.seq, op=entry.op, kind=entry.kind, pubkey=entry.pubkey, algorithm=entry.algorithm,
                       prev=entry.prev, meta=entry.meta, sealed_id=sealed_id)


def replay(entries: Iterable[ChainEntry]) -> dict[str, ChainEntry]:
    """Replay the chain and return the resulting membership, keyed by kind (see replay_state for the rest)."""
    return replay_state(entries).members


def replay_state(entries: Iterable[ChainEntry]) -> ChainState:
    """Replay the chain and return everything it says.

    Raises ChainError on ANY break. There is no partial replay: a chain that
    stops verifying at entry 4 does not yield "the membership as of entry 3",
    because an attacker who can truncate is an attacker who can choose which
    membership you get.
    """
    members: dict[str, ChainEntry] = {}
    previous: ChainEntry | None = None
    sealed_id: str | None = None
    operator_pubkey: bytes | None = None
    sealed_operator_pubkey: bytes | None = None
    device_ever = False
    resets: list[str] = []
    seats: set[tuple[Any, Any]] = set()
    count = 0

    for index, entry in enumerate(entries):
        count += 1
        if entry.seq != index:
            raise ChainError(
                f"chain sequence broken: entry at position {index} declares "
                f"seq {entry.seq}. A gap or reorder means an entry was removed."
            )
        expected_prev = None if previous is None else entry_hash(previous)
        if entry.prev != expected_prev:
            raise ChainError(
                f"entry {entry.seq} does not follow entry {entry.seq - 1}: "
                f"prev={entry.prev!r} but the previous entry hashes to "
                f"{expected_prev!r}. An earlier entry was altered."
            )

        if entry.seq == 0:
            # GENESIS. Unsigned by definition -- there is no prior set. It must
            # be an `add`, because there is nothing yet to remove.
            if entry.op != _ADD:
                raise ChainError(
                    f"the genesis entry must be an {_ADD!r}, got {entry.op!r}"
                )
            if entry.signatures:
                raise ChainError(
                    "the genesis entry must carry no signatures: there is no "
                    "prior set to have signed it, so a signature here is a "
                    "claim nothing can check"
                )
        else:
            # The seal-id entry is the first one in the digest form: it is signed over its OWN id.
            entry_seal = sealed_id
            if entry.op == _SEAL_ID:
                if sealed_id is not None:
                    raise ChainError(f"entry {entry.seq} seals the id a second time; the id is sealed once")
                if not any(k in DEVICE_KINDS for k in members):
                    raise ChainError(f"entry {entry.seq} seals the id with no device sealed - the seal is a top-plane "
                                     f"act, signed by the passphrase and a device")
                entry_seal = _decode_id(entry)
            elif entry.op in (_RESET,) and sealed_id is None:
                raise ChainError(f"entry {entry.seq}: a reset is recorded only after the bootloader id is sealed")
            message = _message(entry, entry_seal)
            if entry.op == _RESET:
                _require_reset(members, entry, message, device_ever)
            else:
                _require_threshold(members, entry, message, device_ever)

        if entry.op in (_ADD, _RESET):
            if entry.op == _RESET:
                if entry.kind not in DEVICE_KINDS:
                    raise ChainError(f"entry {entry.seq}: a reset seats an owner device, not {entry.kind!r}")
                meta = json.loads(entry.meta or "{}")
                if _SLOT_KIND.get(meta.get("slot")) != entry.kind:
                    raise ChainError(f"entry {entry.seq}: the reset's slot {meta.get('slot')!r} is not the slot of "
                                     f"{entry.kind!r}")
                seat = (meta.get("intent_id"), meta.get("slot"))
                if seat in seats:
                    raise ChainError(f"entry {entry.seq}: reset intent {meta.get('intent_id')!r} already seated the "
                                     f"{meta.get('slot')} slot - an intent seats each of its slots once")
                seats.add(seat)
                if meta.get("intent_id") not in resets:
                    resets.append(meta.get("intent_id", ""))
            twin = next((k for k, m in members.items() if k != entry.kind and bytes(m.pubkey) == bytes(entry.pubkey)),
                        None)
            if twin is not None:
                raise ChainError(f"entry {entry.seq}: {entry.kind!r} would share its key with {twin!r} - every "
                                 f"member is its own key, or the passphrase and a device collapse into one factor")
            members[entry.kind] = entry
            if entry.kind in DEVICE_KINDS:
                device_ever = True
        elif entry.op == _REMOVE:
            if entry.kind not in members:
                raise ChainError(
                    f"entry {entry.seq} removes {entry.kind!r}, which is not a "
                    f"member at that point in the chain"
                )
            removed = members[entry.kind]
            if bytes(entry.pubkey) != bytes(removed.pubkey) or entry.algorithm != removed.algorithm:
                raise ChainError(
                    f"entry {entry.seq} removes {entry.kind!r} under a key that is not that member's own - a removal "
                    f"names the member it removes"
                )
            if entry.kind == PASSPHRASE_KIND:
                raise ChainError(
                    f"entry {entry.seq} removes the passphrase. The passphrase is replaced (an add of its kind), "
                    f"never removed: a set without it can never act again (hard rule 14.7)."
                )
            del members[entry.kind]
            if not members:
                raise ChainError(
                    f"entry {entry.seq} removes the last member. A set with no "
                    f"members can never authorise another change -- the vault "
                    f"would be permanently unmanageable."
                )
            if device_ever and PASSPHRASE_KIND in members and not any(k in DEVICE_KINDS for k in members):
                raise ChainError(
                    f"entry {entry.seq} removes the last device. A set left with the passphrase alone could only "
                    f"act by the passphrase alone, which the rule forbids; a lost last device is the owner reset's "
                    f"job (hard rule 14.4)."
                )
        elif entry.op == _SEAL_ID:
            sealed_id = _decode_id(entry)
            sealed_operator_pubkey = _seal_operator_key(entry)
        elif entry.op == _ROTATE:
            if entry.kind != "operator" or len(entry.pubkey) != 64:
                raise ChainError(f"entry {entry.seq}: a rotate-operator entry names kind 'operator' and a 64-byte key")
            operator_pubkey = bytes(entry.pubkey)
        previous = entry

    return ChainState(
        members=members, sealed_id=sealed_id, operator_pubkey=operator_pubkey, device_ever=device_ever,
        tip_hash=None if previous is None else entry_hash(previous), length=count, resets=tuple(resets),
        sealed_operator_pubkey=sealed_operator_pubkey,
    )


def seal_mark_of(entries: Sequence[ChainEntry], state: ChainState) -> dict[str, Any] | None:
    """The high-water mark a sealed chain leaves: the sealed id, the seal entry's seq and hash, the length and the
    tip. None for an unsealed chain."""
    if state.sealed_id is None:
        return None
    seal = next(e for e in entries if e.op == _SEAL_ID)
    return {"sealed_id": state.sealed_id, "seal_seq": seal.seq, "seal_hash": entry_hash(seal),
            "length": state.length, "tip": state.tip_hash}


def check_seal_mark(entries: Sequence[ChainEntry], state: ChainState | None, mark: Any) -> None:
    """Raise ChainError when the stored chain falls behind the recorded seal (hard rule 14.7): truncation, a
    replacement, an unsealed chain after a seal, a SEALED chain with no mark, or a mark that is empty or malformed -
    each would silently undo a rotation, revive a removed device or drop the slot gate back to a phone's approval
    alone. A mark IN FLIGHT ({prev, next}, written before an append) accepts a chain matching either side."""
    sealed = state is not None and state.sealed_id is not None
    if mark is None:
        if sealed:
            raise ChainError("the genesis chain is SEALED but no seal mark is recorded - the mark was deleted")
        return
    if not isinstance(mark, dict) or not mark:
        raise ChainError("the seal mark is empty or malformed")
    if "next" in mark:
        reasons: list[str] = []
        for side in (mark.get("next"), mark.get("prev")):
            if side is None:
                if not sealed:
                    return
                reasons.append("an empty side cannot hold a sealed chain")
                continue
            try:
                _check_one_mark(entries, state, side)
                return
            except ChainError as exc:
                reasons.append(str(exc))
        raise ChainError("the chain matches neither side of the seal mark in flight: " + "; ".join(reasons))
    _check_one_mark(entries, state, mark)


def resolve_seal_mark(entries: Sequence[ChainEntry], state: ChainState | None, mark: Any) -> Any:
    """The PLAIN mark the stored chain answers to: a plain mark as it is; for a mark in flight ({prev, next}), the
    side the chain matches (None when that side is the empty, unsealed one). Raises ChainError as check_seal_mark
    does. A new in-flight mark is always written over this, so a mark never nests inside another."""
    check_seal_mark(entries, state, mark)
    if not isinstance(mark, dict) or "next" not in mark:
        return mark
    for side in (mark.get("next"), mark.get("prev")):
        if side is None:
            if state is None or state.sealed_id is None:
                return None
            continue
        try:
            _check_one_mark(entries, state, side)
            return side
        except ChainError:
            continue
    raise ChainError("the chain matches neither side of the seal mark in flight")


def _check_one_mark(entries: Sequence[ChainEntry], state: ChainState | None, mark: Any) -> None:
    if not isinstance(mark, dict) or not mark.get("sealed_id"):
        raise ChainError("the seal mark is empty or malformed")
    if state is None or state.sealed_id is None:
        raise ChainError("the genesis chain is UNSEALED but a seal was recorded - the chain was truncated or replaced")
    if state.sealed_id != mark.get("sealed_id"):
        raise ChainError(f"the chain seals {state.sealed_id!r} but {mark.get('sealed_id')!r} was recorded")
    length = int(mark.get("length", 0))
    if state.length < length:
        raise ChainError(f"the chain holds {state.length} entries but {length} were accepted - it was truncated")
    if entry_hash(entries[length - 1]) != mark.get("tip"):
        raise ChainError(f"the chain differs at entry {length - 1} from the one accepted - it was replaced")
    seq = int(mark.get("seal_seq", -1))
    if not (0 <= seq < len(entries)) or entry_hash(entries[seq]) != mark.get("seal_hash"):
        raise ChainError("the seal entry differs from the one recorded")


def _require_secp256k1_point(value: bytes, seq: int) -> None:
    """An operator key is a point on secp256k1 (64 bytes, X||Y) - any other 64 bytes would rotate the vault onto a key
    nothing can sign for."""
    from cryptography.hazmat.primitives.asymmetric import ec
    try:
        if len(value) != 64:
            raise ValueError("not 64 bytes")
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), b"\x04" + value)
    except ValueError:
        raise ChainError(f"entry {seq}: the operator key is not a secp256k1 point (64 bytes, X||Y)") from None


def _seal_operator_key(entry: ChainEntry) -> bytes:
    """The operator key a seal-id entry records in its meta (`operator_pubkey`, 128 hex), checked with the identity
    members it records beside it (`identity_members`, a list of hex keys): the inputs the sealed id was derived with,
    so a start compares the key it holds with the chain's and serves inputs a phone recomputes the id from."""
    try:
        meta = json.loads(entry.meta or "")
        value = bytes.fromhex(str(meta["operator_pubkey"]))
        if not isinstance(meta["identity_members"], list):
            raise TypeError
        for member in meta["identity_members"]:
            if not isinstance(member, str):
                raise TypeError
            bytes.fromhex(member)
    except (ValueError, KeyError, TypeError):
        raise ChainError(f"entry {entry.seq}: a seal-id entry records the operator key (operator_pubkey, 128 hex) "
                         f"and the identity members (identity_members, a list of hex keys) in its meta") from None
    _require_secp256k1_point(value, entry.seq)
    return value


def _decode_id(entry: ChainEntry) -> str:
    try:
        value = bytes(entry.pubkey).decode("ascii")
    except UnicodeDecodeError:
        raise ChainError(f"entry {entry.seq}: the sealed id is not ASCII") from None
    if entry.kind != "bootloader-id" or not value or not value.isprintable():
        raise ChainError(f"entry {entry.seq}: a seal-id entry names kind 'bootloader-id' and a printable id")
    return value


def required_signatures(member_count: int) -> int:
    """A majority: `(N // 2) + 1` -- the legacy rule, for a chain with no passphrase member.

    Exposed rather than inlined so the threshold is one value in one place --
    the replay, the writer, and any operator-facing message all read it here.
    """
    return (member_count // 2) + 1


def _satisfied_kinds(members: dict[str, ChainEntry], entry: ChainEntry, message: bytes) -> set[str]:
    """The member KINDS whose signature on this entry verifies - members counted, never signatures."""
    satisfied: set[str] = set()
    for signature in entry.signatures:
        for kind, member in members.items():
            if kind in satisfied:
                continue
            if _verifier_for(member.pubkey, member.algorithm)(signature, message):
                satisfied.add(kind)
                break
    return satisfied


def _require_threshold(members: dict[str, ChainEntry], entry: ChainEntry, message: bytes, device_ever: bool) -> None:
    """Hard rule 14.7: the passphrase AND a device; the passphrase alone only while no device was ever sealed; the
    legacy majority for a set with no passphrase member."""
    if not members:
        raise ChainError(
            f"entry {entry.seq} follows an empty set; nothing could have "
            f"authorised it"
        )
    if PASSPHRASE_KIND not in members:
        _require_majority(members, entry, message)
        return
    satisfied = _satisfied_kinds(members, entry, message)
    if PASSPHRASE_KIND not in satisfied:
        raise ChainError(
            f"entry {entry.seq} ({entry.op} {entry.kind!r}) carries no valid passphrase signature. Every roster "
            f"change needs the passphrase (hard rule 14.7). Signed by: {', '.join(sorted(satisfied)) or 'nobody'}."
        )
    if device_ever and not (satisfied & DEVICE_KINDS):
        held = sorted(k for k in members if k in DEVICE_KINDS)
        raise ChainError(
            f"entry {entry.seq} ({entry.op} {entry.kind!r}) carries the passphrase but no device signature; once a "
            f"device has been sealed ({', '.join(held) or 'none now'}), the set changes only under the passphrase "
            f"AND a device (hard rule 14.7)."
        )


def _require_reset(members: dict[str, ChainEntry], entry: ChainEntry, message: bytes, device_ever: bool) -> None:
    """The owner reset's completion: the passphrase over the digest AND the fresh key's own signature over the
    registration challenge the reset bound. The window and the cancels are the bootloader's (the chain cannot see
    time); what was asked travels in `meta`."""
    if PASSPHRASE_KIND not in members:
        raise ChainError(f"entry {entry.seq}: a reset needs a sealed passphrase")
    if PASSPHRASE_KIND not in _satisfied_kinds({PASSPHRASE_KIND: members[PASSPHRASE_KIND]}, entry, message):
        raise ChainError(f"entry {entry.seq} (reset {entry.kind!r}) carries no valid passphrase signature "
                         f"(hard rule 14.7)")
    try:
        meta = json.loads(entry.meta or "")
        challenge = meta["challenge"]
        intent_id = meta["intent_id"]
        int(meta["not_before"])
        list(meta["lost"])
    except (ValueError, KeyError, TypeError):
        raise ChainError(f"entry {entry.seq}: a reset carries meta with the intent id, the challenge, not_before and "
                         f"the phones named lost") from None
    if not isinstance(challenge, str) or not challenge.startswith(f"{_RESET_CHALLENGE_PREFIX}{intent_id}:"):
        raise ChainError(f"entry {entry.seq}: the reset's challenge is not bound to its intent")
    fresh = _verifier_for(entry.pubkey, entry.algorithm)
    if not any(fresh(sig, challenge.encode("ascii")) for sig in entry.signatures):
        raise ChainError(f"entry {entry.seq}: the fresh device did not sign the reset's challenge - possession of "
                         f"the new key is the reset's device leg")


def _require_majority(members: dict[str, ChainEntry], entry: ChainEntry, message: bytes) -> None:
    """A MAJORITY of the set as it stands must have signed this entry (the legacy rule)."""
    satisfied = _satisfied_kinds(members, entry, message)
    needed = required_signatures(len(members))
    if len(satisfied) < needed:
        raise ChainError(
            f"entry {entry.seq} ({entry.op} {entry.kind!r}) carries "
            f"{len(satisfied)} valid member signature(s); a set of "
            f"{len(members)} requires {needed}. "
            f"Signed by: {', '.join(sorted(satisfied)) or 'nobody'}. "
            f"Membership changes require a majority of the set as it stands, "
            f"so no single member can alter the roster alone."
        )
