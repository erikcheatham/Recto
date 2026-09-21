"""GATE 5 -- the genesis membership chain.

WHY A CHAIN AND NOT A GUARD
---------------------------
`put_genesis_member` used to write whatever it was handed. The obvious fix is
to make the writer demand a signature -- and it would be **security theatre**,
because anyone who can call that function can also open `genesis_members.json`
in an editor. A code path cannot defend a file from someone who has the file.

So membership is a CHAIN, and the defence is DETECTION rather than refusal:

    entry N is signed by every member of the set as it stood at entry N-1,
    and carries the hash of entry N-1.

Edit any entry and its hash stops matching the next `prev`. Append an entry
and it has no valid signatures. Remove one and the sequence breaks. **The file
can still be edited; it can no longer be edited WITHOUT THAT BEING VISIBLE.**

THRESHOLD: A MAJORITY OF CURRENT MEMBERS (operator ruling, 2026-08-19)
-----------------------------------------------------------------------
    k = (N // 2) + 1        N=1 -> 1    N=2 -> 2    N=3 -> 2    N=5 -> 3

**Unanimity was ruled first and then REVERSED, for a reason worth keeping:
requiring all three members made a single lost phone unrecoverable.** Removing
the lost member would have needed its own signature, so the roster would
freeze -- and a frozen roster means you can never enrol a REPLACEMENT either.
One lost device would have permanently degraded the vault to a set it could
not repair.

Majority survives exactly that: with three members, any two can drop a lost
one and admit its replacement. **And no single factor can ever change the
roster alone**, which was the whole point of the stricter rule.

**THE WINDOW TO MINIMISE: at N=2 a majority IS both members**, so a
two-member set has no fault tolerance either. That state is unavoidable on the
way from one member to three -- it should just be short. Get to three.

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
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

from recto.bootloader.sessions import SUPPORTED_ALGORITHMS, verify_signature

__all__ = [
    "ChainError",
    "ChainEntry",
    "CHAIN_DOMAIN",
    "build_entry",
    "entry_hash",
    "replay",
    "signing_bytes",
]

# Domain separation: these bytes are signed by an operator's genesis keys, and
# must never be confusable with any other payload those keys sign.
CHAIN_DOMAIN = "recto-genesis-chain-v1"

_ADD = "add"
_REMOVE = "remove"
_OPS = (_ADD, _REMOVE)


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

    def as_record(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "op": self.op,
            "kind": self.kind,
            "pubkey": self.pubkey.hex(),
            "algorithm": self.algorithm,
            "prev": self.prev,
            "signatures": [_b64u(s) for s in self.signatures],
        }


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode("ascii")


def signing_bytes(
    *, seq: int, op: str, kind: str, pubkey: bytes, algorithm: str, prev: str | None
) -> bytes:
    """The exact bytes a member signs. **Signatures are NOT part of the input**
    -- otherwise the second signer would be signing over the first signature
    and no two members could ever sign the same entry.

    Canonical JSON: sorted keys, no whitespace, so the bytes are reproducible
    on any implementation that follows the same rule.
    """
    body = json.dumps(
        {
            "algorithm": algorithm,
            "kind": kind,
            "op": op,
            "prev": prev,
            "pubkey": bytes(pubkey).hex(),
            "seq": seq,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return CHAIN_DOMAIN.encode("ascii") + b"\x00" + body.encode("utf-8")


def entry_hash(entry: ChainEntry) -> str:
    """Hash of an entry's SIGNED bytes.

    Signatures are excluded deliberately: an entry's identity is what it says,
    not who has countersigned it so far. Including them would change the hash
    as signatures arrived, so `prev` could not be computed until the last
    signer had finished.
    """
    return hashlib.sha256(
        signing_bytes(
            seq=entry.seq, op=entry.op, kind=entry.kind,
            pubkey=entry.pubkey, algorithm=entry.algorithm, prev=entry.prev,
        )
    ).hexdigest()


def build_entry(
    *, seq: int, op: str, kind: str, pubkey: bytes, algorithm: str,
    prev: str | None, signatures: Sequence[bytes] = (),
) -> ChainEntry:
    if op not in _OPS:
        raise ChainError(f"unknown chain op {op!r}; expected one of {_OPS}")
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ChainError(
            f"entry {seq} declares algorithm {algorithm!r}, which no verifier "
            f"supports; it could be written and never used"
        )
    return ChainEntry(
        seq=seq, op=op, kind=kind, pubkey=bytes(pubkey),
        algorithm=algorithm, prev=prev, signatures=tuple(bytes(s) for s in signatures),
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


def replay(entries: Iterable[ChainEntry]) -> dict[str, ChainEntry]:
    """Replay the chain and return the resulting membership, keyed by kind.

    Raises ChainError on ANY break. There is no partial replay: a chain that
    stops verifying at entry 4 does not yield "the membership as of entry 3",
    because an attacker who can truncate is an attacker who can choose which
    membership you get.
    """
    members: dict[str, ChainEntry] = {}
    previous: ChainEntry | None = None

    for index, entry in enumerate(entries):
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
            _require_majority(members, entry)

        if entry.op == _ADD:
            members[entry.kind] = entry
        else:
            if entry.kind not in members:
                raise ChainError(
                    f"entry {entry.seq} removes {entry.kind!r}, which is not a "
                    f"member at that point in the chain"
                )
            del members[entry.kind]
            if not members:
                raise ChainError(
                    f"entry {entry.seq} removes the last member. A set with no "
                    f"members can never authorise another change -- the vault "
                    f"would be permanently unmanageable."
                )
        previous = entry

    return members


def required_signatures(member_count: int) -> int:
    """A majority: `(N // 2) + 1`.

    Exposed rather than inlined so the threshold is one value in one place --
    the replay, the writer, and any operator-facing message all read it here.
    """
    return (member_count // 2) + 1


def _require_majority(members: dict[str, ChainEntry], entry: ChainEntry) -> None:
    """A MAJORITY of the set as it stands must have signed this entry."""
    if not members:
        raise ChainError(
            f"entry {entry.seq} follows an empty set; nothing could have "
            f"authorised it"
        )
    message = signing_bytes(
        seq=entry.seq, op=entry.op, kind=entry.kind,
        pubkey=entry.pubkey, algorithm=entry.algorithm, prev=entry.prev,
    )
    # Count MEMBERS satisfied, never signatures accepted -- one member's
    # signature presented N times must not stand in for N members. Same
    # invariant as `recto.quorum`, restated here because this replay cannot
    # take a verifier map from a caller.
    satisfied: set[str] = set()
    for signature in entry.signatures:
        for kind, member in members.items():
            if kind in satisfied:
                continue
            if _verifier_for(member.pubkey, member.algorithm)(signature, message):
                satisfied.add(kind)
                break
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
