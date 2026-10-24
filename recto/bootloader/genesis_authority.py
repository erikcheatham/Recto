"""GATE 5c-c -- tier 3: an operation authorised by the genesis SET, not one key.

THE SET, AS RULED 2026-08-19
----------------------------
Tier 3 is k-of-N over the SEALED GENESIS MEMBERS: the RECOVERY PHONE and the
PASSPHRASE. **The operator root is NOT a member.** The BIP-39 master stays in
custody and never signs a challenge online -- losing that property was the
whole cost of making it a signer, and it bought only a recovery path that the
passphrase already provides.

That ruling is what makes this file short. An earlier draft carried a verifier
registry, an unverifiable-member error class, and a paragraph of undecided
protocol, all of which existed to accommodate a secp256k1 root. None of it
survived the root leaving the set.

ONE VERIFIER, NOT A SECOND ONE
------------------------------
Verification is `sessions.verify_signature` -- the same trust anchor every
phone approval and signed poll already uses. **A previous draft of this module
reimplemented Ed25519 verification inline.** It looked identical and was not:
the canonical function also covers `ecdsa-p256` and carries a documented
fallback for an iOS client that signs decoded bytes rather than the literal
payload. A second implementation of a verifier is a second answer to "did they
sign", and the copy is always the weaker one.

WHAT THIS MODULE DOES NOT DO
----------------------------
It does not frame the message and it does not supply freshness. Both belong to
the caller, as with `verify_quorum` -- a helper that invented either would be a
second place the framing was decided.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Mapping, Sequence

from recto.bootloader.sessions import SUPPORTED_ALGORITHMS, verify_signature
from recto.bootloader.state import GenesisMember, StateStoreBase
from recto.quorum import QuorumResult, Verifier, verify_quorum

__all__ = [
    "DEVICE_KINDS",
    "GenesisSetError",
    "PASSPHRASE_KIND",
    "TopPlaneResult",
    "build_member_verifiers",
    "collect_genesis_set",
    "verify_tier3",
    "verify_top_plane",
]

# THE TOP PLANE'S RULE (hard rule 14.7): every top-plane act needs the PASSPHRASE
# AND at least one owner DEVICE. Never the passphrase alone - a hijacked bootloader's sealed public key could be
# attacked offline - and never devices alone - a lost or stolen phone must never carry the plane. Not k-of-N: the
# passphrase is a MANDATORY member and the devices are interchangeable.
from recto.bootloader.genesis_chain import DEVICE_KINDS, PASSPHRASE_KIND  # noqa: E402 - one definition, the chain's


class GenesisSetError(Exception):
    """The SET itself is unusable -- empty, or holding a member that cannot
    be verified. Deliberately NOT a quorum failure: "I could not evaluate this
    member" is not "this member did not sign", and reporting the first as the
    second leaves an operator re-presenting correct signatures forever."""


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode("ascii")


def _verifier_for(member: GenesisMember) -> Verifier:
    pubkey_b64u = _b64u(member.pubkey)
    algorithm = member.algorithm

    def verify(signature: bytes, message: bytes) -> bool:
        # `verify_signature` returns False on a bad signature and raises only
        # on unsupported algorithm / decode failure. `verify_quorum` treats a
        # raising verifier as a rejection, which is right for a malformed
        # signature -- but an unsupported ALGORITHM is caught up-front in
        # `build_member_verifiers`, so it can never reach here.
        return verify_signature(
            payload=bytes(message),
            signature_b64u=_b64u(signature),
            public_key_b64u=pubkey_b64u,
            algorithm=algorithm,
        )

    return verify


def collect_genesis_set(state: StateStoreBase) -> dict[str, GenesisMember]:
    """The sealed genesis members. Raises if there are none to form a set."""
    members = dict(state.list_genesis_members_full())
    if not members:
        raise GenesisSetError(
            "no genesis members are sealed; there is no set to form a quorum "
            "over. Seal at least one with `recto vault seal-passphrase`."
        )
    return members


def build_member_verifiers(
    members: Mapping[str, GenesisMember],
) -> dict[str, Verifier]:
    """Turn the set into `identity -> verifier`.

    Raises GenesisSetError naming every member that cannot be verified, rather
    than returning a partial set. A partial set makes the quorum arithmetic
    silently smaller than the roster: 2-of-3 over a set the code can read two
    of is really 2-of-2, and nothing would say so.

    In practice this cannot fire today -- `GENESIS_ALGORITHMS` is exactly
    `SUPPORTED_ALGORITHMS`, and the store refuses to seal anything else. It is
    kept because those two lists live in different files, and a stored member
    outlives the code that sealed it: a member sealed today must still be
    readable by a verifier changed tomorrow.
    """
    unverifiable = sorted(
        (m.kind, m.algorithm)
        for m in members.values()
        if m.algorithm not in SUPPORTED_ALGORITHMS
    )
    if unverifiable:
        detail = ", ".join(f"{kind} ({algo})" for kind, algo in unverifiable)
        raise GenesisSetError(
            f"{len(unverifiable)} sealed member(s) use an algorithm the "
            f"signature verifier does not support, so no tier-3 quorum can be "
            f"evaluated: {detail}. This is NOT a failed authorisation -- the "
            f"same signatures will not start working."
        )
    return {identity: _verifier_for(m) for identity, m in members.items()}


@dataclass(frozen=True)
class TopPlaneResult:
    """`met` is the only field an authorisation decision reads. `passphrase` and `devices` are for the AUDIT row and,
    as with QuorumResult.satisfied_by, an oracle on a recovery path - the caller decides who may see them."""

    met: bool
    passphrase: bool
    devices: frozenset[str]


def verify_top_plane(
    message: bytes,
    signatures: Sequence[bytes],
    state: StateStoreBase,
) -> TopPlaneResult:
    """Verify a top-plane act: a valid signature by the sealed PASSPHRASE member AND by at least one sealed DEVICE
    member, both over `message` (the act's own framed bytes - the caller frames them, as for verify_quorum).

    Raises GenesisSetError before any signature is examined when the set cannot carry the rule at all - no passphrase
    sealed, or no device sealed - so "the set cannot act" is never reported as "the signatures were wrong"."""
    members = collect_genesis_set(state)
    if PASSPHRASE_KIND not in members:
        raise GenesisSetError(
            "no passphrase member is sealed; the top plane needs the passphrase for every act (hard rule 14.7). "
            "Seal it with `recto vault seal-passphrase`."
        )
    devices = {kind: m for kind, m in members.items() if kind in DEVICE_KINDS}
    if not devices:
        raise GenesisSetError(
            "no device member is sealed; the top plane needs the passphrase AND an owner device (hard rule 14.7)."
        )
    gate = {PASSPHRASE_KIND: members[PASSPHRASE_KIND], **devices}
    verifiers = build_member_verifiers(gate)
    satisfied: set[str] = set()
    for signature in signatures:
        for kind, verify in verifiers.items():
            if kind in satisfied:
                continue
            try:
                ok = verify(bytes(signature), bytes(message))
            except Exception:  # noqa: BLE001 - a malformed signature is a rejection, never a crash
                ok = False
            if ok:
                satisfied.add(kind)
                break
    device_hits = frozenset(satisfied & DEVICE_KINDS)
    has_passphrase = PASSPHRASE_KIND in satisfied
    return TopPlaneResult(met=has_passphrase and bool(device_hits), passphrase=has_passphrase, devices=device_hits)


def verify_tier3(
    message: bytes,
    signatures: Sequence[bytes],
    state: StateStoreBase,
    k: int,
) -> QuorumResult:
    """Verify that >= `k` distinct sealed genesis members signed `message`.

    Raises GenesisSetError before any signature is examined, so a structural
    problem can never be mistaken for a signature problem.
    """
    members = collect_genesis_set(state)
    return verify_quorum(message, signatures, build_member_verifiers(members), k)
