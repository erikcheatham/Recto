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
from typing import Mapping, Sequence

from recto.bootloader.sessions import SUPPORTED_ALGORITHMS, verify_signature
from recto.bootloader.state import GenesisMember, StateStoreBase
from recto.quorum import QuorumResult, Verifier, verify_quorum

__all__ = [
    "GenesisSetError",
    "build_member_verifiers",
    "collect_genesis_set",
    "verify_tier3",
]


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
