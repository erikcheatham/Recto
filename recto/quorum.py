"""K-of-N signature quorum -- the first multi-signature verification in Recto.

WHY THIS IS ITS OWN MODULE, ABOVE ANY PLANE
-------------------------------------------
Two places in this codebase need "k distinct valid signatures from this set":

  * the GENESIS member set (PRIMARY phone / RECOVERY device / PASSPHRASE) --
    the root of vault authority;
  * ``profile.revoke_quorum_k`` -- k signatures from a profile's devices to
    authorise ``profile_revoke_device``.

Until now the second one was a RESERVED SURFACE: the field was validated and
stored, and the endpoint refused K>=2 with ``quorum_not_yet_implemented``
rather than aggregate signatures it had no code to aggregate. That refusal was
correct -- it failed closed -- and it is the reason this module exists instead
of a genesis-shaped helper hidden in the bootloader. **Two quorum notions in
one tree is one value in two places**, and the second one always drifts.

THE PROPERTY THIS MODULE EXISTS TO ENFORCE
------------------------------------------
    IT COUNTS MEMBERS SATISFIED. IT DOES NOT COUNT SIGNATURES ACCEPTED.

That single sentence is the whole security argument. The classic K-of-N break
is not a forged signature -- it is ONE valid signature presented k times, or
one member's key matching two roster entries. A verifier that increments a
counter per accepted signature says "2-of-3" while one key opened the vault.

So: every signature is attributed to AT MOST ONE member, every member is
counted AT MOST ONCE, and the returned count is ``len(set_of_members)``.

ALGORITHM-AGNOSTIC BY CONSTRUCTION
----------------------------------
Members are ``identity -> verifier`` pairs. This module never learns what a
key IS -- no curve, no length check, no "32 bytes means Ed25519". Inferring an
algorithm from a key's length is how a secp256k1 pubkey gets verified as
something else, and the caller always knows the algorithm while this module
never can.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Mapping, Sequence

__all__ = [
    "QuorumResult",
    "QuorumConfigError",
    "Verifier",
    "verify_quorum",
]

# A verifier answers ONE question: does this signature verify over this
# message, under the key I close over? It returns a bool and must not raise --
# but see _safe_verify: we assume nothing.
Verifier = Callable[[bytes, bytes], bool]


class QuorumConfigError(ValueError):
    """The quorum ITSELF is impossible or malformed.

    Distinct from "the quorum was not met", deliberately. `k=3` over two
    members can never be satisfied by any set of signatures, so returning
    `met=False` would report a permanent configuration fault as a routine
    authorisation failure -- and the caller would retry forever. A quorum that
    CANNOT be met is a different event from one that WAS not met.
    """


@dataclass(frozen=True)
class QuorumResult:
    """The outcome. `met` is the only field an authorisation decision may read.

    `satisfied_by` exists for AUDIT, and exposing it is a CALLER's decision,
    never this module's. On the profile-revoke plane it belongs in the audit
    row. On a recovery path it is an ORACLE: telling an attacker which of the
    three genesis members they have already defeated lets them attack the
    remaining ones one at a time. This module returns it; who may see it is
    not a question this module can answer.
    """

    met: bool
    k: int
    satisfied_by: frozenset[str] = field(default_factory=frozenset)
    unmatched_signatures: int = 0

    @property
    def count(self) -> int:
        """Distinct MEMBERS satisfied -- never the number of signatures."""
        return len(self.satisfied_by)


def _safe_verify(verifier: Verifier, signature: bytes, message: bytes) -> bool:
    """Call a verifier so that ANY failure is a rejection.

    A verifier that raises must never become an accept, and must never
    propagate: one malformed signature in a batch would otherwise abort the
    whole quorum check, turning a bad input into a denial of service against
    a recovery path -- exactly when the operator can least afford it.
    """
    try:
        return bool(verifier(signature, message))
    except Exception:
        return False


def verify_quorum(
    message: bytes,
    signatures: Sequence[bytes],
    members: Mapping[str, Verifier],
    k: int,
) -> QuorumResult:
    """Return whether >= `k` DISTINCT members of `members` signed `message`.

    Args:
        message: the exact bytes that were signed. Callers are responsible for
            domain separation and freshness (a challenge nonce); this module
            deliberately does not invent either, because a quorum helper that
            silently framed the message would be a second place the framing
            was decided.
        signatures: candidate signatures, in any order. Duplicates are
            harmless -- they cannot inflate the count.
        members: `identity -> verifier`. The identity is opaque to this module
            and is only used to deduplicate.
        k: how many DISTINCT members must sign. Must satisfy
            `1 <= k <= len(members)`.

    Raises:
        QuorumConfigError: if `k` is not a positive int, the member set is
            empty, or `k` exceeds the number of members -- all unsatisfiable
            by construction rather than unsatisfied by these signatures.
    """
    if isinstance(k, bool) or not isinstance(k, int):
        # bool is an int subclass, and `verify_quorum(..., k=True)` meaning
        # k=1 is a silent misread of a caller that thought it passed a flag.
        raise QuorumConfigError(f"k must be an int, got {type(k).__name__}")
    if k < 1:
        raise QuorumConfigError(
            f"k must be >= 1, got {k}; a quorum of zero authorises everyone"
        )
    if not members:
        raise QuorumConfigError(
            "cannot verify a quorum over an empty member set; "
            "k >= 1 could never be met and reporting that as a failed "
            "authorisation would hide a roster that was never populated"
        )
    if k > len(members):
        raise QuorumConfigError(
            f"k={k} exceeds the member set size ({len(members)}); this "
            f"quorum can never be met by any signatures"
        )

    satisfied: set[str] = set()
    unmatched = 0

    for signature in signatures or ():
        if not signature:
            unmatched += 1
            continue
        matched = False
        for identity, verifier in members.items():
            # Already-satisfied members are skipped: a member cannot be
            # counted twice, so re-verifying buys nothing and would let a
            # replayed signature look like fresh participation in a log.
            if identity in satisfied:
                continue
            if _safe_verify(verifier, bytes(signature), bytes(message)):
                satisfied.add(identity)
                matched = True
                # ONE signature satisfies AT MOST ONE member. Breaking here
                # is load-bearing, not an optimisation: without it, a key
                # present under two roster identities would let a single
                # signature count twice and turn 2-of-3 into 1-of-3.
                break
        if not matched:
            unmatched += 1

    return QuorumResult(
        met=len(satisfied) >= k,
        k=k,
        satisfied_by=frozenset(satisfied),
        unmatched_signatures=unmatched,
    )
