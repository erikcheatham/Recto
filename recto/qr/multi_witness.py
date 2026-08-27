"""
recto.qr.multi_witness — multi-witness contract operations.

A multi-witness contract is a QR-encoded artifact that grows as
witnesses sign. The originator creates a base claim with a
`required_witnesses` list; each required witness signs the contract's
state at the time they receive it (i.e. with all prior witnesses
already in the `witnesses` list) and re-renders the QR. The final
QR (after all required witnesses have signed) IS the canonical
contract document — print on paper, store in vault, photograph
forever; the chain back to all participants is intact in the bytes.

Three primitives in this module:

  1. **create_multi_witness_contract** — originator-side builder.
     Returns a `MultiWitnessContract` instance with the originator
     populated, `required_witnesses` set, `witnesses` empty.
     Originator signs by appending themselves as the first witness
     (or not — `required_witnesses` is intentionally separate from
     `iss` so the originator can be a non-witness coordinator).

  2. **add_witness_signature** — witness-side mutator. Takes an
     existing contract + a witness signature, returns a NEW contract
     instance with the witness appended (dataclasses are frozen, so
     no in-place mutation). Verifies the new witness is the next
     required witness in order.

  3. **canonical_signing_input_for_witness** — signing-input
     reconstructor. Given a contract at the state a witness sees it
     (before they sign), returns the canonical-JSON bytes that
     witness signs over.

First concrete use cases:
  - A consumer's first user-to-user citation receipt — sister review
    creator + cited review creator sign, contract = canonical
    citation provenance artifact (per architectural commitment #15)
  - A consumer's first role-elevation certificate — operator +
    promoted principal sign, and further witnesses sign to attest
    the elevation
  - A manumission ceremony — operator + designated witnesses sign
    the manumission JWS as the ceremony's persistent artifact

Cross-references: Recto Hard Rule #13 (artifact-as-canonical-record);
Recto/CLAUDE.md "QR-as-visual-transport for capability JWS +
signed-payload contracts" section's multi-witness extension schema.
"""

from __future__ import annotations

from typing import Any

from recto.qr.encode import _canonical_json, qr_encode_payload
from recto.qr.types import (
    MultiWitnessContract,
    QRMeta,
    QR_SCHEMA_VERSION,
    Witness,
)


def create_multi_witness_contract(
    *,
    iss: str,
    subject: dict[str, Any],
    required_witnesses: tuple[str, ...] | list[str],
    qr_meta: QRMeta | None = None,
) -> MultiWitnessContract:
    """Build a fresh multi-witness contract with no witnesses signed yet.

    The originator calls this to seed the contract; subsequent witnesses
    extend it via `add_witness_signature`. The QR for this initial
    state is encodable via `encode_multi_witness_qr(contract)` —
    typically displayed to the first witness who scans it, signs the
    canonical-JSON, and produces a new QR with their signature
    appended.

    Args:
        iss: Originator principal identifier (e.g. "phone:operator:
            enclave" for operator-initiated contracts; "agent:<id>"
            for agent-initiated; "user:<uuid>" for user-initiated).
        subject: The thing being contracted on. Shape varies by
            contract type — for citation receipts, typically
            `{"cited_review_id": ..., "citing_review_id": ...,
            "citation_text": ...}`. For promotion certificates,
            `{"target_user_id": ..., "new_tier": ..., "reason": ...}`.
            For agent leases, `{"agent_id": ..., "lessee_id": ...,
            "scope": ..., "exp": ...}`.
        required_witnesses: Ordered tuple of principal identifiers who
            must sign in order. Order matters — the next witness to
            sign must match `required_witnesses[len(witnesses)]`.
        qr_meta: Optional transport metadata override. Defaults to
            QRMeta() (PNG, v40-L capacity, no fragmentation).

    Returns:
        A MultiWitnessContract instance with `witnesses=()` and
        `completed_at=None`.
    """
    if not iss:
        raise ValueError("iss must be a non-empty principal identifier")
    if not required_witnesses:
        raise ValueError(
            "required_witnesses must contain at least one principal; "
            "for single-signer artifacts use QRPayloadV1 instead"
        )

    return MultiWitnessContract(
        v=QR_SCHEMA_VERSION,
        kind="multi_witness_contract",
        iss=iss,
        subject=dict(subject),
        required_witnesses=tuple(required_witnesses),
        witnesses=(),
        completed_at=None,
        _qr_meta=qr_meta if qr_meta is not None else QRMeta(),
    )


def add_witness_signature(
    contract: MultiWitnessContract,
    *,
    principal: str,
    signature: str,
    signed_at: int,
) -> MultiWitnessContract:
    """Append a witness signature to a multi-witness contract.

    Returns a NEW contract instance (dataclasses are frozen, so no
    in-place mutation). Validates that:

      - The principal matches `required_witnesses[len(contract.witnesses)]`
        (sign order is enforced — witness N+1 must be the (N+1)th
        required witness)
      - The principal isn't already in `contract.witnesses` (defends
        against accidental re-signing)
      - `signed_at` is a positive integer (sanity check)

    The signature itself is NOT verified here — that's the consumer's
    job after reconstructing the canonical-JSON signing input via
    `canonical_signing_input_for_witness`. This function just stamps
    the signature into the contract's witnesses list.

    Args:
        contract: The contract at the state this witness saw it
            (i.e. with all prior witnesses already present).
        principal: This witness's principal identifier. MUST match
            `contract.required_witnesses[len(contract.witnesses)]`.
        signature: Base64url-encoded signature over the contract's
            canonical-JSON encoding at the time this witness signed
            (computed via `canonical_signing_input_for_witness`).
        signed_at: Unix timestamp when this witness signed.

    Returns:
        A new MultiWitnessContract with this witness appended.
        `completed_at` is populated automatically if this is the
        final required witness.

    Raises:
        ValueError: If principal doesn't match the next required
            witness, is already in the witnesses list, or signed_at
            is invalid.
    """
    if signed_at <= 0:
        raise ValueError(f"signed_at must be positive; got {signed_at}")
    if not signature:
        raise ValueError("signature must be non-empty")

    next_index = len(contract.witnesses)
    if next_index >= len(contract.required_witnesses):
        raise ValueError(
            f"contract already has {len(contract.witnesses)} witnesses; "
            f"required_witnesses has {len(contract.required_witnesses)}; "
            f"no slot for additional witnesses"
        )

    expected_principal = contract.required_witnesses[next_index]
    if principal != expected_principal:
        raise ValueError(
            f"next required witness is '{expected_principal}'; "
            f"got '{principal}' (sign order is enforced)"
        )

    # Defend against accidental re-signing by checking the prior
    # witnesses for this principal. The order check above already
    # catches the canonical case (sign-out-of-order); this catches
    # the corner case where required_witnesses contains duplicates.
    for prior in contract.witnesses:
        if prior.principal == principal:
            raise ValueError(
                f"witness '{principal}' has already signed at "
                f"signed_at={prior.signed_at}"
            )

    new_witness = Witness(
        principal=principal,
        signature=signature,
        signed_at=signed_at,
    )
    new_witnesses = contract.witnesses + (new_witness,)

    # Mark completed if this was the final required witness.
    new_completed_at: int | None
    if len(new_witnesses) == len(contract.required_witnesses):
        new_completed_at = signed_at
    else:
        new_completed_at = contract.completed_at

    return MultiWitnessContract(
        v=contract.v,
        kind=contract.kind,
        iss=contract.iss,
        subject=contract.subject,
        required_witnesses=contract.required_witnesses,
        witnesses=new_witnesses,
        completed_at=new_completed_at,
        _qr_meta=contract._qr_meta,
    )


def canonical_signing_input_for_witness(
    contract: MultiWitnessContract,
) -> bytes:
    """Compute the canonical-JSON bytes a witness signs over.

    A witness sees the contract at a particular state (with prior
    witnesses already signed) and signs over the contract's
    canonical-JSON encoding AT THAT STATE — i.e. WITHOUT their own
    signature appended yet. The signature attests "I, this witness,
    saw the contract in this exact state and approve it as my
    predecessor in the chain."

    This function returns the bytes the next-required witness should
    sign over. Pass the contract BEFORE calling `add_witness_signature`;
    sign the returned bytes; then call `add_witness_signature` with
    the resulting signature.

    The `_qr_meta` field is stripped (consistent with
    `recto.qr.encode.canonical_signing_input` — transport metadata
    is never signed).

    Args:
        contract: The contract at the state the next-required witness
            sees it.

    Returns:
        UTF-8 bytes of the canonical-JSON encoding (without
        `_qr_meta`). Witnesses sign these bytes; verifiers
        reconstruct the same bytes from the contract-at-witness-time
        to recover the signature.
    """
    payload_dict: dict[str, Any] = {
        "v": contract.v,
        "kind": contract.kind,
        "iss": contract.iss,
        "subject": dict(contract.subject),
        "required_witnesses": list(contract.required_witnesses),
        "witnesses": [
            {
                "principal": w.principal,
                "signature": w.signature,
                "signed_at": w.signed_at,
            }
            for w in contract.witnesses
        ],
        "completed_at": contract.completed_at,
    }
    return _canonical_json(payload_dict).encode("utf-8")


def encode_multi_witness_qr(
    contract: MultiWitnessContract,
    *,
    image_format: str = "png",
    error_correction: str = "M",
    box_size: int = 8,
    border: int = 4,
) -> bytes:
    """Render a multi-witness contract as a QR code image.

    Convenience wrapper over `qr_encode_payload` that converts the
    MultiWitnessContract dataclass into the dict shape that
    qr_encode_payload expects. The QR's bytes are the canonical-JSON
    encoding of the contract (INCLUDING `_qr_meta`, since consumers
    need it to know they're looking at a multi-witness contract).

    Args:
        contract: The contract to render. Encodes regardless of
            signature completeness — partially-signed contracts can
            be rendered + passed to the next witness.
        image_format: "png" or "svg".
        error_correction: "L" / "M" / "Q" / "H".
        box_size: PNG pixels per module (PNG only).
        border: Quiet-zone border width in modules.

    Returns:
        PNG or SVG bytes.
    """
    payload_dict: dict[str, Any] = {
        "v": contract.v,
        "kind": contract.kind,
        "iss": contract.iss,
        "subject": dict(contract.subject),
        "required_witnesses": list(contract.required_witnesses),
        "witnesses": [
            {
                "principal": w.principal,
                "signature": w.signature,
                "signed_at": w.signed_at,
            }
            for w in contract.witnesses
        ],
        "completed_at": contract.completed_at,
        "_qr_meta": {
            "format": contract._qr_meta.format,
            "max_size_bytes": contract._qr_meta.max_size_bytes,
            "fragmentation": contract._qr_meta.fragmentation,
        },
    }
    return qr_encode_payload(
        payload_dict,
        image_format=image_format,
        error_correction=error_correction,
        box_size=box_size,
        border=border,
    )
