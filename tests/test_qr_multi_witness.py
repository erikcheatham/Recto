"""
tests/test_qr_multi_witness.py — recto.qr.multi_witness operation tests.

Pins the multi-witness contract operations: create, add witness, sign-
order enforcement, canonical signing input reconstruction, and the
encode → re-render round-trip after each witness signs.

No qrcode dependency for most tests — multi-witness operations are
pure-Python; only the actual encode_multi_witness_qr test gates
behind the optional extra.
"""

from __future__ import annotations

import pytest

from recto.qr.multi_witness import (
    add_witness_signature,
    canonical_signing_input_for_witness,
    create_multi_witness_contract,
    encode_multi_witness_qr,
)
from recto.qr.types import MultiWitnessContract, QRMeta, Witness


class TestCreateMultiWitnessContract:
    """Pin the originator-side contract builder."""

    def test_creates_empty_contract(self) -> None:
        contract = create_multi_witness_contract(
            iss="phone:operator:enclave",
            subject={"citation_id": "cite-123"},
            required_witnesses=("user:alice", "user:bob"),
        )
        assert contract.iss == "phone:operator:enclave"
        assert contract.subject == {"citation_id": "cite-123"}
        assert contract.required_witnesses == ("user:alice", "user:bob")
        assert contract.witnesses == ()
        assert contract.completed_at is None
        assert contract.kind == "multi_witness_contract"
        assert contract.v == 1

    def test_accepts_list_or_tuple_for_required_witnesses(self) -> None:
        as_tuple = create_multi_witness_contract(
            iss="x",
            subject={},
            required_witnesses=("user:a", "user:b"),
        )
        as_list = create_multi_witness_contract(
            iss="x",
            subject={},
            required_witnesses=["user:a", "user:b"],
        )
        assert as_tuple.required_witnesses == as_list.required_witnesses

    def test_rejects_empty_iss(self) -> None:
        with pytest.raises(ValueError, match="iss must be"):
            create_multi_witness_contract(
                iss="",
                subject={},
                required_witnesses=("user:a",),
            )

    def test_rejects_empty_required_witnesses(self) -> None:
        with pytest.raises(ValueError, match="required_witnesses"):
            create_multi_witness_contract(
                iss="x",
                subject={},
                required_witnesses=(),
            )

    def test_custom_qr_meta(self) -> None:
        meta = QRMeta(format="qr-svgv1", max_size_bytes=1273)
        contract = create_multi_witness_contract(
            iss="x",
            subject={},
            required_witnesses=("user:a",),
            qr_meta=meta,
        )
        assert contract._qr_meta.format == "qr-svgv1"
        assert contract._qr_meta.max_size_bytes == 1273

    def test_is_complete_false_when_empty(self) -> None:
        contract = create_multi_witness_contract(
            iss="x",
            subject={},
            required_witnesses=("user:a", "user:b"),
        )
        assert contract.is_complete() is False


class TestAddWitnessSignature:
    """Pin the witness-signature-append behavior + sign-order enforcement."""

    def _fresh_contract(self) -> MultiWitnessContract:
        return create_multi_witness_contract(
            iss="phone:operator:enclave",
            subject={"contract_type": "test"},
            required_witnesses=("user:alice", "user:bob", "user:charlie"),
        )

    def test_appends_first_witness(self) -> None:
        contract = self._fresh_contract()
        updated = add_witness_signature(
            contract,
            principal="user:alice",
            signature="sig-alice-base64url",
            signed_at=1716200100,
        )
        assert len(updated.witnesses) == 1
        assert updated.witnesses[0].principal == "user:alice"
        assert updated.witnesses[0].signature == "sig-alice-base64url"
        assert updated.witnesses[0].signed_at == 1716200100
        # Original contract unchanged (dataclass frozen + returns new)
        assert len(contract.witnesses) == 0

    def test_chains_through_all_required_witnesses(self) -> None:
        contract = self._fresh_contract()
        contract = add_witness_signature(
            contract, principal="user:alice", signature="sa", signed_at=100
        )
        contract = add_witness_signature(
            contract, principal="user:bob", signature="sb", signed_at=200
        )
        contract = add_witness_signature(
            contract, principal="user:charlie", signature="sc", signed_at=300
        )
        assert len(contract.witnesses) == 3
        assert contract.completed_at == 300
        assert contract.is_complete()

    def test_rejects_out_of_order_witness(self) -> None:
        contract = self._fresh_contract()
        # Try to sign as bob before alice has signed
        with pytest.raises(ValueError, match="next required witness is 'user:alice'"):
            add_witness_signature(
                contract,
                principal="user:bob",
                signature="sb",
                signed_at=100,
            )

    def test_rejects_unknown_principal(self) -> None:
        contract = self._fresh_contract()
        with pytest.raises(ValueError, match="next required witness"):
            add_witness_signature(
                contract,
                principal="user:eve",  # Not in required_witnesses
                signature="se",
                signed_at=100,
            )

    def test_rejects_extra_witness_beyond_required(self) -> None:
        contract = self._fresh_contract()
        # Sign all three required witnesses
        contract = add_witness_signature(
            contract, principal="user:alice", signature="sa", signed_at=100
        )
        contract = add_witness_signature(
            contract, principal="user:bob", signature="sb", signed_at=200
        )
        contract = add_witness_signature(
            contract, principal="user:charlie", signature="sc", signed_at=300
        )
        # Fourth witness should be rejected
        with pytest.raises(ValueError, match="no slot for additional witnesses"):
            add_witness_signature(
                contract,
                principal="user:dave",
                signature="sd",
                signed_at=400,
            )

    def test_rejects_zero_or_negative_signed_at(self) -> None:
        contract = self._fresh_contract()
        with pytest.raises(ValueError, match="signed_at"):
            add_witness_signature(
                contract,
                principal="user:alice",
                signature="sa",
                signed_at=0,
            )
        with pytest.raises(ValueError, match="signed_at"):
            add_witness_signature(
                contract,
                principal="user:alice",
                signature="sa",
                signed_at=-100,
            )

    def test_rejects_empty_signature(self) -> None:
        contract = self._fresh_contract()
        with pytest.raises(ValueError, match="signature must be non-empty"):
            add_witness_signature(
                contract,
                principal="user:alice",
                signature="",
                signed_at=100,
            )

    def test_completed_at_only_set_on_final_witness(self) -> None:
        contract = self._fresh_contract()
        contract = add_witness_signature(
            contract, principal="user:alice", signature="sa", signed_at=100
        )
        assert contract.completed_at is None
        contract = add_witness_signature(
            contract, principal="user:bob", signature="sb", signed_at=200
        )
        assert contract.completed_at is None
        contract = add_witness_signature(
            contract, principal="user:charlie", signature="sc", signed_at=300
        )
        assert contract.completed_at == 300


class TestCanonicalSigningInputForWitness:
    """Pin the witness signing-input reconstructor.

    Witness N signs the contract's canonical-JSON at the state they
    saw it (with witnesses[:N] but NOT their own). _qr_meta is
    stripped (transport metadata isn't signed). Verifiers reconstruct
    the same bytes for signature verification.
    """

    def test_strips_qr_meta_from_signing_input(self) -> None:
        contract = create_multi_witness_contract(
            iss="x",
            subject={"id": "test"},
            required_witnesses=("user:a",),
        )
        signing_bytes = canonical_signing_input_for_witness(contract)
        # _qr_meta should not appear in the signing input
        assert b"_qr_meta" not in signing_bytes

    def test_canonical_json_format(self) -> None:
        contract = create_multi_witness_contract(
            iss="x",
            subject={"id": "test"},
            required_witnesses=("user:a", "user:b"),
        )
        signing_bytes = canonical_signing_input_for_witness(contract)
        decoded = signing_bytes.decode("utf-8")
        # Sorted keys + no whitespace
        assert ": " not in decoded
        assert ", " not in decoded
        # Required fields present
        assert '"v":1' in decoded
        assert '"kind":"multi_witness_contract"' in decoded
        assert '"iss":"x"' in decoded

    def test_changes_after_each_witness_signs(self) -> None:
        """Each witness sees a different signing input — the chain grows."""
        contract = create_multi_witness_contract(
            iss="x",
            subject={},
            required_witnesses=("user:a", "user:b"),
        )
        # Witness A signs over the original-empty state
        signing_input_for_a = canonical_signing_input_for_witness(contract)

        # Append A
        contract = add_witness_signature(
            contract, principal="user:a", signature="sa", signed_at=100
        )
        # Witness B signs over the state including A's signature
        signing_input_for_b = canonical_signing_input_for_witness(contract)

        # They MUST differ — that's the whole point of chain-of-trust
        assert signing_input_for_a != signing_input_for_b
        # B's signing input includes A's signature
        assert b"user:a" in signing_input_for_b
        # A's signing input doesn't include any witnesses yet
        assert b'"witnesses":[]' in signing_input_for_a


class TestVerifierReconstructsSigningInput:
    """End-to-end test: verifier can recover witness N's signing input.

    Given a completed contract, a verifier should be able to
    reconstruct witness N's signing input by slicing witnesses[:N]
    and re-encoding.
    """

    def test_verifier_recovers_witness_a_signing_input(self) -> None:
        contract = create_multi_witness_contract(
            iss="phone:operator:enclave",
            subject={"thing": "contracted-on"},
            required_witnesses=("user:a", "user:b"),
        )

        # Capture what witness A signed over BEFORE appending A
        signing_input_when_a_signed = canonical_signing_input_for_witness(contract)

        # Both witnesses sign
        contract = add_witness_signature(
            contract, principal="user:a", signature="sa-sig", signed_at=100
        )
        contract = add_witness_signature(
            contract, principal="user:b", signature="sb-sig", signed_at=200
        )

        # Now verifier has the completed contract. Reconstruct A's signing input
        # by reverting to the state-A-saw-it (witnesses sliced to []).
        verifier_view = MultiWitnessContract(
            v=contract.v,
            kind=contract.kind,
            iss=contract.iss,
            subject=contract.subject,
            required_witnesses=contract.required_witnesses,
            witnesses=contract.witnesses[:0],  # A saw 0 prior witnesses
            completed_at=None,  # Not yet completed at A's signing time
            _qr_meta=contract._qr_meta,
        )
        reconstructed = canonical_signing_input_for_witness(verifier_view)

        # Verifier's reconstruction MUST match what A signed
        assert reconstructed == signing_input_when_a_signed

    def test_verifier_recovers_witness_b_signing_input(self) -> None:
        contract = create_multi_witness_contract(
            iss="phone:operator:enclave",
            subject={"thing": "contracted-on"},
            required_witnesses=("user:a", "user:b"),
        )

        # A signs first
        contract = add_witness_signature(
            contract, principal="user:a", signature="sa-sig", signed_at=100
        )
        # Capture what B signs over (with A already in witnesses)
        signing_input_when_b_signed = canonical_signing_input_for_witness(contract)
        # B signs
        contract = add_witness_signature(
            contract, principal="user:b", signature="sb-sig", signed_at=200
        )

        # Verifier reconstructs B's signing input: contract state with
        # witnesses[:1] (just A) and completed_at=None
        verifier_view = MultiWitnessContract(
            v=contract.v,
            kind=contract.kind,
            iss=contract.iss,
            subject=contract.subject,
            required_witnesses=contract.required_witnesses,
            witnesses=contract.witnesses[:1],
            completed_at=None,
            _qr_meta=contract._qr_meta,
        )
        reconstructed = canonical_signing_input_for_witness(verifier_view)
        assert reconstructed == signing_input_when_b_signed


# ---------------------------------------------------------------------
# qrcode-dependent test (gated behind recto[qr] extra)
# ---------------------------------------------------------------------


qrcode = pytest.importorskip("qrcode", reason="install via `pip install recto[qr]`")


class TestEncodeMultiWitnessQr:
    """Pin the QR-render path for multi-witness contracts."""

    def test_encodes_partial_contract(self) -> None:
        """Partial-signed contracts render fine (passed between witnesses)."""
        contract = create_multi_witness_contract(
            iss="x",
            subject={"id": "test"},
            required_witnesses=("user:a", "user:b"),
        )
        contract = add_witness_signature(
            contract, principal="user:a", signature="sig-a", signed_at=100
        )
        png_bytes = encode_multi_witness_qr(contract)
        assert png_bytes[:8] == b"\x89PNG\r\n\x1a\n"

    def test_encodes_completed_contract(self) -> None:
        contract = create_multi_witness_contract(
            iss="x",
            subject={"id": "test"},
            required_witnesses=("user:a", "user:b"),
        )
        contract = add_witness_signature(
            contract, principal="user:a", signature="sig-a", signed_at=100
        )
        contract = add_witness_signature(
            contract, principal="user:b", signature="sig-b", signed_at=200
        )
        assert contract.is_complete()
        png_bytes = encode_multi_witness_qr(contract)
        assert png_bytes[:8] == b"\x89PNG\r\n\x1a\n"

    def test_svg_output(self) -> None:
        contract = create_multi_witness_contract(
            iss="x", subject={}, required_witnesses=("user:a",)
        )
        svg_bytes = encode_multi_witness_qr(contract, image_format="svg")
        assert b"<svg" in svg_bytes[:200] or b"<?xml" in svg_bytes[:200]
