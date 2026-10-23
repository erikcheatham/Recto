using System;
using System.Collections.Generic;
using System.Text;
using Recto.Shared.QR;
using Xunit;

namespace Recto.Shared.Tests.QR;

/// <summary>
/// Pins the C# multi-witness contract operations against the
/// Python <c>recto.qr.multi_witness</c> module. Each test below has a
/// sister test in <c>tests/test_qr_multi_witness.py</c> — same
/// inputs, same expected behavior.
/// </summary>
public class QrMultiWitnessTests
{
    private static MultiWitnessContract FreshContract() =>
        QrMultiWitness.CreateContract(
            iss: "phone:operator:enclave",
            subject: new Dictionary<string, object?> { ["contract_type"] = "test" },
            requiredWitnesses: new List<string>
            {
                "user:alice", "user:bob", "user:charlie",
            });

    // -----------------------------------------------------------------
    // CreateContract
    // -----------------------------------------------------------------

    [Fact]
    public void CreateContract_BuildsEmpty()
    {
        var contract = QrMultiWitness.CreateContract(
            iss: "phone:operator:enclave",
            subject: new Dictionary<string, object?> { ["citation_id"] = "cite-123" },
            requiredWitnesses: new List<string> { "user:alice", "user:bob" });
        Assert.Equal("phone:operator:enclave", contract.Iss);
        Assert.Equal(2, contract.RequiredWitnesses.Count);
        Assert.Empty(contract.Witnesses);
        Assert.Null(contract.CompletedAt);
        Assert.Equal("multi_witness_contract", contract.Kind);
        Assert.Equal(1, contract.V);
        Assert.False(contract.IsComplete());
    }

    [Fact]
    public void CreateContract_RejectsEmptyIss()
    {
        Assert.Throws<ArgumentException>(() => QrMultiWitness.CreateContract(
            iss: "",
            subject: new Dictionary<string, object?>(),
            requiredWitnesses: new List<string> { "user:a" }));
    }

    [Fact]
    public void CreateContract_RejectsEmptyRequiredWitnesses()
    {
        Assert.Throws<ArgumentException>(() => QrMultiWitness.CreateContract(
            iss: "x",
            subject: new Dictionary<string, object?>(),
            requiredWitnesses: new List<string>()));
    }

    [Fact]
    public void CreateContract_AcceptsCustomQrMeta()
    {
        var meta = new QRMeta(QRFormats.SvgV1, QRCapacities.V40H, null);
        var contract = QrMultiWitness.CreateContract(
            iss: "x",
            subject: new Dictionary<string, object?>(),
            requiredWitnesses: new List<string> { "user:a" },
            qrMeta: meta);
        Assert.Equal(QRFormats.SvgV1, contract.QrMeta.Format);
        Assert.Equal(QRCapacities.V40H, contract.QrMeta.MaxSizeBytes);
    }

    // -----------------------------------------------------------------
    // AddWitnessSignature
    // -----------------------------------------------------------------

    [Fact]
    public void AddWitnessSignature_AppendsFirstWitness()
    {
        var contract = FreshContract();
        var updated = QrMultiWitness.AddWitnessSignature(
            contract, "user:alice", "sig-alice", 1716200100);
        Assert.Single(updated.Witnesses);
        Assert.Equal("user:alice", updated.Witnesses[0].Principal);
        Assert.Equal("sig-alice", updated.Witnesses[0].Signature);
        Assert.Equal(1716200100, updated.Witnesses[0].SignedAt);
        // Original unchanged (records are immutable)
        Assert.Empty(contract.Witnesses);
    }

    [Fact]
    public void AddWitnessSignature_ChainsAllRequiredWitnesses()
    {
        var contract = FreshContract();
        contract = QrMultiWitness.AddWitnessSignature(contract, "user:alice", "sa", 100);
        contract = QrMultiWitness.AddWitnessSignature(contract, "user:bob", "sb", 200);
        contract = QrMultiWitness.AddWitnessSignature(contract, "user:charlie", "sc", 300);
        Assert.Equal(3, contract.Witnesses.Count);
        Assert.Equal(300, contract.CompletedAt);
        Assert.True(contract.IsComplete());
    }

    [Fact]
    public void AddWitnessSignature_RejectsOutOfOrderWitness()
    {
        var contract = FreshContract();
        // Try to sign as bob before alice has signed
        var ex = Assert.Throws<InvalidOperationException>(() =>
            QrMultiWitness.AddWitnessSignature(contract, "user:bob", "sb", 100));
        Assert.Contains("next required witness is 'user:alice'", ex.Message);
    }

    [Fact]
    public void AddWitnessSignature_RejectsUnknownPrincipal()
    {
        var contract = FreshContract();
        var ex = Assert.Throws<InvalidOperationException>(() =>
            QrMultiWitness.AddWitnessSignature(contract, "user:eve", "se", 100));
        Assert.Contains("next required witness", ex.Message);
    }

    [Fact]
    public void AddWitnessSignature_RejectsExtraBeyondRequired()
    {
        var contract = FreshContract();
        contract = QrMultiWitness.AddWitnessSignature(contract, "user:alice", "sa", 100);
        contract = QrMultiWitness.AddWitnessSignature(contract, "user:bob", "sb", 200);
        contract = QrMultiWitness.AddWitnessSignature(contract, "user:charlie", "sc", 300);
        var ex = Assert.Throws<InvalidOperationException>(() =>
            QrMultiWitness.AddWitnessSignature(contract, "user:dave", "sd", 400));
        Assert.Contains("no slot for additional witnesses", ex.Message);
    }

    [Fact]
    public void AddWitnessSignature_RejectsZeroOrNegativeSignedAt()
    {
        var contract = FreshContract();
        Assert.Throws<ArgumentException>(() =>
            QrMultiWitness.AddWitnessSignature(contract, "user:alice", "sa", 0));
        Assert.Throws<ArgumentException>(() =>
            QrMultiWitness.AddWitnessSignature(contract, "user:alice", "sa", -100));
    }

    [Fact]
    public void AddWitnessSignature_RejectsEmptySignature()
    {
        var contract = FreshContract();
        Assert.Throws<ArgumentException>(() =>
            QrMultiWitness.AddWitnessSignature(contract, "user:alice", "", 100));
    }

    [Fact]
    public void AddWitnessSignature_CompletedAtOnlySetOnFinalWitness()
    {
        var contract = FreshContract();
        contract = QrMultiWitness.AddWitnessSignature(contract, "user:alice", "sa", 100);
        Assert.Null(contract.CompletedAt);
        contract = QrMultiWitness.AddWitnessSignature(contract, "user:bob", "sb", 200);
        Assert.Null(contract.CompletedAt);
        contract = QrMultiWitness.AddWitnessSignature(contract, "user:charlie", "sc", 300);
        Assert.Equal(300, contract.CompletedAt);
    }

    // -----------------------------------------------------------------
    // CanonicalSigningInputForWitness
    // -----------------------------------------------------------------

    [Fact]
    public void CanonicalSigningInputForWitness_StripsQrMeta()
    {
        var contract = FreshContract();
        var bytes = QrMultiWitness.CanonicalSigningInputForWitness(contract);
        var decoded = Encoding.UTF8.GetString(bytes);
        Assert.DoesNotContain("_qr_meta", decoded);
    }

    [Fact]
    public void CanonicalSigningInputForWitness_CanonicalShape()
    {
        var contract = FreshContract();
        var bytes = QrMultiWitness.CanonicalSigningInputForWitness(contract);
        var decoded = Encoding.UTF8.GetString(bytes);
        // Sorted keys + no whitespace separators
        Assert.DoesNotContain(": ", decoded);
        Assert.DoesNotContain(", ", decoded);
        Assert.Contains("\"v\":1", decoded);
        Assert.Contains("\"kind\":\"multi_witness_contract\"", decoded);
    }

    [Fact]
    public void CanonicalSigningInputForWitness_ChangesAfterEachSignature()
    {
        // Each witness signs over a different state — the chain
        // grows after every signature.
        var contract = QrMultiWitness.CreateContract(
            iss: "x",
            subject: new Dictionary<string, object?>(),
            requiredWitnesses: new List<string> { "user:a", "user:b" });
        var inputForA = QrMultiWitness.CanonicalSigningInputForWitness(contract);

        contract = QrMultiWitness.AddWitnessSignature(contract, "user:a", "sa", 100);
        var inputForB = QrMultiWitness.CanonicalSigningInputForWitness(contract);

        Assert.NotEqual(inputForA, inputForB);
        // B's signing input includes A's signature
        var inputForBString = Encoding.UTF8.GetString(inputForB);
        Assert.Contains("user:a", inputForBString);
        // A's signing input has empty witnesses
        var inputForAString = Encoding.UTF8.GetString(inputForA);
        Assert.Contains("\"witnesses\":[]", inputForAString);
    }

    // -----------------------------------------------------------------
    // Cross-language byte-parity (Python ↔ C#)
    // -----------------------------------------------------------------

    [Fact]
    public void CrossLanguageByteParity_VerifierRecoversWitnessASigningInput()
    {
        // End-to-end test mirroring
        // test_verifier_recovers_witness_a_signing_input in Python.
        // Confirms a verifier with the completed contract can
        // reconstruct what witness A signed over by slicing
        // witnesses to [] and setting completedAt=null.
        var contract = QrMultiWitness.CreateContract(
            iss: "phone:operator:enclave",
            subject: new Dictionary<string, object?> { ["thing"] = "contracted-on" },
            requiredWitnesses: new List<string> { "user:a", "user:b" });

        // Capture what witness A signed over
        var signingInputWhenASigned =
            QrMultiWitness.CanonicalSigningInputForWitness(contract);

        // Both witnesses sign
        contract = QrMultiWitness.AddWitnessSignature(contract, "user:a", "sa-sig", 100);
        contract = QrMultiWitness.AddWitnessSignature(contract, "user:b", "sb-sig", 200);

        // Verifier reconstructs A's signing input
        var verifierView = contract with
        {
            Witnesses = new List<Witness>(),
            CompletedAt = null,
        };
        var reconstructed =
            QrMultiWitness.CanonicalSigningInputForWitness(verifierView);

        Assert.Equal(signingInputWhenASigned, reconstructed);
    }
}
