using System;
using System.Collections.Generic;
using System.Linq;

namespace Recto.Shared.QR;

/// <summary>
/// Multi-witness contract operations. Mirror of
/// <c>recto/qr/multi_witness.py</c> in C# — same shape, same
/// semantics, same sign-order enforcement.
/// <para>
/// A multi-witness contract grows as witnesses sign. The originator
/// creates a base claim with a <see cref="MultiWitnessContract.RequiredWitnesses"/>
/// list; each required witness signs the contract's state at the time
/// they receive it (with prior witnesses already attached) and the
/// QR re-renders with their signature appended. The final QR (after
/// all required witnesses have signed) IS the canonical contract
/// document.
/// </para>
/// <para>
/// All operations return NEW contract instances (records are
/// immutable). Verifiers reconstruct each witness's signing input by
/// taking the completed contract and slicing
/// <c>witnesses[..N]</c> + setting <c>completedAt=null</c> + stripping
/// <c>_qr_meta</c>, then re-encoding via
/// <see cref="QrCanonicalJson.CanonicalSigningInput"/>.
/// </para>
/// <para>
/// Cross-references: Recto Hard Rule #13 (artifact-as-canonical-record);
/// A consumer commitment on portable signed artifacts; Recto/CLAUDE.md
/// "QR-as-visual-transport" multi-witness contract extension schema.
/// </para>
/// </summary>
public static class QrMultiWitness
{
    /// <summary>
    /// Build a fresh multi-witness contract with no witnesses signed
    /// yet. The originator calls this to seed the contract; subsequent
    /// witnesses extend it via <see cref="AddWitnessSignature"/>.
    /// </summary>
    /// <param name="iss">Originator principal identifier.</param>
    /// <param name="subject">The thing being contracted on.</param>
    /// <param name="requiredWitnesses">Ordered list of principals who
    ///     must sign in order. Order matters — the next witness must
    ///     match <c>requiredWitnesses[witnesses.Count]</c>.</param>
    /// <param name="qrMeta">Optional transport metadata override.
    ///     Defaults to <see cref="QRMeta.Default"/> (PNG, v40-L
    ///     capacity, no fragmentation).</param>
    public static MultiWitnessContract CreateContract(
        string iss,
        IReadOnlyDictionary<string, object?> subject,
        IReadOnlyList<string> requiredWitnesses,
        QRMeta? qrMeta = null)
    {
        if (string.IsNullOrEmpty(iss))
        {
            throw new ArgumentException(
                "iss must be a non-empty principal identifier", nameof(iss));
        }
        if (subject == null) throw new ArgumentNullException(nameof(subject));
        if (requiredWitnesses == null)
        {
            throw new ArgumentNullException(nameof(requiredWitnesses));
        }
        if (requiredWitnesses.Count == 0)
        {
            throw new ArgumentException(
                "requiredWitnesses must contain at least one principal; " +
                "for single-signer artifacts use QRPayloadV1 instead",
                nameof(requiredWitnesses));
        }

        return new MultiWitnessContract(
            V: QRSchema.Version,
            Kind: "multi_witness_contract",
            Iss: iss,
            Subject: subject,
            RequiredWitnesses: requiredWitnesses.ToList(),
            Witnesses: new List<Witness>(),
            CompletedAt: null,
            QrMeta: qrMeta ?? QRMeta.Default());
    }

    /// <summary>
    /// Append a witness signature to a multi-witness contract.
    /// Returns a NEW contract instance (records are immutable).
    /// <para>
    /// Validates that:
    /// <list type="bullet">
    /// <item>The principal matches
    ///     <c>requiredWitnesses[witnesses.Count]</c> (sign order is
    ///     enforced)</item>
    /// <item>The principal isn't already in
    ///     <c>witnesses</c> (defends against accidental re-signing)</item>
    /// <item><paramref name="signedAt"/> is positive (sanity check)</item>
    /// </list>
    /// </para>
    /// <para>
    /// The signature itself is NOT verified here — that's the
    /// consumer's job after reconstructing the canonical-JSON
    /// signing input via
    /// <see cref="CanonicalSigningInputForWitness"/>.
    /// </para>
    /// </summary>
    public static MultiWitnessContract AddWitnessSignature(
        MultiWitnessContract contract,
        string principal,
        string signature,
        long signedAt)
    {
        if (contract == null) throw new ArgumentNullException(nameof(contract));
        if (signedAt <= 0)
        {
            throw new ArgumentException(
                $"signedAt must be positive; got {signedAt}", nameof(signedAt));
        }
        if (string.IsNullOrEmpty(signature))
        {
            throw new ArgumentException(
                "signature must be non-empty", nameof(signature));
        }

        var nextIndex = contract.Witnesses.Count;
        if (nextIndex >= contract.RequiredWitnesses.Count)
        {
            throw new InvalidOperationException(
                $"contract already has {contract.Witnesses.Count} witnesses; " +
                $"requiredWitnesses has {contract.RequiredWitnesses.Count}; " +
                $"no slot for additional witnesses");
        }

        var expectedPrincipal = contract.RequiredWitnesses[nextIndex];
        if (principal != expectedPrincipal)
        {
            throw new InvalidOperationException(
                $"next required witness is '{expectedPrincipal}'; " +
                $"got '{principal}' (sign order is enforced)");
        }

        // Defend against accidental re-signing (corner case: duplicates
        // in requiredWitnesses). The order check above catches the
        // canonical case (sign-out-of-order); this catches the rare
        // duplicate.
        foreach (var prior in contract.Witnesses)
        {
            if (prior.Principal == principal)
            {
                throw new InvalidOperationException(
                    $"witness '{principal}' has already signed at " +
                    $"signedAt={prior.SignedAt}");
            }
        }

        var newWitness = new Witness(principal, signature, signedAt);
        var newWitnesses = contract.Witnesses.ToList();
        newWitnesses.Add(newWitness);

        long? newCompletedAt;
        if (newWitnesses.Count == contract.RequiredWitnesses.Count)
        {
            newCompletedAt = signedAt;
        }
        else
        {
            newCompletedAt = contract.CompletedAt;
        }

        return contract with
        {
            Witnesses = newWitnesses,
            CompletedAt = newCompletedAt,
        };
    }

    /// <summary>
    /// Compute the canonical-JSON bytes the next-required witness
    /// signs over. A witness sees the contract at a particular state
    /// (with prior witnesses already signed) and signs over the
    /// contract's canonical-JSON encoding AT THAT STATE — WITHOUT
    /// their own signature appended yet.
    /// <para>
    /// Pass the contract BEFORE calling
    /// <see cref="AddWitnessSignature"/>, sign the returned bytes,
    /// then call <see cref="AddWitnessSignature"/> with the resulting
    /// signature.
    /// </para>
    /// <para>
    /// The <c>_qr_meta</c> field is stripped (consistent with
    /// <see cref="QrCanonicalJson.CanonicalSigningInput"/> — transport
    /// metadata is never signed). Sister of Python's
    /// <c>recto.qr.multi_witness.canonical_signing_input_for_witness</c>.
    /// </para>
    /// </summary>
    public static byte[] CanonicalSigningInputForWitness(
        MultiWitnessContract contract)
    {
        if (contract == null) throw new ArgumentNullException(nameof(contract));
        var dict = QrCanonicalJson.MultiWitnessContractToDict(contract);
        return QrCanonicalJson.CanonicalSigningInput(dict);
    }
}
