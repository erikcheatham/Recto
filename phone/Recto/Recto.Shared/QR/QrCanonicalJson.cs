using System;
using System.Collections.Generic;
using Recto.Shared.Capability;

namespace Recto.Shared.QR;

/// <summary>
/// Canonical-JSON helpers for QR-encoded signed payloads. Mirror of
/// the <c>_canonical_json</c> + <c>_strip_qr_meta</c> +
/// <c>canonical_signing_input</c> functions in <c>recto/qr/encode.py</c>.
/// <para>
/// The underlying encoder is <see cref="Recto.Shared.Capability.CanonicalJson"/>
/// which already produces byte-identical output to Python's
/// <c>json.dumps(obj, sort_keys=True, separators=(",",":"), ensure_ascii=True)</c>.
/// This module wraps it with the QR-specific <c>_qr_meta</c>-strip
/// behavior so a signed QR payload's signing input is reproducible
/// across runtimes regardless of which transport the payload travels
/// through (HTTP, QR, folder-drop event bus).
/// </para>
/// </summary>
public static class QrCanonicalJson
{
    /// <summary>
    /// Returns a copy of <paramref name="payload"/> with the
    /// <c>_qr_meta</c> key removed. Sister of Python's
    /// <c>_strip_qr_meta</c>.
    /// </summary>
    public static IReadOnlyDictionary<string, object?> StripQrMeta(
        IReadOnlyDictionary<string, object?> payload)
    {
        if (payload == null) throw new ArgumentNullException(nameof(payload));
        var stripped = new Dictionary<string, object?>(payload.Count);
        foreach (var kvp in payload)
        {
            if (kvp.Key == "_qr_meta") continue;
            stripped[kvp.Key] = kvp.Value;
        }
        return stripped;
    }

    /// <summary>
    /// Compute the canonical signing input for a QR-encoded payload.
    /// Strips the <c>_qr_meta</c> transport metadata (which is NOT
    /// signed) and returns the canonical-JSON-encoded bytes of the
    /// remaining fields.
    /// <para>
    /// Cross-references: Python's
    /// <c>recto.qr.encode.canonical_signing_input</c> produces
    /// byte-identical output for the same input dict. Sister of
    /// <see cref="Recto.Shared.Capability.CanonicalJson.Encode"/> which
    /// is used for capability JWS signing inputs; both paths produce
    /// byte-identical canonical-JSON for the same payload dict, so a
    /// capability JWS and its QR-wrapped counterpart sign over
    /// equivalent bytes.
    /// </para>
    /// </summary>
    public static byte[] CanonicalSigningInput(
        IReadOnlyDictionary<string, object?> payload)
    {
        if (payload == null) throw new ArgumentNullException(nameof(payload));
        var stripped = StripQrMeta(payload);
        return CanonicalJson.Encode(stripped);
    }

    /// <summary>
    /// Convert a <see cref="QRMeta"/> record to the dict shape that
    /// <see cref="CanonicalJson"/> expects for encoding. Mirrors the
    /// shape Python emits when serializing the QRMeta dataclass.
    /// </summary>
    public static IReadOnlyDictionary<string, object?> QrMetaToDict(QRMeta meta)
    {
        if (meta == null) throw new ArgumentNullException(nameof(meta));
        var dict = new Dictionary<string, object?>
        {
            ["format"] = meta.Format,
            ["max_size_bytes"] = (long)meta.MaxSizeBytes,
        };
        if (meta.Fragmentation != null)
        {
            var fragDict = new Dictionary<string, object?>();
            foreach (var kvp in meta.Fragmentation)
            {
                fragDict[kvp.Key] = (long)kvp.Value;
            }
            dict["fragmentation"] = fragDict;
        }
        else
        {
            dict["fragmentation"] = null;
        }
        return dict;
    }

    /// <summary>
    /// Convert a <see cref="QRPayloadV1"/> record to the dict shape
    /// that <see cref="CanonicalJson"/> expects for encoding. Mirrors
    /// the Python QRPayloadV1 → dict conversion in
    /// <c>recto.qr.encode.qr_encode_payload</c>.
    /// </summary>
    public static IReadOnlyDictionary<string, object?> QrPayloadV1ToDict(
        QRPayloadV1 payload)
    {
        if (payload == null) throw new ArgumentNullException(nameof(payload));
        var aud = new List<object?>();
        foreach (var a in payload.Aud) aud.Add(a);
        return new Dictionary<string, object?>
        {
            ["v"] = (long)payload.V,
            ["kind"] = payload.Kind,
            ["iss"] = payload.Iss,
            ["aud"] = aud,
            ["iat"] = payload.Iat,
            ["exp"] = payload.Exp,
            ["jti"] = payload.Jti,
            ["body"] = payload.Body,
            ["_qr_meta"] = QrMetaToDict(payload.QrMeta),
        };
    }

    /// <summary>
    /// Convert a <see cref="MultiWitnessContract"/> record to the
    /// dict shape that <see cref="CanonicalJson"/> expects. Mirrors
    /// the Python MultiWitnessContract → dict conversion in
    /// <c>recto.qr.multi_witness.encode_multi_witness_qr</c>.
    /// </summary>
    public static IReadOnlyDictionary<string, object?> MultiWitnessContractToDict(
        MultiWitnessContract contract)
    {
        if (contract == null) throw new ArgumentNullException(nameof(contract));
        var requiredList = new List<object?>();
        foreach (var w in contract.RequiredWitnesses) requiredList.Add(w);

        var witnessesList = new List<object?>();
        foreach (var w in contract.Witnesses)
        {
            witnessesList.Add(new Dictionary<string, object?>
            {
                ["principal"] = w.Principal,
                ["signature"] = w.Signature,
                ["signed_at"] = w.SignedAt,
            });
        }

        return new Dictionary<string, object?>
        {
            ["v"] = (long)contract.V,
            ["kind"] = contract.Kind,
            ["iss"] = contract.Iss,
            ["subject"] = contract.Subject,
            ["required_witnesses"] = requiredList,
            ["witnesses"] = witnessesList,
            ["completed_at"] = contract.CompletedAt,
            ["_qr_meta"] = QrMetaToDict(contract.QrMeta),
        };
    }
}
