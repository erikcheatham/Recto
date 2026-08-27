using System.Collections.Generic;

namespace Recto.Shared.QR;

// ---------------------------------------------------------------------------
// QR wire-format mirror (Phase 1 substrate primitive — recto/qr/types.py)
// ---------------------------------------------------------------------------
//
// Mirror of recto.qr.types in Python. Same field names (snake_case
// preserved on the wire via canonical JSON), same shape, same semantics.
// Cross-language byte-parity is the contract — a QRPayloadV1 encoded
// on Python and decoded on C# (and vice versa) MUST produce identical
// canonical-JSON output to the bit.
//
// Hard rule #13 in play (artifact-as-canonical-record over ledger-as-
// canonical-record): every signed payload here is portable + verifiable
// + timeless without runtime dependency. The QR's bytes ARE the
// canonical record; the dataclass records here are just the in-memory
// view of those bytes.
//
// Cross-references: recto/qr/SPEC.md (canonical wire-format spec);
// Recto/CLAUDE.md "QR-as-visual-transport for capability JWS +
// signed-payload contracts" (architectural framework); Recto.Shared.
// Capability namespace (sister mirror pattern for capability JWS).

/// <summary>
/// Per-QR-spec v40 capacity ceiling at error-correction-level L
/// (the most permissive level). 2953 bytes is the max single-QR
/// payload at L; lower at M/Q/H. Multi-QR fragmentation reserved
/// for v2 via <see cref="QRMeta.Fragmentation"/>.
/// </summary>
public static class QRCapacities
{
    public const int V40L = 2953;
    public const int V40M = 2331;
    public const int V40Q = 1663;
    public const int V40H = 1273;
}

/// <summary>
/// Canonical format-string for the <see cref="QRMeta.Format"/> field.
/// Encodes the transport ("qr"), rendering output ("png" / "svg"),
/// and schema version ("v1"). Future v2 may add "qr-pngv2" for
/// higher-density encodings.
/// </summary>
public static class QRFormats
{
    public const string PngV1 = "qr-pngv1";
    public const string SvgV1 = "qr-svgv1";
}

/// <summary>
/// Schema version for v1 QRPayloadV1 / MultiWitnessContract. Bumped
/// only on breaking schema changes; additive field extensions stay
/// at v1. Future v2 would land as sibling QRPayloadV2 record + version
/// dispatch in encode/decode helpers.
/// </summary>
public static class QRSchema
{
    public const int Version = 1;
}

/// <summary>
/// Transport metadata for a QR-encoded signed payload. Describes how
/// the payload survives QR transport (format versioning, capacity
/// bookkeeping, fragmentation). NOT included in any signature scope
/// — the QR's signature wraps the payload body, not the meta
/// envelope.
/// <para>
/// Two consumers reading the same signed payload via different
/// transports (HTTP, QR, folder-drop event bus) derive byte-
/// identical signing inputs because <c>_qr_meta</c> is stripped
/// before signature computation. See
/// <see cref="QrCanonicalJson.CanonicalSigningInput"/>.
/// </para>
/// </summary>
public sealed record QRMeta(
    string Format,
    int MaxSizeBytes,
    IReadOnlyDictionary<string, int>? Fragmentation
)
{
    /// <summary>
    /// Default QRMeta — PNG output, v40-L capacity, no fragmentation.
    /// Sister of Python's <c>QRMeta()</c> dataclass with defaults.
    /// </summary>
    public static QRMeta Default() => new(QRFormats.PngV1, QRCapacities.V40L, null);
}

/// <summary>
/// Generic signed-payload envelope for single-signer QR artifacts.
/// Used for capability JWS, pairing JWS, manumission JWS, citation
/// receipts, THRU transaction receipts, and any future Recto-produced
/// signed payload that fits the single-signer model.
/// <para>
/// Body shape is kind-specific. For capability JWS, body is typically
/// <c>{"jws": "&lt;3-part JWS string&gt;"}</c>. For richer kinds
/// (citation receipts, promotion certificates), body carries the
/// kind's full structured payload.
/// </para>
/// </summary>
public sealed record QRPayloadV1(
    int V,
    string Kind,
    string Iss,
    IReadOnlyList<string> Aud,
    long Iat,
    long Exp,
    string Jti,
    IReadOnlyDictionary<string, object?> Body,
    QRMeta QrMeta
)
{
    /// <summary>
    /// Construct a QRPayloadV1 with the schema version + default
    /// QRMeta. Convenience for callers who don't need to override the
    /// schema-meta defaults.
    /// </summary>
    public static QRPayloadV1 Create(
        string kind,
        string iss,
        IReadOnlyList<string> aud,
        long iat,
        long exp,
        string jti,
        IReadOnlyDictionary<string, object?> body) =>
        new(
            V: QRSchema.Version,
            Kind: kind,
            Iss: iss,
            Aud: aud,
            Iat: iat,
            Exp: exp,
            Jti: jti,
            Body: body,
            QrMeta: QRMeta.Default()
        );
}

/// <summary>
/// One witness signature in a multi-witness contract. Each witness
/// signs the canonical-JSON encoding of the contract's state AT THE
/// TIME OF THEIR SIGNATURE (i.e. their entry is appended AFTER
/// signing). The QR re-renders after each witness signs; consumers
/// can verify the chain by replaying signatures in order.
/// </summary>
public sealed record Witness(
    string Principal,
    string Signature,
    long SignedAt
);

/// <summary>
/// Multi-signer contract that grows as witnesses sign. The originator
/// signs a base claim with a <see cref="RequiredWitnesses"/> list;
/// sends the QR around; each required witness adds their signature
/// before re-rendering. The final QR (after all required witnesses
/// have signed) IS the canonical contract document.
/// <para>
/// First concrete use cases: a consumer's first user-to-user citation
/// receipt (a consumer architectural commitment), a first civic-office promotion
/// certificate (chat-tier civic-office model), and a consumer-defined
/// manumission ceremony.
/// </para>
/// </summary>
public sealed record MultiWitnessContract(
    int V,
    string Kind,
    string Iss,
    IReadOnlyDictionary<string, object?> Subject,
    IReadOnlyList<string> RequiredWitnesses,
    IReadOnlyList<Witness> Witnesses,
    long? CompletedAt,
    QRMeta QrMeta
)
{
    /// <summary>True when all required_witnesses have signed.</summary>
    public bool IsComplete()
    {
        if (Witnesses.Count != RequiredWitnesses.Count) return false;
        for (int i = 0; i < RequiredWitnesses.Count; i++)
        {
            if (Witnesses[i].Principal != RequiredWitnesses[i]) return false;
        }
        return true;
    }
}
