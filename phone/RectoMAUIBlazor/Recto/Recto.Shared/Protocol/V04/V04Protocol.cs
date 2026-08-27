namespace Recto.Shared.Protocol.V04;

/// <summary>
/// Constants from the Recto v0.4 wire-protocol RFC. See `docs/v0.4-protocol.md`.
/// </summary>
public static class V04Protocol
{
    /// <summary>Wire-protocol version negotiated during pairing. Bump on breaking changes.</summary>
    public const int Version = 1;

    /// <summary>
    /// Ed25519 signature scheme (RFC 8032). Public keys 32 bytes; signatures
    /// 64 bytes raw. Default for Android (StrongBox) and Windows-dev hosts.
    /// </summary>
    public const string AlgorithmEd25519 = "ed25519";

    /// <summary>
    /// ECDSA P-256 signature scheme (FIPS 186-4 + RFC 6979). Public keys 64
    /// bytes (X || Y, big-endian, raw &mdash; no 0x04 prefix, no DER);
    /// signatures 64 bytes (R || S, big-endian, raw &mdash; no DER). Phone
    /// SHA-256-hashes the message before signing. Default for iOS Secure
    /// Enclave (which natively supports P-256, not Ed25519, as of iOS 18).
    /// </summary>
    public const string AlgorithmEcdsaP256 = "ecdsa-p256";
}
