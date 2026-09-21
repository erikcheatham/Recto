using System.Threading;
using System.Threading.Tasks;
using Recto.Shared.Common;
using Recto.Shared.Models;

namespace Recto.Shared.Services;

/// <summary>
/// Phone-side keypair management. The implementation backs onto the
/// platform's hardware enclave where possible:
/// <list type="bullet">
/// <item>iOS: Secure Enclave via <c>SecKey</c> with
/// <c>kSecAttrTokenIDSecureEnclave</c> + biometric ACL. P-256 only
/// (Ed25519 not natively supported by Secure Enclave as of iOS 18).</item>
/// <item>Android: StrongBox via <c>KeyPairGenerator</c> with
/// <c>setIsStrongBoxBacked(true)</c> + <c>setUserAuthenticationRequired(true)</c>.
/// Ed25519, API 31+.</item>
/// <item>Windows / Mac Catalyst dev: software-backed Ed25519 via BouncyCastle,
/// persisted in MAUI <c>SecureStorage</c>. No biometric gate.</item>
/// </list>
/// </summary>
public interface IEnclaveKeyService
{
    /// <summary>
    /// The signature algorithm this implementation produces. One of
    /// <see cref="Protocol.V04.V04Protocol.AlgorithmEd25519"/> or
    /// <see cref="Protocol.V04.V04Protocol.AlgorithmEcdsaP256"/>. Phone
    /// advertises this in its registration request's
    /// <c>supported_algorithms</c> field.
    /// </summary>
    string Algorithm { get; }

    /// <summary>Generates a new keypair under <paramref name="keyAlias"/>. Overwrites any existing.</summary>
    Task<Result<EnclavePublicKey>> GenerateAsync(string keyAlias, CancellationToken ct);

    /// <summary>
    /// Generates a DEVICE key under <paramref name="keyAlias"/>: enclave-resident
    /// where the platform has one, but with NO user-authentication ACL, so
    /// <see cref="SignAsync"/> on it never prompts. This is the poll key of hard
    /// rule 14.2 (ruling A, 2026-09-21): it authenticates the device on the
    /// phone's reads (poll, pending, manage) and is delegated once, at pairing,
    /// by an identity-key signature. It must never sign an approval. The
    /// default falls back to <see cref="GenerateAsync"/> for implementations
    /// that have no ACL to drop (software-backed dev paths, test fakes).
    /// </summary>
    Task<Result<EnclavePublicKey>> GenerateDeviceKeyAsync(string keyAlias, CancellationToken ct)
        => GenerateAsync(keyAlias, ct);

    /// <summary>True if a keypair already exists under <paramref name="keyAlias"/>.</summary>
    Task<Result<bool>> KeyExistsAsync(string keyAlias, CancellationToken ct);

    /// <summary>Returns the public key for an existing alias, in the algorithm's wire encoding.</summary>
    Task<Result<EnclavePublicKey>> GetPublicKeyAsync(string keyAlias, CancellationToken ct);

    /// <summary>
    /// Signs <paramref name="message"/> with the private key under
    /// <paramref name="keyAlias"/>. Returns the raw 64-byte signature in the
    /// algorithm's wire encoding (Ed25519: 64-byte raw; ECDSA P-256: 64-byte
    /// raw R || S, big-endian, NOT DER). Triggers a biometric prompt on
    /// platforms that gate enclave operations behind one.
    /// </summary>
    Task<Result<byte[]>> SignAsync(string keyAlias, byte[] message, CancellationToken ct);

    /// <summary>Removes the keypair under <paramref name="keyAlias"/>. No-op if absent.</summary>
    Task<Result> DeleteAsync(string keyAlias, CancellationToken ct);
}
