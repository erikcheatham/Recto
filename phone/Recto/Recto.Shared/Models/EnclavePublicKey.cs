namespace Recto.Shared.Models;

/// <summary>
/// The public-key half of a phone-side enclave keypair, plus the algorithm
/// the phone uses for signing. Private bytes are deliberately absent &mdash;
/// for hardware-backed keys (iOS Secure Enclave, Android StrongBox) the
/// private key never leaves the device. The service implementation tracks
/// the platform key reference internally via the alias the consumer passes
/// to <see cref="Services.IEnclaveKeyService"/>.
/// </summary>
/// <param name="PublicKey">
/// Raw public-key bytes per the v0.4 protocol RFC's per-algorithm encoding:
/// 32 bytes for <c>ed25519</c>; 64 bytes (X || Y, big-endian) for
/// <c>ecdsa-p256</c>.
/// </param>
/// <param name="Algorithm">
/// One of the <c>Recto.Shared.Protocol.V04.V04Protocol.Algorithm*</c>
/// constants. The bootloader uses this to pick the verification path.
/// </param>
public sealed record EnclavePublicKey(byte[] PublicKey, string Algorithm);
