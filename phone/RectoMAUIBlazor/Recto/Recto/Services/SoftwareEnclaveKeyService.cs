// DEV-HOST ONLY. Compile-time excluded from every device target: the
// #if guard below means this class DOES NOT EXIST in iOS or Android
// binaries (2026-08-05 hardening — previously it shipped in the iOS IPA
// behind a runtime DeviceType.Virtual check; runtime gates on software
// key material are not an acceptable substitute for the code being
// absent). Store builds contain only the hardware-enclave services.
#if !IOS && !ANDROID
using System;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Recto.Shared.Common;
using Recto.Shared.Models;
using Recto.Shared.Protocol.V04;
using Recto.Shared.Services;

namespace Recto.Services;

/// <summary>
/// Software-backed Ed25519 key service. Uses BouncyCastle for keypair
/// generation + signing, persisted via <see cref="ResilientStorage"/> as
/// base64 strings under <c>{alias}.privkey</c> + <c>{alias}.pubkey</c>.
/// <para>
/// This is the Windows-dev / Mac Catalyst-dev loop backing ONLY — dev
/// hosts have no enclave hardware, and dev-host builds never ship to a
/// storefront. Real iOS uses <c>IosSecureEnclaveKeyService</c> (P-256 +
/// Secure Enclave); real Android uses <c>AndroidStrongBoxKeyService</c>
/// (Ed25519 + StrongBox). DO NOT USE IN PRODUCTION.
/// </para>
/// </summary>
public sealed class SoftwareEnclaveKeyService : IEnclaveKeyService
{
    private const string PrivateKeySuffix = ".privkey";
    private const string PublicKeySuffix = ".pubkey";

    public string Algorithm => V04Protocol.AlgorithmEd25519;

    public async Task<Result<EnclavePublicKey>> GenerateAsync(string keyAlias, CancellationToken ct)
    {
        try
        {
            var random = new SecureRandom();
            var privateParams = new Ed25519PrivateKeyParameters(random);
            var publicParams = privateParams.GeneratePublicKey();

            var publicKey = publicParams.GetEncoded();
            var privateKey = privateParams.GetEncoded();

            await ResilientStorage.SetAsync(keyAlias + PrivateKeySuffix, Convert.ToBase64String(privateKey)).ConfigureAwait(false);
            await ResilientStorage.SetAsync(keyAlias + PublicKeySuffix, Convert.ToBase64String(publicKey)).ConfigureAwait(false);

            return Result.Success(new EnclavePublicKey(publicKey, Algorithm));
        }
        catch (Exception ex)
        {
            return Result.Failure<EnclavePublicKey>(Error.Failure($"Failed to generate Ed25519 keypair: {ex.Message}"));
        }
    }

    public async Task<Result<bool>> KeyExistsAsync(string keyAlias, CancellationToken ct)
    {
        try
        {
            var stored = await ResilientStorage.GetAsync(keyAlias + PublicKeySuffix).ConfigureAwait(false);
            return Result.Success(!string.IsNullOrEmpty(stored));
        }
        catch (Exception ex)
        {
            return Result.Failure<bool>(Error.Failure($"Failed to check key existence: {ex.Message}"));
        }
    }

    public async Task<Result<EnclavePublicKey>> GetPublicKeyAsync(string keyAlias, CancellationToken ct)
    {
        try
        {
            var stored = await ResilientStorage.GetAsync(keyAlias + PublicKeySuffix).ConfigureAwait(false);
            if (string.IsNullOrEmpty(stored))
            {
                return Result.Failure<EnclavePublicKey>(Error.NotFound($"No public key found for alias '{keyAlias}'."));
            }

            return Result.Success(new EnclavePublicKey(Convert.FromBase64String(stored), Algorithm));
        }
        catch (Exception ex)
        {
            return Result.Failure<EnclavePublicKey>(Error.Failure($"Failed to read public key: {ex.Message}"));
        }
    }

    public async Task<Result<byte[]>> SignAsync(string keyAlias, byte[] message, CancellationToken ct)
    {
        try
        {
            var privBase64 = await ResilientStorage.GetAsync(keyAlias + PrivateKeySuffix).ConfigureAwait(false);
            if (string.IsNullOrEmpty(privBase64))
            {
                return Result.Failure<byte[]>(Error.NotFound($"No private key found for alias '{keyAlias}'."));
            }

            var privateKey = Convert.FromBase64String(privBase64);
            var privateParams = new Ed25519PrivateKeyParameters(privateKey, 0);

            var signer = new Ed25519Signer();
            signer.Init(forSigning: true, privateParams);
            signer.BlockUpdate(message, 0, message.Length);
            var signature = signer.GenerateSignature();

            return Result.Success(signature);
        }
        catch (Exception ex)
        {
            return Result.Failure<byte[]>(Error.Failure($"Failed to sign: {ex.Message}"));
        }
    }

    public Task<Result> DeleteAsync(string keyAlias, CancellationToken ct)
    {
        try
        {
            ResilientStorage.Remove(keyAlias + PrivateKeySuffix);
            ResilientStorage.Remove(keyAlias + PublicKeySuffix);
            return Task.FromResult(Result.Success());
        }
        catch (Exception ex)
        {
            return Task.FromResult(Result.Failure(Error.Failure($"Failed to delete key: {ex.Message}")));
        }
    }
}
#endif
