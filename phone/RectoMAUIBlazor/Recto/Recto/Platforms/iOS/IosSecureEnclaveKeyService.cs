using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Foundation;
using ObjCRuntime;
using Recto.Shared.Common;
using Recto.Shared.Models;
using Recto.Shared.Protocol.V04;
using Recto.Shared.Services;
using Security;

namespace Recto.Platforms.iOSImpl;

/// <summary>
/// iOS Secure Enclave-backed key service. Generates a P-256 keypair inside
/// the Secure Enclave with a biometric-gated access control; the private key
/// is non-exportable and every sign requires Face ID / Touch ID.
/// <para>
/// Why P-256 and not Ed25519: as of iOS 18 the Secure Enclave only supports
/// <c>kSecAttrKeyTypeECSECPrimeRandom</c> (P-256). The v0.4 protocol's
/// <c>supported_algorithms</c> field lets the phone advertise
/// <c>ecdsa-p256</c> instead of Ed25519 (the default elsewhere).
/// </para>
/// <para>
/// Wire format: <c>SecKeyCreateSignature</c> returns ECDSA signatures in DER
/// form; we convert to raw R || S (64 bytes, big-endian) per the protocol
/// RFC. Public keys are returned by SecKey as the X9.63 65-byte form
/// (0x04 || X || Y); we strip the 0x04 prefix to get the 64-byte raw form.
/// </para>
/// <para>
/// Constants note: the .NET MAUI iOS binding marks <c>SecAttributeKey</c>,
/// <c>SecClass</c>, and <c>SecKeyGenerationAttributeKeys</c> as internal
/// (they're meant to be consumed indirectly via the typed <see cref="SecRecord"/>
/// class). For SecKey generation we need the raw <c>kSec*</c> constants, so we
/// load them directly from the Security framework binary via <c>Dlfcn</c>.
/// </para>
/// </summary>
public sealed class IosSecureEnclaveKeyService : IEnclaveKeyService
{
    public string Algorithm => V04Protocol.AlgorithmEcdsaP256;

    private static NSData TagFor(string keyAlias) =>
        NSData.FromString($"com.recto.phone.enclave.{keyAlias}", NSStringEncoding.UTF8)!;

    public Task<Result<EnclavePublicKey>> GenerateAsync(string keyAlias, CancellationToken ct)
    {
        try
        {
            // Idempotent: clear any prior key under this alias.
            DeleteInternal(keyAlias);

            // Biometric ACL: every private-key operation requires Face ID / Touch ID.
            // .biometryCurrentSet invalidates the key if the user enrolls a new biometric
            // (so a stolen + jailbroken phone can't auto-approve via attacker-enrolled biometrics).
            using var accessControl = new SecAccessControl(
                SecAccessible.WhenUnlockedThisDeviceOnly,
                SecAccessControlCreateFlags.BiometryCurrentSet | SecAccessControlCreateFlags.PrivateKeyUsage);

            // SecAccessControl derives from NativeObject (CFType-bridged), not
            // NSObject — the NSMutableDictionary indexer needs NSObject, so we
            // bridge via the shared handle. CFType <-> NSObject is toll-free,
            // so the wrapper holds the same underlying object.
            using var accessControlAsNSObject =
                Runtime.GetNSObject<NSObject>(accessControl.Handle)
                    ?? throw new InvalidOperationException("Could not bridge SecAccessControl to NSObject.");

            using var privateKeyAttrs = new NSMutableDictionary
            {
                [SecConstants.AttrIsPermanent] = NSNumber.FromBoolean(true),
                [SecConstants.AttrApplicationTag] = TagFor(keyAlias),
                [SecConstants.AttrAccessControl] = accessControlAsNSObject,
            };

            using var attrs = new NSMutableDictionary
            {
                [SecConstants.AttrKeyType] = SecConstants.AttrKeyTypeECSECPrimeRandom,
                [SecConstants.AttrKeySizeInBits] = NSNumber.FromInt32(256),
                [SecConstants.AttrTokenID] = SecConstants.AttrTokenIDSecureEnclave,
                [SecConstants.PrivateKeyAttrs] = privateKeyAttrs,
            };

            var privateKey = SecKey.CreateRandomKey(attrs, out var error);
            if (privateKey is null || error is not null)
            {
                // Surface the raw OSStatus (e.g. -25293 / errSecAuthFailed
                // when biometric isn't enrolled) verbatim here; the UI layer
                // runs it through EnclaveErrors.TranslateRectoEnclaveError,
                // which owns the actionable-copy mapping (single translation
                // point — do NOT pre-translate here or the helper loses the
                // "-25293" token it keys on).
                return Task.FromResult(Result.Failure<EnclavePublicKey>(
                    Error.Failure($"Secure Enclave keygen failed: {error?.LocalizedDescription ?? "unknown"}")));
            }

            using (privateKey)
            using (var publicKey = privateKey.GetPublicKey())
            {
                if (publicKey is null)
                {
                    return Task.FromResult(Result.Failure<EnclavePublicKey>(
                        Error.Failure("Failed to derive public key from Secure Enclave private key.")));
                }

                var pubBytes = ExtractRawP256PublicKey(publicKey);
                return Task.FromResult(Result.Success(new EnclavePublicKey(pubBytes, Algorithm)));
            }
        }
        catch (Exception ex)
        {
            return Task.FromResult(Result.Failure<EnclavePublicKey>(
                Error.Failure($"iOS enclave keygen exception: {ex.GetType().Name}: {ex.Message}")));
        }
    }

    public Task<Result<bool>> KeyExistsAsync(string keyAlias, CancellationToken ct)
    {
        try
        {
            using var key = LoadPrivateKey(keyAlias);
            return Task.FromResult(Result.Success(key is not null));
        }
        catch (Exception ex)
        {
            return Task.FromResult(Result.Failure<bool>(
                Error.Failure($"iOS enclave key-exists check failed: {ex.Message}")));
        }
    }

    public Task<Result<EnclavePublicKey>> GetPublicKeyAsync(string keyAlias, CancellationToken ct)
    {
        try
        {
            using var privateKey = LoadPrivateKey(keyAlias);
            if (privateKey is null)
            {
                return Task.FromResult(Result.Failure<EnclavePublicKey>(
                    Error.NotFound($"No iOS Secure Enclave key found for alias '{keyAlias}'.")));
            }

            using var publicKey = privateKey.GetPublicKey();
            if (publicKey is null)
            {
                return Task.FromResult(Result.Failure<EnclavePublicKey>(
                    Error.Failure("Failed to derive public key from Secure Enclave private key.")));
            }

            var pubBytes = ExtractRawP256PublicKey(publicKey);
            return Task.FromResult(Result.Success(new EnclavePublicKey(pubBytes, Algorithm)));
        }
        catch (Exception ex)
        {
            return Task.FromResult(Result.Failure<EnclavePublicKey>(
                Error.Failure($"iOS enclave public-key read failed: {ex.Message}")));
        }
    }

    public Task<Result<byte[]>> SignAsync(string keyAlias, byte[] message, CancellationToken ct)
    {
        try
        {
            using var privateKey = LoadPrivateKey(keyAlias);
            if (privateKey is null)
            {
                return Task.FromResult(Result.Failure<byte[]>(
                    Error.NotFound($"No iOS Secure Enclave key found for alias '{keyAlias}'.")));
            }

            // Triggers the biometric prompt; user approval gates the signature.
            // EcdsaSignatureMessageX962Sha256 = pre-hash with SHA-256, sign with ECDSA,
            // return DER-encoded signature (SEQUENCE { r INTEGER, s INTEGER }).
            using var data = NSData.FromArray(message);
            var derSignature = privateKey.CreateSignature(
                SecKeyAlgorithm.EcdsaSignatureMessageX962Sha256,
                data,
                out var error);

            if (derSignature is null || error is not null)
            {
                return Task.FromResult(Result.Failure<byte[]>(
                    Error.Failure($"Secure Enclave sign failed: {error?.LocalizedDescription ?? "unknown"}")));
            }

            var rawSignature = EcdsaSignatureFormat.DerToRaw(derSignature.ToArray());
            return Task.FromResult(Result.Success(rawSignature));
        }
        catch (Exception ex)
        {
            return Task.FromResult(Result.Failure<byte[]>(
                Error.Failure($"iOS enclave sign exception: {ex.GetType().Name}: {ex.Message}")));
        }
    }

    public Task<Result> DeleteAsync(string keyAlias, CancellationToken ct)
    {
        try
        {
            DeleteInternal(keyAlias);
            return Task.FromResult(Result.Success());
        }
        catch (Exception ex)
        {
            return Task.FromResult(Result.Failure(
                Error.Failure($"iOS enclave delete failed: {ex.Message}")));
        }
    }

    // --- internals ---

    private static SecKey? LoadPrivateKey(string keyAlias)
    {
        var query = new SecRecord(SecKind.Key)
        {
            KeyClass = SecKeyClass.Private,
            ApplicationTag = TagFor(keyAlias),
            KeyType = SecKeyType.EC,
        };

        var result = SecKeyChain.QueryAsConcreteType(query, out var status);
        return status == SecStatusCode.Success ? result as SecKey : null;
    }

    private static void DeleteInternal(string keyAlias)
    {
        var query = new SecRecord(SecKind.Key)
        {
            KeyClass = SecKeyClass.Private,
            ApplicationTag = TagFor(keyAlias),
        };
        // SecItemDelete equivalent; ignore status — we don't care if the key didn't exist.
        SecKeyChain.Remove(query);
    }

    /// <summary>
    /// SecKey's external representation for a P-256 public key is the 65-byte
    /// uncompressed point (0x04 || X || Y per X9.63). The protocol RFC's
    /// <c>ecdsa-p256</c> wire format is the 64-byte raw concatenation
    /// (X || Y, big-endian), so we strip the 0x04 prefix.
    /// </summary>
    private static byte[] ExtractRawP256PublicKey(SecKey publicKey)
    {
        using var data = publicKey.GetExternalRepresentation();
        if (data is null)
        {
            throw new InvalidOperationException("SecKey.GetExternalRepresentation returned null.");
        }

        var bytes = data.ToArray();
        if (bytes.Length == 65 && bytes[0] == 0x04)
        {
            var raw = new byte[64];
            Buffer.BlockCopy(bytes, 1, raw, 0, 64);
            return raw;
        }
        if (bytes.Length == 64)
        {
            return bytes;
        }
        throw new InvalidOperationException(
            $"Unexpected P-256 public-key external representation length: {bytes.Length}");
    }

    /// <summary>
    /// kSec* NSString constants loaded directly from the Security framework
    /// binary at runtime. We can't use the <c>SecAttributeKey</c> /
    /// <c>SecKeyGenerationAttributeKeys</c> classes because the .NET MAUI iOS
    /// binding marks them as internal — they're meant to be accessed indirectly
    /// via <see cref="SecRecord"/>, but SecKey generation needs the raw
    /// dictionary form.
    /// </summary>
    private static class SecConstants
    {
        private const string SecurityLibrary =
            "/System/Library/Frameworks/Security.framework/Security";

        private static readonly IntPtr _handle = Dlfcn.dlopen(SecurityLibrary, 0);

        public static readonly NSString AttrKeyType = Load("kSecAttrKeyType");
        public static readonly NSString AttrKeyTypeECSECPrimeRandom = Load("kSecAttrKeyTypeECSECPrimeRandom");
        public static readonly NSString AttrTokenID = Load("kSecAttrTokenID");
        public static readonly NSString AttrTokenIDSecureEnclave = Load("kSecAttrTokenIDSecureEnclave");
        public static readonly NSString AttrIsPermanent = Load("kSecAttrIsPermanent");
        public static readonly NSString AttrApplicationTag = Load("kSecAttrApplicationTag");
        public static readonly NSString AttrAccessControl = Load("kSecAttrAccessControl");
        public static readonly NSString AttrKeySizeInBits = Load("kSecAttrKeySizeInBits");
        public static readonly NSString PrivateKeyAttrs = Load("kSecPrivateKeyAttrs");

        private static NSString Load(string symbol)
        {
            if (_handle == IntPtr.Zero)
            {
                throw new InvalidOperationException(
                    $"Failed to dlopen Security.framework while loading '{symbol}'.");
            }

            // dlsym gives us the address of the NSString* — i.e. a pointer to a
            // pointer. Dereference once to get the actual NSString instance.
            var symAddr = Dlfcn.dlsym(_handle, symbol);
            if (symAddr == IntPtr.Zero)
            {
                throw new InvalidOperationException(
                    $"Symbol '{symbol}' not found in Security.framework.");
            }

            var nsStringPtr = Marshal.ReadIntPtr(symAddr);
            if (nsStringPtr == IntPtr.Zero)
            {
                throw new InvalidOperationException(
                    $"Symbol '{symbol}' resolved but its NSString value is null.");
            }

            return Runtime.GetNSObject<NSString>(nsStringPtr)
                ?? throw new InvalidOperationException(
                    $"Could not wrap NSString for '{symbol}'.");
        }
    }
}
