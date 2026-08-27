using System;
using System.Threading;
using System.Threading.Tasks;
using Android.Security.Keystore;
using AndroidX.Biometric;
using AndroidX.Core.Content;
using AndroidX.Fragment.App;
using Java.Security;
using Java.Security.Spec;
using Recto.Shared.Common;
using Recto.Shared.Models;
using Recto.Shared.Protocol.V04;
using Recto.Shared.Services;

namespace Recto.Platforms.AndroidImpl;

/// <summary>
/// Android StrongBox-backed key service. Generates an ECDSA P-256 keypair
/// inside the StrongBox HSM (Titan M / Pixel chip / Samsung Knox HSM,
/// depending on device). Every signing operation is gated by an explicit
/// <see cref="BiometricPrompt"/> with <see cref="BiometricPrompt.CryptoObject"/>
/// so the user authorizes each signature individually &mdash; matches the
/// "operator approves every cryptographic operation" security model.
/// <para>
/// Why P-256 and not Ed25519: AndroidKeyStore's public
/// <c>KEY_ALGORITHM_*</c> constants list EC / RSA / AES / HMAC / XDH but
/// not Ed25519, even on Android 16 / API 35. The v0.4 protocol's
/// <c>supported_algorithms</c> field lets the phone advertise
/// <c>ecdsa-p256</c> &mdash; same as iOS Secure Enclave.
/// </para>
/// <para>
/// Key authentication model: per-use (<c>setUserAuthenticationParameters(0,
/// BIOMETRIC_STRONG | DEVICE_CREDENTIAL)</c>) so every <c>Signature.sign()</c>
/// call requires a fresh <c>BiometricPrompt</c> authorization. The
/// <c>InitSign</c> call succeeds without prior auth (key is "armed"); the
/// actual signature operation requires the prompt to authorize the
/// <c>CryptoObject</c>.
/// </para>
/// </summary>
public sealed class AndroidStrongBoxKeyService : IEnclaveKeyService
{
    private const string AndroidKeyStoreProvider = "AndroidKeyStore";
    private const string SignatureAlgorithm = "SHA256withECDSA";
    private const string EcCurveName = "secp256r1";

    public string Algorithm => V04Protocol.AlgorithmEcdsaP256;

    public Task<Result<EnclavePublicKey>> GenerateAsync(string keyAlias, CancellationToken ct)
    {
        try
        {
            DeleteInternal(keyAlias);

            var generator = KeyPairGenerator.GetInstance(KeyProperties.KeyAlgorithmEc, AndroidKeyStoreProvider)
                ?? throw new InvalidOperationException("KeyPairGenerator.GetInstance returned null.");

            var spec = BuildSpec(keyAlias, strongBox: true);
            try
            {
                generator.Initialize(spec);
                using var pair = generator.GenerateKeyPair();
                return Task.FromResult(BuildPublicKeyResult(pair));
            }
            catch (StrongBoxUnavailableException)
            {
                spec = BuildSpec(keyAlias, strongBox: false);
                generator.Initialize(spec);
                using var pair = generator.GenerateKeyPair();
                return Task.FromResult(BuildPublicKeyResult(pair));
            }
        }
        catch (Exception ex)
        {
            return Task.FromResult(Result.Failure<EnclavePublicKey>(
                Error.Failure($"Android StrongBox keygen failed: {ex.GetType().Name}: {ex.Message}")));
        }
    }

    public Task<Result<bool>> KeyExistsAsync(string keyAlias, CancellationToken ct)
    {
        try
        {
            using var keyStore = KeyStore.GetInstance(AndroidKeyStoreProvider);
            keyStore!.Load(null);
            return Task.FromResult(Result.Success(keyStore.ContainsAlias(keyAlias)));
        }
        catch (Exception ex)
        {
            return Task.FromResult(Result.Failure<bool>(
                Error.Failure($"Android keystore check failed: {ex.Message}")));
        }
    }

    public Task<Result<EnclavePublicKey>> GetPublicKeyAsync(string keyAlias, CancellationToken ct)
    {
        try
        {
            using var keyStore = KeyStore.GetInstance(AndroidKeyStoreProvider);
            keyStore!.Load(null);

            using var entry = keyStore.GetEntry(keyAlias, null);
            if (entry is not KeyStore.PrivateKeyEntry pkEntry || pkEntry.Certificate is null)
            {
                return Task.FromResult(Result.Failure<EnclavePublicKey>(
                    Error.NotFound($"No Android keystore entry for alias '{keyAlias}'.")));
            }

            var publicKey = pkEntry.Certificate.PublicKey
                ?? throw new InvalidOperationException("Certificate has no public key.");
            var encoded = publicKey.GetEncoded()
                ?? throw new InvalidOperationException("PublicKey.GetEncoded returned null.");

            return Task.FromResult(Result.Success(new EnclavePublicKey(
                ExtractRawP256PublicKey(encoded), Algorithm)));
        }
        catch (Exception ex)
        {
            return Task.FromResult(Result.Failure<EnclavePublicKey>(
                Error.Failure($"Android keystore public-key read failed: {ex.Message}")));
        }
    }

    public Task<Result<byte[]>> SignAsync(string keyAlias, byte[] message, CancellationToken ct)
    {
        try
        {
            using var keyStore = KeyStore.GetInstance(AndroidKeyStoreProvider);
            keyStore!.Load(null);

            using var entry = keyStore.GetEntry(keyAlias, null);
            if (entry is not KeyStore.PrivateKeyEntry pkEntry)
            {
                return Task.FromResult(Result.Failure<byte[]>(
                    Error.NotFound($"No Android keystore entry for alias '{keyAlias}'.")));
            }

            // InitSign succeeds without prior user auth on per-use keys (timeout=0).
            // The Signature is "armed" but cannot complete .sign() until the
            // BiometricPrompt authorizes the CryptoObject wrapping it.
            var signer = Signature.GetInstance(SignatureAlgorithm)
                ?? throw new InvalidOperationException("Signature.GetInstance returned null.");
            signer.InitSign(pkEntry.PrivateKey);

            return AuthenticateAndSignAsync(signer, message, keyAlias, ct);
        }
        catch (Exception ex)
        {
            return Task.FromResult(Result.Failure<byte[]>(
                Error.Failure($"Android sign exception: {ex.GetType().Name}: {ex.Message}")));
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
                Error.Failure($"Android keystore delete failed: {ex.Message}")));
        }
    }

    // --- BiometricPrompt + CryptoObject sign flow ---

    /// <summary>
    /// Wraps the armed <see cref="Signature"/> in a
    /// <see cref="BiometricPrompt.CryptoObject"/> and shows the system
    /// biometric prompt. On success the prompt's success callback runs
    /// <c>signer.update(message)</c> + <c>signer.sign()</c>, converts the
    /// DER-encoded signature to raw R || S, and resolves the
    /// <see cref="TaskCompletionSource{TResult}"/>. On user cancel / error
    /// the TCS resolves with a <see cref="Result.Failure"/>.
    /// </summary>
    private static async Task<Result<byte[]>> AuthenticateAndSignAsync(
        Signature signer, byte[] message, string keyAlias, CancellationToken ct)
    {
        var activity = Microsoft.Maui.ApplicationModel.Platform.CurrentActivity as FragmentActivity
            ?? throw new InvalidOperationException(
                "Current activity is not a FragmentActivity; BiometricPrompt requires it.");

        var executor = ContextCompat.GetMainExecutor(activity)
            ?? throw new InvalidOperationException("ContextCompat.GetMainExecutor returned null.");

        var tcs = new TaskCompletionSource<Result<byte[]>>(TaskCreationOptions.RunContinuationsAsynchronously);

        var callback = new BiometricAuthCallback(tcs, message);
        var prompt = new BiometricPrompt(activity, executor, callback);

        var cryptoObject = new BiometricPrompt.CryptoObject(signer);

        var promptInfo = new BiometricPrompt.PromptInfo.Builder()
            .SetTitle("Recto")
            .SetSubtitle($"Authorize signing for {keyAlias}")
            .SetDescription("Your fingerprint approves this cryptographic operation.")
            .SetNegativeButtonText("Cancel")
            .Build();

        prompt.Authenticate(promptInfo, cryptoObject);

        // Honor cancellation by resolving the TCS; the prompt itself doesn't
        // have a cancel API from outside the user's input.
        using var registration = ct.Register(() => tcs.TrySetResult(
            Result.Failure<byte[]>(Error.Failure("Operation cancelled."))));

        return await tcs.Task.ConfigureAwait(false);
    }

    private sealed class BiometricAuthCallback : BiometricPrompt.AuthenticationCallback
    {
        private readonly TaskCompletionSource<Result<byte[]>> _tcs;
        private readonly byte[] _message;

        public BiometricAuthCallback(TaskCompletionSource<Result<byte[]>> tcs, byte[] message)
        {
            _tcs = tcs;
            _message = message;
        }

        public override void OnAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result)
        {
            try
            {
                var sig = result.CryptoObject?.Signature;
                if (sig is null)
                {
                    _tcs.TrySetResult(Result.Failure<byte[]>(
                        Error.Failure("BiometricPrompt CryptoObject signature was null.")));
                    return;
                }
                sig.Update(_message);
                var derSig = sig.Sign()
                    ?? throw new InvalidOperationException("Signature.Sign returned null.");
                var raw = EcdsaSignatureFormat.DerToRaw(derSig);
                _tcs.TrySetResult(Result.Success(raw));
            }
            catch (Exception ex)
            {
                _tcs.TrySetResult(Result.Failure<byte[]>(
                    Error.Failure($"Android sign post-auth exception: {ex.GetType().Name}: {ex.Message}")));
            }
        }

        public override void OnAuthenticationError(int errorCode, Java.Lang.ICharSequence errString)
        {
            _tcs.TrySetResult(Result.Failure<byte[]>(
                Error.Failure($"BiometricPrompt error {errorCode}: {errString}")));
        }

        // OnAuthenticationFailed (single attempt didn't match) is intentionally
        // not overridden &mdash; the system retries automatically and ultimately
        // surfaces failure via OnAuthenticationError(ERROR_LOCKOUT or similar).
    }

    // --- internals ---

    private static KeyGenParameterSpec BuildSpec(string keyAlias, bool strongBox)
    {
        var builder = new KeyGenParameterSpec.Builder(keyAlias, KeyStorePurpose.Sign)
            .SetAlgorithmParameterSpec(new ECGenParameterSpec(EcCurveName))
            .SetDigests(KeyProperties.DigestSha256!)
            .SetUserAuthenticationRequired(true);

        // Per-use authentication: timeout 0 means every cryptographic operation
        // requires a fresh BiometricPrompt.authenticate(CryptoObject) call. This
        // matches the protocol's "operator approves every operation" model.
        builder.SetUserAuthenticationParameters(
            timeout: 0,
            type: (int)(KeyPropertiesAuthType.BiometricStrong | KeyPropertiesAuthType.DeviceCredential));

        if (strongBox)
        {
            builder.SetIsStrongBoxBacked(true);
        }

        return builder.Build();
    }

    private static Result<EnclavePublicKey> BuildPublicKeyResult(KeyPair pair)
    {
        var publicKey = pair.Public
            ?? throw new InvalidOperationException("KeyPair.Public was null.");
        var encoded = publicKey.GetEncoded()
            ?? throw new InvalidOperationException("PublicKey.GetEncoded returned null.");

        return Result.Success(new EnclavePublicKey(
            ExtractRawP256PublicKey(encoded), V04Protocol.AlgorithmEcdsaP256));
    }

    private static byte[] ExtractRawP256PublicKey(byte[] encoded)
    {
        if (encoded.Length != 91)
        {
            throw new InvalidOperationException(
                $"Unexpected EC P-256 SubjectPublicKeyInfo length: {encoded.Length}");
        }
        if (encoded[26] != 0x04)
        {
            throw new InvalidOperationException(
                "EC P-256 SubjectPublicKeyInfo missing 0x04 uncompressed-point prefix.");
        }
        var raw = new byte[64];
        Buffer.BlockCopy(encoded, 27, raw, 0, 64);
        return raw;
    }

    private static void DeleteInternal(string keyAlias)
    {
        try
        {
            using var keyStore = KeyStore.GetInstance(AndroidKeyStoreProvider);
            keyStore!.Load(null);
            if (keyStore.ContainsAlias(keyAlias))
            {
                keyStore.DeleteEntry(keyAlias);
            }
        }
        catch
        {
            // Swallow &mdash; DeleteAsync is "no-op if absent" and we don't
            // want a stale-keystore error masking a fresh GenerateAsync.
        }
    }
}
