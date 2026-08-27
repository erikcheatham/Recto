using System;
using System.Diagnostics;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Maui.Storage;
using Recto.Shared.Common;
using Recto.Shared.Services;

namespace Recto.Services;

/// <summary>
/// SecureStorage-backed TOTP service. Each provisioned secret lives
/// under the key <c>recto.phone.totp.{alias}</c>; the value is a JSON
/// blob carrying the base32 secret + the algorithm parameters so
/// every Generate is self-contained.
/// <para>
/// Round-5 stores TOTP secrets in the OS keychain (iOS Keychain /
/// Android Keystore-encrypted prefs / Windows DPAPI for unpackaged
/// MAUI hosts). They're encrypted at rest and scoped to the app, but
/// not biometric-gated per access (unlike the SignSync path on
/// IEnclaveKeyService). A future round can wrap each TOTP secret
/// with an enclave-resident KEK if biometric-per-code is desired.
/// </para>
/// </summary>
public sealed class MauiTotpService : ITotpService
{
    private const string KeyPrefix = "recto.phone.totp.";

    private sealed record StoredSecret(
        string SecretB32,
        int PeriodSeconds,
        int Digits,
        string Algorithm);

    public async Task<Result> ProvisionAsync(
        string alias,
        string secretB32,
        int periodSeconds,
        int digits,
        string algorithm,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(alias))
        {
            return Result.Failure(Error.Validation([new ValidationErrors("alias", "Alias is required.")]));
        }
        if (string.IsNullOrWhiteSpace(secretB32))
        {
            return Result.Failure(Error.Validation([new ValidationErrors("secretB32", "TOTP secret is required.")]));
        }

        try
        {
            // Validate the secret decodes cleanly before persisting (defense in depth — the
            // bootloader should never send a malformed one, but reject early if it does).
            _ = TotpCodeCalculator.DecodeBase32(secretB32);

            var stored = new StoredSecret(secretB32, periodSeconds, digits, algorithm);
            var json = JsonSerializer.Serialize(stored);
            await ResilientStorage.SetAsync(KeyPrefix + alias, json).ConfigureAwait(false);
            return Result.Success();
        }
        catch (Exception ex)
        {
            return Result.Failure(Error.Failure($"Failed to provision TOTP secret for '{alias}': {ex.Message}"));
        }
    }

    public async Task<Result<bool>> ExistsAsync(string alias, CancellationToken ct)
    {
        try
        {
            var json = await ResilientStorage.GetAsync(KeyPrefix + alias).ConfigureAwait(false);
            return Result.Success(!string.IsNullOrEmpty(json));
        }
        catch (Exception ex)
        {
            return Result.Failure<bool>(Error.Failure($"Failed to check TOTP existence for '{alias}': {ex.Message}"));
        }
    }

    public async Task<Result<string>> GenerateAsync(string alias, CancellationToken ct)
    {
        try
        {
            var json = await ResilientStorage.GetAsync(KeyPrefix + alias).ConfigureAwait(false);
            if (string.IsNullOrEmpty(json))
            {
                return Result.Failure<string>(Error.NotFound($"No TOTP secret provisioned for '{alias}'."));
            }

            var stored = JsonSerializer.Deserialize<StoredSecret>(json);
            if (stored is null)
            {
                return Result.Failure<string>(Error.Failure($"Stored TOTP entry for '{alias}' is corrupt."));
            }

            var secret = TotpCodeCalculator.DecodeBase32(stored.SecretB32);
            var code = TotpCodeCalculator.Generate(
                secret,
                DateTimeOffset.UtcNow,
                stored.PeriodSeconds,
                stored.Digits,
                stored.Algorithm);
            return Result.Success(code);
        }
        catch (Exception ex)
        {
            return Result.Failure<string>(Error.Failure($"Failed to generate TOTP code for '{alias}': {ex.Message}"));
        }
    }

    public Task<Result> DeleteAsync(string alias, CancellationToken ct)
    {
        try
        {
            ResilientStorage.Remove(KeyPrefix + alias);
            return Task.FromResult(Result.Success());
        }
        catch (Exception ex)
        {
            return Task.FromResult(Result.Failure(Error.Failure($"Failed to delete TOTP secret for '{alias}': {ex.Message}")));
        }
    }

    public Task<Result> ClearAllAsync(CancellationToken ct)
    {
        try
        {
            // SecureStorage doesn't expose enumeration of stored keys, so
            // we can't iterate "all keys with our prefix" directly.
            // RemoveAll wipes the entire SecureStorage namespace for this
            // app, which is the right semantic for a Settings "Unpair all"
            // emergency wipe -- both TOTP secrets AND the pairing record
            // (also stored in SecureStorage) get cleared in one step.
            //
            // DIAG-2026-04-30 (auto-unpair investigation): log every caller.
            // UnpairAllAsync in Settings.razor is the only known caller; if
            // anything else trips this, the stack trace tells us where. This
            // path nukes the pairing record AS A SIDE EFFECT (RemoveAll
            // wipes everything in SecureStorage) so it's a candidate for
            // the auto-unpair-after-typed-data-approval mystery.
            Debug.WriteLine($"[Recto/DIAG] MauiTotpService.ClearAllAsync called (RemoveAll - nukes pairing too).{Environment.NewLine}" +
                            $"  Caller stack:{Environment.NewLine}{new System.Diagnostics.StackTrace(true)}");
            ResilientStorage.RemoveAll();
            return Task.FromResult(Result.Success());
        }
        catch (Exception ex)
        {
            return Task.FromResult(Result.Failure(Error.Failure(
                $"Failed to clear TOTP secrets: {ex.Message}")));
        }
    }
}
