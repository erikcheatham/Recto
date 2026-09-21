using System;
using System.Diagnostics;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Recto.Services;
using Recto.Shared.Common;
using Recto.Shared.Models;
using Recto.Shared.Services;

namespace Recto.Services;

/// <summary>
/// MAUI-side persistence for the phone's pairing record + persistent phone id.
/// Routes through <see cref="ResilientStorage"/> which wraps SecureStorage on
/// real devices and falls back to file storage on iOS Simulator (where
/// Keychain Services returns errSecMissingEntitlement for unsigned simulator
/// builds — see ResilientStorage.cs comments for the full story).
/// <para>
/// The pairing JSON lives under <c>recto.phone.pairing</c>, the phone id
/// under <c>recto.phone.id</c>.
/// </para>
/// </summary>
public sealed class MauiPairingStateService : IPairingStateService
{
    private const string PhoneIdKey = "recto.phone.id";
    private const string PairingStateKey = "recto.phone.pairing";

    public async Task<Result<PairingState?>> GetCurrentAsync(CancellationToken ct)
    {
        try
        {
            var json = await ResilientStorage.GetAsync(PairingStateKey).ConfigureAwait(false);
            if (string.IsNullOrEmpty(json))
            {
                return Result.Success<PairingState?>(null);
            }

            var state = JsonSerializer.Deserialize<PairingState>(json);
            return Result.Success(state);
        }
        catch (Exception ex)
        {
            return Result.Failure<PairingState?>(Error.Failure($"Failed to read pairing state: {ex.Message}"));
        }
    }

    public async Task<Result> SaveAsync(PairingState state, CancellationToken ct)
    {
        try
        {
            // DIAG-2026-04-30 (auto-unpair investigation): log who's saving
            // null pairing state. Manual UnpairAll button in Settings.razor
            // is the only known caller; if anything else trips this, the
            // stack trace tells us where.
            if (state is null)
            {
                Debug.WriteLine($"[Recto/DIAG] MauiPairingStateService.SaveAsync(null) called.{Environment.NewLine}" +
                                $"  Caller stack:{Environment.NewLine}{new StackTrace(true)}");
            }
            var json = JsonSerializer.Serialize(state);
            await ResilientStorage.SetAsync(PairingStateKey, json).ConfigureAwait(false);
            return Result.Success();
        }
        catch (Exception ex)
        {
            return Result.Failure(Error.Failure($"Failed to save pairing state: {ex.Message}"));
        }
    }

    public Task<Result> ClearAsync(CancellationToken ct)
    {
        try
        {
            // DIAG-2026-04-30 (auto-unpair investigation): log every caller.
            // HandleUnpairClick in Home.razor is the only known caller; any
            // other path that lands here means something is unpairing the
            // phone unexpectedly. Stack trace identifies the culprit.
            Debug.WriteLine($"[Recto/DIAG] MauiPairingStateService.ClearAsync called.{Environment.NewLine}" +
                            $"  Caller stack:{Environment.NewLine}{new StackTrace(true)}");
            ResilientStorage.Remove(PairingStateKey);
            return Task.FromResult(Result.Success());
        }
        catch (Exception ex)
        {
            return Task.FromResult(Result.Failure(Error.Failure($"Failed to clear pairing state: {ex.Message}")));
        }
    }

    public async Task<Result<string>> GetOrCreatePhoneIdAsync(CancellationToken ct)
    {
        try
        {
            var existing = await ResilientStorage.GetAsync(PhoneIdKey).ConfigureAwait(false);
            if (!string.IsNullOrEmpty(existing))
            {
                return Result.Success(existing);
            }

            var newId = Guid.NewGuid().ToString();
            await ResilientStorage.SetAsync(PhoneIdKey, newId).ConfigureAwait(false);
            return Result.Success(newId);
        }
        catch (Exception ex)
        {
            return Result.Failure<string>(Error.Failure($"Failed to get phone id: {ex.Message}"));
        }
    }
}
