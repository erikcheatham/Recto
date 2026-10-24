using System;
using System.Threading;
using System.Threading.Tasks;
using Recto.Shared.Common;
using Recto.Shared.Services;

namespace Recto.Services;

/// <summary>
/// MAUI-side persistence for the genesis-membership marker. Routes through
/// <see cref="ResilientStorage"/> like the pairing record, but under its OWN
/// key — membership must survive the pairing record's deletion (the surgical
/// per-bootloader unpair), because it describes the enclave key, not the
/// pairing. The stored value is the derived bootloader id captured when the
/// genesis set sealed; any non-empty value means membership.
/// </summary>
public sealed class MauiGenesisStateService : IGenesisStateService
{
    private const string GenesisKey = "recto.phone.genesis";

    public async Task<Result<bool>> IsGenesisMemberAsync(CancellationToken ct)
    {
        try
        {
            var value = await ResilientStorage.GetAsync(GenesisKey).ConfigureAwait(false);
            return Result.Success(!string.IsNullOrEmpty(value));
        }
        catch (Exception ex)
        {
            // A failure here is NOT "not a member" — callers guarding
            // destructive actions fail closed on it (see IUnpairService).
            return Result.Failure<bool>(Error.Failure($"Failed to read genesis state: {ex.Message}"));
        }
    }

    public async Task<Result> MarkGenesisMemberAsync(string derivedBootloaderId, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(derivedBootloaderId))
        {
            return Result.Failure(Error.Failure("A genesis marker requires the derived bootloader id."));
        }

        try
        {
            await ResilientStorage.SetAsync(GenesisKey, derivedBootloaderId).ConfigureAwait(false);
            return Result.Success();
        }
        catch (Exception ex)
        {
            return Result.Failure(Error.Failure($"Failed to write genesis state: {ex.Message}"));
        }
    }

    public Task<Result> ClearAsync(CancellationToken ct)
    {
        try
        {
            ResilientStorage.Remove(GenesisKey);
            return Task.FromResult(Result.Success());
        }
        catch (Exception ex)
        {
            return Task.FromResult(Result.Failure(Error.Failure($"Failed to clear genesis state: {ex.Message}")));
        }
    }
}
