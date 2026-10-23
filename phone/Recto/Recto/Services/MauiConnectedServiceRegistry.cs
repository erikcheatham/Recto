using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Maui.Storage;
using Recto.Shared.Common;
using Recto.Shared.Models;
using Recto.Shared.Protocol.V04;
using Recto.Shared.Services;
// Disambiguate AppContext: System.AppContext (the .NET runtime app-context
// class) collides with the protocol's Recto.Shared.Protocol.V04.AppContext
// at the type name. Alias keeps the parameter signature on
// RecordObservedAsync clean. Sister of the same fix in
// IConnectedServiceRegistry.cs.
using AppContext = Recto.Shared.Protocol.V04.AppContext;

namespace Recto.Services;

/// <summary>
/// MAUI-side persistence for the phone's Connected Services registry.
/// Backing store is <see cref="SecureStorage"/> under
/// <c>recto.phone.connected-services</c> as a JSON array of
/// <see cref="ConnectedService"/> records.
///
/// <para>
/// Concurrency: a single <see cref="SemaphoreSlim"/> serializes reads
/// and writes so concurrent <see cref="RecordObservedAsync"/> calls
/// from rapid back-to-back pending-request fetches don't lose updates.
/// </para>
/// </summary>
public sealed class MauiConnectedServiceRegistry : IConnectedServiceRegistry
{
    private const string StorageKey = "recto.phone.connected-services";
    private readonly SemaphoreSlim _gate = new(initialCount: 1, maxCount: 1);

    public async Task<Result<IReadOnlyList<ConnectedService>>> GetAllAsync(CancellationToken ct)
    {
        try
        {
            var list = await ReadInternalAsync(ct).ConfigureAwait(false);
            // Newest-activity first — that's the sort the vault home
            // expects so freshly-active services bubble to the top.
            var sorted = list
                .OrderByDescending(s => s.LastSeenUtc)
                .ThenBy(s => s.AppName, StringComparer.OrdinalIgnoreCase)
                .ToList();
            return Result.Success<IReadOnlyList<ConnectedService>>(sorted);
        }
        catch (Exception ex)
        {
            return Result.Failure<IReadOnlyList<ConnectedService>>(
                Error.Failure($"Failed to read connected services: {ex.Message}"));
        }
    }

    public async Task<Result<ConnectedService?>> GetByIdAsync(string appId, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(appId))
        {
            return Result.Success<ConnectedService?>(null);
        }
        try
        {
            var list = await ReadInternalAsync(ct).ConfigureAwait(false);
            var match = list.FirstOrDefault(s => s.AppId == appId);
            return Result.Success<ConnectedService?>(match);
        }
        catch (Exception ex)
        {
            return Result.Failure<ConnectedService?>(
                Error.Failure($"Failed to read connected service {appId}: {ex.Message}"));
        }
    }

    public async Task<Result> RecordObservedAsync(AppContext? appContext, CancellationToken ct)
    {
        // No-op for unregistered agents. They render as "Unknown app" on the
        // approval card; they don't populate the vault home until the consumer
        // formally registers AppContext at the bootloader.
        if (appContext is null || string.IsNullOrEmpty(appContext.AppId) || string.IsNullOrEmpty(appContext.AppName))
        {
            return Result.Success();
        }

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var list = await ReadInternalAsync(ct).ConfigureAwait(false);
            var now = DateTimeOffset.UtcNow;
            var idx = list.FindIndex(s => s.AppId == appContext.AppId);
            if (idx >= 0)
            {
                // Upsert: refresh display fields (consumer may have updated
                // their AppContext registration since last sight), bump
                // LastSeenUtc + RequestCount.
                var prev = list[idx];
                list[idx] = prev with
                {
                    AppName = appContext.AppName,
                    AppDescription = appContext.AppDescription ?? string.Empty,
                    AppUrl = appContext.AppUrl,
                    AppIconUrl = appContext.AppIconUrl,
                    LastSeenUtc = now,
                    RequestCount = prev.RequestCount + 1,
                };
            }
            else
            {
                // First sight — create a fresh row.
                list.Add(new ConnectedService(
                    AppId: appContext.AppId,
                    AppName: appContext.AppName,
                    AppDescription: appContext.AppDescription ?? string.Empty,
                    AppUrl: appContext.AppUrl,
                    AppIconUrl: appContext.AppIconUrl,
                    FirstSeenUtc: now,
                    LastSeenUtc: now,
                    RequestCount: 1));
            }

            await WriteInternalAsync(list, ct).ConfigureAwait(false);
            return Result.Success();
        }
        catch (Exception ex)
        {
            return Result.Failure(
                Error.Failure($"Failed to record connected service {appContext?.AppId}: {ex.Message}"));
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<Result> ClearAllAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            ResilientStorage.Remove(StorageKey);
            return Result.Success();
        }
        catch (Exception ex)
        {
            return Result.Failure(
                Error.Failure($"Failed to clear connected services: {ex.Message}"));
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<Result> UnpairAsync(string appId, CancellationToken ct)
    {
        // Empty/whitespace AppId is idempotent no-op — there's nothing
        // to remove. Returning Success preserves the canonical
        // "I no longer want this service in my list" contract.
        if (string.IsNullOrWhiteSpace(appId))
        {
            return Result.Success();
        }

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var list = await ReadInternalAsync(ct).ConfigureAwait(false);
            var removed = list.RemoveAll(s => s.AppId == appId);
            if (removed == 0)
            {
                // AppId never matched any row. The contract is idempotent
                // by design (matches Result.Success regardless of pre-state),
                // so a missed match isn't a failure — the caller's goal
                // ("this service should no longer be in my list") is
                // already satisfied.
                return Result.Success();
            }

            await WriteInternalAsync(list, ct).ConfigureAwait(false);
            return Result.Success();
        }
        catch (Exception ex)
        {
            return Result.Failure(
                Error.Failure($"Failed to unpair connected service {appId}: {ex.Message}"));
        }
        finally
        {
            _gate.Release();
        }
    }

    // ---- internal helpers ----

    private static async Task<List<ConnectedService>> ReadInternalAsync(CancellationToken ct)
    {
        var json = await ResilientStorage.GetAsync(StorageKey).ConfigureAwait(false);
        if (string.IsNullOrEmpty(json))
        {
            return new List<ConnectedService>();
        }
        // Tolerate malformed JSON (e.g. from a future schema change that hasn't
        // shipped a migration yet) by falling back to empty list rather than
        // letting the deserialization exception bubble. Vault home recovers
        // gracefully; user sees an empty state which is correct semantics
        // given the cache is unreadable.
        try
        {
            var list = JsonSerializer.Deserialize<List<ConnectedService>>(json);
            return list ?? new List<ConnectedService>();
        }
        catch (JsonException)
        {
            return new List<ConnectedService>();
        }
    }

    private static async Task WriteInternalAsync(List<ConnectedService> list, CancellationToken ct)
    {
        var json = JsonSerializer.Serialize(list);
        await ResilientStorage.SetAsync(StorageKey, json).ConfigureAwait(false);
    }
}
