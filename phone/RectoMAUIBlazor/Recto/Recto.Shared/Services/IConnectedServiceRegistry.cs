using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Recto.Shared.Common;
using Recto.Shared.Models;
using Recto.Shared.Protocol.V04;
// Disambiguate AppContext: System.AppContext (the .NET runtime app-context
// class, implicit via SDK using directives) collides with the protocol's
// Recto.Shared.Protocol.V04.AppContext at the type name. CS0104 banked the
// first time this surfaced (build feedback 2026-05-18). The alias here +
// in MauiConnectedServiceRegistry.cs is the canonical fix.
using AppContext = Recto.Shared.Protocol.V04.AppContext;

namespace Recto.Shared.Services;

/// <summary>
/// Tracks the unique consumer services the phone has been authorized
/// to receive requests from — the data model behind the vault-home
/// "Connected Services" list view (the Authy-analog).
///
/// <para>
/// Implementations persist across app launches via the platform's
/// secure storage (<see cref="Microsoft.Maui.Storage.SecureStorage"/>
/// on the MAUI phone host). The list is local-only — never
/// transmitted to any server, never synchronized between paired
/// phones, never queried from the bootloader. It's derived purely
/// from the <see cref="AppContext"/> entries observed on this
/// phone's incoming requests.
/// </para>
///
/// <para>
/// Architectural rationale: Recto's phone is the operator's
/// authority surface — it answers "who's asking?" by reading the
/// AppContext on each pending request. The vault home generalizes
/// that per-request answer into "who CAN ask?" by aggregating
/// across history. v1 scope is observational (services appear in
/// the list once they've sent at least one request). v1.1+ may add
/// explicit pairing flows (manually add a service before any
/// request arrives) + per-service mute/unmute toggles.
/// </para>
/// </summary>
public interface IConnectedServiceRegistry
{
    /// <summary>
    /// Returns all known services, newest-activity first.
    /// </summary>
    Task<Result<IReadOnlyList<ConnectedService>>> GetAllAsync(CancellationToken ct);

    /// <summary>
    /// Looks up a single service by AppId. Returns <c>null</c> on miss
    /// (Result.Success with null value; not Result.Failure — missing
    /// is a normal state for a vault-home tap on a row whose AppContext
    /// hasn't been observed yet).
    /// </summary>
    Task<Result<ConnectedService?>> GetByIdAsync(string appId, CancellationToken ct);

    /// <summary>
    /// Upserts the registry from an observed pending request's
    /// <see cref="AppContext"/>. If the AppId is new, creates a row
    /// with <c>FirstSeenUtc = LastSeenUtc = now</c> and
    /// <c>RequestCount = 1</c>. If the AppId already exists, updates
    /// <c>LastSeenUtc = now</c>, increments <c>RequestCount</c>, and
    /// refreshes the name/description/icon/url fields from the
    /// current AppContext (in case the consumer has since updated
    /// their registration).
    ///
    /// <para>
    /// No-op when <paramref name="appContext"/> is null — requests
    /// without AppContext are "unknown app" warnings rendered on the
    /// approval card; they don't populate the vault home (the
    /// consumer hasn't formally registered yet).
    /// </para>
    /// </summary>
    Task<Result> RecordObservedAsync(AppContext? appContext, CancellationToken ct);

    /// <summary>
    /// Wipes the registry. Called when the phone unpairs from its
    /// bootloader (operator-side action in Settings). Triggers a UX
    /// reset back to the empty-state "No services connected yet".
    /// </summary>
    Task<Result> ClearAllAsync(CancellationToken ct);

    /// <summary>
    /// Removes a single service by AppId. Returns
    /// <see cref="Result.Success"/> whether or not the AppId matched
    /// any row — idempotency is the canonical "I no longer want this
    /// service in my list" contract regardless of pre-state.
    /// <para>
    /// Build 6 (2026-06-02): added alongside the Per-service unpair
    /// UI on the Vault home. v1 of the unpair flow is LOCAL-only —
    /// the bootloader-side trust state (master pubkey binding on
    /// the consumer's User row) is NOT revoked by this call. v1.x
    /// will ship a server-side <c>devices:pairing_revoke</c> action
    /// per architectural commitment #9 (capability-bounded
    /// revocation); until then a consumer-side stale master pubkey
    /// requires a separate Postgres NULL workaround OR a wait for
    /// the v1.x revoke endpoint. Documented gap; banking deferred
    /// because v1's unpair is sufficient for App Store reviewers
    /// (who are exercising the demo service exit path) and for
    /// operators who explicitly understand the local-only semantic.
    /// </para>
    /// <para>
    /// The demo service (AppId == <c>"demo-service"</c>, matching
    /// <c>BuildDemoPendingRequest</c>'s synthetic AppContext sentinel
    /// + Home.razor's <c>DemoServiceAppId</c> const) is treated the
    /// same as any real service at the registry layer — no
    /// special-case. The demo-mode state machine in Home.razor's
    /// <c>HandleConfirmUnpairServiceAsync</c> routes demo-service
    /// AppId matches to <c>HandleStartFreshClick</c> so the broader
    /// exit ceremony (TOTP wipe + pairing wipe + Connected Services
    /// wipe + UI reset) fires when the demo service is unpaired
    /// from this surface.
    /// </para>
    /// </summary>
    Task<Result> UnpairAsync(string appId, CancellationToken ct);
}
