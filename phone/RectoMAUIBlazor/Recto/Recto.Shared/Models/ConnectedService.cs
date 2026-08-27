using System;

namespace Recto.Shared.Models;

/// <summary>
/// A consumer service the phone has been authorized to receive signing
/// requests from. Derived from the <see cref="Recto.Shared.Protocol.V04.AppContext"/>
/// metadata that bootloader-side rendering injects into every pending
/// request — when a request with a new <c>AppId</c> first arrives,
/// the registry creates a record; subsequent requests update the
/// last-seen timestamp + request count.
///
/// <para>
/// This is the phone-side model of "services the user has connected
/// to" — the Authy-analog list view at the top of the vault home.
/// Persisted to <c>SecureStorage</c> under
/// <c>recto.phone.connected-services</c> so the list survives app
/// launches + bootloader restarts.
/// </para>
///
/// <para>
/// All fields after <see cref="AppId"/> + <see cref="AppName"/> are
/// optional (the consumer may not have populated them at AppContext-
/// registration time). The vault-home row renders progressively:
/// always shows the name; description + icon URL appear when present.
/// </para>
/// </summary>
/// <param name="AppId">
/// Canonical service identifier (matches <c>AppContext.AppId</c>).
/// Primary key for upsert.
/// </param>
/// <param name="AppName">Display name for the service.</param>
/// <param name="AppDescription">One-line description shown below the name.</param>
/// <param name="AppUrl">Service homepage URL (https://...).</param>
/// <param name="AppIconUrl">Service icon URL (https://...).</param>
/// <param name="FirstSeenUtc">UTC timestamp when this service first sent a request to this phone.</param>
/// <param name="LastSeenUtc">UTC timestamp of the most recent request observed from this service.</param>
/// <param name="RequestCount">Total number of requests observed from this service since first-pair.</param>
public sealed record ConnectedService(
    string AppId,
    string AppName,
    string AppDescription,
    string? AppUrl,
    string? AppIconUrl,
    DateTimeOffset FirstSeenUtc,
    DateTimeOffset LastSeenUtc,
    int RequestCount);
