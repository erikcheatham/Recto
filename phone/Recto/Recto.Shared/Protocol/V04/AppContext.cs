using System.Text.Json.Serialization;

namespace Recto.Shared.Protocol.V04;

/// <summary>
/// Operator-administered identity of the application that submitted
/// a phone-rendered <see cref="PendingRequest"/>. Mirror of
/// <c>recto.bootloader.state.AppContext</c> in Python.
///
/// <para>
/// Recto is public-OSS, designed to be used alongside any
/// application -- a single Recto-equipped phone might be paired
/// with bootloaders for multiple apps (a media review platform, a
/// banking app, a self-hosted password manager, a CI runner that
/// needs commit signing, etc.). Without <c>AppContext</c>, the
/// operator would see opaque agent_ids on the approval card
/// ("agent:darwin@staging") and have to infer which app each one
/// belongs to. With it, the phone shows the app's name, brief
/// description, icon, and homepage URL at the top of every approval
/// card, so the operator knows which app is asking before granting
/// any capability or signing operation.
/// </para>
///
/// <para>
/// Each consumer registers its <c>AppContext</c> once at deploy time
/// (typically via service.yaml or a CLI command); the bootloader
/// injects the matching context into every <see cref="PendingRequest"/>
/// at queue time. The phone trusts the bootloader's identification
/// (the Ed25519 envelope already proves the request came from the
/// paired bootloader); within that trust scope, AppContext is
/// authoritative.
/// </para>
///
/// <para>
/// Optional fields (<see cref="AppUrl"/>, <see cref="AppIconUrl"/>,
/// <see cref="AppVersion"/>) are null when the consumer didn't
/// populate them at registration time. Required fields are
/// <see cref="AppId"/> + <see cref="AppName"/>; when AppContext is
/// present at all, those are guaranteed non-empty.
/// </para>
///
/// <para>
/// When <see cref="PendingRequestContext.AppContext"/> is null
/// (no AppContext was registered for the requesting principal),
/// the phone's render arm shows an "Unknown app" warning banner
/// rather than a nice display, so unregistered agents are visible
/// rather than silently approved.
/// </para>
/// </summary>
public sealed record AppContext(
    [property: JsonPropertyName("app_id")] string AppId,
    [property: JsonPropertyName("app_name")] string AppName,
    [property: JsonPropertyName("app_description")] string AppDescription = "",
    [property: JsonPropertyName("app_url")] string? AppUrl = null,
    [property: JsonPropertyName("app_icon_url")] string? AppIconUrl = null,
    [property: JsonPropertyName("app_version")] string? AppVersion = null);
