using System.Text.Json;

namespace Recto.Shared.Services;

/// <summary>
/// THE KNOWN CONSUMER IS DEPLOYMENT CONFIG, NOT SUBSTRATE (2026-09-21). v1 hardcoded one consumer
/// (host, audience, app id, name, tagline) as constants in Home.razor - which put a sibling project's
/// name and origin into this public tree, where the history sweep found it twice and the tree carried
/// it for a year. The substrate does not know who consumes it; the BUILD does. A maintainer drops
/// <c>Resources/KnownConsumer/known-consumer.json</c> beside the example (git-ignored; the csproj embeds
/// it only when it exists) and the store build carries that one consumer. No file = no known consumer:
/// the "Add a service" card says so and the pair-a-service flow is not offered. Nothing else changes -
/// pairing, signing and the bootloader relay are consumer-agnostic already.
/// </summary>
public static class KnownConsumer
{
    public const string ResourceName = "Recto.Shared.Resources.KnownConsumer.known-consumer.json";

    /// <summary>One consumer, as the build carries it. Every field required; the icon URL is composed.</summary>
    public sealed record Manifest(string BaseUrl, string Aud, string AppId, string AppName, string AppDescription)
    {
        /// <summary>The consumer serves its brand folder as a Blazor static web asset at
        /// /_content/&lt;SharedAssemblyName&gt;/brand/&lt;appId&gt;-logo-1024.png (INTEGRATION.md). Composed here so
        /// the host and the name each appear in exactly one place - the manifest.</summary>
        public string AppIconUrl => $"{BaseUrl}/_content/{AppName}.Shared/brand/{AppId}-logo-1024.png";
    }

    private static readonly Lazy<Manifest?> _current = new(Load);

    /// <summary>The build's consumer, or null when the build carries none.</summary>
    public static Manifest? Current => _current.Value;

    public static bool IsConfigured => Current is not null;

    /// <summary>Parse a manifest; refuses by name rather than half-loading (a consumer with no audience
    /// would mint a pairing JWS nobody can verify).</summary>
    public static Manifest Parse(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var r = doc.RootElement;
        string Need(string key)
        {
            if (!r.TryGetProperty(key, out var v) || v.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(v.GetString()))
                throw new InvalidOperationException($"known-consumer.json: '{key}' is required and must be a non-empty string.");
            return v.GetString()!.Trim();
        }
        var baseUrl = Need("base_url").TrimEnd('/');
        if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
            throw new InvalidOperationException("known-consumer.json: 'base_url' must be an absolute https URL.");
        return new Manifest(baseUrl, Need("aud"), Need("app_id"), Need("app_name"), Need("app_description"));
    }

    private static Manifest? Load()
    {
        var asm = typeof(KnownConsumer).Assembly;
        using var stream = asm.GetManifestResourceStream(ResourceName);
        if (stream is null) return null;   // the build carries no consumer - by design, not by accident
        using var reader = new StreamReader(stream);
        return Parse(reader.ReadToEnd());
    }
}
