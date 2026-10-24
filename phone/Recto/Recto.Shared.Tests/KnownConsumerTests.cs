using System;
using Recto.Shared.Services;
using Xunit;

namespace Recto.Shared.Tests;

/// <summary>
/// THE KNOWN CONSUMER IS THE BUILD'S (2026-09-21): the manifest parses whole or refuses by name; a build
/// carrying none reports so. The positive here is the parse, not the embed - whether a test host embeds a
/// manifest depends on the machine, and a test that read it would pass or fail by who ran it.
/// </summary>
public class KnownConsumerTests
{
    private const string Good = """
        {"base_url": "https://consumer.example/", "aud": "example", "app_id": "example",
         "app_name": "Example", "app_description": "An example consumer"}
        """;

    [Fact]
    public void A_manifest_parses_whole_and_composes_the_icon_url()
    {
        var m = KnownConsumer.Parse(Good);
        Assert.Equal("https://consumer.example", m.BaseUrl);   // trailing slash trimmed
        Assert.Equal("example", m.Aud);
        Assert.Equal("https://consumer.example/_content/Example.Shared/brand/example-logo-1024.png", m.AppIconUrl);
    }

    [Theory]
    [InlineData("""{"aud": "x", "app_id": "x", "app_name": "x", "app_description": "x"}""", "base_url")]
    [InlineData("""{"base_url": "https://c.example", "app_id": "x", "app_name": "x", "app_description": "x"}""", "aud")]
    [InlineData("""{"base_url": "https://c.example", "aud": "", "app_id": "x", "app_name": "x", "app_description": "x"}""", "aud")]
    public void A_manifest_missing_a_field_is_refused_by_name(string json, string field)
    {
        var ex = Assert.Throws<InvalidOperationException>(() => KnownConsumer.Parse(json));
        Assert.Contains($"'{field}'", ex.Message);
    }

    [Fact]
    public void A_manifest_with_a_non_https_origin_is_refused()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => KnownConsumer.Parse(
            """{"base_url": "http://c.example", "aud": "x", "app_id": "x", "app_name": "x", "app_description": "x"}"""));
        Assert.Contains("https", ex.Message);
    }

    [Fact]
    public void The_substrate_names_no_consumer_the_manifest_does_not()
    {
        // Configured or not, every value the page reads comes from the manifest - nothing is left over
        // from the constants era. When this host embeds none, Current is null and the page hides the surface.
        if (KnownConsumer.Current is { } m)
            Assert.StartsWith(m.BaseUrl, m.AppIconUrl);
        else
            Assert.False(KnownConsumer.IsConfigured);
    }
}
