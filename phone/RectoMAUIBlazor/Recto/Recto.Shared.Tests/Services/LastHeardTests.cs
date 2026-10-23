using System;
using Recto.Shared.Services;
using Xunit;

namespace Recto.Shared.Tests.Services;

/// <summary>
/// Pairing details says, as a relative time, when the phone last had a
/// verified reply from its bootloader.
/// </summary>
public class LastHeardTests
{
    private static readonly DateTimeOffset Now = new(2030, 1, 2, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void NothingHeardYet_SaysSo()
    {
        Assert.Equal("not yet since the app opened", LastHeard.Describe(null, Now));
    }

    [Theory]
    [InlineData(0, "just now")]
    [InlineData(9, "just now")]
    [InlineData(10, "10 s ago")]
    [InlineData(59, "59 s ago")]
    [InlineData(60, "1 min ago")]
    [InlineData(59 * 60 + 59, "59 min ago")]
    [InlineData(60 * 60, "1 h ago")]
    [InlineData(47 * 3600 + 3599, "47 h ago")]
    [InlineData(48 * 3600, "2 days ago")]
    [InlineData(19 * 86400, "19 days ago")]
    public void AnAge_ReadsAsARelativeTime(int secondsAgo, string expected)
    {
        Assert.Equal(expected, LastHeard.Describe(Now.AddSeconds(-secondsAgo), Now));
    }

    [Fact]
    public void AStampFromTheFuture_ReadsAsJustNow()
    {
        // The wall clock can step back (a time-zone or NTP correction).
        Assert.Equal("just now", LastHeard.Describe(Now.AddMinutes(5), Now));
    }
}
