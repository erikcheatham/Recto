using Recto.Shared.Services;
using Xunit;

namespace Recto.Shared.Tests.Services;

/// <summary>The consumer's QR may carry the pairing record's fields (user_id, not_after);
/// the parser surfaces both or neither, and older QRs without them still parse.</summary>
public class PairDeepLinkRecordParamsTests
{
    private const string Base = "recto://pair?code=ABCD1234&bootstrap_bootloader=https%3A%2F%2Fbl.example&bootstrap_pair_code=482917";

    [Fact]
    public void RecordParams_AreSurfaced_WhenBothPresent()
    {
        var p = PairDeepLinkParser.TryParse(Base + "&user_id=0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0&not_after=1800000600");
        Assert.NotNull(p);
        Assert.True(p.HasRecord);
        Assert.Equal("0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0", p.UserId);
        Assert.Equal(1800000600, p.NotAfter);
        Assert.Equal("482917", p.BootstrapPairCode);
    }

    [Fact]
    public void OlderQr_WithoutRecordParams_StillParses_WithoutARecord()
    {
        var p = PairDeepLinkParser.TryParse(Base);
        Assert.NotNull(p);
        Assert.False(p.HasRecord);
        Assert.Null(p.UserId);
        Assert.Null(p.NotAfter);
    }

    [Theory]
    [InlineData("&user_id=u1")]
    [InlineData("&not_after=1800000600")]
    [InlineData("&user_id=u1&not_after=soon")]
    [InlineData("&user_id=u1&not_after=0")]
    public void HalfARecord_IsNoRecord(string tail)
    {
        var p = PairDeepLinkParser.TryParse(Base + tail);
        Assert.NotNull(p);
        Assert.False(p.HasRecord);
    }

    [Fact]
    public void BootloaderKind_IgnoresRecordParams()
    {
        var p = PairDeepLinkParser.TryParse("recto://pair?code=000000&bootloader=demo%3A%2F%2Frecto-app-review&kind=bootloader&user_id=u1&not_after=1800000600");
        Assert.NotNull(p);
        Assert.False(p.HasRecord);
    }
}
