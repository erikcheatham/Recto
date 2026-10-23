using System.Collections.Generic;
using Recto.Shared.Services;
using Xunit;

namespace Recto.Shared.Tests.Services;

/// <summary>
/// The screen-capture guard behind the recovery phrase (FLAG_SECURE on
/// Android): set while any holder protects the screen, cleared when the last
/// one lets go, and never cleared by a holder that already let go.
/// </summary>
public class ScreenCaptureGuardTests
{
    [Fact]
    public void Protect_SetsTheFlag_AndReleasingClearsIt()
    {
        var guard = new RecordingGuard();

        var hold = guard.Protect();
        Assert.True(guard.IsProtected);
        hold.Dispose();

        Assert.False(guard.IsProtected);
        Assert.Equal(new[] { true, false }, guard.Applied);
    }

    [Fact]
    public void OverlappingHolders_ClearOnlyWhenTheLastOneLeaves()
    {
        var guard = new RecordingGuard();

        var a = guard.Protect();
        var b = guard.Protect();
        a.Dispose();
        Assert.True(guard.IsProtected);
        Assert.Equal(new[] { true }, guard.Applied);

        b.Dispose();
        Assert.False(guard.IsProtected);
        Assert.Equal(new[] { true, false }, guard.Applied);
    }

    [Fact]
    public void ReleasingTwice_DoesNotClearAnotherHoldersProtection()
    {
        var guard = new RecordingGuard();

        var a = guard.Protect();
        var b = guard.Protect();
        a.Dispose();
        a.Dispose();

        Assert.True(guard.IsProtected);
        Assert.Equal(new[] { true }, guard.Applied);
        b.Dispose();
        Assert.Equal(new[] { true, false }, guard.Applied);
    }

    [Fact]
    public void ProtectingAgainAfterRelease_SetsTheFlagAgain()
    {
        var guard = new RecordingGuard();

        guard.Protect().Dispose();
        guard.Protect().Dispose();

        Assert.Equal(new[] { true, false, true, false }, guard.Applied);
    }

    [Fact]
    public void TheNullGuard_KeepsTheContract_WithoutAPlatform()
    {
        IScreenCaptureGuard guard = new NullScreenCaptureGuard();

        var hold = guard.Protect();
        Assert.True(guard.IsProtected);
        hold.Dispose();
        Assert.False(guard.IsProtected);
    }

    // ------------------------------------------------------------------
    // a page's hold: follows show/hide, and ends with the page
    // ------------------------------------------------------------------

    [Fact]
    public void APageHold_FollowsShowAndHide_AndRepeatsChangeNothing()
    {
        var guard = new RecordingGuard();
        var page = new ScreenCaptureHold(guard);

        page.Set(true);
        page.Set(true);
        Assert.True(guard.IsProtected);
        Assert.True(page.IsHeld);

        page.Set(false);
        page.Set(false);
        Assert.False(guard.IsProtected);
        Assert.Equal(new[] { true, false }, guard.Applied);
    }

    [Fact]
    public void APageLeftWhileShowing_LetsTheScreenGo()
    {
        var guard = new RecordingGuard();
        var page = new ScreenCaptureHold(guard);

        page.Set(true);
        page.Dispose();

        Assert.False(guard.IsProtected);
        Assert.False(page.IsHeld);
        Assert.Equal(new[] { true, false }, guard.Applied);
    }

    [Fact]
    public void AShowRequestedAfterThePageIsGone_IsRefused_AndTheScreenStaysClear()
    {
        // The page was left while an await was in flight; the await finishes
        // and asks to show the phrase. No hold may be taken: nothing would
        // ever release it.
        var guard = new RecordingGuard();
        var page = new ScreenCaptureHold(guard);

        page.Dispose();
        page.Set(true);

        Assert.True(page.IsDisposed);
        Assert.False(page.IsHeld);
        Assert.False(guard.IsProtected);
        Assert.Empty(guard.Applied);
    }

    [Fact]
    public void AFreshPageAfterALateShowRequest_StillClearsTheScreenWhenItLeaves()
    {
        var guard = new RecordingGuard();
        var gone = new ScreenCaptureHold(guard);
        gone.Dispose();
        gone.Set(true);

        var next = new ScreenCaptureHold(guard);
        next.Set(true);
        next.Dispose();

        Assert.False(guard.IsProtected);
        Assert.Equal(new[] { true, false }, guard.Applied);
    }

    private sealed class RecordingGuard : ScreenCaptureGuard
    {
        public List<bool> Applied { get; } = new();
        protected override void Apply(bool secure) => Applied.Add(secure);
    }
}
