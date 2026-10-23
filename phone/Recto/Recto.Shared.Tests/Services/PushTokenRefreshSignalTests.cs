using System;
using Recto.Shared.Services;
using Xunit;

namespace Recto.Shared.Tests.Services;

/// <summary>
/// A rotated platform token (Android's <c>OnNewToken</c>, an iOS token that
/// arrives with no fetch waiting) asks for a send. With a listener the send
/// runs now; with none the request waits for the next launch or resume.
/// </summary>
public class PushTokenRefreshSignalTests
{
    public PushTokenRefreshSignalTests()
    {
        // The signal is process-wide; start each test from a clean slate.
        new InMemoryPushTokenRefreshSignal().TryConsumeDue();
    }

    [Fact]
    public void ANewTokenWithNoListener_IsKeptDueForTheNextResume()
    {
        var signal = new InMemoryPushTokenRefreshSignal();

        InMemoryPushTokenRefreshSignal.MarkDueGlobal();

        Assert.True(signal.TryConsumeDue());
        Assert.False(signal.TryConsumeDue());
    }

    [Fact]
    public void ANewTokenWithAListener_RunsTheSendNow()
    {
        var signal = new InMemoryPushTokenRefreshSignal();
        var raised = 0;
        Action handler = () => raised++;
        signal.RefreshRequested += handler;
        try
        {
            InMemoryPushTokenRefreshSignal.MarkDueGlobal();
        }
        finally
        {
            signal.RefreshRequested -= handler;
        }

        Assert.Equal(1, raised);
        Assert.False(signal.TryConsumeDue());
    }

    [Fact]
    public void AListenerThatThrows_NeverReachesThePlatformCallback()
    {
        var signal = new InMemoryPushTokenRefreshSignal();
        Action handler = () => throw new InvalidOperationException("listener fault");
        signal.RefreshRequested += handler;
        try
        {
            InMemoryPushTokenRefreshSignal.MarkDueGlobal();
        }
        finally
        {
            signal.RefreshRequested -= handler;
        }

        // The send it asked for is still owed.
        Assert.True(signal.TryConsumeDue());
    }

    [Fact]
    public void AnUnsubscribedListener_IsNotCalled()
    {
        var signal = new InMemoryPushTokenRefreshSignal();
        var raised = 0;
        Action handler = () => raised++;
        signal.RefreshRequested += handler;
        signal.RefreshRequested -= handler;

        InMemoryPushTokenRefreshSignal.MarkDueGlobal();

        Assert.Equal(0, raised);
        Assert.True(signal.TryConsumeDue());
    }
}
