using System;
using System.Threading;

namespace Recto.Shared.Services;

/// <summary>
/// Process-memory implementation of <see cref="IPushTokenRefreshSignal"/>.
/// Singleton-registered; the DI-injected instance and the static
/// <see cref="MarkDueGlobal"/> share one class-level event and one due flag,
/// so a platform callback can ask for a send without a resolved container
/// (the <see cref="InMemoryPushWakeSignal"/> pattern).
/// </summary>
public sealed class InMemoryPushTokenRefreshSignal : IPushTokenRefreshSignal
{
    private static event Action? s_refreshRequested;
    private static int s_due;

    /// <summary>
    /// Ask for a push-token send. Raises the event when a listener exists;
    /// otherwise, or when a listener throws, the request is kept as due.
    /// Never throws: platform callbacks call this.
    /// </summary>
    public static void MarkDueGlobal()
    {
        var handler = s_refreshRequested;
        if (handler is null)
        {
            Volatile.Write(ref s_due, 1);
            return;
        }
        try
        {
            handler.Invoke();
        }
        catch
        {
            Volatile.Write(ref s_due, 1);
        }
    }

    public bool TryConsumeDue() => Interlocked.Exchange(ref s_due, 0) == 1;

    public event Action? RefreshRequested
    {
        add => s_refreshRequested += value;
        remove => s_refreshRequested -= value;
    }
}
