using System;

namespace Recto.Shared.Services;

/// <summary>
/// Process-memory implementation of <see cref="IAppResumeSignal"/>: the
/// host's window raises <see cref="SignalResumedGlobal"/>, and the DI-injected
/// instance's event forwards to the same static field (the
/// <see cref="InMemoryPushWakeSignal"/> pattern).
/// </summary>
public sealed class InMemoryAppResumeSignal : IAppResumeSignal
{
    private static event Action? s_resumed;

    /// <summary>Raise the resume signal. Never throws back into the host.</summary>
    public static void SignalResumedGlobal()
    {
        var handler = s_resumed;
        try
        {
            handler?.Invoke();
        }
        catch
        {
            // A lifecycle callback must not fail because a listener did.
        }
    }

    public event Action? Resumed
    {
        add => s_resumed += value;
        remove => s_resumed -= value;
    }
}
