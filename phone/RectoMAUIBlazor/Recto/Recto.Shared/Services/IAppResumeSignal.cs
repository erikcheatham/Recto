using System;

namespace Recto.Shared.Services;

/// <summary>
/// Raised when the app comes back to the foreground after the OS stopped it
/// (MAUI <c>Window.Resumed</c>). Not raised on a cold launch: the page's own
/// initialization covers that. A resumed page re-sends a changed push token
/// and fetches pending at once instead of waiting out the poll interval, so a
/// reply held across a long freeze is replaced by a fresh one.
///
/// <para>Same static-bridge shape and listener rules as
/// <see cref="IPushWakeSignal"/>.</para>
/// </summary>
public interface IAppResumeSignal
{
    /// <summary>Fires when the app returns to the foreground.</summary>
    event Action? Resumed;
}
