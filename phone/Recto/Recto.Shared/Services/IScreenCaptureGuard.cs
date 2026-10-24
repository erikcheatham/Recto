using System;

namespace Recto.Shared.Services;

/// <summary>
/// Keeps the app's screen out of screenshots, screen recordings and the
/// app-switcher thumbnail while a secret is on it (the recovery phrase). On
/// Android this is the window's FLAG_SECURE; other platforms keep the
/// contract with no effect.
/// </summary>
public interface IScreenCaptureGuard
{
    /// <summary>
    /// Protects the screen until the returned handle is disposed. Holders may
    /// overlap; the screen stays protected until the last one lets go.
    /// Disposing a handle twice is harmless.
    /// </summary>
    IDisposable Protect();

    /// <summary>True while any holder protects the screen.</summary>
    bool IsProtected { get; }
}

/// <summary>
/// The counting half of <see cref="IScreenCaptureGuard"/>; a platform supplies
/// <see cref="Apply"/>. <c>Apply(true)</c> runs when the first holder arrives
/// and <c>Apply(false)</c> when the last one leaves, in that order, never twice
/// in a row.
/// </summary>
public abstract class ScreenCaptureGuard : IScreenCaptureGuard
{
    private readonly object _lock = new();
    private int _holders;

    public bool IsProtected
    {
        get { lock (_lock) return _holders > 0; }
    }

    public IDisposable Protect()
    {
        lock (_lock)
        {
            if (_holders++ == 0) Apply(true);
        }
        return new Hold(this);
    }

    /// <summary>Sets (true) or clears (false) the platform's protection.</summary>
    protected abstract void Apply(bool secure);

    private void Release()
    {
        lock (_lock)
        {
            if (_holders == 0) return;
            if (--_holders == 0) Apply(false);
        }
    }

    private sealed class Hold : IDisposable
    {
        private ScreenCaptureGuard? _owner;
        public Hold(ScreenCaptureGuard owner) => _owner = owner;
        public void Dispose() => System.Threading.Interlocked.Exchange(ref _owner, null)?.Release();
    }
}

/// <summary>
/// One page's claim on an <see cref="IScreenCaptureGuard"/>, following the
/// page's show/hide state: <see cref="Set"/>(true) takes a single hold and
/// Set(false) lets it go; repeats change nothing. Once the page is disposed a
/// request to protect is refused, so an await that finishes after the page
/// has gone cannot leave the screen protected for the rest of the process.
/// </summary>
public sealed class ScreenCaptureHold : IDisposable
{
    private readonly IScreenCaptureGuard _guard;
    private IDisposable? _hold;

    public ScreenCaptureHold(IScreenCaptureGuard guard) => _guard = guard;

    /// <summary>True once <see cref="Dispose"/> has run.</summary>
    public bool IsDisposed { get; private set; }

    /// <summary>True while this claim holds the guard.</summary>
    public bool IsHeld => _hold is not null;

    /// <summary>Protects the screen (true) or lets it go (false).</summary>
    public void Set(bool protect)
    {
        if (protect && !IsDisposed)
        {
            _hold ??= _guard.Protect();
            return;
        }
        _hold?.Dispose();
        _hold = null;
    }

    public void Dispose()
    {
        IsDisposed = true;
        _hold?.Dispose();
        _hold = null;
    }
}

/// <summary>
/// <see cref="IScreenCaptureGuard"/> for platforms with no window flag to set
/// (iOS, Windows and Mac Catalyst dev hosts): it counts holders and does
/// nothing else.
/// </summary>
public sealed class NullScreenCaptureGuard : ScreenCaptureGuard
{
    protected override void Apply(bool secure)
    {
    }
}
