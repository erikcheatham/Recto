using Android.Views;
using Recto.Shared.Services;

namespace Recto.Platforms.AndroidImpl;

/// <summary>
/// <see cref="IScreenCaptureGuard"/> on Android: the activity window's
/// FLAG_SECURE, which blanks the Recents thumbnail and blocks screenshots and
/// screen recording while it is set. Window flags belong to the UI thread;
/// a call from another thread is posted there, and one already on it runs at
/// once.
/// </summary>
public sealed class AndroidScreenCaptureGuard : ScreenCaptureGuard
{
    protected override void Apply(bool secure)
    {
        MainThread.BeginInvokeOnMainThread(() =>
        {
            var window = Microsoft.Maui.ApplicationModel.Platform.CurrentActivity?.Window;
            if (window is null) return;
            if (secure)
            {
                window.AddFlags(WindowManagerFlags.Secure);
            }
            else
            {
                window.ClearFlags(WindowManagerFlags.Secure);
            }
        });
    }
}
