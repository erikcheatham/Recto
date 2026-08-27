using Foundation;
using ObjCRuntime;
using Recto.Platforms.iOSImpl;
using Recto.Shared.Services;
using UIKit;

namespace Recto;

[Register("AppDelegate")]
public class AppDelegate : MauiUIApplicationDelegate
{
    protected override MauiApp CreateMauiApp() => MauiProgram.CreateMauiApp();

    /// <summary>
    /// Called by iOS when another app (Mail, Messages, Safari, etc.) or
    /// the OS itself opens a recto://... URL while Recto Phone is
    /// foreground OR cold-launched the app for it. We parse the URL via
    /// the shared <see cref="PairDeepLinkParser"/> and stash the
    /// validated payload in <see cref="InMemoryPairDeepLinkState"/>'s
    /// static state holder so <c>Home.razor.OnInitializedAsync</c> can
    /// consume it on first render.
    /// <para>
    /// Wired via <c>[Export]</c> selector rather than <c>override</c>
    /// because <see cref="MauiUIApplicationDelegate"/> doesn't expose
    /// <c>application:openURL:options:</c> as a virtual method in
    /// modern .NET MAUI bindings; the Objective-C runtime dispatches
    /// by selector regardless of CLR inheritance. Sister of the APNs
    /// callbacks below.
    /// </para>
    /// <para>
    /// Return TRUE so iOS knows we handled the URL. Returning FALSE
    /// would cause iOS to fall through to other registered handlers
    /// (which is fine for malformed URLs but defeats the
    /// PairDeepLinkParser-rejected-silently posture banked in
    /// IPairDeepLinkState.cs's design rationale).
    /// </para>
    /// </summary>
    [Export("application:openURL:options:")]
    public bool OpenUrl(UIApplication app, NSUrl url, NSDictionary options)
    {
        // NSUrl.AbsoluteString is the canonical string form including
        // scheme + host + query. Pass through the shared parser; null
        // return collapses to a no-op which is the right behavior for
        // malformed URLs.
        var raw = url?.AbsoluteString;
        var payload = PairDeepLinkParser.TryParse(raw);
        if (payload is not null)
        {
            InMemoryPairDeepLinkState.SetGlobal(payload);
        }
        // Return true regardless of whether the URL parsed cleanly —
        // we DID receive and process it (even if processing was "drop
        // it silently"). False would surface a "could not open" error
        // to the user from whatever app sent us the URL.
        return true;
    }

    /// <summary>
    /// Called by iOS after a successful APNs registration. Forwards the
    /// device token to <see cref="IosApnsPushTokenService"/> which resolves
    /// any pending fetch.
    /// <para>
    /// Wired via <c>[Export]</c> selector rather than <c>override</c>
    /// because <see cref="MauiUIApplicationDelegate"/>'s base class doesn't
    /// expose this as a virtual method in modern .NET MAUI iOS bindings;
    /// the Objective-C runtime dispatches by selector regardless of CLR
    /// inheritance.
    /// </para>
    /// </summary>
    [Export("application:didRegisterForRemoteNotificationsWithDeviceToken:")]
    public void RegisteredForRemoteNotifications(UIApplication application, NSData deviceToken)
    {
        IosApnsPushTokenService.OnRegisteredForRemoteNotifications(deviceToken);
    }

    /// <summary>
    /// Called by iOS when APNs registration fails (typically: missing push
    /// entitlement on the provisioning profile, or the bundle ID isn't
    /// configured for push in the Apple Developer Program).
    /// </summary>
    [Export("application:didFailToRegisterForRemoteNotificationsWithError:")]
    public void FailedToRegisterForRemoteNotifications(UIApplication application, NSError error)
    {
        IosApnsPushTokenService.OnFailedToRegisterForRemoteNotifications(error);
    }

    /// <summary>
    /// Build 12 (2026-07-11, wave-C consumer) — receives silent-push wakes
    /// from the bootloader on iOS. The bootloader sends a
    /// <c>content-available: 1</c> background push when a pending request
    /// lands; iOS calls this (even while backgrounded, given the
    /// <c>remote-notification</c> background mode + push entitlement), and we
    /// raise the process-wide wake signal so Home.razor fetches pending
    /// immediately instead of waiting out the poll interval.
    /// <para>
    /// Trust posture (Hard Rule #9): the push userInfo is NEVER trusted — we
    /// ignore it entirely and just nudge an authenticated fetch. Must call
    /// the completion handler promptly (iOS budgets ~30s and penalizes apps
    /// that don't); <see cref="UIBackgroundFetchResult.NewData"/> tells iOS
    /// the wake did useful work so it keeps granting background wakes.
    /// </para>
    /// <para>
    /// Wired via <c>[Export]</c> selector for the same reason as the APNs
    /// callbacks above — the base MAUI delegate doesn't surface this as a
    /// virtual method.
    /// </para>
    /// </summary>
    [Export("application:didReceiveRemoteNotification:fetchCompletionHandler:")]
    public void DidReceiveRemoteNotification(
        UIApplication application,
        NSDictionary userInfo,
        System.Action<UIBackgroundFetchResult> completionHandler)
    {
        InMemoryPushWakeSignal.SignalWakeGlobal();
        completionHandler(UIBackgroundFetchResult.NewData);
    }
}
