using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.OS;
using Recto.Shared.Services;

namespace Recto;

// ---------------------------------------------------------------------------
// MainActivity — extended 2026-05-31 with recto:// URL-scheme intent
// handler (Task #22 Phase 1). Cold-launch path: OS routes recto://pair?...
// intent through OnCreate (Intent.Data carries the URL). Warm-launch path
// (app already running): OS calls OnNewIntent with the new intent without
// re-running OnCreate. Both paths funnel through ProcessIntent which
// parses via the shared PairDeepLinkParser and pushes to the singleton
// InMemoryPairDeepLinkState. Sister of the iOS AppDelegate.OpenUrl: handler.
// ---------------------------------------------------------------------------

[Activity(
    Theme = "@style/Maui.SplashTheme",
    MainLauncher = true,
    Exported = true,
    LaunchMode = LaunchMode.SingleTask,
    ConfigurationChanges = ConfigChanges.ScreenSize | ConfigChanges.Orientation | ConfigChanges.UiMode | ConfigChanges.ScreenLayout | ConfigChanges.SmallestScreenSize | ConfigChanges.Density)]
// recto://pair?code=X&bootloader=Y intent-filter — registers the activity as
// the OS-level handler for the recto:// custom scheme with "pair" host. The
// android.intent.action.VIEW + DEFAULT + BROWSABLE categories together
// describe "this activity can be opened by tapping a URL of this scheme
// from another app or the system" per Android's intent-filter conventions.
// AutoVerify=true lets Play Console assert the filter at install time so
// the OS routes without a chooser dialog (sister of Apple's Universal Links
// assert).
//
// LaunchMode = SingleTask (banked Build 8, 2026-06-03 night after Pixel
// warm-start deep-link bug). UPGRADED from SingleTop. The SingleTop
// semantic is "reuse existing instance ONLY IF it's at the top of its
// task" — which fails when Google Camera fires the deep-link intent with
// Intent.FLAG_ACTIVITY_NEW_TASK (so the URL doesn't pollute Camera's
// own back-stack). With NEW_TASK + SingleTop, Android can decide to
// spawn a brand-new MainActivity in a brand-new task if the existing
// Recto task has been buried under other apps in recents — producing
// the "Recto opens on top of its own app" visual artifact (two Recto
// tasks in the recents stack, neither holds the deep-link payload).
// SingleTask semantic is stricter: at most ONE MainActivity exists
// system-wide; new intents ALWAYS route to it via OnNewIntent; Android
// brings the existing task forward (popping any activities on top, of
// which there are none for our single-activity app). Handles the
// Camera+NEW_TASK + buried-in-recents + foregrounded + backgrounded
// cases uniformly. Cold-launch still routes through OnCreate (Intent.Data
// carries the URL); warm-launch ALWAYS routes through OnNewIntent.
// Both paths funnel through ProcessIntent below.
[IntentFilter(
    new[] { Intent.ActionView },
    Categories = new[] { Intent.CategoryDefault, Intent.CategoryBrowsable },
    DataScheme = "recto",
    DataHost = "pair",
    AutoVerify = true)]
public class MainActivity : MauiAppCompatActivity
{
    /// <summary>
    /// Cold-launch entry point. If the OS launched us in response to a
    /// recto://... intent tap, Intent.Data carries the URL and we
    /// process it before the Blazor render lifecycle kicks in.
    /// InMemoryPairDeepLinkState's static-state backing means
    /// Home.razor.OnInitializedAsync sees the pending payload regardless
    /// of how early in app-bootstrap we hand it off.
    /// </summary>
    protected override void OnCreate(Bundle? savedInstanceState)
    {
        base.OnCreate(savedInstanceState);
        ProcessIntent(Intent);
    }

    /// <summary>
    /// Warm-launch entry point. Called by Android when the activity is
    /// already running and a new intent arrives (the user taps another
    /// recto:// URL while Recto Phone is foreground OR backgrounded).
    /// LaunchMode=SingleTask on the [Activity] attribute is what causes
    /// Android to call this instead of stacking a fresh MainActivity —
    /// even when Camera fires with FLAG_ACTIVITY_NEW_TASK (Build 8 fix
    /// for the Pixel "Recto opens on top of itself" bug).
    /// </summary>
    protected override void OnNewIntent(Intent? intent)
    {
        base.OnNewIntent(intent);
        // Android also updates the activity's Intent property to the new
        // one so subsequent reads see the latest — but we process the
        // explicit parameter to avoid coupling to that side effect.
        ProcessIntent(intent);
    }

    /// <summary>
    /// Shared cold/warm-launch intent processor. Pulls the URL from
    /// <see cref="Intent.DataString"/>, parses via the platform-agnostic
    /// <see cref="PairDeepLinkParser"/>, pushes the validated payload to
    /// <see cref="InMemoryPairDeepLinkState.SetGlobal"/>. Malformed URLs
    /// drop silently — same posture as iOS AppDelegate.OpenUrl per the
    /// IPairDeepLinkState design rationale.
    /// </summary>
    private static void ProcessIntent(Intent? intent)
    {
        if (intent is null) return;
        if (intent.Action != Intent.ActionView) return;
        var url = intent.DataString;
        var payload = PairDeepLinkParser.TryParse(url);
        if (payload is not null)
        {
            InMemoryPairDeepLinkState.SetGlobal(payload);
        }
    }
}
