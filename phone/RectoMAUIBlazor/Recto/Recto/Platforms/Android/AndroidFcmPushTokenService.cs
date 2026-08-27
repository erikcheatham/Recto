using System;
using System.Threading.Tasks;
using Android.Gms.Tasks;
using Firebase.Messaging;
using Recto.Shared.Common;
using Recto.Shared.Services;
// NOTE: deliberately NOT importing System.Threading at file-scope; pulling
// it in alongside Android.Gms.Tasks creates a CancellationToken ambiguity
// (both namespaces define one). The interface signature uses .NET's
// CancellationToken, so we fully-qualify it on the public method below
// and use the unambiguous Android.Gms.Tasks types directly elsewhere.
using DotNetCancellationToken = System.Threading.CancellationToken;

namespace Recto.Platforms.AndroidImpl;

/// <summary>
/// Android push-token service backed by Firebase Cloud Messaging. Returns
/// the device-specific FCM registration token used by the bootloader to
/// send wakeup pushes when a pending request lands.
/// <para>
/// The token can rotate per Google's recommendation (uninstall/reinstall,
/// app data wipe, restoration from backup). The phone is expected to
/// re-register the token after each app startup; the bootloader's
/// <c>POST /v0.4/manage/push_token</c> endpoint handles in-place
/// updates.
/// </para>
/// </summary>
public sealed class AndroidFcmPushTokenService : IPushTokenService
{
    public async Task<Result<PushToken?>> GetTokenAsync(DotNetCancellationToken ct)
    {
        try
        {
            // FirebaseMessaging.GetToken() returns a Google Play Services Task<string>.
            // Wrap it in a TaskCompletionSource so we can await it from .NET.
            var fcmTask = FirebaseMessaging.Instance.GetToken();
            var tcs = new TaskCompletionSource<string?>(TaskCreationOptions.RunContinuationsAsynchronously);

            ct.Register(() => tcs.TrySetCanceled(ct));

            fcmTask.AddOnSuccessListener(new SuccessListener(token => tcs.TrySetResult(token?.ToString())));
            fcmTask.AddOnFailureListener(new FailureListener(ex => tcs.TrySetException(ex)));
            fcmTask.AddOnCanceledListener(new CanceledListener(() => tcs.TrySetCanceled(ct)));

            var token = await tcs.Task.ConfigureAwait(false);
            if (string.IsNullOrEmpty(token))
            {
                return Result.Failure<PushToken?>(Error.Failure("FCM returned an empty token."));
            }
            return Result.Success<PushToken?>(new PushToken(token, PushPlatform.Fcm));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return Result.Failure<PushToken?>(Error.Failure("FCM token fetch was cancelled."));
        }
        catch (Exception ex)
        {
            return Result.Failure<PushToken?>(Error.Failure(
                $"FCM token fetch failed: {ex.GetType().Name}: {ex.Message}"));
        }
    }

    private sealed class SuccessListener : Java.Lang.Object, IOnSuccessListener
    {
        private readonly Action<Java.Lang.Object?> _onSuccess;
        public SuccessListener(Action<Java.Lang.Object?> onSuccess) => _onSuccess = onSuccess;
        public void OnSuccess(Java.Lang.Object? result) => _onSuccess(result);
    }

    private sealed class FailureListener : Java.Lang.Object, IOnFailureListener
    {
        private readonly Action<Java.Lang.Exception> _onFailure;
        public FailureListener(Action<Java.Lang.Exception> onFailure) => _onFailure = onFailure;
        public void OnFailure(Java.Lang.Exception ex) => _onFailure(ex);
    }

    private sealed class CanceledListener : Java.Lang.Object, IOnCanceledListener
    {
        private readonly Action _onCanceled;
        public CanceledListener(Action onCanceled) => _onCanceled = onCanceled;
        public void OnCanceled() => _onCanceled();
    }
}
