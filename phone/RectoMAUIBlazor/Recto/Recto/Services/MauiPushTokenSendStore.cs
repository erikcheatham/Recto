using System.Threading;
using System.Threading.Tasks;
using Recto.Shared.Services;

namespace Recto.Services;

/// <summary>
/// <see cref="IPushTokenSendStore"/> backed by MAUI's <see cref="Preferences"/>
/// (not SecureStorage: the values are hashes, not secrets). One key per phone
/// and bootloader; the value is a <see cref="PushTokenSync.TokenHash"/>, never
/// the token.
/// </summary>
public sealed class MauiPushTokenSendStore : IPushTokenSendStore
{
    private const string KeyPrefix = "recto.push_token.sent.v1:";

    public Task<string?> GetLastSentHashAsync(string bootloaderKey, CancellationToken ct)
    {
        var value = Preferences.Default.Get(KeyPrefix + bootloaderKey, string.Empty);
        return Task.FromResult<string?>(string.IsNullOrEmpty(value) ? null : value);
    }

    public Task SetLastSentHashAsync(string bootloaderKey, string tokenHash, CancellationToken ct)
    {
        Preferences.Default.Set(KeyPrefix + bootloaderKey, tokenHash);
        return Task.CompletedTask;
    }

    public Task ForgetAsync(string bootloaderKey, CancellationToken ct)
    {
        Preferences.Default.Remove(KeyPrefix + bootloaderKey);
        return Task.CompletedTask;
    }
}
