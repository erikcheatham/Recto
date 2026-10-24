using System.Threading;
using System.Threading.Tasks;

namespace Recto.Shared.Services;

/// <summary>
/// Remembers, per phone and bootloader, a hash of the last push token this
/// phone successfully sent there, so <see cref="PushTokenSync"/> sends once
/// per change rather than on every launch. It holds hashes only: a raw token
/// is never written here.
/// </summary>
public interface IPushTokenSendStore
{
    /// <summary>The hash last recorded for <paramref name="bootloaderKey"/>, or null.</summary>
    Task<string?> GetLastSentHashAsync(string bootloaderKey, CancellationToken ct);

    /// <summary>Records <paramref name="tokenHash"/> (a <see cref="PushTokenSync.TokenHash"/>) as sent.</summary>
    Task SetLastSentHashAsync(string bootloaderKey, string tokenHash, CancellationToken ct);

    /// <summary>Drops the record, so the next sync sends whatever token it finds.</summary>
    Task ForgetAsync(string bootloaderKey, CancellationToken ct);
}
