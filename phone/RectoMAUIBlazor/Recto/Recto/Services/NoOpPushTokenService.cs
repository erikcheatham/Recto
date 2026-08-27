using System.Threading;
using System.Threading.Tasks;
using Recto.Shared.Common;
using Recto.Shared.Services;

namespace Recto.Services;

/// <summary>
/// Push-token service that returns null on platforms with no push transport
/// (Windows desktop, Mac Catalyst dev hosts). The bootloader falls back to
/// the 3s poll cycle for these phones, which is fine for dev iteration.
/// </summary>
public sealed class NoOpPushTokenService : IPushTokenService
{
    public Task<Result<PushToken?>> GetTokenAsync(CancellationToken ct)
        => Task.FromResult(Result.Success<PushToken?>(null));
}
