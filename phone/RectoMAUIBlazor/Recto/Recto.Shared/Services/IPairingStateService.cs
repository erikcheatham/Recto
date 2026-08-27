using System.Threading;
using System.Threading.Tasks;
using Recto.Shared.Common;
using Recto.Shared.Models;

namespace Recto.Shared.Services;

/// <summary>
/// Persists pairing state across app launches. Backing store is platform-
/// specific (MAUI SecureStorage on the phone host); the abstraction lets
/// future surfaces (CLI helper, desktop pairing assistant) plug in their own.
/// </summary>
public interface IPairingStateService
{
    /// <summary>Returns the current pairing if any, or <c>null</c> when unpaired.</summary>
    Task<Result<PairingState?>> GetCurrentAsync(CancellationToken ct);

    /// <summary>Persists <paramref name="state"/> as the current pairing.</summary>
    Task<Result> SaveAsync(PairingState state, CancellationToken ct);

    /// <summary>Removes the current pairing record. Does not delete enclave keys.</summary>
    Task<Result> ClearAsync(CancellationToken ct);

    /// <summary>Gets the persistent phone identifier, minting a fresh uuid4 on first call.</summary>
    Task<Result<string>> GetOrCreatePhoneIdAsync(CancellationToken ct);
}
