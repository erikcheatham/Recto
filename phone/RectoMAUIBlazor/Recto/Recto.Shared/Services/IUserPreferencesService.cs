using System.Threading;
using System.Threading.Tasks;
using Recto.Shared.Models;

namespace Recto.Shared.Services;

/// <summary>
/// Phone-side user preferences. Backed by MAUI's <c>Preferences</c> on
/// device hosts; in-memory only on Windows / Mac Catalyst dev builds.
/// </summary>
public interface IUserPreferencesService
{
    /// <summary>
    /// Loads the persisted preferences, or returns defaults if none have
    /// been saved yet (first launch).
    /// </summary>
    Task<UserPreferences> LoadAsync(CancellationToken ct);

    /// <summary>
    /// Persists the preferences. Overwrites any existing record.
    /// </summary>
    Task SaveAsync(UserPreferences preferences, CancellationToken ct);
}
