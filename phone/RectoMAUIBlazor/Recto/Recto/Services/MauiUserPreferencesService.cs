using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Recto.Shared.Models;
using Recto.Shared.Services;

namespace Recto.Services;

/// <summary>
/// User-preferences service backed by MAUI's <see cref="Preferences"/>.
/// Single JSON blob under one key for simplicity; on phones with very
/// large preference sets we'd shard, but Recto's preferences fit in
/// &lt; 200 bytes so a single key is fine.
/// </summary>
public sealed class MauiUserPreferencesService : IUserPreferencesService
{
    private const string PreferenceKey = "recto.user_preferences.v1";

    public Task<UserPreferences> LoadAsync(CancellationToken ct)
    {
        var json = Preferences.Default.Get(PreferenceKey, string.Empty);
        if (string.IsNullOrEmpty(json))
        {
            return Task.FromResult(new UserPreferences());
        }
        try
        {
            var prefs = JsonSerializer.Deserialize<UserPreferences>(json);
            return Task.FromResult(prefs ?? new UserPreferences());
        }
        catch
        {
            // Corrupted preferences -- fall back to defaults rather than
            // crashing. The user can re-set their preferences from scratch.
            return Task.FromResult(new UserPreferences());
        }
    }

    public Task SaveAsync(UserPreferences preferences, CancellationToken ct)
    {
        var json = JsonSerializer.Serialize(preferences);
        Preferences.Default.Set(PreferenceKey, json);
        return Task.CompletedTask;
    }
}
