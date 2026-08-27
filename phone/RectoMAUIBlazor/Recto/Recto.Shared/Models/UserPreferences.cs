namespace Recto.Shared.Models;

/// <summary>
/// User-tunable phone-side settings. Persisted to MAUI <c>Preferences</c>
/// (not SecureStorage; these aren't secrets and don't need biometric gate
/// to read). Defaults are chosen so the first-launch experience is good
/// without any settings configuration; the operator only needs to visit
/// the settings page to deviate from defaults.
/// <para>
/// This is a plain class with mutable properties (rather than a positional
/// record) because Razor's <c>@bind</c> two-way binding needs settable
/// properties. Init-only properties (the default for record positional
/// parameters) can't be assigned outside an object initializer / ctor /
/// init accessor.
/// </para>
/// </summary>
public sealed class UserPreferences
{
    /// <summary>
    /// How often the phone polls the bootloader for pending requests.
    /// Default 3. Set to 0 to disable polling entirely (push-only mode).
    /// </summary>
    public int PollingIntervalSeconds { get; set; } = 3;

    /// <summary>
    /// Max number of audit-log events to fetch when displaying history.
    /// Default 50.
    /// </summary>
    public int AuditHistoryLimit { get; set; } = 50;

    /// <summary>
    /// One of "system" / "light" / "dark". Default "system".
    /// </summary>
    public string ThemePreference { get; set; } = "system";
}
