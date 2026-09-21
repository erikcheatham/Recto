using System.Threading.Tasks;
using Microsoft.Maui.Storage;

namespace Recto.Services;

/// <summary>
/// Thin wrapper over <see cref="SecureStorage"/>. All targets — real iOS,
/// Android, Windows, Mac Catalyst — use platform SecureStorage unchanged.
/// <para>
/// HISTORY (2026-08-05): this class previously carried an iOS-Simulator
/// file-storage fallback (plaintext on disk, runtime-gated on
/// <c>DeviceType.Virtual</c>) to dodge the simulator's
/// <c>errSecMissingEntitlement</c> Keychain failure during screenshot
/// capture and dev smoke. That path was REMOVED together with the
/// simulator's SoftwareEnclaveKeyService branch: plaintext-at-rest code
/// must not exist in a production binary, even behind a runtime check.
/// Simulator runs now hit the real Keychain failure by design — key work
/// rides real hardware. The wrapper itself stays so the six call sites
/// keep a single storage seam (and so any future storage policy change
/// lands in one file).
/// </para>
/// </summary>
public static class ResilientStorage
{
    public static Task<string?> GetAsync(string key)
        => SecureStorage.Default.GetAsync(key);

    public static Task SetAsync(string key, string value)
        => SecureStorage.Default.SetAsync(key, value);

    public static bool Remove(string key)
        => SecureStorage.Default.Remove(key);

    /// <summary>
    /// Wipes every entry in the app's SecureStorage namespace. Used by
    /// <c>MauiTotpService.ClearAllAsync</c> as the canonical Settings
    /// "Unpair all" emergency wipe — clears TOTP secrets AND the pairing
    /// record in one step (they share the SecureStorage namespace).
    /// </summary>
    public static void RemoveAll()
        => SecureStorage.Default.RemoveAll();
}
