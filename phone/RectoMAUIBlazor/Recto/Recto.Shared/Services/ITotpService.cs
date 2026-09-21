using System.Threading;
using System.Threading.Tasks;
using Recto.Shared.Common;

namespace Recto.Shared.Services;

/// <summary>
/// TOTP shared-secret management. Round-5 introduces this alongside
/// <see cref="IEnclaveKeyService"/> as the second kind of phone-side
/// credential the universal-vault model supports. Secrets persist in
/// platform secure storage; codes are computed via RFC 6238 from the
/// stored secret + current UTC time.
/// </summary>
public interface ITotpService
{
    /// <summary>
    /// Stores a base32-encoded TOTP shared secret under <paramref name="alias"/>.
    /// Overwrites any existing secret for that alias.
    /// </summary>
    Task<Result> ProvisionAsync(
        string alias,
        string secretB32,
        int periodSeconds,
        int digits,
        string algorithm,
        CancellationToken ct);

    /// <summary>True if a secret has been provisioned under <paramref name="alias"/>.</summary>
    Task<Result<bool>> ExistsAsync(string alias, CancellationToken ct);

    /// <summary>
    /// Generates the current TOTP code for <paramref name="alias"/> from
    /// the stored secret and parameters. Returns the zero-padded numeric
    /// string (e.g. <c>"012345"</c>).
    /// </summary>
    Task<Result<string>> GenerateAsync(string alias, CancellationToken ct);

    /// <summary>Removes the secret under <paramref name="alias"/>. No-op if absent.</summary>
    Task<Result> DeleteAsync(string alias, CancellationToken ct);

    /// <summary>
    /// Removes every TOTP secret on the phone. Used by the Settings
    /// "Unpair all" emergency wipe. Returns success even if no secrets
    /// were stored.
    /// </summary>
    Task<Result> ClearAllAsync(CancellationToken ct);
}
