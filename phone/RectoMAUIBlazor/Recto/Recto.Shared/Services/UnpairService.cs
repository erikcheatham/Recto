using System;
using System.Threading;
using System.Threading.Tasks;
using Recto.Shared.Common;

namespace Recto.Shared.Services;

/// <summary>Outcome of a full-wipe attempt.</summary>
public enum UnpairAllStatus
{
    /// <summary>Wipe completed: pairing, TOTP secrets, and enclave key are gone.</summary>
    Completed,

    /// <summary>
    /// Refused: this phone is (or must be presumed) a genesis member, and
    /// the wipe would destroy a trust-root key. The message names the
    /// ceremony that is the legitimate route.
    /// </summary>
    RefusedGenesisMember,

    /// <summary>The wipe was attempted and a step failed.</summary>
    Failed
}

public sealed record UnpairAllResult(UnpairAllStatus Status, string? Message = null);

/// <summary>
/// The ONE full-wipe path. Every caller that intends to destroy the enclave
/// identity key routes through <see cref="UnpairAllAsync"/> — the guard
/// lives here, ahead of the first destructive call, so no UI surface can
/// reach the key deletion without passing it.
/// </summary>
public interface IUnpairService
{
    /// <summary>
    /// Wipes pairing state, TOTP secrets, and the enclave key under
    /// <paramref name="keyAlias"/> — unless this phone is a genesis member,
    /// in which case it refuses without touching anything.
    /// </summary>
    Task<UnpairAllResult> UnpairAllAsync(string keyAlias, CancellationToken ct);
}

public sealed class UnpairService : IUnpairService
{
    /// <summary>
    /// The refusal names the ceremony (the guard's contract): a refusal
    /// without a route gets worked around, not respected.
    /// </summary>
    public const string GenesisRefusalMessage =
        "This phone is a genesis member — its key helps constitute the trust root, " +
        "and \"Unpair all\" would destroy it unrecoverably. To retire this device, " +
        "run the recovery ceremony: restore from the recovery phrase, then re-enrol " +
        "the member set on the bootloader.";

    public const string FailClosedPrefix =
        "Genesis membership could not be read; refusing the wipe (fail closed). ";

    private readonly IPairingStateService _pairing;
    private readonly ITotpService _totp;
    private readonly IEnclaveKeyService _enclaveKeys;
    private readonly IGenesisStateService _genesis;

    public UnpairService(
        IPairingStateService pairing,
        ITotpService totp,
        IEnclaveKeyService enclaveKeys,
        IGenesisStateService genesis)
    {
        _pairing = pairing;
        _totp = totp;
        _enclaveKeys = enclaveKeys;
        _genesis = genesis;
    }

    public async Task<UnpairAllResult> UnpairAllAsync(string keyAlias, CancellationToken ct)
    {
        // THE GUARD — ahead of the first destructive call, fail-closed:
        // an unreadable marker is treated as membership, because the cost
        // of a wrong "no" is a retry and the cost of a wrong "yes" is a
        // destroyed trust-root member.
        var membership = await _genesis.IsGenesisMemberAsync(ct).ConfigureAwait(false);
        if (!membership.IsSuccess)
        {
            return new UnpairAllResult(
                UnpairAllStatus.RefusedGenesisMember,
                FailClosedPrefix + GenesisRefusalMessage);
        }

        if (membership.Value)
        {
            return new UnpairAllResult(UnpairAllStatus.RefusedGenesisMember, GenesisRefusalMessage);
        }

        try
        {
            // Wipe order preserved verbatim from the pre-guard Settings
            // sequence: pairing FIRST so any in-flight poll loops see
            // "no longer paired" before their backing keys are torn down.
            // (SaveAsync(null) rather than ClearAsync is the historical
            // behavior of this path — kept identical; see the DIAG note in
            // MauiPairingStateService.)
            await _pairing.SaveAsync(null!, ct).ConfigureAwait(false);
            await _totp.ClearAllAsync(ct).ConfigureAwait(false);
            await _enclaveKeys.DeleteAsync(keyAlias, ct).ConfigureAwait(false);
            return new UnpairAllResult(UnpairAllStatus.Completed);
        }
        catch (Exception ex)
        {
            return new UnpairAllResult(UnpairAllStatus.Failed, $"{ex.GetType().Name}: {ex.Message}");
        }
    }
}
