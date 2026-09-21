using System.Threading;
using System.Threading.Tasks;
using Recto.Shared.Common;

namespace Recto.Shared.Services;

/// <summary>
/// Phone-side genesis-membership state. Presence of the marker means this
/// phone's enclave identity key is a member of a sealed genesis set: the
/// bootloader's identity is derived from the member key set, and destroying
/// a member key is an unrecoverable reduction of the trust root.
/// <para>
/// The marker deliberately lives in its OWN storage entry rather than inside
/// the pairing record: the surgical per-bootloader unpair clears the pairing
/// record while the enclave key survives, and membership must survive with
/// the key it describes — a guard that vanishes with the pairing record
/// guards nothing.
/// </para>
/// </summary>
public interface IGenesisStateService
{
    /// <summary>
    /// True when this phone is a genesis member. A read FAILURE is not
    /// false: callers guarding destructive actions must fail closed and
    /// treat an unreadable marker as membership.
    /// </summary>
    Task<Result<bool>> IsGenesisMemberAsync(CancellationToken ct);

    /// <summary>
    /// Records genesis membership. Called by the enrolment ceremony when
    /// the genesis set seals; <paramref name="derivedBootloaderId"/> is the
    /// bootloader identity derived from the member key set at that moment.
    /// </summary>
    Task<Result> MarkGenesisMemberAsync(string derivedBootloaderId, CancellationToken ct);

    /// <summary>
    /// Removes the membership marker. ONLY the recovery ceremony may call
    /// this — clearing the marker outside that ceremony re-arms the one-tap
    /// key destruction the marker exists to prevent.
    /// </summary>
    Task<Result> ClearAsync(CancellationToken ct);
}
