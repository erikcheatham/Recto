using System.Threading;
using System.Threading.Tasks;

namespace Recto.Shared.Services;

/// <summary>
/// Signs the phone's READS to a bootloader (hard rule 14.2):
/// <c>GET /v0.4/pending</c>, <c>GET /v0.4/manage/phones</c>,
/// <c>POST /v0.4/manage/push_token</c>. Returns the header pair to attach,
/// or null when this pairing carries no poll key (demo mode only) -- the
/// read then goes bare and a real bootloader answers it with a verdict.
/// <para>
/// The seam exists so <see cref="BootloaderClient"/> attaches the headers at
/// the ONE place the URL path is known, and so tests can prove the headers
/// are attached without an enclave.
/// </para>
/// </summary>
public interface IReadSigner
{
    Task<PollSignatureHeaders?> SignReadAsync(string phoneId, string path, CancellationToken ct);
}

/// <summary>
/// The production <see cref="IReadSigner"/>: signs with the enclave key under
/// <see cref="PollSigning.PollKeyAlias"/> -- the non-gated device key -- when
/// the current pairing recorded one, and only then. A signing failure is
/// reported as "no signature" rather than thrown: a read that goes bare is
/// answered by the bootloader's mode with a verdict; a read that never leaves
/// the phone is silence.
/// </summary>
public sealed class PollKeyReadSigner : IReadSigner
{
    private readonly IEnclaveKeyService _enclave;
    private readonly IPairingStateService _pairing;

    public PollKeyReadSigner(IEnclaveKeyService enclave, IPairingStateService pairing)
    {
        _enclave = enclave;
        _pairing = pairing;
    }

    public async Task<PollSignatureHeaders?> SignReadAsync(string phoneId, string path, CancellationToken ct)
    {
        var current = await _pairing.GetCurrentAsync(ct).ConfigureAwait(false);
        if (current.IsFailure || current.Value?.PollPublicKeyB64u is null)
        {
            return null;
        }
        var signed = await PollSigning
            .SignPollAsync(_enclave, PollSigning.PollKeyAlias, phoneId, path, ct)
            .ConfigureAwait(false);
        return signed.IsSuccess ? signed.Value : null;
    }
}
