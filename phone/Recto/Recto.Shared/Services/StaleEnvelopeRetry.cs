using System;
using System.Threading;
using System.Threading.Tasks;
using Recto.Shared.Common;

namespace Recto.Shared.Services;

/// <summary>
/// ONE REFETCH BEFORE A STALE REPLY IS JUDGED. A signed bootloader reply
/// (the <c>/v0.4/pending</c> envelope, an <c>/v0.4/attest</c> answer) carries
/// a short exp. An app the OS froze mid-request resumes holding a reply that
/// was genuine when it arrived and is past its exp when it is checked. That
/// reply is not a changed server, so the phone asks once more and judges the
/// fresh answer by every rule.
/// <para>
/// Only <see cref="AttestationResult.Expired"/> earns the refetch, and only
/// one: any other refusal, or a second refusal of any kind, stands. An old
/// reply bound to another nonce, other cards or another phone is not Expired
/// and is refused at once; an old reply replayed whole buys one extra request
/// and nothing else, and the fresh reply must still verify against the key
/// pinned at pairing.
/// </para>
/// </summary>
public static class StaleEnvelopeRetry
{
    /// <summary>
    /// Verifies <paramref name="first"/>; when it is stale, fetches once more
    /// and verifies that instead.
    /// </summary>
    /// <param name="first">The reply as received.</param>
    /// <param name="verify">The full check, applied to each reply.</param>
    /// <param name="refetch">Asks the bootloader again (a fresh nonce, where the reply needs one).</param>
    /// <param name="ct">Cancels the refetch.</param>
    public static async Task<EnvelopeJudgement<T>> JudgeAsync<T>(
        T first,
        Func<T, AttestationResult> verify,
        Func<CancellationToken, Task<Result<T>>> refetch,
        CancellationToken ct)
    {
        var verdict = verify(first);
        if (verdict.Verified || !verdict.Expired)
        {
            return new EnvelopeJudgement<T>(verdict.Verified ? first : default, verdict, Refetched: false, RefetchError: null);
        }

        var again = await refetch(ct).ConfigureAwait(false);
        if (again.IsFailure)
        {
            return new EnvelopeJudgement<T>(default, verdict, Refetched: true, RefetchError: again.Error);
        }

        var fresh = verify(again.Value);
        return new EnvelopeJudgement<T>(fresh.Verified ? again.Value : default, fresh, Refetched: true, RefetchError: null);
    }
}

/// <summary>
/// The outcome of <see cref="StaleEnvelopeRetry.JudgeAsync{T}"/>.
/// </summary>
/// <param name="Response">The reply that verified, or default when none did.</param>
/// <param name="Verdict">The verdict on the last reply checked.</param>
/// <param name="Refetched">True when the first reply was stale and a second was asked for.</param>
/// <param name="RefetchError">
/// Set when the second request did not reach the bootloader. Nothing was
/// judged then: the caller treats it as an unreachable bootloader, not as a
/// refused identity, and asks again on its next tick.
/// </param>
public sealed record EnvelopeJudgement<T>(T? Response, AttestationResult Verdict, bool Refetched, Error? RefetchError);
