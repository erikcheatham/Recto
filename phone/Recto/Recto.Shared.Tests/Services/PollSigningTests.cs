using Recto.Shared.Services;
using Xunit;

namespace Recto.Shared.Tests.Services;

/// <summary>
/// Pins the phone-side signed-poll payload against the bootloader's
/// verifier (recto/bootloader/server.py, POLL_SIG_PREFIX et al).
/// Cross-language byte parity: the Python side reconstructs
/// <c>recto-poll-v1|{phone_id}|{ts}|{path}</c> as ASCII and verifies
/// the enclave signature over exactly those bytes &mdash; any drift in
/// this format breaks every signed poll at the required-mode flip.
/// </summary>
public class PollSigningTests
{
    [Fact]
    public void BuildPayload_MatchesServerCanonicalShape()
    {
        var payload = PollSigning.BuildPayload(
            "11111111-2222-3333-4444-555555555555",
            1_755_000_000,
            "/v0.4/pending");
        Assert.Equal(
            "recto-poll-v1|11111111-2222-3333-4444-555555555555|1755000000|/v0.4/pending",
            payload);
    }

    [Fact]
    public void HeaderNames_MatchServerConstants()
    {
        Assert.Equal("X-Recto-Phone-Sig", PollSigning.SignatureHeader);
        Assert.Equal("X-Recto-Phone-Ts", PollSigning.TimestampHeader);
        Assert.Equal("recto-poll-v1", PollSigning.Prefix);
    }
}
