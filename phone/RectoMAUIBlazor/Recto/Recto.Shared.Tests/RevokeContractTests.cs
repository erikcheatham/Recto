using System.Text.Json;
using Recto.Shared.Protocol.V04;
using Xunit;

namespace Recto.Shared.Tests;

/// <summary>
/// Pins the phone-side revoke request to the bootloader's wire contract
/// (server.py _handle_revoke_phone). This lane shipped once with THREE
/// simultaneous disagreements — route, field names, and signature payload —
/// and every one failed silently: the 404/401 landed in a polling-error
/// field that the next poll overwrote seconds later. A client whose contract
/// lives only in string literals can fork from the server without any test
/// going red; this file is the red-build for the field-name half.
/// (The route and the colon-bound signature payload live at the call sites
/// with loud comments; an end-to-end exercise against a live bootloader is
/// the only full proof, and the 2026-08-23 finding is why.)
/// </summary>
public class RevokeContractTests
{
    [Fact]
    public void RevokeRequest_SerializesTheServersFieldNames_Exactly()
    {
        var req = new RevokeRequest(
            RevokerPhoneId: "revoker-1",
            TargetPhoneId: "target-2",
            ChallengeB64u: "chal-3",
            SignatureB64u: "sig-4");

        var json = JsonSerializer.Serialize(req);
        using var doc = JsonDocument.Parse(json);

        // Exact keys, exact order of declaration — the server reads
        // revoker_phone_id / target_phone_id / challenge_b64u /
        // signature_b64u and treats anything missing as a 400.
        var keys = doc.RootElement.EnumerateObject().Select(p => p.Name).ToArray();
        Assert.Equal(
            new[] { "revoker_phone_id", "target_phone_id", "challenge_b64u", "signature_b64u" },
            keys);

        Assert.Equal("revoker-1", doc.RootElement.GetProperty("revoker_phone_id").GetString());
        Assert.Equal("target-2", doc.RootElement.GetProperty("target_phone_id").GetString());
        Assert.Equal("chal-3", doc.RootElement.GetProperty("challenge_b64u").GetString());
        Assert.Equal("sig-4", doc.RootElement.GetProperty("signature_b64u").GetString());
    }
}
