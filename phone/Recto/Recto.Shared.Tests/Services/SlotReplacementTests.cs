using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Recto.Shared.Protocol.V04;
using Recto.Shared.Services;
using Xunit;

namespace Recto.Shared.Tests.Services;

/// <summary>
/// THE SLOTS (hard rule 14.4, 2026-09-21) -- the phone half of the replacement question.
/// The registry answers a registration into an occupied slot with 409 slot_occupied and
/// the occupant; that one 409 is an ANSWER, not an error, and the client hands it to the
/// pairing flow as a RegistrationResponse with Registered=false. Every other 409 stays a
/// failure. The claim the identity key signs must match the server byte for byte.
/// </summary>
public class SlotReplacementTests
{
    [Fact]
    public async Task ASlotOccupied409_IsAQuestion_NotAFailure()
    {
        var handler = new RecordingHandler(_ => Json(HttpStatusCode.Conflict,
            "{\"error\":\"slot_occupied\",\"slot\":\"primary\",\"occupant\":{\"phone_ref\":\"pk_aaaa\"," +
            "\"device_label\":\"pixel 9 pro\",\"last_seen_unix\":1755000000,\"registered_at_unix\":1750000000}," +
            "\"detail\":\"the primary slot holds 'pixel 9 pro'\"}"));
        var sut = Make(handler);

        var result = await sut.RegisterAsync("http://h", Sample(), CancellationToken.None);

        Assert.True(result.IsSuccess, result.IsFailure ? result.Error.Message : "");
        Assert.False(result.Value.Registered);
        Assert.Equal("slot_occupied", result.Value.Error);
        Assert.NotNull(result.Value.Occupant);
        Assert.Equal("pk_aaaa", result.Value.Occupant!.PhoneRef);
        Assert.Equal("pixel 9 pro", result.Value.Occupant.DeviceLabel);
        Assert.Equal(1755000000, result.Value.Occupant.LastSeenUnix);
    }

    [Fact]
    public async Task AnyOther409_StaysAFailure()
    {
        var handler = new RecordingHandler(_ => Json(HttpStatusCode.Conflict,
            "{\"error\":\"pubkey_already_bound\",\"detail\":\"x\"}"));
        var sut = Make(handler);

        var result = await sut.RegisterAsync("http://h", Sample(), CancellationToken.None);

        Assert.True(result.IsFailure);
        Assert.Contains("pubkey_already_bound", result.Error.Message);
    }

    [Fact]
    public async Task TheSlotAndTheClaim_RideTheRegistrationBody()
    {
        string? captured = null;
        var handler = new RecordingHandler(req =>
        {
            captured = req.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
            return Json(HttpStatusCode.Created,
                "{\"registered\":true,\"phone_id\":\"pk_bbbb\",\"bootloader_id\":\"b\",\"managed_secrets\":[]," +
                "\"slot\":\"recovery\",\"displaced_phone_ref\":\"pk_aaaa\"}");
        });
        var sut = Make(handler);

        var result = await sut.RegisterAsync("http://h",
            Sample() with { Slot = "recovery", SlotReplaceB64u = "claim-sig" }, CancellationToken.None);

        Assert.True(result.IsSuccess);
        using var doc = JsonDocument.Parse(captured!);
        Assert.Equal("recovery", doc.RootElement.GetProperty("slot").GetString());
        Assert.Equal("claim-sig", doc.RootElement.GetProperty("slot_replace_b64u").GetString());
        Assert.Equal("recovery", result.Value.Slot);
        Assert.Equal("pk_aaaa", result.Value.DisplacedPhoneRef);
    }

    [Fact]
    public void TheDefaultSlotIsPrimary_AndTheClaimIsAbsentUntilAsked()
    {
        var req = Sample();
        Assert.Equal("primary", req.Slot);
        Assert.Null(req.SlotReplaceB64u);
    }

    [Fact]
    public void SlotReplacePayload_MatchesTheServerReconstruction()
    {
        // server: f"recto-slot-replace-v1|{slot}|{occupant_phone_ref}|{incoming_public_key_b64u}".encode("ascii")
        var bytes = PollSigning.BuildSlotReplacePayload("primary", "pk_aaaa", "INCOMING_b64u");
        Assert.Equal("recto-slot-replace-v1|primary|pk_aaaa|INCOMING_b64u", Encoding.ASCII.GetString(bytes));
        Assert.Equal("recto-slot-replace-v1", PollSigning.SlotReplacePrefix);
    }

    // --- helpers ---

    private static BootloaderClient Make(RecordingHandler handler)
        => new(new HttpClient(handler), NullLogger<BootloaderClient>.Instance);

    private static RegistrationRequest Sample() => new(
        PhoneId: "pk_bbbb", DeviceLabel: "pixel 10", PublicKeyB64u: "INCOMING_b64u",
        SupportedAlgorithms: new[] { V04Protocol.AlgorithmEcdsaP256 }, V04Protocol: V04Protocol.Version,
        RegistrationProof: new RegistrationProof("c", "s"),
        PollPublicKeyB64u: "POLL_b64u", PollKeyDelegationB64u: "delegation");

    private static HttpResponseMessage Json(HttpStatusCode status, string body) =>
        new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private sealed class RecordingHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _respond;
        public List<HttpRequestMessage> Requests { get; } = new();
        public RecordingHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) => _respond = respond;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Requests.Add(request);
            return Task.FromResult(_respond(request));
        }
    }
}
