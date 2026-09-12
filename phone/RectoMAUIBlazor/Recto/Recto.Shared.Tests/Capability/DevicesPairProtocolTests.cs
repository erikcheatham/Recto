using System.Text.Json;
using Recto.Shared.Protocol.V04;
using Xunit;

namespace Recto.Shared.Tests.Capability;

/// <summary>
/// Pins the C# protocol-DTO shape for Phase H's <c>devices:pair</c>
/// surface against the Python wire shape in
/// <c>recto/bootloader/server.py::_handle_devices_pair</c>. Any drift
/// between the C# DTOs and the Python emit-keys silently breaks end-to-
/// end routing — the phone either sends a request the bootloader can't
/// parse OR receives a response it can't deserialize (Status defaults
/// to 0, orchestrator's <c>resp.Status &lt; 200</c> trips the fail path
/// even when the pair succeeded server-side).
///
/// <para>
/// First Phase H smoke 2026-05-19 night hit exactly this bug: the C#
/// DTO was originally <c>JsonPropertyName("status")</c> /
/// <c>JsonPropertyName("body")</c> matching the BOOTLOADER'S DOCSTRING
/// at <c>recto/bootloader/server.py:2253</c>, but the actual code emit
/// at line ~2402 uses <c>{consumer_status, consumer_body}</c>. The
/// emit is authoritative; the docstring lies. These tests pin the
/// emit-side reality so the next contributor doesn't have to re-
/// discover this via a frustrating end-to-end smoke.
/// </para>
///
/// <para>
/// Sister to <see cref="ProfileCreateProtocolTests"/> and
/// <see cref="CapabilityRequestProtocolTests"/>; same byte-parity
/// discipline applied to the Phase H devices:pair surface.
/// </para>
/// </summary>
public class DevicesPairProtocolTests
{
    // -----------------------------------------------------------------
    // DevicesPairRequest — POST /v0.4/devices/pair body shape
    // -----------------------------------------------------------------

    private static readonly string Phone = string.Concat(Enumerable.Repeat("ab", 64));

    private static DevicesPairRecord Record() =>
        new("bl-test", "user-1", Phone, "A1B2C3D4", 1800000600);

    [Fact]
    public void DevicesPairRequest_Serializes_With_Snake_Case_Wire_Keys()
    {
        // The bootloader's body validation reads these EXACT keys.
        var req = new DevicesPairRequest(
            ConsumerBaseUrl: "https://staging.allthruit.com",
            Record: Record(),
            UserJws: "header.payload.signature");

        var json = JsonSerializer.Serialize(req);

        Assert.Contains("\"consumer_base_url\":", json);
        Assert.Contains("\"record\":", json);
        Assert.Contains("\"bootloader_id\":", json);
        Assert.Contains("\"user_id\":", json);
        Assert.Contains("\"phone_pubkey\":", json);
        Assert.Contains("\"code\":", json);
        Assert.Contains("\"not_after\":", json);
        Assert.Contains("\"user_jws\":", json);
        Assert.DoesNotContain("\"ConsumerBaseUrl\":", json);
        Assert.DoesNotContain("\"PhonePubkey\":", json);
    }

    [Fact]
    public void DevicesPairRequest_RoundTrip_Preserves_All_Fields()
    {
        var original = new DevicesPairRequest(
            ConsumerBaseUrl: "https://staging.allthruit.com",
            Record: Record(),
            UserJws: "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiJ1c2VyIn0.signature");

        var json = JsonSerializer.Serialize(original);
        var restored = JsonSerializer.Deserialize<DevicesPairRequest>(json);

        Assert.NotNull(restored);
        Assert.Equal(original.ConsumerBaseUrl, restored.ConsumerBaseUrl);
        Assert.Equal(original.Record, restored.Record);
        Assert.Equal(original.UserJws, restored.UserJws);
    }

    [Fact]
    public void DevicesPairRecord_Fingerprint_Matches_The_Bootloaders_Pin()
    {
        // The same tuple the bootloader's suite pins (tests/test_capability_pair_record.py):
        // canonical bytes are sorted keys, no whitespace; the fingerprint is their SHA-256.
        var expectedBytes = "{\"bootloader_id\":\"bl-test\",\"code\":\"A1B2C3D4\",\"not_after\":1800000600," +
                            "\"phone_pubkey\":\"" + Phone + "\",\"user_id\":\"user-1\"}";
        var expected = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(expectedBytes))).ToLowerInvariant();
        Assert.Equal(expected, Record().Fingerprint());
    }

    [Theory]
    [InlineData("bootloader_id")]
    [InlineData("user_id")]
    [InlineData("phone_pubkey")]
    [InlineData("code")]
    [InlineData("not_after")]
    public void DevicesPairRecord_EveryField_MovesTheFingerprint(string field)
    {
        var r = Record();
        var changed = field switch
        {
            "bootloader_id" => r with { BootloaderId = "bl-other" },
            "user_id" => r with { UserId = "user-2" },
            "phone_pubkey" => r with { PhonePubkey = string.Concat(Enumerable.Repeat("cd", 64)) },
            "code" => r with { Code = "Z9Y8X7W6" },
            _ => r with { NotAfter = r.NotAfter + 1 },
        };
        Assert.NotEqual(r.Fingerprint(), changed.Fingerprint());
    }

    // -----------------------------------------------------------------
    // DevicesPairResponse — bootloader's relay response shape
    // -----------------------------------------------------------------
    //
    // CRITICAL: these tests pin the FIX from the 2026-05-19 night smoke
    // discovery. The bootloader emits {consumer_status, consumer_body}
    // NOT {status, body}. Banking the wire shape via test so a future
    // edit that "simplifies" these property mappings doesn't re-break
    // the Phase H flow.

    [Fact]
    public void DevicesPairResponse_Deserializes_From_Bootloader_Wire_Shape()
    {
        // Exact JSON shape the bootloader emits at
        // recto/bootloader/server.py::_handle_devices_pair line ~2402:
        //   self._send_json(relayed_status, {
        //       "consumer_status": consumer_status,
        //       "consumer_body": consumer_body,
        //   })
        var json = """
            {
              "consumer_status": 200,
              "consumer_body": {
                "masterPubkeyHex": "2b29338b...4112d1",
                "userId": "user-guid-here"
              }
            }
            """;

        var resp = JsonSerializer.Deserialize<DevicesPairResponse>(json);

        Assert.NotNull(resp);
        Assert.Equal(200, resp!.Status);
        Assert.NotNull(resp.Body);
        Assert.Equal(JsonValueKind.Object, resp.Body!.Value.ValueKind);
    }

    [Fact]
    public void DevicesPairResponse_Deserializes_Consumer_Error_Shape()
    {
        // When the consumer rejects (e.g. pubkey_already_bound,
        // pairing_code_expired, capability_invalid), the bootloader
        // STILL emits the same {consumer_status, consumer_body} envelope
        // with the consumer's 4xx + reason inside consumer_body.
        var json = """
            {
              "consumer_status": 400,
              "consumer_body": {
                "error": "pubkey_already_bound",
                "reason": "This master pubkey is already bound to user X."
              }
            }
            """;

        var resp = JsonSerializer.Deserialize<DevicesPairResponse>(json);

        Assert.NotNull(resp);
        Assert.Equal(400, resp!.Status);
        Assert.NotNull(resp.Body);
        Assert.True(resp.Body!.Value.TryGetProperty("reason", out var reason));
        Assert.Equal("This master pubkey is already bound to user X.", reason.GetString());
    }

    [Fact]
    public void DevicesPairResponse_Rejects_Legacy_status_body_Shape()
    {
        // Defense against regression: if a future edit changes the C#
        // DTO back to {status, body}, deserialization from the
        // bootloader's actual emit fails silently (Status defaults to
        // 0, Body to null) — exactly the bug the 2026-05-19 night
        // smoke surfaced. This test guarantees that scenario fails-
        // loud-via-zero-status as a signal that the wire shape drifted.
        //
        // The "legacy" {status, body} shape (which the bootloader's
        // own docstring at line 2253 lies about) should leave the
        // current Status=0 / Body=null on the C# side, because the
        // attributes only match consumer_status / consumer_body.
        var json = """
            {
              "status": 200,
              "body": { "masterPubkeyHex": "abc" }
            }
            """;

        var resp = JsonSerializer.Deserialize<DevicesPairResponse>(json);

        Assert.NotNull(resp);
        // Status defaults to 0 because the JSON has "status" but the
        // DTO maps "consumer_status". This is the documented behavior
        // protecting against the wire-shape mismatch.
        Assert.Equal(0, resp!.Status);
        // Body similarly defaults to null because of the
        // consumer_body vs body mismatch.
        Assert.Null(resp.Body);
    }
}
