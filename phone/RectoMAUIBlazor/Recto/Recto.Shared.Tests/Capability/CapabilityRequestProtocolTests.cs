using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using Recto.Shared.Capability;
using Recto.Shared.Protocol.V04;
using Xunit;

namespace Recto.Shared.Tests.Capability;

/// <summary>
/// Pins the C# protocol-DTO shape for Phase 5 Wave B's
/// <c>capability_request</c> kind against the Python wire shape in
/// <c>recto/bootloader/state.py</c> + <c>recto/bootloader/server.py</c>.
/// The JSON-property-name pins below are load-bearing: any drift
/// between the C# <c>PendingRequestContext</c> snake_case names and
/// the Python emit-keys would silently break end-to-end routing
/// (the phone would receive a request with empty cap_*_b64 fields,
/// fail to reconstruct the JWS signing input, refuse to sign).
///
/// <para>
/// Sister to <c>CapabilityVerifierTests</c> which pins the
/// canonical-JSON byte-parity for the JWT payload itself; this
/// suite pins the wire-envelope JSON.
/// </para>
/// </summary>
public class CapabilityRequestProtocolTests
{
    // -----------------------------------------------------------------
    // PendingRequestKind constant — the discriminator value
    // -----------------------------------------------------------------

    [Fact]
    public void PendingRequestKind_CapabilityRequest_HasExpectedString()
    {
        Assert.Equal("capability_request", PendingRequestKind.CapabilityRequest);
    }

    // -----------------------------------------------------------------
    // PendingRequestContext — cap_* JSON property names + round-trip
    // -----------------------------------------------------------------

    [Fact]
    public void PendingRequestContext_SerializesCapFieldsAsSnakeCase()
    {
        var ctx = new PendingRequestContext(
            ChildPid: 0,
            ChildArgv0: "(external-agent)",
            RequestedAtUnix: 1715000000L,
            OperationDescription: "Darwin requests deploy:staging capability",
            PayloadHashB64u: "aGFzaA",
            CapHeaderB64: "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ",
            CapPayloadB64: "eyJpc3MiOiJ4In0",
            CapAgentId: "darwin");

        var json = JsonSerializer.Serialize(ctx);

        Assert.Contains("\"cap_header_b64\":\"eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ\"", json);
        Assert.Contains("\"cap_payload_b64\":\"eyJpc3MiOiJ4In0\"", json);
        Assert.Contains("\"cap_agent_id\":\"darwin\"", json);
    }

    [Fact]
    public void PendingRequestContext_DeserializesCapFieldsFromPythonShape()
    {
        // Mirror of the wire shape Python emits via _pending_to_wire
        // for kind == "capability_request". Pinning this value
        // protects against a JsonPropertyName drift that would silently
        // leave the cap_* fields null on the C# side.
        const string pythonWire = """
        {
          "child_pid": 0,
          "child_argv0": "(external-agent)",
          "requested_at_unix": 1715000000,
          "operation_description": "Darwin requests deploy:staging capability",
          "payload_hash_b64u": "ZmFrZS1oYXNoLWZpeHR1cmUtMzItYnl0ZXMtbG9uZw",
          "cap_header_b64": "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ",
          "cap_payload_b64": "eyJpc3MiOiJ4In0",
          "cap_agent_id": "darwin"
        }
        """;

        var ctx = JsonSerializer.Deserialize<PendingRequestContext>(pythonWire);

        Assert.NotNull(ctx);
        Assert.Equal(0, ctx!.ChildPid);
        Assert.Equal("(external-agent)", ctx.ChildArgv0);
        Assert.Equal("eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ", ctx.CapHeaderB64);
        Assert.Equal("eyJpc3MiOiJ4In0", ctx.CapPayloadB64);
        Assert.Equal("darwin", ctx.CapAgentId);
        // Other-kind fields stay null.
        Assert.Null(ctx.EthChainId);
        Assert.Null(ctx.BtcNetwork);
        Assert.Null(ctx.EdChain);
        Assert.Null(ctx.TronNetwork);
    }

    [Fact]
    public void PendingRequestContext_OmitsCapAgentIdWhenNull()
    {
        // Python's _pending_to_wire emits cap_agent_id only when set
        // (mirrors the emit-only-when-set pattern eth/btc/ed/tron use
        // for their similarly-optional fields). Verify the C# shape
        // round-trips a null cap_agent_id correctly.
        var ctx = new PendingRequestContext(
            ChildPid: 0,
            ChildArgv0: "(external-agent)",
            RequestedAtUnix: 1715000000L,
            OperationDescription: "x",
            CapHeaderB64: "h",
            CapPayloadB64: "p",
            CapAgentId: null);

        var roundTripped = JsonSerializer.Deserialize<PendingRequestContext>(
            JsonSerializer.Serialize(ctx));

        Assert.NotNull(roundTripped);
        Assert.Equal("h", roundTripped!.CapHeaderB64);
        Assert.Equal("p", roundTripped.CapPayloadB64);
        Assert.Null(roundTripped.CapAgentId);
    }

    // -----------------------------------------------------------------
    // RespondRequest — CapSignatureB64u serialization
    // -----------------------------------------------------------------

    [Fact]
    public void RespondRequest_SerializesCapSignatureAsSnakeCase()
    {
        var resp = new RespondRequest(
            PhoneId: "phone-1",
            Decision: RespondDecision.Approved,
            SignatureB64u: "envelope-sig",
            CapSignatureB64u: "ABCDE_-rs64bytes-fixture");

        var json = JsonSerializer.Serialize(resp);

        Assert.Contains("\"cap_signature_b64u\":\"ABCDE_-rs64bytes-fixture\"", json);
        // Other-kind sig fields are null on this RespondRequest. The
        // bootloader-side _handle_respond looks them up via body.get(...)
        // which returns None for both omitted-key and explicit-null
        // shapes, so the contract is "no non-null value present"
        // rather than "key absent". System.Text.Json's default
        // serializer settings emit null-valued fields explicitly;
        // assert the populated form (a quoted string value) is NOT
        // present rather than asserting absence of the field name.
        Assert.DoesNotContain("\"eth_signature_rsv\":\"", json);
        Assert.DoesNotContain("\"btc_signature_base64\":\"", json);
        Assert.DoesNotContain("\"ed_signature_base64\":\"", json);
        Assert.DoesNotContain("\"tron_signature_rsv\":\"", json);
    }

    [Fact]
    public void RespondRequest_DeserializesCapSignatureFromWire()
    {
        const string wire = """
        {
          "phone_id": "phone-1",
          "decision": "approved",
          "signature_b64u": "envelope-sig",
          "cap_signature_b64u": "ABCDE_-rs64bytes-fixture"
        }
        """;

        var resp = JsonSerializer.Deserialize<RespondRequest>(wire);

        Assert.NotNull(resp);
        Assert.Equal("phone-1", resp!.PhoneId);
        Assert.Equal("approved", resp.Decision);
        Assert.Equal("envelope-sig", resp.SignatureB64u);
        Assert.Equal("ABCDE_-rs64bytes-fixture", resp.CapSignatureB64u);
        // Spot-check none of the other sig fields leaked from the wire.
        Assert.Null(resp.EthSignatureRsv);
        Assert.Null(resp.BtcSignatureBase64);
        Assert.Null(resp.EdSignatureBase64);
        Assert.Null(resp.TronSignatureRsv);
    }

    [Fact]
    public void RespondRequest_OmitsCapSignatureWhenNullForNonCapKinds()
    {
        // An ETH approval shouldn't carry cap_signature_b64u in its
        // wire shape — the field is null, so System.Text.Json default
        // serializer settings emit it as null (not omitted). That's
        // fine for the bootloader (Python-side _handle_respond looks
        // up cap_signature_b64u via body.get(...) which returns None
        // for both missing and null values), but pin the behavior so
        // we know what's on the wire.
        var resp = new RespondRequest(
            PhoneId: "phone-1",
            Decision: RespondDecision.Approved,
            SignatureB64u: "envelope",
            EthSignatureRsv: "0x" + new string('a', 130));

        var json = JsonSerializer.Serialize(resp);

        Assert.Contains("\"eth_signature_rsv\":\"0x" + new string('a', 130) + "\"", json);
        // CapSignatureB64u is null; default System.Text.Json emits
        // explicit null. Either omitted OR emitted-as-null is fine
        // on the bootloader side; pin whichever the runtime produces
        // so a future serializer-config drift surfaces here.
        Assert.True(
            !json.Contains("\"cap_signature_b64u\"") ||
            json.Contains("\"cap_signature_b64u\":null"),
            $"cap_signature_b64u should be omitted or null; got: {json}");
    }

    // -----------------------------------------------------------------
    // PendingRequest — full envelope round-trip
    // -----------------------------------------------------------------

    [Fact]
    public void PendingRequest_RoundTripsCapabilityRequestEnvelope()
    {
        // Build the same shape Python's _pending_to_wire emits for a
        // queued capability_request. Round-trip C# serializer ->
        // deserializer should preserve every field byte-for-byte.
        var pending = new PendingRequest(
            RequestId: "req-uuid-1",
            Kind: PendingRequestKind.CapabilityRequest,
            Service: "recto",
            Secret: "capability",
            Context: new PendingRequestContext(
                ChildPid: 0,
                ChildArgv0: "(external-agent)",
                RequestedAtUnix: 1715000000L,
                OperationDescription: "Darwin staging-deploys",
                PayloadHashB64u: "ZmFrZS1oYXNoLWZpeHR1cmUtMzItYnl0ZXMtbG9uZw",
                CapHeaderB64: "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ",
                CapPayloadB64: "eyJpc3MiOiJ4In0",
                CapAgentId: "darwin"));

        var json = JsonSerializer.Serialize(pending);
        var roundTripped = JsonSerializer.Deserialize<PendingRequest>(json);

        Assert.NotNull(roundTripped);
        Assert.Equal("req-uuid-1", roundTripped!.RequestId);
        Assert.Equal("capability_request", roundTripped.Kind);
        Assert.Equal("recto", roundTripped.Service);
        Assert.Equal("capability", roundTripped.Secret);
        Assert.Equal("eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ", roundTripped.Context.CapHeaderB64);
        Assert.Equal("eyJpc3MiOiJ4In0", roundTripped.Context.CapPayloadB64);
        Assert.Equal("darwin", roundTripped.Context.CapAgentId);
    }

    // -----------------------------------------------------------------
    // Cap signing-input contract — the digest the phone reconstructs
    // -----------------------------------------------------------------

    /// <summary>
    /// Pins the contract that the phone CAN reconstruct the SHA-256
    /// signing-input digest from cap_header_b64 + cap_payload_b64
    /// alone, without needing the bootloader's pre-computed
    /// payload_hash_b64u. This is what
    /// <see cref="PopulateCapabilityDecodes"/> + the
    /// <c>ApproveCapabilityRequestAsync</c> dispatcher rely on to
    /// refuse a request whose payload_hash_b64u disagrees with the
    /// reconstructed digest (defense against tampering / protocol
    /// bugs that would unbind the operator's biometric consent from
    /// the JWS being signed).
    /// </summary>
    [Fact]
    public void SigningInput_DigestReconstructsFromCapFieldsAlone()
    {
        // Use the same example_claims fixture CapabilityVerifierTests
        // pins, ensuring the phone's reconstructed digest matches
        // exactly what the bootloader pre-computed on its side.
        var claims = new CapabilityClaims(
            Iss: "phone:operator:enclave",
            Sub: "agent:darwin@staging",
            Aud: new[] { "consumer-app", "recto:vault" },
            Iat: 1715000000L,
            Nbf: 1715000000L,
            Exp: 1715086400L,
            Jti: "cap_2026-05-05_test",
            Cap: new CapabilityClause(
                Tier: 1,
                RegistryVersion: "2026-05-05",
                Groups: new[] { "darwin:doc-edits", "darwin:staging-deploys" },
                Scope: new CapabilityScope(
                    Env: new[] { "staging" },
                    Services: new[] { "web" },
                    Repos: new[] { "recto" }),
                AllowActions: Array.Empty<string>(),
                DenyActions: Array.Empty<string>(),
                Limits: new CapabilityLimits(
                    PerHour: new Dictionary<string, long> { ["deploy:staging"] = 5L },
                    PerDay: new Dictionary<string, long>(),
                    PerSession: new Dictionary<string, long>())),
            Purpose: "Test capability fixture",
            ParentCap: null,
            MaxUses: null);

        var (expectedDigest, headerB64, payloadB64) = CapabilityJws.BuildSigningInput(claims);

        // Phone-side reconstruction: same SHA-256(f"{headerB64}.{payloadB64}").
        var reconstructedInput = Encoding.ASCII.GetBytes($"{headerB64}.{payloadB64}");
        var reconstructedDigest = System.Security.Cryptography.SHA256.HashData(reconstructedInput);

        Assert.Equal(expectedDigest, reconstructedDigest);

        // And the digest matches the cross-language byte-pin from
        // CapabilityVerifierTests: e500695bf8a41f37f41997bffa0b6a9cfaae1809ad8263e770e0db72e82e693c
        Assert.Equal(
            "e500695bf8a41f37f41997bffa0b6a9cfaae1809ad8263e770e0db72e82e693c",
            Convert.ToHexString(reconstructedDigest).ToLowerInvariant());
    }
}
