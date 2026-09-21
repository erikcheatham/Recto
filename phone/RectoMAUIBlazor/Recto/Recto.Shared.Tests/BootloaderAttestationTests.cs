using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Recto.Shared.Capability;
using Recto.Shared.Protocol.V04;
using Recto.Shared.Services;
using Xunit;

namespace Recto.Shared.Tests;

/// <summary>
/// The C# sister of tests/test_bootloader_devices_pair.py::TestBootloaderAttest.
/// The phone drops the TLS leaf pin (2026-09-16) for THIS: a signature by the
/// key pinned at pairing over a nonce the phone chose. Every refusal is by name.
/// </summary>
public class BootloaderAttestationTests
{
    private const string BootloaderId = "rb1-test";
    private const long Now = 1_789_570_000L;

    private static string Mint(
        byte[] priv,
        string nonceB64u,
        string iss = $"bootloader:{BootloaderId}",
        string aud = BootloaderAttestation.Audience,
        string action = BootloaderAttestation.Action,
        long exp = Now + 120,
        string? payloadShaOverride = null,
        string sub = $"bootloader:{BootloaderId}")
    {
        var nonce = CapabilityJws.Base64UrlDecode(nonceB64u);
        var sha = payloadShaOverride
            ?? Convert.ToHexString(SHA256.HashData(nonce)).ToLowerInvariant();
        var header = CapabilityJws.Base64UrlEncode(CanonicalJson.Encode(
            new Dictionary<string, object?> { ["alg"] = "ES256K", ["typ"] = "JWT" }));
        var payload = new Dictionary<string, object?>
        {
            ["iss"] = iss,
            ["sub"] = sub,
            ["aud"] = new[] { aud },
            ["iat"] = Now,
            ["nbf"] = Now,
            ["exp"] = exp,
            ["jti"] = $"attest-{nonceB64u}",
            ["cap"] = new Dictionary<string, object?>
            {
                ["tier"] = 0L,
                ["registry_version"] = "0",
                ["groups"] = Array.Empty<string>(),
                ["scope"] = new Dictionary<string, object?>
                {
                    ["env"] = Array.Empty<string>(),
                    ["services"] = Array.Empty<string>(),
                    ["repos"] = Array.Empty<string>(),
                    ["payload_sha256"] = sha,
                },
                ["allow_actions"] = new[] { action },
                ["deny_actions"] = Array.Empty<string>(),
                ["limits"] = new Dictionary<string, object?>(),
            },
            ["purpose"] = "bootloader attest",
            ["max_uses"] = 1L,
        };
        var payloadB64 = CapabilityJws.Base64UrlEncode(CanonicalJson.Encode(payload));
        var digest = SHA256.HashData(Encoding.ASCII.GetBytes($"{header}.{payloadB64}"));
        var rsv = EthSigningOps.SignWithRecovery(digest, priv);
        var rs = new byte[64];
        Buffer.BlockCopy(rsv, 0, rs, 0, 64);
        return CapabilityJws.AssembleJws(header, payloadB64, rs);
    }

    private static (byte[] priv, string pubHex) Key()
    {
        var priv = EthSigningOps.GeneratePrivateKey();
        var pub = EthSigningOps.PublicKeyFromPrivate(priv);
        return (priv, Convert.ToHexString(pub).ToLowerInvariant());
    }

    [Fact]
    public void Nonce_Is32RandomBytesBase64Url()
    {
        var a = BootloaderAttestation.NewNonceB64u();
        var b = BootloaderAttestation.NewNonceB64u();
        Assert.NotEqual(a, b);
        Assert.Equal(32, CapabilityJws.Base64UrlDecode(a).Length);
    }

    [Fact]
    public void Verify_SignatureByThePinnedKeyOverThisNonce_Verifies()
    {
        var (priv, pubHex) = Key();
        var nonce = BootloaderAttestation.NewNonceB64u();
        var resp = new AttestResponse(BootloaderId, nonce, Mint(priv, nonce));

        var r = BootloaderAttestation.Verify(resp, pubHex, BootloaderId, nonce, now: Now + 1);

        Assert.True(r.Verified, r.Error);
    }

    [Fact]
    public void Verify_AnotherKey_FailsBySignature()
    {
        var (priv, _) = Key();
        var (_, otherPubHex) = Key();
        var nonce = BootloaderAttestation.NewNonceB64u();
        var resp = new AttestResponse(BootloaderId, nonce, Mint(priv, nonce));

        var r = BootloaderAttestation.Verify(resp, otherPubHex, BootloaderId, nonce, now: Now + 1);

        Assert.False(r.Verified);
        Assert.StartsWith("signature:", r.Error);
    }

    [Fact]
    public void Verify_NoKeyPinnedAtPairing_FailsByPin_NeverAdoptsFromTheWire()
    {
        // A legacy pairing (before this build) holds no signing key. The
        // response CARRIES the key -- and the phone must not take it.
        var (priv, pubHex) = Key();
        var nonce = BootloaderAttestation.NewNonceB64u();
        var resp = new AttestResponse(BootloaderId, nonce, Mint(priv, nonce), DevicesPairPubkeyHex: pubHex);

        var r = BootloaderAttestation.Verify(resp, expectedPubkeyHex: null, BootloaderId, nonce, now: Now + 1);

        Assert.False(r.Verified);
        Assert.StartsWith("pin:", r.Error);
    }

    [Fact]
    public void Verify_ReplayedForAnotherNonce_FailsByNonce()
    {
        var (priv, pubHex) = Key();
        var mine = BootloaderAttestation.NewNonceB64u();
        var theirs = BootloaderAttestation.NewNonceB64u();
        // Echo matches, signature covers a different nonce.
        var resp = new AttestResponse(BootloaderId, mine, Mint(priv, theirs));

        var r = BootloaderAttestation.Verify(resp, pubHex, BootloaderId, mine, now: Now + 1);

        Assert.False(r.Verified);
        Assert.StartsWith("nonce:", r.Error);
    }

    [Fact]
    public void Verify_EchoOfADifferentNonce_FailsByNonce()
    {
        var (priv, pubHex) = Key();
        var mine = BootloaderAttestation.NewNonceB64u();
        var resp = new AttestResponse(BootloaderId, BootloaderAttestation.NewNonceB64u(), Mint(priv, mine));

        var r = BootloaderAttestation.Verify(resp, pubHex, BootloaderId, mine, now: Now + 1);

        Assert.False(r.Verified);
        Assert.StartsWith("nonce:", r.Error);
    }

    [Fact]
    public void Verify_AnotherBootloaderId_FailsByIdentity()
    {
        var (priv, pubHex) = Key();
        var nonce = BootloaderAttestation.NewNonceB64u();
        var resp = new AttestResponse("rb1-other", nonce, Mint(priv, nonce));

        var r = BootloaderAttestation.Verify(resp, pubHex, BootloaderId, nonce, now: Now + 1);

        Assert.False(r.Verified);
        Assert.StartsWith("identity:", r.Error);
    }

    [Fact]
    public void Verify_IssNamingAnotherBootloader_FailsByClaims()
    {
        var (priv, pubHex) = Key();
        var nonce = BootloaderAttestation.NewNonceB64u();
        var resp = new AttestResponse(BootloaderId, nonce, Mint(priv, nonce, iss: "bootloader:rb1-other"));

        var r = BootloaderAttestation.Verify(resp, pubHex, BootloaderId, nonce, now: Now + 1);

        Assert.False(r.Verified);
        Assert.StartsWith("claims: iss", r.Error);
    }

    [Fact]
    public void Verify_APairResultReusedAsAttest_FailsByAction()
    {
        // The bootloader signs other things with the same key (the pairing
        // result). None of them may pass as an attestation.
        var (priv, pubHex) = Key();
        var nonce = BootloaderAttestation.NewNonceB64u();
        var resp = new AttestResponse(BootloaderId, nonce, Mint(priv, nonce, action: "devices:pair_result"));

        var r = BootloaderAttestation.Verify(resp, pubHex, BootloaderId, nonce, now: Now + 1);

        Assert.False(r.Verified);
        Assert.Contains("allow_actions", r.Error);
    }

    [Fact]
    public void Verify_Expired_FailsByClaims()
    {
        var (priv, pubHex) = Key();
        var nonce = BootloaderAttestation.NewNonceB64u();
        var resp = new AttestResponse(BootloaderId, nonce, Mint(priv, nonce));

        var r = BootloaderAttestation.Verify(resp, pubHex, BootloaderId, nonce, now: Now + 121);

        Assert.False(r.Verified);
        Assert.Contains("exp=", r.Error);
    }

    [Fact]
    public void Verify_WrongAudience_Fails()
    {
        var (priv, pubHex) = Key();
        var nonce = BootloaderAttestation.NewNonceB64u();
        var resp = new AttestResponse(BootloaderId, nonce, Mint(priv, nonce, aud: "consumer"));

        var r = BootloaderAttestation.Verify(resp, pubHex, BootloaderId, nonce, now: Now + 1);

        Assert.False(r.Verified);
        Assert.Contains("expected_aud", r.Error);
    }

    // -----------------------------------------------------------------
    // SERVER-SIGNED CARDS: the /v0.4/pending envelope
    // -----------------------------------------------------------------

    private const string PhoneId = "0e21fbd1-43e0-4734-a845-d2863c0d2a0e";
    private const string Raw = "[{\"request_id\": \"r1\", \"summary\": \"a card\"}]";

    private static string MintPending(byte[] priv, string raw, string sub = $"phone:{PhoneId}",
        string action = BootloaderAttestation.PendingAction, string iss = $"bootloader:{BootloaderId}")
    {
        var sha = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(raw))).ToLowerInvariant();
        // Mint() hashes a nonce; hand it the digest directly and any nonce.
        return Mint(priv, BootloaderAttestation.NewNonceB64u(), iss: iss, action: action,
            exp: Now + 300, payloadShaOverride: sha, sub: sub);
    }

    private static PendingRequestsResponse Envelope(string? jws, string? raw = Raw)
        => new(Array.Empty<PendingRequest>(), jws) { RequestsRawJson = raw };

    [Fact]
    public void Pending_SignedByThePinnedKeyOverTheseBytes_Verifies()
    {
        var (priv, pubHex) = Key();
        var r = BootloaderAttestation.VerifyPendingEnvelope(
            Envelope(MintPending(priv, Raw)), pubHex, BootloaderId, PhoneId, now: Now + 1);
        Assert.True(r.Verified, r.Error);
    }

    [Fact]
    public void Pending_Unsigned_FailsByEnvelope()
    {
        var (_, pubHex) = Key();
        var r = BootloaderAttestation.VerifyPendingEnvelope(Envelope(null), pubHex, BootloaderId, PhoneId, now: Now + 1);
        Assert.False(r.Verified);
        Assert.StartsWith("envelope:", r.Error);
    }

    [Fact]
    public void Pending_ACardChangedOnTheWire_FailsByEnvelope()
    {
        // The interposer's move: relay attest, alter a card. The signature covers
        // the bytes the phone received, so the altered list does not verify.
        var (priv, pubHex) = Key();
        var altered = Raw.Replace("a card", "approve everything");
        var r = BootloaderAttestation.VerifyPendingEnvelope(
            Envelope(MintPending(priv, Raw), altered), pubHex, BootloaderId, PhoneId, now: Now + 1);
        Assert.False(r.Verified);
        Assert.Contains("does not cover these cards", r.Error);
    }

    [Fact]
    public void Pending_AnotherPhonesEnvelope_FailsBySub()
    {
        var (priv, pubHex) = Key();
        var r = BootloaderAttestation.VerifyPendingEnvelope(
            Envelope(MintPending(priv, Raw, sub: "phone:someone-else")), pubHex, BootloaderId, PhoneId, now: Now + 1);
        Assert.False(r.Verified);
        Assert.Contains("another phone", r.Error);
    }

    [Fact]
    public void Pending_AnAttestReusedAsEnvelope_FailsByAction()
    {
        var (priv, pubHex) = Key();
        var r = BootloaderAttestation.VerifyPendingEnvelope(
            Envelope(MintPending(priv, Raw, action: BootloaderAttestation.Action)), pubHex, BootloaderId, PhoneId, now: Now + 1);
        Assert.False(r.Verified);
        Assert.Contains("allow_actions", r.Error);
    }

    [Fact]
    public void Pending_AnotherKey_FailsBySignature()
    {
        var (priv, _) = Key();
        var (_, otherPub) = Key();
        var r = BootloaderAttestation.VerifyPendingEnvelope(
            Envelope(MintPending(priv, Raw)), otherPub, BootloaderId, PhoneId, now: Now + 1);
        Assert.False(r.Verified);
        Assert.StartsWith("signature:", r.Error);
    }

    [Fact]
    public void Pending_NoKeyPinned_FailsByPin()
    {
        var (priv, _) = Key();
        var r = BootloaderAttestation.VerifyPendingEnvelope(
            Envelope(MintPending(priv, Raw)), null, BootloaderId, PhoneId, now: Now + 1);
        Assert.False(r.Verified);
        Assert.StartsWith("pin:", r.Error);
    }
}
