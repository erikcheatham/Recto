using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Recto.Shared.Capability;
using Recto.Shared.Common;
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
        string action = BootloaderAttestation.PendingAction, string iss = $"bootloader:{BootloaderId}",
        long exp = Now + 300)
    {
        var sha = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(raw))).ToLowerInvariant();
        // Mint() hashes a nonce; hand it the digest directly and any nonce.
        return Mint(priv, BootloaderAttestation.NewNonceB64u(), iss: iss, action: action,
            exp: exp, payloadShaOverride: sha, sub: sub);
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

    // -----------------------------------------------------------------
    // A REPLY THAT WAITED: a past exp on a reply the pinned key signed
    // (a frozen app resuming, a slow network) is its own class, and earns
    // exactly one refetch before the phone judges.
    // -----------------------------------------------------------------

    [Fact]
    public void Pending_SignedByThePinnedKeyWithAPastExp_IsClassedStale()
    {
        var (priv, pubHex) = Key();
        var r = BootloaderAttestation.VerifyPendingEnvelope(
            Envelope(MintPending(priv, Raw, exp: Now + 10)), pubHex, BootloaderId, PhoneId, now: Now + 11);

        Assert.False(r.Verified);
        Assert.True(r.Expired);
        Assert.Contains("exp=", r.Error);
    }

    [Fact]
    public void Pending_APastExpUnderAnotherKey_IsNotStale()
    {
        // The signature is checked before the clock: a stranger's old reply
        // is a stranger's reply, not a late one.
        var (priv, _) = Key();
        var (_, otherPub) = Key();
        var r = BootloaderAttestation.VerifyPendingEnvelope(
            Envelope(MintPending(priv, Raw, exp: Now + 10)), otherPub, BootloaderId, PhoneId, now: Now + 11);

        Assert.False(r.Verified);
        Assert.False(r.Expired);
        Assert.StartsWith("signature:", r.Error);
    }

    [Fact]
    public void Pending_ANotBeforeInTheFuture_IsNotStale()
    {
        var (priv, pubHex) = Key();
        var r = BootloaderAttestation.VerifyPendingEnvelope(
            Envelope(MintPending(priv, Raw)), pubHex, BootloaderId, PhoneId, now: Now - 60);

        Assert.False(r.Verified);
        Assert.False(r.Expired);
    }

    [Fact]
    public void Attest_SignedByThePinnedKeyWithAPastExp_IsClassedStale()
    {
        var (priv, pubHex) = Key();
        var nonce = BootloaderAttestation.NewNonceB64u();
        var resp = new AttestResponse(BootloaderId, nonce, Mint(priv, nonce));

        var r = BootloaderAttestation.Verify(resp, pubHex, BootloaderId, nonce, now: Now + 121);

        Assert.False(r.Verified);
        Assert.True(r.Expired);
    }

    [Fact]
    public void AVerifiedOrRefusedReply_IsNeverStale()
    {
        var (priv, pubHex) = Key();
        Assert.False(BootloaderAttestation.VerifyPendingEnvelope(
            Envelope(MintPending(priv, Raw)), pubHex, BootloaderId, PhoneId, now: Now + 1).Expired);
        Assert.False(BootloaderAttestation.VerifyPendingEnvelope(
            Envelope(null), pubHex, BootloaderId, PhoneId, now: Now + 1).Expired);
    }

    // A past exp is classed stale only on a reply that passes every other
    // check. An old reply bound to another nonce, other cards, another phone,
    // issuer, action or audience is refused by that binding: an interposer
    // replaying captured replies is reported as one, not as a clock problem.

    [Fact]
    public void Attest_APastExpOverAnotherNonce_IsRefusedByNonce_NotStale()
    {
        // A captured attest with its unsigned echo rewritten to this phone's
        // nonce: the signature still covers the nonce it was minted for.
        var (priv, pubHex) = Key();
        var mine = BootloaderAttestation.NewNonceB64u();
        var resp = new AttestResponse(BootloaderId, mine, Mint(priv, BootloaderAttestation.NewNonceB64u()));

        var r = BootloaderAttestation.Verify(resp, pubHex, BootloaderId, mine, now: Now + 121);

        Assert.False(r.Verified);
        Assert.False(r.Expired);
        Assert.StartsWith("nonce:", r.Error);
    }

    [Fact]
    public void Attest_APastExpUnderAnotherIssuerOrAction_IsNotStale()
    {
        var (priv, pubHex) = Key();
        var nonce = BootloaderAttestation.NewNonceB64u();

        var otherIss = BootloaderAttestation.Verify(
            new AttestResponse(BootloaderId, nonce, Mint(priv, nonce, iss: "bootloader:rb1-other")),
            pubHex, BootloaderId, nonce, now: Now + 121);
        var otherAction = BootloaderAttestation.Verify(
            new AttestResponse(BootloaderId, nonce, Mint(priv, nonce, action: "devices:pair_result")),
            pubHex, BootloaderId, nonce, now: Now + 121);

        Assert.False(otherIss.Expired);
        Assert.StartsWith("claims: iss", otherIss.Error);
        Assert.False(otherAction.Expired);
        Assert.Contains("allow_actions", otherAction.Error);
    }

    [Fact]
    public void Attest_APastExpForAnotherAudience_IsNotStale()
    {
        var (priv, pubHex) = Key();
        var nonce = BootloaderAttestation.NewNonceB64u();

        var r = BootloaderAttestation.Verify(
            new AttestResponse(BootloaderId, nonce, Mint(priv, nonce, aud: "consumer")),
            pubHex, BootloaderId, nonce, now: Now + 121);

        Assert.False(r.Verified);
        Assert.False(r.Expired);
    }

    [Fact]
    public void Pending_APastExpOverOtherCards_IsRefusedByEnvelope_NotStale()
    {
        var (priv, pubHex) = Key();
        var other = Raw.Replace("a card", "approve everything");

        var r = BootloaderAttestation.VerifyPendingEnvelope(
            Envelope(MintPending(priv, Raw, exp: Now + 10), other), pubHex, BootloaderId, PhoneId, now: Now + 11);

        Assert.False(r.Verified);
        Assert.False(r.Expired);
        Assert.Contains("does not cover these cards", r.Error);
    }

    [Fact]
    public void Pending_APastExpForAnotherPhone_IsRefusedBySub_NotStale()
    {
        var (priv, pubHex) = Key();

        var r = BootloaderAttestation.VerifyPendingEnvelope(
            Envelope(MintPending(priv, Raw, sub: "phone:someone-else", exp: Now + 10)),
            pubHex, BootloaderId, PhoneId, now: Now + 11);

        Assert.False(r.Verified);
        Assert.False(r.Expired);
        Assert.Contains("another phone", r.Error);
    }

    [Fact]
    public void Pending_APastExpUnderAnotherIssuerOrAction_IsNotStale()
    {
        var (priv, pubHex) = Key();

        var otherIss = BootloaderAttestation.VerifyPendingEnvelope(
            Envelope(MintPending(priv, Raw, iss: "bootloader:rb1-other", exp: Now + 10)),
            pubHex, BootloaderId, PhoneId, now: Now + 11);
        var otherAction = BootloaderAttestation.VerifyPendingEnvelope(
            Envelope(MintPending(priv, Raw, action: BootloaderAttestation.Action, exp: Now + 10)),
            pubHex, BootloaderId, PhoneId, now: Now + 11);

        Assert.False(otherIss.Expired);
        Assert.StartsWith("claims: iss", otherIss.Error);
        Assert.False(otherAction.Expired);
        Assert.Contains("allow_actions", otherAction.Error);
    }

    [Fact]
    public async Task AnOldAttestReplayedOverAnotherNonce_IsRefusedWithoutARefetch()
    {
        var (priv, pubHex) = Key();
        var mine = BootloaderAttestation.NewNonceB64u();
        var replayed = new AttestResponse(
            BootloaderId, mine, Mint(priv, BootloaderAttestation.NewNonceB64u(), exp: Now + 10));
        var refetches = 0;

        var judged = await StaleEnvelopeRetry.JudgeAsync(
            (Response: replayed, Nonce: mine),
            a => BootloaderAttestation.Verify(a.Response, pubHex, BootloaderId, a.Nonce, now: Now + 100),
            _ => { refetches++; return Task.FromResult(Result.Success((Response: replayed, Nonce: mine))); },
            CancellationToken.None);

        Assert.Equal(0, refetches);
        Assert.False(judged.Refetched);
        Assert.False(judged.Verdict.Verified);
        Assert.False(judged.Verdict.Expired);
        Assert.StartsWith("nonce:", judged.Verdict.Error);
    }

    [Fact]
    public async Task AnOldEnvelopeReplayedOverOtherCards_IsRefusedWithoutARefetch()
    {
        var (priv, pubHex) = Key();
        var replayed = Envelope(MintPending(priv, Raw, exp: Now + 10), Raw.Replace("a card", "approve everything"));
        var refetches = 0;

        var judged = await StaleEnvelopeRetry.JudgeAsync(
            replayed,
            e => BootloaderAttestation.VerifyPendingEnvelope(e, pubHex, BootloaderId, PhoneId, now: Now + 100),
            _ => { refetches++; return Task.FromResult(Result.Success(replayed)); },
            CancellationToken.None);

        Assert.Equal(0, refetches);
        Assert.False(judged.Verdict.Verified);
        Assert.False(judged.Verdict.Expired);
        Assert.Contains("does not cover these cards", judged.Verdict.Error);
    }

    [Fact]
    public async Task AStaleEnvelope_IsRefetchedOnce_AndTheFreshOneDecides()
    {
        var (priv, pubHex) = Key();
        var stale = Envelope(MintPending(priv, Raw, exp: Now + 10));
        var fresh = Envelope(MintPending(priv, Raw, exp: Now + 600));
        var refetches = 0;

        var judged = await StaleEnvelopeRetry.JudgeAsync(
            stale,
            e => BootloaderAttestation.VerifyPendingEnvelope(e, pubHex, BootloaderId, PhoneId, now: Now + 100),
            _ => { refetches++; return Task.FromResult(Result.Success(fresh)); },
            CancellationToken.None);

        Assert.Equal(1, refetches);
        Assert.True(judged.Refetched);
        Assert.True(judged.Verdict.Verified, judged.Verdict.Error);
        Assert.Same(fresh, judged.Response);
    }

    [Fact]
    public async Task AFreshEnvelope_IsJudgedWithoutARefetch()
    {
        var (priv, pubHex) = Key();
        var fresh = Envelope(MintPending(priv, Raw));
        var refetches = 0;

        var judged = await StaleEnvelopeRetry.JudgeAsync(
            fresh,
            e => BootloaderAttestation.VerifyPendingEnvelope(e, pubHex, BootloaderId, PhoneId, now: Now + 1),
            _ => { refetches++; return Task.FromResult(Result.Success(fresh)); },
            CancellationToken.None);

        Assert.Equal(0, refetches);
        Assert.False(judged.Refetched);
        Assert.True(judged.Verdict.Verified);
        Assert.Same(fresh, judged.Response);
    }

    [Fact]
    public async Task AGenuineIdentityChange_IsRefusedWithoutARefetch()
    {
        var (priv, _) = Key();
        var (_, pinnedPub) = Key();
        var refetches = 0;

        var judged = await StaleEnvelopeRetry.JudgeAsync(
            Envelope(MintPending(priv, Raw)),
            e => BootloaderAttestation.VerifyPendingEnvelope(e, pinnedPub, BootloaderId, PhoneId, now: Now + 1),
            _ => { refetches++; return Task.FromResult(Result.Success(Envelope(MintPending(priv, Raw)))); },
            CancellationToken.None);

        Assert.Equal(0, refetches);
        Assert.False(judged.Verdict.Verified);
        Assert.False(judged.Verdict.Expired);
        Assert.StartsWith("signature:", judged.Verdict.Error);
    }

    [Fact]
    public async Task AStaleEnvelope_FollowedByAnotherKeysEnvelope_IsRefused()
    {
        var (priv, pubHex) = Key();
        var (strangerPriv, _) = Key();
        var refetches = 0;

        var judged = await StaleEnvelopeRetry.JudgeAsync(
            Envelope(MintPending(priv, Raw, exp: Now + 10)),
            e => BootloaderAttestation.VerifyPendingEnvelope(e, pubHex, BootloaderId, PhoneId, now: Now + 100),
            _ => { refetches++; return Task.FromResult(Result.Success(Envelope(MintPending(strangerPriv, Raw, exp: Now + 600)))); },
            CancellationToken.None);

        Assert.Equal(1, refetches);
        Assert.False(judged.Verdict.Verified);
        Assert.StartsWith("signature:", judged.Verdict.Error);
    }

    [Fact]
    public async Task AStaleEnvelope_ThatIsStaleAgain_IsRefused_AfterOneRefetch()
    {
        var (priv, pubHex) = Key();
        var refetches = 0;

        var judged = await StaleEnvelopeRetry.JudgeAsync(
            Envelope(MintPending(priv, Raw, exp: Now + 10)),
            e => BootloaderAttestation.VerifyPendingEnvelope(e, pubHex, BootloaderId, PhoneId, now: Now + 100),
            _ => { refetches++; return Task.FromResult(Result.Success(Envelope(MintPending(priv, Raw, exp: Now + 20)))); },
            CancellationToken.None);

        Assert.Equal(1, refetches);
        Assert.False(judged.Verdict.Verified);
        Assert.True(judged.Verdict.Expired);
        Assert.Null(judged.RefetchError);
    }

    [Fact]
    public async Task AStaleEnvelope_WhoseRefetchCannotReachTheBootloader_IsNotJudged()
    {
        var (priv, pubHex) = Key();

        var judged = await StaleEnvelopeRetry.JudgeAsync(
            Envelope(MintPending(priv, Raw, exp: Now + 10)),
            e => BootloaderAttestation.VerifyPendingEnvelope(e, pubHex, BootloaderId, PhoneId, now: Now + 100),
            _ => Task.FromResult(Result.Failure<PendingRequestsResponse>(Error.Failure("Bootloader request timed out."))),
            CancellationToken.None);

        Assert.True(judged.Refetched);
        Assert.NotNull(judged.RefetchError);
        Assert.False(judged.Verdict.Verified);
        Assert.Null(judged.Response);
    }

    [Fact]
    public async Task AStaleAttest_IsAskedAgainWithAFreshNonce()
    {
        var (priv, pubHex) = Key();
        var firstNonce = BootloaderAttestation.NewNonceB64u();
        string? secondNonce = null;

        var judged = await StaleEnvelopeRetry.JudgeAsync(
            (Response: new AttestResponse(BootloaderId, firstNonce, Mint(priv, firstNonce, exp: Now + 10)), Nonce: firstNonce),
            a => BootloaderAttestation.Verify(a.Response, pubHex, BootloaderId, a.Nonce, now: Now + 100),
            _ =>
            {
                secondNonce = BootloaderAttestation.NewNonceB64u();
                var again = new AttestResponse(BootloaderId, secondNonce, Mint(priv, secondNonce, exp: Now + 600));
                return Task.FromResult(Result.Success((Response: again, Nonce: secondNonce)));
            },
            CancellationToken.None);

        Assert.NotNull(secondNonce);
        Assert.NotEqual(firstNonce, secondNonce);
        Assert.True(judged.Verdict.Verified, judged.Verdict.Error);
    }
}
