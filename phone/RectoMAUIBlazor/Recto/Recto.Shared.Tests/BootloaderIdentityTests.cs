using System;
using System.Linq;
using Recto.Shared.Protocol.V04;
using Recto.Shared.Services;
using Xunit;

namespace Recto.Shared.Tests;

/// <summary>
/// The C# sister of tests/test_bootloader_identity.py on the Python side.
/// The two parity pins are THE cross-language contract: if these fail, the
/// C# derivation is wrong — or the server derivation changed without bumping
/// its version string. Never repair a parity failure by editing the pin.
/// </summary>
public class BootloaderIdentityTests
{
    private static readonly byte[] Operator =
        Enumerable.Range(0, 64).Select(b => (byte)b).ToArray();

    private static readonly byte[] Member =
        Operator.Select(b => (byte)((b + 7) % 256)).ToArray();

    private static string B64u(byte[] b) =>
        Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    // ── the cross-language contract ──────────────────────────────────────

    [Fact]
    public void ParityPin_OperatorOnly_MatchesThePythonBootloader()
    {
        Assert.Equal("rb1-1f344bc9162a781dff78b772d05c17e4",
            BootloaderIdentity.Derive(Operator));
    }

    [Fact]
    public void ParityPin_OperatorPlusMember_MatchesThePythonBootloader()
    {
        Assert.Equal("rb1-340247a518af7a52e22f56f9f88bff5e",
            BootloaderIdentity.Derive(Operator, new[] { Member }));
    }

    // ── the three properties, mirrored ───────────────────────────────────

    [Fact]
    public void Derivation_IsOrderIndependent()
    {
        var a = BootloaderIdentity.Derive(Operator, new[] { new byte[] { 1 }, new byte[] { 2 } });
        var b = BootloaderIdentity.Derive(Operator, new[] { new byte[] { 2 }, new byte[] { 1 } });
        Assert.Equal(a, b);
    }

    [Fact]
    public void DuplicateMembers_DoNotChangeTheId()
    {
        Assert.Equal(
            BootloaderIdentity.Derive(Operator, new[] { Member }),
            BootloaderIdentity.Derive(Operator, new[] { Member, Member }));
    }

    [Fact]
    public void LengthPrefixing_PreventsConcatenationAmbiguity()
    {
        Assert.NotEqual(
            BootloaderIdentity.Derive(Operator, new[] { "AB"u8.ToArray(), "C"u8.ToArray() }),
            BootloaderIdentity.Derive(Operator, new[] { "A"u8.ToArray(), "BC"u8.ToArray() }));
    }

    [Fact]
    public void AddingAMember_ChangesTheId()
    {
        Assert.NotEqual(
            BootloaderIdentity.Derive(Operator),
            BootloaderIdentity.Derive(Operator, new[] { Member }));
    }

    // ── the pairing-time gate ────────────────────────────────────────────

    [Fact]
    public void Check_LegacyOrDemoId_MakesNoClaim()
    {
        var result = BootloaderIdentity.Check("demo-bootloader-app-review", null);
        Assert.Equal(BootloaderIdentityStatus.NoClaim, result.Status);
    }

    [Fact]
    public void Check_DerivedIdWithoutInputs_Refuses()
    {
        // An rb1- id claims to be recomputable; withholding the inputs is
        // treated as failure, not as an excuse — fail closed.
        var result = BootloaderIdentity.Check("rb1-1f344bc9162a781dff78b772d05c17e4", null);
        Assert.Equal(BootloaderIdentityStatus.Refused, result.Status);
        Assert.Contains("no key set", result.Reason);
    }

    [Fact]
    public void Check_MatchingIdentity_Verifies()
    {
        var identity = new BootloaderIdentityInfo(
            BootloaderIdentity.DerivationV1,
            B64u(Operator),
            new[] { B64u(Member) });
        var result = BootloaderIdentity.Check(
            "rb1-340247a518af7a52e22f56f9f88bff5e", identity);
        Assert.Equal(BootloaderIdentityStatus.Verified, result.Status);
    }

    [Fact]
    public void Check_CorrectKeySetButWrongId_Refuses()
    {
        // The load-bearing falsifier, asserted literally: correct key set +
        // wrong id -> REFUSE to pair.
        var identity = new BootloaderIdentityInfo(
            BootloaderIdentity.DerivationV1,
            B64u(Operator),
            new[] { B64u(Member) });
        var result = BootloaderIdentity.Check(
            "rb1-00000000000000000000000000000000", identity);
        Assert.Equal(BootloaderIdentityStatus.Refused, result.Status);
        Assert.Contains("mismatch", result.Reason);
    }

    [Fact]
    public void Check_UnknownDerivationVersion_Refuses()
    {
        var identity = new BootloaderIdentityInfo(
            "recto-bootloader-id-v999",
            B64u(Operator),
            Array.Empty<string>());
        var result = BootloaderIdentity.Check(
            "rb1-1f344bc9162a781dff78b772d05c17e4", identity);
        Assert.Equal(BootloaderIdentityStatus.Refused, result.Status);
    }

    // ── membership discovery (the genesis-marker trigger) ────────────────

    [Fact]
    public void IsMemberOfIdentity_FindsMyOwnKeyInTheMemberSet()
    {
        var identity = new BootloaderIdentityInfo(
            BootloaderIdentity.DerivationV1, B64u(Operator), new[] { B64u(Member) });
        Assert.True(BootloaderIdentity.IsMemberOfIdentity(Member, identity));
    }

    [Fact]
    public void IsMemberOfIdentity_OperatorKeyIsNotAMember()
    {
        // The operator key is the DERIVATION ANCHOR, not a member entry —
        // a phone holding it must not self-mark off this list.
        var identity = new BootloaderIdentityInfo(
            BootloaderIdentity.DerivationV1, B64u(Operator), new[] { B64u(Member) });
        Assert.False(BootloaderIdentity.IsMemberOfIdentity(Operator, identity));
    }

    [Fact]
    public void IsMemberOfIdentity_NoIdentity_IsNever_a_Member()
    {
        Assert.False(BootloaderIdentity.IsMemberOfIdentity(Member, null));
        Assert.False(BootloaderIdentity.IsMemberOfIdentity(null, null));
    }

    [Fact]
    public void Check_MalformedKeyMaterial_Refuses()
    {
        var identity = new BootloaderIdentityInfo(
            BootloaderIdentity.DerivationV1,
            "!!!not-base64url!!!",
            Array.Empty<string>());
        var result = BootloaderIdentity.Check(
            "rb1-1f344bc9162a781dff78b772d05c17e4", identity);
        Assert.Equal(BootloaderIdentityStatus.Refused, result.Status);
    }
}
