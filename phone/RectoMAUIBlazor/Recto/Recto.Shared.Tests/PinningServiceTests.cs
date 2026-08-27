using Recto.Shared.Services;
using Xunit;

namespace Recto.Shared.Tests;

public class PinningServiceTests
{
    private const string Host = "127.0.0.1";
    private const string PinA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private const string PinB = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    [Fact]
    public void Validate_NoPinNoObservation_AcceptsAnyCert()
    {
        // The pre-pairing TOFU window: nothing has been seen yet, no pin
        // is set. Accept whatever the bootloader presents -- the observed
        // SPKI is recorded so the pairing flow can promote it later.
        var sut = new PinningService();

        var ok = sut.Validate(Host, PinA, systemTrustOk: false);

        Assert.True(ok);
        Assert.Equal(PinA, sut.GetObservedPin(Host));
        Assert.Null(sut.GetPin(Host));
    }

    [Fact]
    public void Validate_NoPinSelfSignedCert_StillAcceptsForTofu()
    {
        // Even when system trust says NO (typical for self-signed dev/LAN
        // bootloaders), the TOFU window must accept the connection so the
        // pairing handshake can complete.
        var sut = new PinningService();

        var ok = sut.Validate(Host, PinA, systemTrustOk: false);

        Assert.True(ok);
    }

    [Fact]
    public void GetObservedPin_BeforeAnyValidate_ReturnsNull()
    {
        var sut = new PinningService();
        Assert.Null(sut.GetObservedPin(Host));
    }

    [Fact]
    public void Validate_AfterSetPinMatchingCert_Accepts()
    {
        var sut = new PinningService();
        sut.SetPin(Host, PinA);

        var ok = sut.Validate(Host, PinA, systemTrustOk: true);

        Assert.True(ok);
    }

    [Fact]
    public void Validate_AfterSetPinMismatchedCert_Rejects()
    {
        var sut = new PinningService();
        sut.SetPin(Host, PinA);

        var ok = sut.Validate(Host, PinB, systemTrustOk: true);

        Assert.False(ok);
    }

    [Fact]
    public void Validate_AfterSetPin_IgnoresSystemTrustOutcome()
    {
        // Once a pin is registered, system trust is irrelevant -- only the
        // pin match decides. This is what makes self-signed LAN bootloaders
        // viable post-pairing: the pin is the canonical identity, not the
        // (absent) CA chain.
        var sut = new PinningService();
        sut.SetPin(Host, PinA);

        Assert.True(sut.Validate(Host, PinA, systemTrustOk: false));
        Assert.False(sut.Validate(Host, PinB, systemTrustOk: true));
    }

    [Fact]
    public void Validate_RecordsObservedEvenOnMismatch()
    {
        var sut = new PinningService();
        sut.SetPin(Host, PinA);

        sut.Validate(Host, PinB, systemTrustOk: true);

        // Observed gets updated regardless of whether validation passes --
        // useful for diagnostics when the user reports "my pin keeps
        // failing", we can show what the actual cert is presenting.
        Assert.Equal(PinB, sut.GetObservedPin(Host));
    }

    [Fact]
    public void ClearPin_RemovesPinAndReturnsToTofuMode()
    {
        var sut = new PinningService();
        sut.SetPin(Host, PinA);

        sut.ClearPin(Host);

        Assert.Null(sut.GetPin(Host));
        // Back in TOFU window -- new connection accepts whatever cert.
        Assert.True(sut.Validate(Host, PinB, systemTrustOk: false));
    }

    [Fact]
    public void RecordObserved_StoresIndependentlyOfValidate()
    {
        var sut = new PinningService();

        sut.RecordObserved(Host, PinA);

        Assert.Equal(PinA, sut.GetObservedPin(Host));
    }

    [Fact]
    public void Pins_ScopedPerHost()
    {
        var sut = new PinningService();
        sut.SetPin("host-a.example", PinA);
        sut.SetPin("host-b.example", PinB);

        Assert.True(sut.Validate("host-a.example", PinA, systemTrustOk: false));
        Assert.True(sut.Validate("host-b.example", PinB, systemTrustOk: false));
        Assert.False(sut.Validate("host-a.example", PinB, systemTrustOk: false));
        Assert.False(sut.Validate("host-b.example", PinA, systemTrustOk: false));
    }
}
