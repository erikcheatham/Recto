using Recto.Shared.Services;
using Xunit;

namespace Recto.Shared.Tests;

public class PinningServiceTests
{
    private const string Host = "127.0.0.1";
    private const string PinA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private const string PinB = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    [Fact]
    public void Validate_NoPinNoObservation_OutsidePairing_Refuses()
    {
        // Recurve 2026-09-25 (fail-open-pinning): with no pin and no system
        // trust, and NO pairing in flight, an unknown certificate is refused.
        // The observed SPKI is still recorded (HasDrifted needs it).
        var sut = new PinningService();

        var ok = sut.Validate(Host, PinA, systemTrustOk: false);

        Assert.False(ok);
        Assert.Equal(PinA, sut.GetObservedPin(Host));
        Assert.Null(sut.GetPin(Host));
    }

    [Fact]
    public void Validate_DuringPairing_SelfSignedCert_AcceptsForTofu()
    {
        // The pre-pairing TOFU window: between BeginPairing(host) and
        // EndPairing(), a self-signed dev/LAN bootloader is accepted so the
        // pairing handshake can complete, and the observed SPKI is recorded
        // for the pairing flow to promote.
        var sut = new PinningService();
        sut.BeginPairing(Host);

        var ok = sut.Validate(Host, PinA, systemTrustOk: false);

        Assert.True(ok);
        Assert.Equal(PinA, sut.GetObservedPin(Host));
    }

    [Fact]
    public void Validate_DuringPairing_OtherHost_Refuses()
    {
        // The window is for ONE host. A different host presenting an
        // untrusted certificate while a pairing is in flight is refused.
        var sut = new PinningService();
        sut.BeginPairing(Host);

        var ok = sut.Validate("other.example", PinA, systemTrustOk: false);

        Assert.False(ok);
    }

    [Fact]
    public void Validate_AfterEndPairing_Refuses()
    {
        // The window closes with the pairing operation, whether or not a pin
        // was set; nothing about "no pin yet" reopens it.
        var sut = new PinningService();
        sut.BeginPairing(Host);
        sut.EndPairing();

        var ok = sut.Validate(Host, PinA, systemTrustOk: false);

        Assert.False(ok);
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
    public void Validate_AfterSetPin_CaTrustedReissue_AcceptsAndReportsDrift()
    {
        // 2026-09-16 -- THE CLOUDFLARE REISSUE. The edge certificate for the
        // bootloader host was reissued with a new key on the CA's schedule.
        // The old semantics ("a pin is the only thing that matters") failed
        // the handshake below HTTP on every paired phone and the pairing
        // flow ran through the same branch, so even a re-pair failed until
        // the pin was cleared by hand. A CA-trusted chain is now accepted
        // and the change is REPORTED, so the caller proves the server with
        // GET /v0.4/attest (signed by the key pinned at pairing) and re-pins.
        var sut = new PinningService();
        sut.SetPin(Host, PinA);

        Assert.False(sut.HasDrifted(Host));
        var ok = sut.Validate(Host, PinB, systemTrustOk: true);

        Assert.True(ok);
        Assert.True(sut.HasDrifted(Host));
        Assert.Equal(PinA, sut.GetPin(Host));       // the pin is the caller's to move
        Assert.Equal(PinB, sut.GetObservedPin(Host));
    }

    [Fact]
    public void Validate_AfterSetPin_UntrustedMismatch_Rejects()
    {
        // A self-signed LAN bootloader whose cert changed, or an interposer
        // with no CA behind it: no system trust AND no pin match = refuse.
        var sut = new PinningService();
        sut.SetPin(Host, PinA);

        var ok = sut.Validate(Host, PinB, systemTrustOk: false);

        Assert.False(ok);
        Assert.True(sut.HasDrifted(Host));
    }

    [Fact]
    public void Validate_AfterSetPin_SelfSignedMatch_StillAccepts()
    {
        // The pin remains the ANCHOR for self-signed LAN bootloaders: a
        // matching cert is accepted with no CA chain at all.
        var sut = new PinningService();
        sut.SetPin(Host, PinA);

        Assert.True(sut.Validate(Host, PinA, systemTrustOk: false));
        Assert.False(sut.HasDrifted(Host));
    }

    [Fact]
    public void HasDrifted_IsFalseWithNoPinOrNoObservation()
    {
        var sut = new PinningService();
        Assert.False(sut.HasDrifted(Host));
        sut.Validate(Host, PinA, systemTrustOk: true);
        Assert.False(sut.HasDrifted(Host));     // observed, nothing pinned
        sut.SetPin("other.example", PinA);
        Assert.False(sut.HasDrifted("other.example")); // pinned, nothing observed
    }

    [Fact]
    public void Validate_RecordsObservedEvenOnMismatch()
    {
        var sut = new PinningService();
        sut.SetPin(Host, PinA);

        sut.Validate(Host, PinB, systemTrustOk: false);

        // Observed gets updated regardless of whether validation passes --
        // useful for diagnostics when the user reports "my pin keeps
        // failing", we can show what the actual cert is presenting.
        Assert.Equal(PinB, sut.GetObservedPin(Host));
    }

    [Fact]
    public void ClearPin_RemovesPin_ButDoesNotReopenTofu()
    {
        var sut = new PinningService();
        sut.SetPin(Host, PinA);

        sut.ClearPin(Host);

        Assert.Null(sut.GetPin(Host));
        // No pin is not a window: an untrusted cert is refused until a
        // pairing opens the window for this host (recurve 2026-09-25).
        Assert.False(sut.Validate(Host, PinB, systemTrustOk: false));
        sut.BeginPairing(Host);
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
