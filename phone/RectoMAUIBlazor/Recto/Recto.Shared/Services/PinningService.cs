using System.Collections.Concurrent;

namespace Recto.Shared.Services;

/// <summary>
/// Thread-safe in-memory pinning service. Pins are persisted in
/// <see cref="Models.PairingState.BootloaderSpkiPin"/> alongside the rest
/// of the pairing record; on app start, Home.razor restores the pin into
/// this service from PairingState before any HTTP traffic begins.
/// </summary>
public sealed class PinningService : IPinningService
{
    private readonly ConcurrentDictionary<string, string> _pins = new();
    private readonly ConcurrentDictionary<string, string> _observed = new();

    public void RecordObserved(string host, string spkiPinB64u)
    {
        _observed[host] = spkiPinB64u;
    }

    public string? GetObservedPin(string host)
    {
        return _observed.TryGetValue(host, out var pin) ? pin : null;
    }

    public void SetPin(string host, string spkiPinB64u)
    {
        _pins[host] = spkiPinB64u;
    }

    public string? GetPin(string host)
    {
        return _pins.TryGetValue(host, out var pin) ? pin : null;
    }

    public void ClearPin(string host)
    {
        _pins.TryRemove(host, out _);
    }

    public bool Validate(string host, string actualSpki, bool systemTrustOk)
    {
        // Always record what we saw so the pairing flow can promote the
        // observed pin to a permanent one.
        _observed[host] = actualSpki;

        // If a pin is registered for this host, it's the only thing that
        // matters &mdash; system-trust outcome is irrelevant (this is what
        // makes self-signed LAN bootloaders viable post-pairing).
        if (_pins.TryGetValue(host, out var pinned))
        {
            return pinned == actualSpki;
        }

        // No pin yet -- this is the pre-pairing TOFU window. Accept
        // whatever the bootloader presents (CA-signed prod cert, Let's
        // Encrypt via tunnel, or self-signed LAN dev cert) so the pairing
        // handshake can complete; the observed SPKI is recorded above and
        // gets promoted to a permanent pin via SetPin once pairing
        // succeeds. Subsequent connections after SetPin run through the
        // pinned branch above where any change in the cert chain fails
        // validation regardless of system trust. The TOFU window is small
        // by design: it spans only the explicit user-initiated pairing
        // operation, after which the pin is locked.
        return true;
    }
}
