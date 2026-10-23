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
    private volatile string? _pairingHost;

    public void BeginPairing(string host)
    {
        _pairingHost = host;
    }

    public void EndPairing()
    {
        _pairingHost = null;
    }

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

    public bool HasDrifted(string host)
    {
        return _pins.TryGetValue(host, out var pinned)
            && _observed.TryGetValue(host, out var seen)
            && pinned != seen;
    }

    public bool Validate(string host, string actualSpki, bool systemTrustOk)
    {
        // Always record what we saw: the pairing flow promotes the observed
        // pin to a permanent one, and HasDrifted compares it to the pin.
        _observed[host] = actualSpki;

        // 2026-09-16 -- THE LEAF PIN IS NO LONGER A LOCK. Until this build a
        // registered pin was the only thing that mattered: Cloudflare
        // reissued the edge certificate for the bootloader host on its own
        // schedule and every paired phone failed the handshake, below HTTP,
        // with no way back but a hand re-pair (and the pairing flow itself
        // ran through the same pinned branch, so even that failed until the
        // pin was cleared). The pin stays as an ANCHOR so a self-signed LAN
        // bootloader keeps working after pairing; a CA-trusted chain is
        // accepted whether or not it matches, and the change is surfaced by
        // HasDrifted so the caller can prove the server's identity with
        // GET /v0.4/attest (signed by the key pinned at pairing) and re-pin.
        if (systemTrustOk)
        {
            return true;
        }
        if (_pins.TryGetValue(host, out var pinned))
        {
            return pinned == actualSpki;
        }

        // No pin and no system trust: the pre-pairing TOFU window for a
        // self-signed dev/LAN bootloader. It is OPEN only between
        // BeginPairing(host) and EndPairing() - the user-initiated pairing
        // operation - and only for THAT host; SetPin locks the anchor once
        // pairing succeeds. Any other host, or any time outside the window,
        // is refused (recurve 2026-09-25: the comment promised this scope,
        // the code did not keep it).
        return string.Equals(_pairingHost, host, StringComparison.OrdinalIgnoreCase);
    }
}
