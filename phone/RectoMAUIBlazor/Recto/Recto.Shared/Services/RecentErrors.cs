namespace Recto.Shared.Services;

/// <summary>
/// THE ERROR THAT OUTLIVES ITS PANEL (2026-09-21). The home page's polling warning clears itself the moment the next
/// 3-second poll succeeds - so a failure that happens DURING an approve (the respond, or the refresh right after) is on
/// screen for one tick and gone, and the operator reports "a slight yellow panel" with no sentence to bring. A refusal
/// a user cannot read is the same class as one they cannot see (Settings, 2026-08-23). This keeps the last few, in
/// memory, with the UTC time and the phase that raised each; Settings renders them. Process-lifetime only: nothing is
/// persisted, nothing leaves the phone, and a message here is the app's own text - never a token, never a payload.
/// </summary>
public static class RecentErrors
{
    public sealed record Entry(DateTimeOffset AtUtc, string Phase, string Message);

    private const int Keep = 12;
    private static readonly object _gate = new();
    private static readonly LinkedList<Entry> _entries = new();

    /// <summary>Record one. <paramref name="phase"/> names where it came from (poll · approve/respond · approve/refresh · retry).</summary>
    public static void Record(string phase, string? message)
    {
        if (string.IsNullOrWhiteSpace(message)) return;
        lock (_gate)
        {
            // the same message repeating (a poll loop against a dead host) is one row with a count, not twelve rows
            if (_entries.First?.Value is { } last && last.Phase == phase && last.Message == message) return;
            _entries.AddFirst(new Entry(DateTimeOffset.UtcNow, phase, message.Length > 400 ? message[..400] : message));
            while (_entries.Count > Keep) _entries.RemoveLast();
        }
    }

    public static IReadOnlyList<Entry> Snapshot()
    {
        lock (_gate) return _entries.ToList();
    }

    public static void Clear()
    {
        lock (_gate) _entries.Clear();
    }
}
