using System;

namespace Recto.Shared.Services;

/// <summary>
/// How long ago the phone last had a verified reply from its bootloader, in
/// words for Pairing details. The stamp lives in memory: it survives the OS
/// freezing the app, and a fresh launch says it has heard nothing yet.
/// </summary>
public static class LastHeard
{
    public const string NotYet = "not yet since the app opened";

    public static string Describe(DateTimeOffset? at, DateTimeOffset now)
    {
        if (at is null) return NotYet;
        var age = now - at.Value;
        if (age < TimeSpan.FromSeconds(10)) return "just now";
        if (age < TimeSpan.FromMinutes(1)) return $"{(int)age.TotalSeconds} s ago";
        if (age < TimeSpan.FromHours(1)) return $"{(int)age.TotalMinutes} min ago";
        if (age < TimeSpan.FromHours(48)) return $"{(int)age.TotalHours} h ago";
        return $"{(int)age.TotalDays} days ago";
    }
}
