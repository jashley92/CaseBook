using System.Text;
using System.Text.RegularExpressions;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Cases;

/// <summary>CAP-20: the parts of a handoff entry, as <see cref="HandoffNote.Parse"/> reads them back. Null when absent.</summary>
public sealed record HandoffParts(string? HandedTo, string? WhereItStands, string? DoneSince, string? StillOpen, string? WatchFor);

/// <summary>CAP-20: the last handoff's "watch for" note, for the card on Now.</summary>
/// <param name="EntryId">The handoff entry (its current version).</param>
/// <param name="HandedBy">Who handed the case off: the user id that recorded the entry's first version.</param>
/// <param name="HandedAtUtc">When the handoff was first recorded (an edit doesn't move it, BUG-363).</param>
/// <param name="HandedTo">The recipient's name as the entry gives it, or null when it can't be read (edited away).</param>
/// <param name="WatchFor">The "Watch for" part, as Markdown.</param>
public sealed record HandoverWatch(Guid EntryId, string HandedBy, DateTimeOffset HandedAtUtc, string? HandedTo, string WatchFor);

/// <summary>
/// CAP-20 (INV-15): a handoff is stored as one Markdown text the hand-off form writes: "**Handed to Name**", then a bold
/// heading line and its text for each part filled in (<see cref="Heading"/>). This reads it back. The entry can be edited,
/// so the reading is lenient: a heading may be bold, a Markdown heading or plain, end in a colon, or carry its text on the
/// same line after a colon ("Watch for: lateral movement"); text before the first heading isn't a part. A line is read as
/// a heading only when it is nothing but the label, or the label and a colon, so "Still open questions are…" stays text.
/// An entry with no headings (written another way, or rewritten) has no parts, and so no card.
/// </summary>
public static partial class HandoffNote
{
    public const string WhereItStands = "Where it stands";
    public const string DoneSince = "Done since the last handoff";
    public const string StillOpen = "Still open";
    public const string WatchFor = "Watch for";

    /// <summary>The line the form writes before a part's text.</summary>
    public static string Heading(string label) => $"**{label}**";

    /// <summary>The line the form writes first, naming the recipient.</summary>
    public static string HandedToLine(string name) => $"**Handed to {name}**";

    [GeneratedRegex(@"^(?:#{1,6}\s+)?(?:\*\*|__)?\s*(?<label>where it stands|done since the last handoff|still open|watch for)(?<sep>\s*(?::\s*(?:\*\*|__)?|(?:\*\*|__)\s*:?))?\s*(?<rest>.*)$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 1000)]
    private static partial Regex HeadingLine();

    [GeneratedRegex(@"^(?:\*\*|__)?\s*handed\s+(?:off\s+)?to\s+(?<name>.+?)\s*(?:\*\*|__)?\s*$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 1000)]
    private static partial Regex HandedToPattern();

    /// <summary>The parts of a handoff's text. Never throws; what it can't read is null.</summary>
    public static HandoffParts Parse(string? text)
    {
        string? to = null;
        var parts = new Dictionary<string, StringBuilder>(StringComparer.OrdinalIgnoreCase);
        StringBuilder? current = null;
        foreach (var raw in (text ?? "").Replace("\r\n", "\n").Split('\n'))
        {
            var line = raw.Trim();
            if (HeadingLine().Match(line) is { Success: true } h
                && (h.Groups["rest"].Length == 0 || h.Groups["sep"].Value.Contains(':')))
            {
                var label = h.Groups["label"].Value;
                if (!parts.TryGetValue(label, out current)) parts[label] = current = new StringBuilder();
                if (h.Groups["rest"].Length > 0) current.Append(h.Groups["rest"].Value).Append('\n');
                continue;
            }
            if (current is null)
            {
                if (to is null && HandedToPattern().Match(line) is { Success: true } m) to = m.Groups["name"].Value.Trim();
                continue;
            }
            current.Append(raw.TrimEnd()).Append('\n');
        }
        string? Part(string label) => parts.TryGetValue(label, out var sb) && sb.ToString().Trim() is { Length: > 0 } s ? s : null;
        return new HandoffParts(string.IsNullOrWhiteSpace(to) ? null : to, Part(WhereItStands), Part(DoneSince), Part(StillOpen), Part(WatchFor));
    }

    /// <summary>
    /// The latest handoff's "watch for", or null when the latest handoff (by when it was first recorded) has none. An
    /// earlier handoff's note isn't carried past a later handoff: the case has moved on to someone else since.
    /// </summary>
    public static HandoverWatch? Latest(Case c)
    {
        var latest = c.TimelineEntries.Where(e => e.IsCurrent && e.Type == TimelineEntryType.Handoff)
            .Select(e => (Entry: e, First: HandoffDraft.FirstVersion(c, e)))
            .OrderByDescending(x => x.First.CreatedAtUtc).FirstOrDefault();
        if (latest.Entry is null) return null;
        var parts = Parse(latest.Entry.Description);
        return parts.WatchFor is { } watch
            ? new HandoverWatch(latest.Entry.Id, latest.First.CreatedBy, latest.First.CreatedAtUtc, parts.HandedTo, watch)
            : null;
    }

    /// <summary>
    /// Whether <paramref name="userId"/> is the person the case was handed to. The entry names them as the form wrote
    /// them (their display name), so that's what is compared, ignoring case. When the name can't be read, nobody is.
    /// </summary>
    public static bool IsRecipient(HandoverWatch w, string? userId, Func<string?, string> displayName) =>
        !string.IsNullOrWhiteSpace(userId) && w.HandedTo is { } to
        && string.Equals(displayName(userId).Trim(), to, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Whether the person who took the case has taken stock since the handoff: revised the brief (a version they wrote;
    /// one CaseBook appended for them, WF-30, doesn't count) or confirmed it still stands. When the entry no longer names
    /// the recipient, anyone but the person who handed off counts, so the card can't outstay the handover.
    /// </summary>
    public static bool TakenStock(Case c, HandoverWatch w, Func<string?, string> displayName)
    {
        bool Taker(string? actor) => !string.IsNullOrWhiteSpace(actor)
            && (w.HandedTo is not null ? IsRecipient(w, actor, displayName) : !string.Equals(actor, w.HandedBy, StringComparison.OrdinalIgnoreCase));
        return c.Briefs.Any(b => (!b.Appended && b.CreatedAtUtc > w.HandedAtUtc && Taker(b.CreatedBy))
                                 || (b.ConfirmedAtUtc is { } at && at > w.HandedAtUtc && Taker(b.ConfirmedBy)));
    }

    /// <summary>The card Now shows: the latest handoff's watch-for note until the person who took the case takes stock.</summary>
    public static HandoverWatch? ForNow(Case c, Func<string?, string> displayName) =>
        Latest(c) is { } w && !TakenStock(c, w, displayName) ? w : null;
}
