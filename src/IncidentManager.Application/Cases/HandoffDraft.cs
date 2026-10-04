using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Cases;

/// <summary>
/// INV-21: the "done since the last handoff" pre-fill. It lists what the team did (investigation entries,
/// decisions labelled as such, and response milestones such as phase changes and completed tasks), not what the
/// adversary did: event steps logged in the window are only counted, so a handoff saved unedited never records
/// the attacker's actions as the team's work. The analyst edits the text before handing off.
/// </summary>
public static class HandoffDraft
{
    // Milestones that are response work. Case opened, evidence added and final reports stay out: they're noise
    // in a handoff, and the reader can see them on the timeline.
    private static readonly HashSet<MilestoneKind> WorkMilestones =
    [
        MilestoneKind.Classification, MilestoneKind.Severity, MilestoneKind.Phase, MilestoneKind.Materiality,
        MilestoneKind.Gate, MilestoneKind.Reported, MilestoneKind.TaskDone, MilestoneKind.Verdict, MilestoneKind.Assessment
    ];

    /// <summary>When the last handoff was recorded, or when the case was opened if there hasn't been one.</summary>
    public static DateTimeOffset Since(Case c) =>
        c.TimelineEntries.Where(e => e.IsCurrent && e.Type == TimelineEntryType.Handoff)
            .Select(e => (DateTimeOffset?)e.CreatedAtUtc).Max() ?? c.CreatedAtUtc;

    /// <summary>
    /// The pre-fill as Markdown bullets, ordered by when things happened, or null when nothing was recorded
    /// since the last handoff. The window is by recorded time: what was logged since the last handoff.
    /// </summary>
    /// <param name="oneLine">Flattens an entry's Markdown to a single short line.</param>
    public static string? DoneSince(Case c, MilestoneLabels labels, Func<string, string> oneLine)
    {
        var since = Since(c);

        var entries = c.TimelineEntries
            .Where(e => e.IsCurrent && e.Kind == TimelineKind.Investigation && e.Type != TimelineEntryType.Handoff
                        && FirstRecorded(c, e) > since)
            .Select(e => (At: e.OccurredAtUtc,
                Text: (e.Type == TimelineEntryType.Decision ? "Decision: " : "") + oneLine(e.Description)));

        var milestones = CaseMilestones.Project(c, labels)
            .Where(m => WorkMilestones.Contains(m.Kind) && (m.RecordedAtUtc ?? m.AtUtc) > since)
            .Select(m => (At: m.AtUtc, Text: m.Title));

        var lines = entries.Concat(milestones).OrderBy(x => x.At).Select(x => "- " + x.Text).ToList();

        var learned = c.TimelineEntries.Count(e => e.IsCurrent && e.Kind == TimelineKind.Event
                                                   && FirstRecorded(c, e) > since);
        if (learned > 0)
            lines.Add($"- Learned: {learned} event step{(learned == 1 ? "" : "s")} added to the timeline");

        return lines.Count > 0 ? string.Join("\n", lines) : null;
    }

    // An edited entry was first recorded when its original version was, so an edit doesn't pull an old entry
    // into the window.
    private static DateTimeOffset FirstRecorded(Case c, TimelineEntry e)
    {
        var first = e;
        while (first.SupersedesEntryId is { } prior && c.TimelineEntries.FirstOrDefault(x => x.Id == prior) is { } p)
            first = p;
        return first.CreatedAtUtc;
    }
}
