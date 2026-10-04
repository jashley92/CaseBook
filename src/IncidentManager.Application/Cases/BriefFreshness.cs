using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Cases;

/// <summary>
/// INV-27: how far the record has moved on since the current brief was written, so a stale brief is visible. Counts
/// what was recorded after the brief (timeline entries and response milestones, by recorded time) and names the most
/// recent change that usually changes where a case stands (a decision, a handoff, a phase, classification or
/// materiality change), so the brief card can suggest an update. A read-time view: it never writes, and nothing is
/// forced.
/// </summary>
public static class BriefFreshness
{
    /// <param name="Count">Entries and milestones recorded after the brief.</param>
    /// <param name="Breakdown">The same, by kind, e.g. ("timeline entries", 3), ("phase changes", 1).</param>
    /// <param name="Prompt">Why the brief may need updating, from the latest decision / handoff / phase /
    /// classification / materiality change after it, or null when there's none.</param>
    public sealed record Result(int Count, IReadOnlyList<(string What, int Count)> Breakdown, string? Prompt);

    public static Result Since(Case c, CaseBrief brief, MilestoneLabels labels)
    {
        var since = brief.CreatedAtUtc;

        var entries = c.TimelineEntries.Where(e => e.IsCurrent && e.CreatedAtUtc > since).ToList();
        var milestones = CaseMilestones.Project(c, labels)
            .Where(m => m.Kind != MilestoneKind.Opened && (m.RecordedAtUtc ?? m.AtUtc) > since)
            .ToList();

        var breakdown = new List<(string, int)>();
        if (entries.Count > 0) breakdown.Add((entries.Count == 1 ? "timeline entry" : "timeline entries", entries.Count));
        foreach (var g in milestones.GroupBy(m => m.Kind).OrderBy(g => g.Key))
            breakdown.Add((KindName(g.Key, g.Count()), g.Count()));

        // The latest change that usually moves where the case stands, by when it was recorded.
        var candidates = entries
            .Where(e => e.Type is TimelineEntryType.Decision or TimelineEntryType.Handoff)
            .Select(e => (At: e.CreatedAtUtc, Text: e.Type == TimelineEntryType.Decision
                ? "A decision was recorded after this version."
                : "The case was handed off after this version."))
            .Concat(milestones
                .Where(m => m.Kind is MilestoneKind.Phase or MilestoneKind.Classification or MilestoneKind.Materiality)
                .Select(m => (At: m.RecordedAtUtc ?? m.AtUtc, Text: m.Kind switch
                {
                    MilestoneKind.Phase => $"The case moved to {After(m.Title)} after this version.",
                    MilestoneKind.Classification => $"The case was reclassified as {After(m.Title)} after this version.",
                    _ => "The materiality determination changed after this version."
                })));
        var prompt = candidates.OrderByDescending(x => x.At).Select(x => x.Text).FirstOrDefault();

        return new Result(entries.Count + milestones.Count, breakdown, prompt);
    }

    // "Phase Containment → Eradication" → "Eradication".
    private static string After(string title) =>
        title.LastIndexOf('→') is var i and >= 0 ? title[(i + 1)..].Trim() : title;

    private static string KindName(MilestoneKind kind, int n) => (kind, n == 1) switch
    {
        (MilestoneKind.Classification, true) => "classification change",
        (MilestoneKind.Classification, false) => "classification changes",
        (MilestoneKind.Severity, true) => "severity change",
        (MilestoneKind.Severity, false) => "severity changes",
        (MilestoneKind.Phase, true) => "phase change",
        (MilestoneKind.Phase, false) => "phase changes",
        (MilestoneKind.Materiality, _) => "materiality determination" + (n == 1 ? "" : "s"),
        (MilestoneKind.TaskDone, true) => "task completed",
        (MilestoneKind.TaskDone, false) => "tasks completed",
        (MilestoneKind.EvidenceAdded, _) => n == 1 ? "evidence file" : "evidence files",
        (MilestoneKind.Command, _) => n == 1 ? "team change" : "team changes",
        (MilestoneKind.Verdict, _) => n == 1 ? "verdict change" : "verdict changes",
        _ => n == 1 ? "other milestone" : "other milestones"
    };
}
