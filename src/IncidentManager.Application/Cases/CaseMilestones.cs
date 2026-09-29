using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Cases;

/// <summary>What kind of case record a <see cref="CaseMilestone"/> was derived from.</summary>
public enum MilestoneKind
{
    Opened,
    Classification,
    Severity,
    Phase,
    Materiality,
    Gate,
    Reported,
    TaskDone,
    EvidenceAdded,
    ReportFinal
}

/// <summary>
/// One response milestone shown on the case timeline (INV-01). A read-time view of a record the case already
/// holds, such as a phase change or a gate passage: nothing is copied or stored, so the audit chain is untouched
/// and the milestone can never drift from its source. <see cref="Key"/> is stable per source record.
/// </summary>
/// <param name="Actor">The user id of whoever made the change, or null when the source doesn't record one.</param>
/// <param name="Source">Where the milestone comes from, in words (e.g. "phase change").</param>
/// <param name="Flagged">True when the milestone deserves attention, such as a gate that was overridden.</param>
/// <param name="RecordedAtUtc">INV-05: when the change was recorded, set only when it was dated to an earlier
/// effective time (<see cref="AtUtc"/>) — so the timeline can say it was recorded later.</param>
/// <param name="Transition">INV-05b: for a classification, phase or severity change, its kind and record id, so
/// the time it happened can be corrected. Null for every other milestone.</param>
public sealed record CaseMilestone(
    string Key,
    DateTimeOffset AtUtc,
    MilestoneKind Kind,
    string Title,
    string? Detail,
    string? Actor,
    string Source,
    bool Flagged = false,
    DateTimeOffset? RecordedAtUtc = null,
    (TransitionKind Kind, Guid ChangeId)? Transition = null);

/// <summary>Display labels the projection needs, supplied by the caller (they're admin-customizable).</summary>
public sealed record MilestoneLabels(
    Func<Classification?, string> Classification,
    Func<Severity, string> Severity,
    Func<CasePhase, string> Phase,
    Func<MaterialityStatus, string> Materiality);

/// <summary>
/// INV-01: projects a case's existing change records onto its timeline as milestones — case opened,
/// classification / severity / phase and materiality changes, stage-gate passages, the reported-to-regulators
/// milestone, completed tasks, evidence added and final reports. Deterministic, read-only, and consistent with
/// the human-gated stance: every milestone is a human act that already happened; the timeline only shows it.
/// </summary>
public static class CaseMilestones
{
    /// <param name="c">The case with its change histories, gate passages, tasks, evidence, reports and timeline loaded.</param>
    public static IReadOnlyList<CaseMilestone> Project(Case c, MilestoneLabels labels)
    {
        var list = new List<CaseMilestone>();

        // The opening state: the initial classification (a Complex Event has none) and severity.
        var initialClass = c.ClassificationChanges.FirstOrDefault(IsInitial(c));
        var initialSev = c.SeverityChanges.Where(x => x.From is null).OrderBy(x => x.ChangedAtUtc).FirstOrDefault();
        list.Add(new CaseMilestone($"open:{c.Id}", c.CreatedAtUtc, MilestoneKind.Opened,
            $"Case opened as {labels.Classification(initialClass?.To)}" +
            (initialSev is null ? "" : $" · {labels.Severity(initialSev.To)}"),
            null, c.CreatedBy, "case creation"));

        foreach (var x in c.ClassificationChanges.Where(x => !IsInitial(c)(x)))
            list.Add(new CaseMilestone($"cls:{x.Id}", x.EffectiveAt, MilestoneKind.Classification,
                $"Classification {labels.Classification(x.From)} → {labels.Classification(x.To)}",
                Blank(x.Reason), x.ChangedBy, "classification change", RecordedAtUtc: Recorded(x.EffectiveAtUtc, x.ChangedAtUtc),
                Transition: (TransitionKind.Classification, x.Id)));

        foreach (var x in c.SeverityChanges.Where(x => x.From is not null))
            list.Add(new CaseMilestone($"sev:{x.Id}", x.EffectiveAt, MilestoneKind.Severity,
                $"Severity {labels.Severity(x.From!.Value)} → {labels.Severity(x.To)}",
                Blank(x.Reason), x.ChangedBy, "severity change", RecordedAtUtc: Recorded(x.EffectiveAtUtc, x.ChangedAtUtc),
                Transition: (TransitionKind.Severity, x.Id)));

        foreach (var x in c.StatusChanges.Where(x => x.From is not null))
            list.Add(new CaseMilestone($"phase:{x.Id}", x.EffectiveAt, MilestoneKind.Phase,
                $"Phase {labels.Phase(x.From!.Value)} → {labels.Phase(x.To)}",
                Blank(x.Reason), x.ChangedBy, "phase change", RecordedAtUtc: Recorded(x.EffectiveAtUtc, x.ChangedAtUtc),
                Transition: (TransitionKind.Phase, x.Id)));

        foreach (var x in c.MaterialityChanges)
        {
            var decided = x.DecisionMaker is { Length: > 0 } who
                ? $"Decided by {who}" + (x.DecidedOnUtc is { } on ? $" on {on.UtcDateTime:yyyy-MM-dd}" : "") + "."
                : null;
            var detail = string.Join(" ", new[] { decided, Blank(x.Rationale) }.Where(s => s is not null));
            list.Add(new CaseMilestone($"mat:{x.Id}", x.ChangedAtUtc, MilestoneKind.Materiality,
                $"Materiality {labels.Materiality(x.From)} → {labels.Materiality(x.To)}",
                Blank(detail), x.ChangedBy, "materiality record"));
        }

        foreach (var g in c.GatePassages)
            list.Add(new CaseMilestone($"gate:{g.Id}", g.PassedAtUtc, MilestoneKind.Gate,
                $"{GateName(g.Trigger)} gate {(g.WasOverridden ? "overridden" : "passed")}",
                g.WasOverridden ? Blank(g.OverrideJustification) is { } why ? $"Justification: {why}" : null
                                : Blank(g.Commentary),
                g.PassedBy, "stage gate", Flagged: g.WasOverridden));

        if (c.ReportedAtUtc is { } reported)
            list.Add(new CaseMilestone($"reported:{c.Id}", reported, MilestoneKind.Reported,
                "Reported to regulators", null, null, "reported milestone"));

        foreach (var t in c.ActionItems.Where(t => t.Status == ActionItemStatus.Done && t.CompletedAtUtc is not null))
            list.Add(new CaseMilestone($"task:{t.Id}", t.CompletedAtUtc!.Value, MilestoneKind.TaskDone,
                $"Task done: {t.Title}", null, t.ModifiedBy ?? t.Owner, "task"));

        // A screenshot pasted into a timeline entry already shows on that entry; list only the rest.
        var onEntries = c.TimelineEntries.Where(e => e.EvidenceId is not null).Select(e => e.EvidenceId!.Value).ToHashSet();
        foreach (var ev in c.Evidence.Where(ev => !onEntries.Contains(ev.Id)))
            list.Add(new CaseMilestone($"ev:{ev.Id}", ev.CreatedAtUtc, MilestoneKind.EvidenceAdded,
                $"Evidence added: {ev.OriginalFileName}", Blank(ev.Description), ev.CreatedBy, "evidence"));

        foreach (var r in c.Reports.Where(r => r.IsFinal && r.ApprovedAtUtc is not null))
            list.Add(new CaseMilestone($"report:{r.Id}", r.ApprovedAtUtc!.Value, MilestoneKind.ReportFinal,
                $"{(r.Kind == ReportKind.LessonsLearned ? "Lessons-learned report" : "Case report")} v{r.Version} approved as final",
                null, r.ApprovedBy, "report"));

        return list.OrderBy(m => m.AtUtc).ThenBy(m => (int)m.Kind).ToList();
    }

    // The opening classification is stamped at creation with no "from"; a later null-"from" change is a
    // Complex Event's promotion onto the ladder, which is a milestone in its own right.
    private static Func<ClassificationChange, bool> IsInitial(Case c) =>
        x => x.From is null && x.ChangedAtUtc <= c.CreatedAtUtc;

    private static DateTimeOffset? Recorded(DateTimeOffset? effective, DateTimeOffset recorded) =>
        effective is not null ? recorded : null;

    private static string? Blank(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();

    private static string GateName(StageGateTrigger t) => t switch
    {
        StageGateTrigger.PromoteToAdverseEvent => "Promotion",
        StageGateTrigger.EscalateToIncident => "Incident escalation",
        StageGateTrigger.EscalateToBreach => "Breach escalation",
        StageGateTrigger.CloseCase => "Close",
        _ => t.ToString()
    };
}
