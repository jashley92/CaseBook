using System.Text.RegularExpressions;
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
    ReportFinal,
    /// <summary>INV-31: someone joined, changed role (including command) or left the case.</summary>
    Command,
    /// <summary>HR-05: an entity's verdict changed (a finding), with why.</summary>
    Verdict,
    /// <summary>HR-06: the brief's working assessment changed: what the team believes, in sequence.</summary>
    Assessment,
    /// <summary>HR-07: when the activity began (the case's initial-activity time), the start of the story.</summary>
    ActivityBegan,
    /// <summary>CAP-21: an evidence file was withdrawn: its "Evidence added" milestone, in its place, with why.</summary>
    EvidenceWithdrawn,
    /// <summary>FR-51: the case was contained (marked contained, or said when moving on), the end of time-to-contain.</summary>
    Contained,
    /// <summary>HR-07: when the activity was detected or reported, its own row when that was before the case was opened.</summary>
    Detected
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
    (TransitionKind Kind, Guid ChangeId)? Transition = null,
    string? Note = null);

/// <summary>Display labels the projection needs, supplied by the caller (they're admin-customizable). CAP-38 review:
/// <paramref name="Standing"/> is the case's standing with its regulators (<see cref="NoticeStanding"/>, the reading every
/// view uses); given, the reported milestone follows it, so the timeline, brief and handoff can't say "reported" while a
/// regulator's clock runs. Without it (a caller that has no clocks to hand), the stored reported time.</summary>
public sealed partial record MilestoneLabels(
    Func<Classification?, string> Classification,
    Func<Severity, string> Severity,
    Func<CasePhase, string> Phase,
    Func<MaterialityStatus, string> Materiality,
    Func<string, string>? Outcome = null,
    Func<EntityDisposition, string>? Disposition = null,
    Func<DateTimeOffset, string>? Day = null,
    NoticeStanding? Standing = null)
{
    /// <summary>BUG-112: a calendar date as the reader's zone has it (the UI passes one); the UTC date otherwise.</summary>
    public string DayLabel(DateTimeOffset at) =>
        Day?.Invoke(at) ?? at.UtcDateTime.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);

    /// <summary>HR-05: a verdict's label (admin-customizable when supplied, else the member name).</summary>
    public string DispositionLabel(EntityDisposition d) => Disposition?.Invoke(d) ?? d.ToString();

    /// <summary>HR-01: an outcome's label (admin-managed when supplied, else the built-in default).</summary>
    public string OutcomeLabel(string key) => Outcome?.Invoke(key) ?? Admin.CaseOutcomeCatalog.Label(key);

    /// <summary>INV-31: a case role as it's written in a sentence ("incident commander", "analyst").</summary>
    public static string Role(CaseAssignmentRole role) => role switch
    {
        CaseAssignmentRole.IncidentCommander => "incident commander",
        _ => InnerCapitalRx().Replace(role.ToString(), " $1").ToLowerInvariant()
    };

    [GeneratedRegex("(?<!^)([A-Z])")]
    private static partial Regex InnerCapitalRx();
}

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
        // HR-07: detection before the case was opened is its own row, at its own time; the case is opened when it was.
        // (One row at detection titled "Detected; case opened as …" read as the case opened then.) Filed well after
        // detection, the detection row is marked as recorded later and the opening says how long after.
        var lead = c.DetectedAtUtc is { } detected ? c.CreatedAtUtc - detected : TimeSpan.Zero;
        var filedLater = lead > CaseService.BackdateReasonThreshold;
        if (lead >= TimeSpan.FromMinutes(1))
            list.Add(new CaseMilestone($"detected:{c.Id}", c.DetectedAtUtc!.Value, MilestoneKind.Detected,
                $"Detected{(string.IsNullOrWhiteSpace(c.DetectionCaseId) ? "" : $" ({c.DetectionCaseId.Trim()})")}",
                null, null, "case record", RecordedAtUtc: filedLater ? c.CreatedAtUtc : null));
        list.Add(new CaseMilestone($"open:{c.Id}", c.CreatedAtUtc, MilestoneKind.Opened,
            "Case opened as " + labels.Classification(initialClass?.To) +
            (initialSev is null ? "" : $" · {labels.Severity(initialSev.To)}"),
            filedLater ? $"{Span(lead)} after detection" : null, c.CreatedBy, "case creation"));

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
                $"Phase {labels.Phase(x.From!.Value)} → {labels.Phase(x.To)}"
                    + (x.OutcomeKey is { } outcome ? $" · {labels.OutcomeLabel(outcome)}" : ""),   // HR-01
                Blank(x.Reason), x.ChangedBy, "phase change", RecordedAtUtc: Recorded(x.EffectiveAtUtc, x.ChangedAtUtc),
                Transition: (TransitionKind.Phase, x.Id)));

        // FR-51: when it was contained, from the case's contained time. Before FR-51 entering Containment set it, and that
        // phase change already tells it; a skip that recorded "not needed" holds the decision's time, not a containment.
        if (c.ContainedAtUtc is { } contained && c.ContainmentNotNeededReason is null
            && !c.StatusChanges.Any(x => x.To == CasePhase.Containment && x.From is not null && x.EffectiveAt == contained))
            list.Add(new CaseMilestone($"contained:{c.Id}", contained, MilestoneKind.Contained, "Contained",
                c.DetectedAtUtc is { } det && contained > det ? $"{Span(contained - det)} after detection" : null,
                c.ContainedBy, "containment",   // FR-51: who recorded it; its time is corrected like a transition's
                RecordedAtUtc: c.ContainedRecordedAtUtc is { } rec ? Later(contained, rec) : null,
                Transition: (TransitionKind.Contained, c.Id)));

        // HR-05: findings: an entity re-assessed (e.g. Unknown → Compromised), with the reason given.
        foreach (var x in c.VerdictChanges)
            list.Add(new CaseMilestone($"verdict:{x.Id}", x.EffectiveAt, MilestoneKind.Verdict,   // BUG-414: when it was reached
                $"{x.EntityLabel} assessed {labels.DispositionLabel(x.To)}"
                    + (x.From == EntityDisposition.Unknown ? "" : $" (was {labels.DispositionLabel(x.From)})"),
                Blank(x.Reason), x.ChangedBy, "verdict change", RecordedAtUtc: Recorded(x.EffectiveAtUtc, x.ChangedAtUtc),
                Transition: (TransitionKind.Verdict, x.Id)));

        // HR-06: changes in understanding. Each brief version whose working assessment differs from the one before.
        // A closing brief's conclusion is left out: the Closed milestone already carries it.
        string? previous = null;
        foreach (var b in c.Briefs.OrderBy(b => b.Version))
        {
            var text = b.WorkingAssessment?.Trim();
            var atClose = c.StatusChanges.Any(s => s.To == CasePhase.Closed && s.ChangedAtUtc == b.CreatedAtUtc);
            if (!string.IsNullOrEmpty(text) && text != previous && !atClose)
                list.Add(new CaseMilestone($"assessment:{b.Id}", b.CreatedAtUtc, MilestoneKind.Assessment,
                    previous is null ? $"Working assessment recorded (brief v{b.Version})" : $"Assessment revised (brief v{b.Version})",
                    text.Length > 600 ? text[..599] + "…" : text, b.CreatedBy, "brief"));
            if (!string.IsNullOrEmpty(text)) previous = text;
        }

        // INV-31: who took command, joined, changed role or left. A commander handing over as someone else takes
        // command (both at the same moment) reads as one milestone.
        foreach (var x in c.AssignmentChanges)
        {
            var handedOver = x.From == CaseAssignmentRole.IncidentCommander && x.To is not null
                && c.AssignmentChanges.Any(y => y.ChangedAtUtc == x.ChangedAtUtc && y.To == CaseAssignmentRole.IncidentCommander && y.UserId != x.UserId);
            if (handedOver) continue;
            var previousIc = x.To == CaseAssignmentRole.IncidentCommander
                ? c.AssignmentChanges.FirstOrDefault(y => y.ChangedAtUtc == x.ChangedAtUtc && y.From == CaseAssignmentRole.IncidentCommander && y.UserId != x.UserId)
                : null;
            var title = (x.From, x.To) switch
            {
                (_, CaseAssignmentRole.IncidentCommander) => $"{x.UserDisplayName} is incident commander" +
                    (previousIc is null ? "" : $", taking over from {previousIc.UserDisplayName}"),
                (null, { } to) => $"{x.UserDisplayName} joined as {MilestoneLabels.Role(to)}",
                ({ } from, null) => $"{x.UserDisplayName} is no longer on the case (was {MilestoneLabels.Role(from)})",
                (_, { } to) => $"{x.UserDisplayName} is now {MilestoneLabels.Role(to)}",
                _ => $"{x.UserDisplayName}'s role changed"
            };
            list.Add(new CaseMilestone($"command:{x.Id}", x.ChangedAtUtc, MilestoneKind.Command, title, null, x.ChangedBy, "assignment"));
        }

        // WF-12: the notification clock follows the latest Material call, so a call taken back to Under review stops it and
        // a new Material call restarts it from its own time. The record says so where it happens.
        DateTimeOffset? runningFrom = null;
        foreach (var x in c.MaterialityChanges.OrderBy(m => m.ChangedAtUtc))
        {
            var decided = x.DecisionMaker is { Length: > 0 } who
                ? $"Decided by {who}" + (x.DecidedOnUtc is { } on ? $" on {labels.DayLabel(on)}" : "") + "."
                : null;
            string? clock = null;
            if (x.To == MaterialityStatus.Material)
            {
                var from = x.DecidedOnUtc ?? x.ChangedAtUtc;
                if (x.From != MaterialityStatus.Material && c.MaterialityChanges.Any(m => m.To == MaterialityStatus.Material && m.ChangedAtUtc < x.ChangedAtUtc))
                    clock = $"The notification clock restarts from this call ({labels.DayLabel(from)}).";
                runningFrom = from;
            }
            else if (x.From == MaterialityStatus.Material && x.To != MaterialityStatus.NotMaterial && runningFrom is { } ran)
            {
                clock = $"The notification clock stopped (it ran from {labels.DayLabel(ran)}).";
                runningFrom = null;
            }
            var detail = string.Join(" ", new[] { decided, Blank(x.Rationale), clock }.Where(s => s is not null));
            list.Add(new CaseMilestone($"mat:{x.Id}", x.ChangedAtUtc, MilestoneKind.Materiality,
                x.From == x.To ? $"Materiality determination revised ({labels.Materiality(x.To)})"   // REV-13
                    : $"Materiality {labels.Materiality(x.From)} → {labels.Materiality(x.To)}",
                Blank(detail), x.ChangedBy, "materiality record"));
        }

        // HR-07: a gate passage belongs to the transition it guarded (recorded in the same save). A passed gate folds
        // into that milestone as a note; an override stays its own flagged row, at the transition's time.
        // BUG-492: a climb (Complex Event to Incident) passes a gate per rung in one save; each folds in, in climb order.
        var folded = new Dictionary<int, List<StageGateTrigger>>();
        var filing = FilingPassages(c);
        var opened = list.FindIndex(m => m.Kind == MilestoneKind.Opened);
        var summaries = c.Briefs.Select(b => b.Summary?.Trim()).Append(c.Summary?.Trim())
            .Where(x => !string.IsNullOrEmpty(x)).ToHashSet(StringComparer.Ordinal);
        foreach (var g in c.GatePassages.OrderBy(g => g.PassedAtUtc).ThenBy(g => g.Trigger))
        {
            // FR-52: the gates passed in filing fold into "Case opened as …" as one note. Their commentary is the summary
            // the case was filed with, which the case already tells; repeated on a row per gate it said the same thing
            // twice in the timeline and the report. A commentary of its own, or an override, keeps its row.
            if (filing.Contains(g) && !g.WasOverridden && opened >= 0
                && (Blank(g.Commentary) is not { } said || summaries.Contains(said.Trim())))
            {
                if (!folded.TryGetValue(opened, out var filed)) folded[opened] = filed = [];
                if (!filed.Contains(g.Trigger)) filed.Add(g.Trigger);
                list[opened] = list[opened] with { Note = PassedNote(filed) };
                continue;
            }
            var guarded = filing.Contains(g) ? null : GuardedTransitionKey(c, g);   // BUG-504
            var at = guarded is { } gk && list.FirstOrDefault(m => m.Key == gk) is { } tm ? tm.AtUtc : g.PassedAtUtc;
            if (!g.WasOverridden && guarded is { } key && list.FindIndex(m => m.Key == key) is var i and >= 0)
            {
                if (!folded.TryGetValue(i, out var gates)) folded[i] = gates = [];
                if (!gates.Contains(g.Trigger)) gates.Add(g.Trigger);
                list[i] = list[i] with { Note = PassedNote(gates) };
                continue;
            }
            list.Add(new CaseMilestone($"gate:{g.Id}", at, MilestoneKind.Gate,
                $"{GateName(g.Trigger)} gate {(g.WasOverridden ? "overridden" : "passed")}",
                g.WasOverridden ? Blank(g.OverrideJustification) is { } why ? $"Justification: {why}" : null
                                : Blank(g.Commentary),
                g.PassedBy, "stage gate", Flagged: g.WasOverridden, RecordedAtUtc: at != g.PassedAtUtc ? g.PassedAtUtc : null));
        }

        // HR-07: the story starts when the activity did.
        // ST-04: when it comes from an approximate first step, it says so and measures nothing from it.
        if (c.OccurredAtUtc is { } began && (c.DetectedAtUtc is null || began < c.DetectedAtUtc))
            list.Add(StepTime.ActivityBeganCaveat(c) is { } approx
                ? new CaseMilestone($"began:{c.Id}", began, MilestoneKind.ActivityBegan, "Activity began (approximately)",
                    $"Approximate: {approx}.", null, "case record")
                : new CaseMilestone($"began:{c.Id}", began, MilestoneKind.ActivityBegan, "Activity began",
                    c.DetectedAtUtc is { } det ? $"{Span(det - began)} before detection" : null, null, "case record"));

        // BUG-09: with more than one regulator, each notice is its own milestone; the case is reported when the last is.
        // CAP-07: its detail says how the regulator was notified, when that's recorded. CAP-38: and while the case is partly
        // reported (a regulator in play still owed), even one notice is its own "Notified NY": the case isn't reported yet.
        // CAP-38 review: reported by the standing when the caller has it, so a stored time set over a running clock isn't told.
        var reportedAt = labels.Standing is { } standing ? standing.ReportedAtUtc : c.ReportedAtUtc;
        if (c.JurisdictionNotices.Count > 1 || (c.JurisdictionNotices.Count == 1 && reportedAt is null))
            foreach (var n in c.JurisdictionNotices.OrderBy(n => n.NotifiedAtUtc))
                list.Add(new CaseMilestone($"notice:{n.Id}", n.NotifiedAtUtc, MilestoneKind.Reported,
                    $"Notified {n.Jurisdiction}", Compliance.NoticeDetailText.Summary(n, c.Evidence), n.CreatedBy, "notice",
                    RecordedAtUtc: Later(n.NotifiedAtUtc, n.CreatedAtUtc)));
        // BUG-364: dated when it happened, recorded when the (last) notice was entered, so a backdated notice still counts
        // as new in the "since" windows. CAP-07: with one notice, this milestone tells it, so it carries how it was given.
        if (reportedAt is { } reported)
            list.Add(new CaseMilestone($"reported:{c.Id}", reported, MilestoneKind.Reported,
                c.JurisdictionNotices.Count > 1 ? "Reported to every regulator in play" : "Reported to regulators",
                c.JurisdictionNotices.Count == 1 ? Compliance.NoticeDetailText.Summary(c.JurisdictionNotices[0], c.Evidence) : null,
                null, "reported milestone",
                RecordedAtUtc: c.JurisdictionNotices.Count > 0 ? Later(reported, c.JurisdictionNotices.Max(n => n.CreatedAtUtc)) : null));

        // A task whose result was logged on the timeline (INV-08) is told by that entry; don't say it twice.
        var loggedTasks = c.TimelineEntries.Where(e => e.IsCurrent && e.ActionItemId is not null)
            .Select(e => e.ActionItemId!.Value).ToHashSet();
        foreach (var t in c.ActionItems.Where(t => t.Status == ActionItemStatus.Done && t.CompletedAtUtc is not null
                                                   && !loggedTasks.Contains(t.Id)))
            // BUG-365: credited to who completed it (HR-02), not whoever edited the task last; BUG-364: and recorded when
            // the completion was. Tasks completed before either was kept fall back as before.
            list.Add(new CaseMilestone($"task:{t.Id}", t.CompletedAtUtc!.Value, MilestoneKind.TaskDone,
                $"Task done: {t.Title}", null, t.CompletedBy ?? t.ModifiedBy ?? t.Owner, "task",
                RecordedAtUtc: t.CompletionRecordedAtUtc is { } rec ? Later(t.CompletedAtUtc!.Value, rec) : null));

        // A screenshot pasted into a timeline entry already shows on that entry; so does a file an entry cites (HR-07).
        // BUG-443: only a current entry shows it; a retracted (or superseded) one is off the timeline.
        var current = c.TimelineEntries.Where(e => e.IsCurrent).ToList();
        var currentIds = current.Select(e => e.Id).ToHashSet();
        var onEntries = current.Where(e => e.EvidenceId is not null).Select(e => e.EvidenceId!.Value)
            .Concat(c.Citations.Where(x => currentIds.Contains(x.TimelineEntryId)).Select(x => x.EvidenceId)).ToHashSet();
        // CAP-08: dated when it was collected, when that's recorded, and "recorded later" (at the upload) when the upload
        // was in a later minute; where from and by whom follow the description.
        // CAP-21: a withdrawn file's milestone stays in its place, as a retracted entry's stub does (BUG-413), and says it was
        // withdrawn, by whom and why, whether or not an entry cites it (a citation no longer shows it).
        foreach (var ev in c.Evidence.Where(ev => ev.IsWithdrawn || !onEntries.Contains(ev.Id)))
        {
            var collected = Evidence.EvidenceCollection.Source(ev) is { } source ? $"Collected {source}." : null;
            var detail = Blank(ev.Description) is { } d
                ? collected is null ? d : $"{d}{(d.EndsWith('.') || d.EndsWith('?') || d.EndsWith('!') ? "" : ".")} {collected}"
                : collected;
            var recorded = ev.CollectedAtUtc is { } at ? Later(at, ev.CreatedAtUtc) : null;
            if (ev.IsWithdrawn)
                list.Add(new CaseMilestone($"ev:{ev.Id}", ev.CollectedOrUploadedAtUtc, MilestoneKind.EvidenceWithdrawn,
                    $"Evidence withdrawn: {ev.OriginalFileName} ({Common.TextFit.Cap(ev.WithdrawnReason?.Trim().TrimEnd('.'), 300)})",
                    detail, ev.WithdrawnBy, "evidence", RecordedAtUtc: recorded));
            else
                list.Add(new CaseMilestone($"ev:{ev.Id}", ev.CollectedOrUploadedAtUtc, MilestoneKind.EvidenceAdded,
                    $"Evidence added: {ev.OriginalFileName}", detail, ev.CreatedBy, "evidence", RecordedAtUtc: recorded));
        }

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

    // BUG-364: the recorded time when it's in a later minute than the time given (entered after the fact); null when it
    // was entered as it happened, so the timeline doesn't mark every notice "recorded".
    private static DateTimeOffset? Later(DateTimeOffset happened, DateTimeOffset recorded) =>
        Case.ToMinute(recorded) > Case.ToMinute(happened) ? recorded : null;

    private static string? Blank(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();

    // HR-07: the transition milestone a gate passage guarded: the change to Closed for the close gate, the change to
    // the gate's classification (or past it, on a climb) for the others, recorded within a minute of the passage (the same save).
    private static string? GuardedTransitionKey(Case c, GatePassage g)
    {
        static bool Near(DateTimeOffset a, DateTimeOffset b) => (a - b).Duration() <= TimeSpan.FromMinutes(1);
        if (g.Trigger == StageGateTrigger.CloseCase)
            return c.StatusChanges.Where(s => s.To == CasePhase.Closed && s.From is not null && Near(s.ChangedAtUtc, g.PassedAtUtc))
                .OrderBy(s => (s.ChangedAtUtc - g.PassedAtUtc).Duration()).Select(s => $"phase:{s.Id}").FirstOrDefault();
        Classification? to = g.Trigger switch
        {
            StageGateTrigger.PromoteToAdverseEvent => Classification.AdverseEvent,
            StageGateTrigger.EscalateToIncident => Classification.Incident,
            StageGateTrigger.EscalateToBreach => Classification.Breach,
            _ => null
        };
        return c.ClassificationChanges.Where(x => !IsInitial(c)(x) && Near(x.ChangedAtUtc, g.PassedAtUtc)
                                                  // BUG-492: a rung passed on the way up guards the climb past it
                                                  && (to is null || x.To >= to || g.Trigger == StageGateTrigger.PromoteToAdverseEvent))
            .OrderBy(x => (x.ChangedAtUtc - g.PassedAtUtc).Duration()).Select(x => $"cls:{x.Id}").FirstOrDefault();
    }

    // BUG-504: the passages the creation save recorded: a case filed onto a rung passes the climb up to it (CreateAsync),
    // once per gate. Each is the first passage of a gate on that climb, recorded before any later classification change
    // (passing one of those gates again needs a lowering first). They guard the filing, so they never fold into a later change.
    private static HashSet<GatePassage> FilingPassages(Case c)
    {
        if (c.ClassificationChanges.FirstOrDefault(IsInitial(c)) is not { } initial) return [];
        var firstChange = c.ClassificationChanges.Where(x => !IsInitial(c)(x)).Select(x => (DateTimeOffset?)x.ChangedAtUtc).Min();
        return StageGates.StageGateTriggers.Climb(null, initial.To)
            .Select(t => c.GatePassages.Where(g => g.Trigger == t && (firstChange is null || g.PassedAtUtc <= firstChange))
                .MinBy(g => g.PassedAtUtc))
            .OfType<GatePassage>().ToHashSet();
    }

    private static string Span(TimeSpan t) =>
        t.TotalMinutes < 90 ? $"{Math.Max(1, (int)Math.Round(t.TotalMinutes))} min"
        : t.TotalHours < 48 ? $"{(int)Math.Round(t.TotalHours)} h"
        : $"{(int)t.TotalDays} d {(int)(t.TotalHours % 24)} h";

    // BUG-492: "Promotion gate passed"; for a climb, "Promotion and Incident escalation gates passed".
    private static string PassedNote(List<StageGateTrigger> gates)
    {
        var names = gates.Select(GateName).ToList();
        return names.Count == 1 ? $"{names[0]} gate passed"
            : $"{string.Join(", ", names.Take(names.Count - 1))} and {names[^1]} gates passed";
    }

    private static string GateName(StageGateTrigger t) => t switch
    {
        StageGateTrigger.PromoteToAdverseEvent => "Promotion",
        StageGateTrigger.EscalateToIncident => "Incident escalation",
        StageGateTrigger.EscalateToBreach => "Breach escalation",
        StageGateTrigger.CloseCase => "Close",
        _ => t.ToString()
    };
}
