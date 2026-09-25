using System.Globalization;
using System.Text;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Application.Common;

namespace IncidentManager.Application.Lessons;

/// <summary>
/// PROD-27: drafts the "What happened" account of a post-incident review from the case record itself: key
/// times, the attack/disclosure sequence from the event timeline, and the recorded decisions (classification,
/// severity and phase changes with their reasons). Deterministic and template-based — CaseBook never calls an
/// AI — and only ever a <b>draft</b>: it fills the editor, a person edits it, and nothing is saved until they
/// save the review. Neutral, factual wording (the review is discoverable), UTC timestamps (it can be exported).
/// </summary>
public static class CaseNarrative
{
    /// <summary>Longest sequence we list before summarising the rest; the full timeline stays on the case.</summary>
    public const int MaxSteps = 25;

    /// <param name="c">The case with its timeline entries (and their tactics) and change histories loaded.</param>
    /// <param name="entityLabel">Resolves an entity id to a short label for actor/target attribution.</param>
    /// <param name="severityLabel">The org's display label for a severity.</param>
    public static string Draft(Case c, Func<Guid, string?> entityLabel, Func<Severity, string> severityLabel, DateTimeOffset nowUtc)
    {
        var sb = new StringBuilder();
        sb.Append(CultureInfo.InvariantCulture, $"_Drafted from the case record on {Day(nowUtc)}. Review and edit before saving._\n\n");

        // Opening line: what the matter is, as recorded now.
        sb.Append(CultureInfo.InvariantCulture,
            $"{Sentence(c.Title)} Recorded as {Article(ClassificationWord(c.Classification))} of {severityLabel(c.Severity)} severity");
        sb.Append(c.Origin == CaseOrigin.ThirdParty ? ", reported to us by a third party.\n\n" : ", identified internally.\n\n");

        // Key times.
        var times = new List<string>();
        void Time(string label, DateTimeOffset? at, DateTimeOffset? from = null, string? sinceLabel = null)
        {
            if (at is not { } t) return;
            var line = $"- **{label}:** {Stamp(t)}";
            if (from is { } f && t >= f) line += $" ({Span(t - f)} after {sinceLabel})";
            times.Add(line);
        }
        Time("Activity began", c.OccurredAtUtc);
        Time("Detected", c.DetectedAtUtc, c.OccurredAtUtc, "activity began");
        Time("Contained", c.ContainedAtUtc, c.DetectedAtUtc, "detection");
        Time("Resolved", c.ResolvedAtUtc, c.DetectedAtUtc, "detection");
        Time("Reported to regulators", c.ReportedAtUtc, c.DetectedAtUtc, "detection");
        Time("Closed", c.ClosedAtUtc);
        if (times.Count > 0)
        {
            sb.Append("### Key times (UTC)\n");
            foreach (var t in times) sb.Append(t).Append('\n');
            sb.Append('\n');
        }

        // Sequence of events: the event timeline (attack steps or, for a vendor matter, disclosure milestones).
        var steps = c.TimelineEntries.Where(e => e.Kind == TimelineKind.Event).OrderBy(e => e.OccurredAtUtc).ToList();
        if (steps.Count > 0)
        {
            sb.Append(c.Origin == CaseOrigin.ThirdParty ? "### Disclosure sequence\n" : "### Sequence of events\n");
            foreach (var e in steps.Take(MaxSteps))
            {
                var tactics = e.Tactics.Select(t => t.Tactic).Where(t => t != MitreTactic.Unspecified).Distinct().ToList();
                var tag = tactics.Count > 0 ? string.Join(", ", tactics.Select(TacticWord))
                    : c.Origin == CaseOrigin.ThirdParty ? TypeWord(e.Type) : null;
                sb.Append(CultureInfo.InvariantCulture, $"- {Stamp(e.OccurredAtUtc)}");
                if (tag is not null) sb.Append(CultureInfo.InvariantCulture, $" ({tag}{(e.TechniqueId is { Length: > 0 } tid ? $", {tid}" : "")})");
                sb.Append(": ").Append(Sentence(e.Description));
                var actor = e.ActorEntityId is { } a ? entityLabel(a) : null;
                var target = e.TargetEntityId is { } tg ? entityLabel(tg) : null;
                if (actor is not null || target is not null)
                    sb.Append(' ').Append(actor is not null && target is not null ? $"({actor} → {target})"
                        : actor is not null ? $"(from {actor})" : $"(affecting {target})");
                sb.Append('\n');
            }
            if (steps.Count > MaxSteps)
                sb.Append(CultureInfo.InvariantCulture, $"- …and {Plural.Of(steps.Count - MaxSteps, "further step")} on the case timeline.\n");
            sb.Append('\n');
        }

        // Decisions: every recorded reclassification / severity / phase change, in order, with its reason.
        var decisions = new List<(DateTimeOffset At, string Text)>();
        // The opening classification (no "from", stamped at creation) is the starting point, not a decision; a
        // later null-"from" entry is a complex event's promotion onto the ladder, which is.
        foreach (var x in c.ClassificationChanges.Where(x => x.From is not null || x.ChangedAtUtc > c.CreatedAtUtc))
            decisions.Add((x.ChangedAtUtc, $"Classification changed from {ClassificationWord(x.From)} to {ClassificationWord(x.To)}{Because(x.Reason)}"));
        foreach (var x in c.SeverityChanges.Where(x => x.From is not null))
            decisions.Add((x.ChangedAtUtc, $"Severity changed from {severityLabel(x.From!.Value)} to {severityLabel(x.To)}{Because(x.Reason)}"));
        foreach (var x in c.StatusChanges.Where(x => x.From is not null))
            decisions.Add((x.ChangedAtUtc, $"Moved from {PhaseWord(x.From!.Value)} to {PhaseWord(x.To)}{Because(x.Reason)}"));
        if (decisions.Count > 0)
        {
            sb.Append("### Decisions and milestones\n");
            foreach (var (at, text) in decisions.OrderBy(d => d.At))
                sb.Append(CultureInfo.InvariantCulture, $"- {Stamp(at)}: {text}\n");
            sb.Append('\n');
        }

        if (steps.Count == 0 && decisions.Count == 0)
            sb.Append("_The case has no event timeline or recorded decisions yet. Add the account here._\n");

        return sb.ToString().TrimEnd() + "\n";
    }

    private static string Because(string? reason) =>
        string.IsNullOrWhiteSpace(reason) ? "." : $". Reason given: {Sentence(reason)}";

    private static string Sentence(string? s)
    {
        var t = (s ?? "").Trim().Replace("\r", "").Replace('\n', ' ');
        if (t.Length == 0) return "";
        return ".!?".Contains(t[^1]) ? t : t + ".";
    }

    private static string Stamp(DateTimeOffset t) => t.UtcDateTime.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) + " UTC";
    private static string Day(DateTimeOffset t) => t.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);

    private static string Span(TimeSpan s) =>
        s.TotalDays >= 2 ? $"{s.TotalDays:0.#} days" : s.TotalHours >= 1 ? $"{s.TotalHours:0.#} hours" : $"{Math.Max(1, s.TotalMinutes):0} minutes";

    private static string Article(string word) => ("aeiou".Contains(char.ToLowerInvariant(word[0])) ? "an " : "a ") + word;

    private static string ClassificationWord(Classification? c) => c switch
    {
        null => "complex event",
        Classification.AdverseEvent => "adverse event",
        Classification.Incident => "incident",
        Classification.Breach => "breach",
        _ => c.ToString()!.ToLowerInvariant(),
    };

    private static string PhaseWord(CasePhase p) => p switch
    {
        CasePhase.PostIncident => "Post-incident",
        _ => p.ToString(),
    };

    private static string TacticWord(MitreTactic t) => t switch
    {
        MitreTactic.InitialAccess => "Initial Access",
        MitreTactic.PrivilegeEscalation => "Privilege Escalation",
        MitreTactic.CredentialAccess => "Credential Access",
        MitreTactic.LateralMovement => "Lateral Movement",
        MitreTactic.CommandAndControl => "Command and Control",
        MitreTactic.ResourceDevelopment => "Resource Development",
        MitreTactic.DefenseImpairment => "Defense Impairment",
        _ => t.ToString(),
    };

    private static string TypeWord(TimelineEntryType t) => t switch
    {
        TimelineEntryType.Notified => "vendor notified us",
        TimelineEntryType.ScopeConfirmed => "scope confirmed",
        TimelineEntryType.DataConfirmed => "our data confirmed in scope",
        TimelineEntryType.RegulatoryNotification => "regulatory notification",
        _ => t.ToString().ToLowerInvariant(),
    };
}
