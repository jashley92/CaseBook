using IncidentManager.Application.Sla;

namespace IncidentManager.Application.Compliance;

/// <summary>What instant the regulatory-notification clock is measured from (PROD-07).</summary>
public enum NotificationStartBasis
{
    /// <summary>The materiality determination (PROD-18) — matches NYDFS 500.17(a) / SEC Item 1.05
    /// ("from determination"). The clock runs only once the case is determined <b>Material</b>.</summary>
    Determination = 0,
    /// <summary>Detection (<c>DetectedAtUtc</c>) — matches state laws phrased "from discovery". The clock runs
    /// for a Breach-classified case regardless of the materiality call.</summary>
    Detection = 1
}

/// <summary>The live, administered notification-deadline settings (the <c>Compliance:NotificationDeadlines:*</c>
/// group). <see cref="Enabled"/> gates the whole feature — off by default.</summary>
public sealed record NotificationDeadlineSettings(
    bool Enabled,
    NotificationStartBasis StartBasis,
    int DefaultWindowHours,
    int AtRiskThresholdPercent)
{
    public static readonly NotificationDeadlineSettings Off =
        new(false, NotificationStartBasis.Determination, 72, NotificationDeadlinePolicy.DefaultAtRiskThresholdPercent);
}

/// <summary>The active per-jurisdiction rules, plus the default window that covers any jurisdiction without an
/// explicit rule — so a countdown always exists once the feature is on.</summary>
public sealed record NotificationRuleSet(
    IReadOnlyDictionary<string, (string Label, int WindowHours)> Rules,
    int DefaultWindowHours)
{
    public static NotificationRuleSet WithDefault(int defaultWindowHours) =>
        new(new Dictionary<string, (string, int)>(StringComparer.OrdinalIgnoreCase), defaultWindowHours);

    /// <summary>The label + window for a jurisdiction code: its explicit rule, else the default window
    /// (labelled by the bare code).</summary>
    public (string Label, int WindowHours) Resolve(string code) =>
        Rules.TryGetValue(code, out var r) ? r : (code, DefaultWindowHours);
}

/// <summary>A case's standing against one jurisdiction's notification deadline. Reuses <see cref="SlaState"/>
/// for the on-track / at-risk / breached / met / missed vocabulary.</summary>
public sealed record NotificationDeadlineStatus(
    SlaState State,
    string JurisdictionCode,
    string JurisdictionLabel,
    int WindowHours,
    DateTimeOffset? DueAtUtc,
    TimeSpan? Remaining,
    double? ElapsedHours,
    DateTimeOffset? NotifiedAtUtc = null)   // BUG-09: when this jurisdiction was notified, if it has been
{
    /// <summary>The clock is still running (not yet reported).</summary>
    public bool IsActive => State is SlaState.OnTrack or SlaState.AtRisk or SlaState.Breached;
    /// <summary>Should be surfaced now — approaching or past the deadline.</summary>
    public bool NeedsAttention => State is SlaState.AtRisk or SlaState.Breached;
}

/// <summary>
/// Turns a case's clock-start instant, the jurisdictions in play, and the administered rules into
/// per-jurisdiction <see cref="NotificationDeadlineStatus"/>es. Pure and side-effect free, so the timing
/// rules are unit-tested independently of the DB/UI plumbing (mirrors <see cref="SlaPolicy"/>). The clock
/// stops at <c>reportedAtUtc</c>; a null <paramref name="startInstant"/> means the obligation has not been
/// triggered yet (no material determination / not a breach), so nothing counts down.
/// </summary>
public static class NotificationDeadlinePolicy
{
    public const int DefaultAtRiskThresholdPercent = 80;

    /// <summary>Per-jurisdiction statuses, in code order. Empty when the clock has not started or no
    /// jurisdiction is in play.</summary>
    public static IReadOnlyList<NotificationDeadlineStatus> Evaluate(
        DateTimeOffset? startInstant, DateTimeOffset? reportedAtUtc, IEnumerable<string> jurisdictionCodes,
        NotificationRuleSet rules, int atRiskThresholdPercent, DateTimeOffset nowUtc) =>
        EvaluateByJurisdiction(startInstant, _ => reportedAtUtc, jurisdictionCodes, rules, atRiskThresholdPercent, nowUtc);

    /// <summary>
    /// BUG-09: each jurisdiction's clock stops on its own notice. <paramref name="notifiedAt"/> gives the time a
    /// jurisdiction was notified, or null while it hasn't been.
    /// </summary>
    public static IReadOnlyList<NotificationDeadlineStatus> EvaluateByJurisdiction(
        DateTimeOffset? startInstant, Func<string, DateTimeOffset?> notifiedAt, IEnumerable<string> jurisdictionCodes,
        NotificationRuleSet rules, int atRiskThresholdPercent, DateTimeOffset nowUtc,
        Func<string, DateTimeOffset?>? frozenDue = null)
    {
        if (startInstant is not { } start)
            return Array.Empty<NotificationDeadlineStatus>();

        var codes = jurisdictionCodes
            .Where(c => !string.IsNullOrWhiteSpace(c))
            .Select(c => c.Trim().ToUpperInvariant())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(c => c, StringComparer.Ordinal);

        var pct = atRiskThresholdPercent is > 0 and <= 100 ? atRiskThresholdPercent : DefaultAtRiskThresholdPercent;
        var list = new List<NotificationDeadlineStatus>();
        foreach (var code in codes)
        {
            var (label, window) = rules.Resolve(code);
            var notified = notifiedAt(code);
            // BUG-286 (WF-77): a notice is judged against the deadline it was made under, kept when it was recorded, so a
            // window or a materiality date changed later doesn't turn a timely notice late, or a late one timely.
            if (notified is not null && frozenDue?.Invoke(code) is { } kept)
            {
                list.Add(EvaluateOne(code, label, window, start, notified, pct, nowUtc, kept));
                continue;
            }
            if (window <= 0) continue; // a zero/blank window means "no deadline tracked" for this jurisdiction
            list.Add(EvaluateOne(code, label, window, start, notified, pct, nowUtc));
        }
        return list;
    }

    /// <summary>The single headline: the most urgent still-running clock (soonest due) if any, else the
    /// worst historical outcome (Missed over Met), else null when nothing applies.</summary>
    public static NotificationDeadlineStatus? Headline(IReadOnlyList<NotificationDeadlineStatus> statuses)
    {
        var active = statuses.Where(s => s.IsActive).OrderBy(s => s.DueAtUtc).ToList();
        if (active.Count > 0) return active[0];
        var missed = statuses.FirstOrDefault(s => s.State == SlaState.Missed);
        if (missed is not null) return missed;
        return statuses.FirstOrDefault(s => s.State == SlaState.Met);
    }

    private static NotificationDeadlineStatus EvaluateOne(string code, string label, int windowHours,
        DateTimeOffset start, DateTimeOffset? reportedAtUtc, int atRiskPercent, DateTimeOffset now, DateTimeOffset? keptDue = null)
    {
        var due = keptDue ?? start.AddHours(windowHours);

        if (reportedAtUtc is { } reported)
        {
            var elapsed = Math.Round((reported - start).TotalHours, 1);
            var outcome = reported <= due ? SlaState.Met : SlaState.Missed;
            return new NotificationDeadlineStatus(outcome, code, label, windowHours, due, null, elapsed, reported);
        }

        var elapsedNow = Math.Round((now - start).TotalHours, 1);
        var atRiskAt = start.AddHours(windowHours * (atRiskPercent / 100.0));
        var state = now >= due ? SlaState.Breached
                  : now >= atRiskAt ? SlaState.AtRisk
                  : SlaState.OnTrack;
        return new NotificationDeadlineStatus(state, code, label, windowHours, due, due - now, elapsedNow);
    }
}
