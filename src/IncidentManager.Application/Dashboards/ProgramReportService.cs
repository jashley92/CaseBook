using System.Globalization;
using System.Text;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Mitre;
using IncidentManager.Application.Sla;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;
using static IncidentManager.Application.Common.Csv;

namespace IncidentManager.Application.Dashboards;

/// <summary>A calendar quarter (UTC). <see cref="End"/> is exclusive.</summary>
public sealed record ProgramPeriod(int Year, int Quarter)
{
    public DateTimeOffset Start => new(Year, (Quarter - 1) * 3 + 1, 1, 0, 0, 0, TimeSpan.Zero);
    public DateTimeOffset End => Start.AddMonths(3);
    public string Label => $"Q{Quarter} {Year}";
    public ProgramPeriod Previous => Quarter == 1 ? new(Year - 1, 4) : new(Year, Quarter - 1);

    public static ProgramPeriod Containing(DateTimeOffset t) => new(t.UtcDateTime.Year, (t.UtcDateTime.Month - 1) / 3 + 1);

    /// <summary>Validates a requested quarter; null for nonsense.</summary>
    public static ProgramPeriod? TryCreate(int year, int quarter) =>
        year is >= 2000 and <= 2100 && quarter is >= 1 and <= 4 ? new(year, quarter) : null;
}

public sealed record CountBy<T>(T Key, int Count);

/// <summary>Met/missed against target for one SLA clock, over milestones reached in the period.</summary>
public sealed record SlaAttainment(SlaClock Clock, int Met, int Missed)
{
    public int? Percent => Met + Missed == 0 ? null : (int)Math.Round(Met * 100.0 / (Met + Missed));
}

/// <summary>Mean and median hours for one interval (null when nothing reached it in the period).</summary>
public sealed record Interval(double? MeanHours, double? MedianHours, int Count);

/// <summary>One quarter's program figures.</summary>
public sealed record ProgramSnapshot(
    int Opened, int Closed, int OpenAtEnd,
    IReadOnlyList<CountBy<Classification?>> OpenedByClassification,
    IReadOnlyList<CountBy<Severity>> OpenedBySeverity,
    Interval TimeToDetect, Interval TimeToContain, Interval TimeToResolve,
    IReadOnlyList<SlaAttainment> Sla,
    int BreachesOpened, int ReportedToRegulators, Interval DetectToReport,
    int ReviewsRecorded, int ActionsOpened, int ActionsCompleted, int ActionsNotPursued,
    int ActionsOpenAtEnd, int ActionsPastTargetAtEnd,
    IReadOnlyList<CountBy<string>> ActionAreas);

public sealed record ProgramTechnique(string TechniqueId, string Name, int Cases);

/// <param name="Current">The requested quarter.</param>
/// <param name="Previous">The quarter before, for comparison.</param>
public sealed record ProgramReport(ProgramPeriod Period, ProgramSnapshot Current, ProgramSnapshot Previous,
    IReadOnlyList<ProgramTechnique> TopTechniques, bool IncludesExercises, DateTimeOffset GeneratedAtUtc);

/// <summary>
/// E-31: the quarterly program-metrics roll-up — distinct from the per-case report and the live dashboard. For a
/// chosen calendar quarter (and the one before it, for comparison): case volumes by classification and severity,
/// time to detect / contain / resolve (mean and median), SLA attainment, regulatory reporting, ATT&amp;CK techniques
/// faced, and post-incident review follow-through (E-26). For leadership, board and exam packs (the CISO's 500.4
/// report). Need-to-know scoped like every metric; exercise cases excluded unless asked for. Read-only.
/// Figures are "in the period" by the date the thing happened (opened, contained, reported…), so a quarter's
/// numbers don't move when later quarters' work is recorded.
/// </summary>
public sealed class ProgramReportService
{
    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;
    private readonly ISlaTargetsProvider _sla;
    private readonly AttackCoverageService _attack;

    public ProgramReportService(IAppDbContextFactory factory, ICurrentUser user, IClock clock,
        ISlaTargetsProvider sla, AttackCoverageService attack)
    {
        _factory = factory;
        _user = user;
        _clock = clock;
        _sla = sla;
        _attack = attack;
    }

    public async Task<ProgramReport> BuildAsync(ProgramPeriod period, bool includeExercises = false, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var cases = db.Cases.AsNoTracking().ForUser(_user);
        if (!includeExercises) cases = cases.ExcludingExercises();

        var rows = await cases.Select(c => new CaseRow(c.Id, c.Classification, c.Severity, c.Phase, c.CreatedAtUtc,
            c.OccurredAtUtc, c.DetectedAtUtc, c.ContainedAtUtc, c.ResolvedAtUtc, c.ReportedAtUtc, c.ClosedAtUtc)).ToListAsync(ct);
        var ids = rows.Select(r => r.Id).ToList();

        var breachFirstAt = (await db.ClassificationChanges.AsNoTracking()
                .Where(x => ids.Contains(x.CaseId) && x.To == Classification.Breach)
                .Select(x => new { x.CaseId, x.ChangedAtUtc }).ToListAsync(ct))
            .GroupBy(x => x.CaseId).ToDictionary(g => g.Key, g => g.Min(x => x.ChangedAtUtc));
        var reviews = await db.PostIncidentReviews.AsNoTracking().Where(r => ids.Contains(r.CaseId))
            .Select(r => r.CreatedAtUtc).ToListAsync(ct);
        var actions = await db.ImprovementActions.AsNoTracking().Where(a => ids.Contains(a.CaseId))
            .Select(a => new ActionRow(a.CreatedAtUtc, a.ClosedAtUtc, a.Status, a.TargetDateUtc, a.RelatedArea))
            .ToListAsync(ct);

        var targets = _sla.Current;
        var coverage = await _attack.GetForPeriodAsync(period.Start, period.End, includeExercises, ct);
        var top = coverage.Tactics.SelectMany(t => t.Techniques)
            .GroupBy(t => t.TechniqueId)
            .Select(g => new ProgramTechnique(g.Key, g.First().Name, g.SelectMany(t => t.Cases).Select(c => c.CaseId).Distinct().Count()))
            .OrderByDescending(t => t.Cases).ThenBy(t => t.TechniqueId, StringComparer.Ordinal)
            .Take(10).ToList();

        return new ProgramReport(period,
            Snapshot(period, rows, breachFirstAt, reviews, actions, targets),
            Snapshot(period.Previous, rows, breachFirstAt, reviews, actions, targets),
            top, includeExercises, _clock.UtcNow);
    }

    private sealed record CaseRow(Guid Id, Classification? Classification, Severity Severity, CasePhase Phase,
        DateTimeOffset CreatedAtUtc, DateTimeOffset? OccurredAtUtc, DateTimeOffset? DetectedAtUtc, DateTimeOffset? ContainedAtUtc,
        DateTimeOffset? ResolvedAtUtc, DateTimeOffset? ReportedAtUtc, DateTimeOffset? ClosedAtUtc);

    private sealed record ActionRow(DateTimeOffset CreatedAtUtc, DateTimeOffset? ClosedAtUtc, ImprovementActionStatus Status,
        DateTimeOffset? TargetDateUtc, string? RelatedArea);

    // Everything is computed in memory: DateTimeOffset comparison and arithmetic stay off SQLite (F-08).
    private static ProgramSnapshot Snapshot(ProgramPeriod p, List<CaseRow> rows, Dictionary<Guid, DateTimeOffset> breachAt,
        List<DateTimeOffset> reviews, List<ActionRow> actions, SlaTargets targets)
    {
        bool In(DateTimeOffset? t) => t is { } v && v >= p.Start && v < p.End;

        var opened = rows.Where(r => In(r.CreatedAtUtc)).ToList();

        Interval Span(IEnumerable<(DateTimeOffset? From, DateTimeOffset? To)> pairs)
        {
            var hours = pairs.Where(x => x.From is not null && x.To is { } to && In(to) && to >= x.From)
                .Select(x => (x.To!.Value - x.From!.Value).TotalHours).OrderBy(h => h).ToList();
            if (hours.Count == 0) return new(null, null, 0);
            var mid = hours.Count / 2;
            var median = hours.Count % 2 == 1 ? hours[mid] : (hours[mid - 1] + hours[mid]) / 2;
            return new(Math.Round(hours.Average(), 1), Math.Round(median, 1), hours.Count);
        }

        // SLA outcomes for milestones reached in the period (a historical Met/Missed never changes afterwards).
        int cMet = 0, cMiss = 0, rMet = 0, rMiss = 0, dMet = 0, dMiss = 0;
        foreach (var r in rows)
        {
            var (cont, res) = SlaPolicy.Breakdown(r.Severity, r.Phase, r.DetectedAtUtc, r.ContainedAtUtc, r.ResolvedAtUtc,
                targets, p.End, r.Classification);
            if (In(r.ContainedAtUtc)) { if (cont.State == SlaState.Met) cMet++; else if (cont.State == SlaState.Missed) cMiss++; }
            if (In(r.ResolvedAtUtc)) { if (res.State == SlaState.Met) rMet++; else if (res.State == SlaState.Missed) rMiss++; }
            if (In(r.DetectedAtUtc))
            {
                var det = SlaPolicy.EvaluateDetection(r.Severity, r.OccurredAtUtc, r.DetectedAtUtc, targets);
                if (det.State == SlaState.Met) dMet++; else if (det.State == SlaState.Missed) dMiss++;
            }
        }

        var openAtEnd = actions.Where(a => a.CreatedAtUtc < p.End && (a.ClosedAtUtc is null || a.ClosedAtUtc >= p.End)).ToList();

        return new ProgramSnapshot(
            Opened: opened.Count,
            Closed: rows.Count(r => In(r.ClosedAtUtc)),
            OpenAtEnd: rows.Count(r => r.CreatedAtUtc < p.End && (r.ClosedAtUtc is null || r.ClosedAtUtc >= p.End)),
            OpenedByClassification: opened.GroupBy(r => r.Classification)
                .Select(g => new CountBy<Classification?>(g.Key, g.Count())).OrderBy(x => x.Key is null ? -1 : (int)x.Key).ToList(),
            OpenedBySeverity: opened.GroupBy(r => r.Severity)
                .Select(g => new CountBy<Severity>(g.Key, g.Count())).OrderByDescending(x => x.Key).ToList(),
            TimeToDetect: Span(rows.Select(r => (r.OccurredAtUtc, r.DetectedAtUtc))),
            TimeToContain: Span(rows.Select(r => (r.DetectedAtUtc, r.ContainedAtUtc))),
            TimeToResolve: Span(rows.Select(r => (r.DetectedAtUtc, r.ResolvedAtUtc))),
            Sla: [new(SlaClock.Detection, dMet, dMiss), new(SlaClock.Containment, cMet, cMiss), new(SlaClock.Resolution, rMet, rMiss)],
            BreachesOpened: breachAt.Values.Count(t => In(t)),
            ReportedToRegulators: rows.Count(r => In(r.ReportedAtUtc)),
            DetectToReport: Span(rows.Select(r => (r.DetectedAtUtc, r.ReportedAtUtc))),
            ReviewsRecorded: reviews.Count(t => In(t)),
            ActionsOpened: actions.Count(a => In(a.CreatedAtUtc)),
            ActionsCompleted: actions.Count(a => a.Status == ImprovementActionStatus.Completed && In(a.ClosedAtUtc)),
            ActionsNotPursued: actions.Count(a => a.Status == ImprovementActionStatus.NotPursued && In(a.ClosedAtUtc)),
            ActionsOpenAtEnd: openAtEnd.Count,
            ActionsPastTargetAtEnd: openAtEnd.Count(a => a.TargetDateUtc is { } t && t < p.End),
            ActionAreas: actions.Where(a => In(a.CreatedAtUtc))
                .GroupBy(a => string.IsNullOrWhiteSpace(a.RelatedArea) ? "Unspecified" : a.RelatedArea.Trim(), StringComparer.OrdinalIgnoreCase)
                .Select(g => new CountBy<string>(g.First().RelatedArea?.Trim() is { Length: > 0 } s ? s : "Unspecified", g.Count()))
                .OrderByDescending(x => x.Count).ThenBy(x => x.Key, StringComparer.OrdinalIgnoreCase).Take(8).ToList());
    }

    /// <summary>The report as a two-period CSV (metric, this quarter, previous quarter) for exam/board packs.</summary>
    public static string ToCsv(ProgramReport r, Func<Classification?, string> classLabel, Func<Severity, string> sevLabel)
    {
        var inv = CultureInfo.InvariantCulture;
        var sb = new StringBuilder();
        sb.Append("# CaseBook program report ").Append(r.Period.Label)
          .Append(r.IncludesExercises ? " (includes exercise cases)" : "")
          .Append(", generated ").Append(r.GeneratedAtUtc.UtcDateTime.ToString("yyyy-MM-dd HH:mm", inv)).Append(" UTC\r\n");
        sb.Append("section,metric,").Append(Escape(r.Period.Label)).Append(',').Append(Escape(r.Period.Previous.Label)).Append("\r\n");
        void Row(string section, string metric, string cur, string prev) =>
            sb.Append(Escape(section)).Append(',').Append(Escape(metric)).Append(',').Append(Escape(cur)).Append(',').Append(Escape(prev)).Append("\r\n");
        static string N(double? v) => v is { } d ? d.ToString("0.#", CultureInfo.InvariantCulture) : "";
        var c = r.Current; var p = r.Previous;

        Row("Volume", "Cases opened", c.Opened.ToString(inv), p.Opened.ToString(inv));
        Row("Volume", "Cases closed", c.Closed.ToString(inv), p.Closed.ToString(inv));
        Row("Volume", "Open at quarter end", c.OpenAtEnd.ToString(inv), p.OpenAtEnd.ToString(inv));
        foreach (var k in c.OpenedByClassification.Select(x => x.Key).Union(p.OpenedByClassification.Select(x => x.Key)))
            Row("Opened by classification", classLabel(k),
                (c.OpenedByClassification.FirstOrDefault(x => x.Key == k)?.Count ?? 0).ToString(inv),
                (p.OpenedByClassification.FirstOrDefault(x => x.Key == k)?.Count ?? 0).ToString(inv));
        foreach (var k in c.OpenedBySeverity.Select(x => x.Key).Union(p.OpenedBySeverity.Select(x => x.Key)).OrderByDescending(x => x))
            Row("Opened by severity", sevLabel(k),
                (c.OpenedBySeverity.FirstOrDefault(x => x.Key == k)?.Count ?? 0).ToString(inv),
                (p.OpenedBySeverity.FirstOrDefault(x => x.Key == k)?.Count ?? 0).ToString(inv));
        foreach (var (name, cur, prev) in new[] { ("Time to detect", c.TimeToDetect, p.TimeToDetect),
                     ("Time to contain", c.TimeToContain, p.TimeToContain), ("Time to resolve", c.TimeToResolve, p.TimeToResolve),
                     ("Detection to regulatory report", c.DetectToReport, p.DetectToReport) })
        {
            Row("Timing (hours)", name + " — mean", N(cur.MeanHours), N(prev.MeanHours));
            Row("Timing (hours)", name + " — median", N(cur.MedianHours), N(prev.MedianHours));
        }
        foreach (var s in c.Sla)
        {
            var ps = p.Sla.First(x => x.Clock == s.Clock);
            Row("SLA attainment", $"{s.Clock} within target %", s.Percent?.ToString(inv) ?? "", ps.Percent?.ToString(inv) ?? "");
            Row("SLA attainment", $"{s.Clock} met / missed", $"{s.Met} / {s.Missed}", $"{ps.Met} / {ps.Missed}");
        }
        Row("Regulatory", "Cases classified as breach", c.BreachesOpened.ToString(inv), p.BreachesOpened.ToString(inv));
        Row("Regulatory", "Reported to regulators", c.ReportedToRegulators.ToString(inv), p.ReportedToRegulators.ToString(inv));
        Row("Post-incident", "Reviews recorded", c.ReviewsRecorded.ToString(inv), p.ReviewsRecorded.ToString(inv));
        Row("Post-incident", "Improvement actions opened", c.ActionsOpened.ToString(inv), p.ActionsOpened.ToString(inv));
        Row("Post-incident", "Improvement actions completed", c.ActionsCompleted.ToString(inv), p.ActionsCompleted.ToString(inv));
        Row("Post-incident", "Improvement actions not pursued", c.ActionsNotPursued.ToString(inv), p.ActionsNotPursued.ToString(inv));
        Row("Post-incident", "Open at quarter end", c.ActionsOpenAtEnd.ToString(inv), p.ActionsOpenAtEnd.ToString(inv));
        Row("Post-incident", "Past target at quarter end", c.ActionsPastTargetAtEnd.ToString(inv), p.ActionsPastTargetAtEnd.ToString(inv));
        foreach (var a in c.ActionAreas)
            Row("Improvement areas (opened)", a.Key, a.Count.ToString(inv), "");
        foreach (var t in r.TopTechniques)
            Row("ATT&CK techniques (cases)", $"{t.TechniqueId} {t.Name}", t.Cases.ToString(inv), "");
        return sb.ToString();
    }
}
