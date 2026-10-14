using System.Globalization;
using System.Text;
using System.Text.Json;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Compliance;
using IncidentManager.Application.Mitre;
using IncidentManager.Application.Sla;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;
using static IncidentManager.Application.Common.Csv;

namespace IncidentManager.Application.Dashboards;

/// <summary>
/// A calendar quarter. Where it begins and ends depends on the organization's reporting time zone
/// (<see cref="IOrganizationTimeZone"/>), so the bounds take the zone; the quarter itself is just year + number.
/// </summary>
public sealed record ProgramPeriod(int Year, int Quarter)
{
    /// <summary>When the quarter begins: local midnight on its first day in <paramref name="zone"/>.</summary>
    public DateTimeOffset StartUtc(TimeZoneInfo zone) => ZonedMonths.StartUtc(Year, (Quarter - 1) * 3 + 1, zone);

    /// <summary>When the next quarter begins; the quarter's exclusive end.</summary>
    public DateTimeOffset EndUtc(TimeZoneInfo zone) => Next.StartUtc(zone);

    public string Label => $"Q{Quarter} {Year}";
    public ProgramPeriod Previous => Quarter == 1 ? new(Year - 1, 4) : new(Year, Quarter - 1);
    public ProgramPeriod Next => Quarter == 4 ? new(Year + 1, 1) : new(Year, Quarter + 1);

    /// <summary>The quarter that <paramref name="t"/> falls in, on the calendar of <paramref name="zone"/>.</summary>
    public static ProgramPeriod Containing(DateTimeOffset t, TimeZoneInfo zone)
    {
        var (year, month) = ZonedMonths.Of(t, zone);
        return new(year, (month - 1) / 3 + 1);
    }

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

/// <summary>Met/missed against one severity's target (null when that severity has none).</summary>
public sealed record SeverityAttainment(Severity Severity, int? TargetHours, int Met, int Missed);

/// <summary>A stretch of time to measure: from <see cref="StartUtc"/> up to (not including) <see cref="EndUtc"/>.</summary>
public sealed record ProgramWindow(DateTimeOffset StartUtc, DateTimeOffset EndUtc, string Label);

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
    IReadOnlyList<CountBy<string>> ActionAreas,
    // Containment met/missed per severity, and regulatory notices made inside or outside their window.
    IReadOnlyList<SeverityAttainment>? ContainmentBySeverity = null,
    int NoticesMet = 0, int NoticesMissed = 0,
    // Cases closed in the period that have a post-incident review, and the improvement actions open at its end by area.
    int ClosedWithReview = 0, IReadOnlyList<CountBy<string>>? OpenActionAreas = null)
{
    /// <summary>Percent of notices made inside their window, or null when none were made.</summary>
    public int? NoticesPercent => NoticesMet + NoticesMissed == 0 ? null : (int)Math.Round(NoticesMet * 100.0 / (NoticesMet + NoticesMissed));
}

public sealed record ProgramTechnique(string TechniqueId, string Name, int Cases);

/// <param name="Current">The requested quarter.</param>
/// <param name="Previous">The quarter before, for comparison.</param>
/// <param name="Zone">The reporting time zone the quarter was cut in (UTC when not given).</param>
public sealed record ProgramReport(ProgramPeriod Period, ProgramSnapshot Current, ProgramSnapshot Previous,
    IReadOnlyList<ProgramTechnique> TopTechniques, bool IncludesExercises, DateTimeOffset GeneratedAtUtc,
    TimeZoneInfo? Zone = null)
{
    public TimeZoneInfo ReportingZone => Zone ?? TimeZoneInfo.Utc;

    /// <summary>The quarter's first and last calendar days in the reporting time zone.</summary>
    public DateOnly FirstDay => DateOnly.FromDateTime(TimeZoneInfo.ConvertTime(Period.StartUtc(ReportingZone), ReportingZone).DateTime);
    public DateOnly LastDay => DateOnly.FromDateTime(TimeZoneInfo.ConvertTime(Period.EndUtc(ReportingZone), ReportingZone).DateTime).AddDays(-1);

    /// <summary>The zone's name as Administration lists it, for example "Eastern (New York)".</summary>
    public string ZoneLabel => Admin.SettingsCatalog.TimeZoneLabel(ReportingZone);
}

/// <summary>
/// E-31: the quarterly program-metrics roll-up — distinct from the per-case report and the live dashboard. For a
/// chosen calendar quarter (and the one before it, for comparison): case volumes by classification and severity,
/// time to detect / contain / resolve (mean and median), SLA attainment, regulatory reporting, ATT&amp;CK techniques
/// faced, and post-incident review follow-through (E-26). For leadership, board and exam packs (the CISO's 500.4
/// report). Need-to-know scoped like every metric; exercise cases excluded unless asked for. Read-only.
/// Figures are "in the period" by the date the thing happened (opened, contained, reported…), so a quarter's
/// numbers don't move when later quarters' work is recorded. One exception (REV-59): no archive time is recorded, so a case
/// never closed and archived since drops out of a past quarter's open-at-end count.
/// </summary>
public sealed class ProgramReportService
{
    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;
    private readonly ISlaTargetsProvider _sla;
    private readonly AttackCoverageService _attack;
    private readonly IOrganizationTimeZone? _zone;
    private readonly INotificationDeadlineSettingsProvider? _notify;
    private readonly Admin.NotificationRuleService? _rules;
    private readonly IServerSettingValues? _server;

    public ProgramReportService(IAppDbContextFactory factory, ICurrentUser user, IClock clock,
        ISlaTargetsProvider sla, AttackCoverageService attack, IOrganizationTimeZone? zone = null,
        INotificationDeadlineSettingsProvider? notify = null, Admin.NotificationRuleService? rules = null,
        IServerSettingValues? server = null)
    {
        _server = server;
        _zone = zone;
        _notify = notify;
        _rules = rules;
        _factory = factory;
        _user = user;
        _clock = clock;
        _sla = sla;
        _attack = attack;
    }

    public async Task<ProgramReport> BuildAsync(ProgramPeriod period, bool includeExercises = false, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var data = await LoadAsync(db, includeExercises, ct);

        // Quarters are cut in the organization's reporting time zone, like the dashboard's months.
        var zone = _zone?.Current ?? TimeZoneInfo.Utc;
        var coverage = await _attack.GetForPeriodAsync(period.StartUtc(zone), period.EndUtc(zone), includeExercises, ct);
        var top = coverage.Tactics.SelectMany(t => t.Techniques)
            .GroupBy(t => t.TechniqueId)
            .Select(g => new ProgramTechnique(g.Key, g.First().Name, g.SelectMany(t => t.Cases).Select(c => c.CaseId).Distinct().Count()))
            .OrderByDescending(t => t.Cases).ThenBy(t => t.TechniqueId, StringComparer.Ordinal)
            .Take(10).ToList();

        return new ProgramReport(period,
            Snapshot(period.StartUtc(zone), period.EndUtc(zone), data),
            Snapshot(period.Previous.StartUtc(zone), period.Previous.EndUtc(zone), data),
            top, includeExercises, _clock.UtcNow, zone);
    }

    /// <summary>The same figures for each window, from one read of the cases (the Program overview's period, the
    /// one before it, and its monthly trend lines).</summary>
    public async Task<IReadOnlyList<ProgramSnapshot>> SnapshotsAsync(IReadOnlyList<ProgramWindow> windows,
        bool includeExercises = false, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var data = await LoadAsync(db, includeExercises, ct);
        return windows.Select(w => Snapshot(w.StartUtc, w.EndUtc, data)).ToList();
    }

    private sealed record Loaded(List<CaseRow> Rows, Dictionary<Guid, DateTimeOffset> BreachAt, List<(Guid CaseId, DateTimeOffset At)> Reviews,
        List<ActionRow> Actions, SlaTargets Targets, List<(Guid CaseId, DateTimeOffset At, SlaState State)> Notices, History History,
        DateTimeOffset NowUtc, Func<DateTimeOffset, SlaTargets> TargetsAt);

    /// <summary>
    /// WF-38: each case's phase, classification and severity changes, in order, so a quarter is figured as the record stood
    /// then (owner's decision: past quarters are frozen). A case reopened and closed again later, or reclassified later,
    /// no longer changes a quarter the board has already seen.
    /// </summary>
    private sealed record History(
        Dictionary<Guid, List<(CasePhase? From, CasePhase To, DateTimeOffset At)>> Phases,
        Dictionary<Guid, List<(Classification? From, Classification? To, DateTimeOffset At)>> Classes,
        Dictionary<Guid, List<(Severity? From, Severity To, DateTimeOffset At)>> Severities)
    {
        // A case's closures and reopenings, when the record has them; one closed without a phase change (data from before
        // phase changes were recorded) is judged by its closed time, as before.
        private List<(CasePhase? From, CasePhase To, DateTimeOffset At)>? Closures(Guid id) =>
            Phases.TryGetValue(id, out var ph) && ph.Any(x => x.To == CasePhase.Closed || x.From == CasePhase.Closed) ? ph : null;

        public bool ClosedAt(Guid id, DateTimeOffset t, DateTimeOffset? closedNow) =>
            Closures(id) is { } ph
                ? ph.Where(x => x.At < t).Select(x => (CasePhase?)x.To).LastOrDefault() == CasePhase.Closed
                : closedNow is { } c && c < t;

        public bool ClosedIn(Guid id, DateTimeOffset start, DateTimeOffset end, DateTimeOffset? closedNow) =>
            Closures(id) is { } ph
                ? ph.Any(x => x.To == CasePhase.Closed && x.At >= start && x.At < end)
                : closedNow is { } c && c >= start && c < end;

        public bool EverClosed(Guid id, DateTimeOffset? closedNow) => closedNow is not null || Closures(id) is not null;

        public Classification? ClassAt(Guid id, DateTimeOffset t, Classification? now) =>
            Classes.TryGetValue(id, out var ch) && ch.Count > 0
                ? (ch.Any(x => x.At < t) ? ch.Last(x => x.At < t).To : ch[0].From)
                : now;

        public Severity SevAt(Guid id, DateTimeOffset t, Severity now) =>
            Severities.TryGetValue(id, out var ch) && ch.Count > 0
                ? (ch.Any(x => x.At < t) ? ch.Last(x => x.At < t).To : ch[0].From ?? now)
                : now;
    }

    private async Task<Loaded> LoadAsync(IAppDbContext db, bool includeExercises, CancellationToken ct)
    {
        var cases = db.Cases.AsNoTracking().ForUser(_user);
        if (!includeExercises) cases = cases.ExcludingExercises();

        // BUG-165: a case that didn't need containment has no time to contain and no containment target outcome.
        var rows = await cases.Select(c => new CaseRow(c.Id, c.Classification, c.Severity, c.Phase, c.CreatedAtUtc,
            c.OccurredAtUtc, c.DetectedAtUtc, c.ContainmentNotNeededReason == null ? c.ContainedAtUtc : null, c.ResolvedAtUtc,
            c.ReportedAtUtc, c.ClosedAtUtc, c.IsArchived)).ToListAsync(ct);
        // The child tables filter by a subquery over the same visible cases rather than a list of every id.
        var ids = cases.Select(c => c.Id);

        var breachFirstAt = (await db.ClassificationChanges.AsNoTracking()
                .Where(x => ids.Contains(x.CaseId) && x.To == Classification.Breach)
                .Select(x => new { x.CaseId, x.ChangedAtUtc, x.EffectiveAtUtc }).ToListAsync(ct))
            .GroupBy(x => x.CaseId).ToDictionary(g => g.Key, g => g.Min(x => x.EffectiveAtUtc ?? x.ChangedAtUtc));
        // BUG-324: a review counts once it says what happened (PostIncidentReview.IsRecorded, as the close gate reads it);
        // a stub saved with nothing in it, or only what worked well, isn't a review recorded. BUG-347: dated by when it did.
        var reviews = await ReviewsRecordedAsync(db, ids, ct);
        var actionRows = await db.ImprovementActions.AsNoTracking().Where(a => ids.Contains(a.CaseId))
            .Select(a => new { a.Id, a.CreatedAtUtc, a.ClosedAtUtc, a.Status, a.TargetDateUtc, a.RelatedArea })
            .ToListAsync(ct);
        // WF-80: each action's edits (what each changed field held before), so a quarter is figured from the action as it
        // stood at the quarter's end: reopened, re-statused or re-targeted later, it doesn't move a quarter already reported.
        var actionIds = actionRows.Select(a => a.Id.ToString()).ToList();
        var edits = (await db.AuditLog.AsNoTracking()
                .Where(x => x.EntityType == "ImprovementAction" && x.Action == AuditAction.Update && x.BeforeJson != null
                            && x.EntityId != null && actionIds.Contains(x.EntityId))
                .Select(x => new { x.EntityId, x.AtUtc, x.Sequence, x.BeforeJson })
                .ToListAsync(ct))
            .GroupBy(x => x.EntityId!)
            .ToDictionary(g => g.Key, g => g.OrderByDescending(x => x.Sequence).Select(x => (x.AtUtc, x.BeforeJson!)).ToList());
        var actions = actionRows.Select(a => new ActionRow(a.CreatedAtUtc, a.ClosedAtUtc, a.Status, a.TargetDateUtc, a.RelatedArea,
            edits.GetValueOrDefault(a.Id.ToString()) ?? [])).ToList();

        // BUG-287: each notice given, when it was given and whether inside its window (its kept deadline, WF-77, so a later
        // change to a rule's window or to the materiality decision doesn't move a past quarter), when deadlines are tracked.
        var notices = new List<(Guid CaseId, DateTimeOffset At, SlaState State)>();
        if (_notify?.Current is { Enabled: true } nd && _rules is not null)
        {
            var ruleSet = await _rules.LoadRuleSetAsync(nd.DefaultWindowHours, ct);
            notices = await NotificationDeadlineService.NoticeOutcomesAsync(db, cases, nd, ruleSet, _clock.UtcNow, ct);
        }

        // WF-38: the history each quarter is figured from (effective times, as the record dates them). WF-97: in the order
        // it was recorded, which is the order the states followed each other: a change dated before the case was filed
        // (allowed) sorted by its date put the opening row after it, and the case read as never closed.
        var phases = (await db.StatusChanges.AsNoTracking().Where(x => ids.Contains(x.CaseId))
                .Select(x => new { x.CaseId, x.From, x.To, At = x.EffectiveAtUtc ?? x.ChangedAtUtc, x.ChangedAtUtc }).ToListAsync(ct))
            .GroupBy(x => x.CaseId).ToDictionary(g => g.Key, g => g.OrderBy(x => x.ChangedAtUtc).Select(x => ((CasePhase?)x.From, x.To, x.At)).ToList());
        var classes = (await db.ClassificationChanges.AsNoTracking().Where(x => ids.Contains(x.CaseId))
                .Select(x => new { x.CaseId, x.From, x.To, At = x.EffectiveAtUtc ?? x.ChangedAtUtc, x.ChangedAtUtc }).ToListAsync(ct))
            .GroupBy(x => x.CaseId).ToDictionary(g => g.Key, g => g.OrderBy(x => x.ChangedAtUtc).Select(x => (x.From, (Classification?)x.To, x.At)).ToList());
        var severities = (await db.SeverityChanges.AsNoTracking().Where(x => ids.Contains(x.CaseId))
                .Select(x => new { x.CaseId, x.From, x.To, At = x.EffectiveAtUtc ?? x.ChangedAtUtc, x.ChangedAtUtc }).ToListAsync(ct))
            .GroupBy(x => x.CaseId).ToDictionary(g => g.Key, g => g.OrderBy(x => x.ChangedAtUtc).Select(x => ((Severity?)x.From, x.To, x.At)).ToList());

        // BUG-322: each milestone is judged against the targets in force when it was reached (rebuilt from the audited
        // setting changes; the server's own values where the app overrode none). Without the server's values to fall back
        // on (a test), today's targets throughout.
        var current = _sla.Current;
        Func<DateTimeOffset, SlaTargets> targetsAt = _ => current;
        if (_server is { } server)
        {
            var history = await SlaTargetHistory.LoadAsync(db, server.ValueOf, ct);
            targetsAt = history.At;
        }
        return new Loaded(rows, breachFirstAt, reviews, actions, current, notices, new History(phases, classes, severities), _clock.UtcNow,
            targetsAt);
    }

    /// <summary>
    /// BUG-347: each review dated by when "What happened" was first filled in, not when its stub was saved, so filling
    /// one in later doesn't move a quarter already reported. Read from the review's audit trail (a create carries every
    /// field, an update only the ones it changed). A create is dated by the review's own CreatedAtUtc: the same moment,
    /// and what seeded rows are dated by. A review from before the trail is dated by CreatedAtUtc when it was already
    /// filled in then, or by the edit that filled it. One never filled in isn't counted.
    /// </summary>
    private static async Task<List<(Guid CaseId, DateTimeOffset At)>> ReviewsRecordedAsync(IAppDbContext db,
        IQueryable<Guid> caseIds, CancellationToken ct)
    {
        var rows = await db.PostIncidentReviews.AsNoTracking().Where(r => caseIds.Contains(r.CaseId))
            .Select(r => new { r.Id, r.CaseId, r.CreatedAtUtc, Recorded = r.WhatHappened != null && r.WhatHappened.Trim() != "" })
            .ToListAsync(ct);
        if (rows.Count == 0) return [];

        // One read for every review's trail; only the entries that carry "What happened" are needed.
        var keys = rows.Select(r => r.Id.ToString()).ToList();
        var field = "\"" + nameof(PostIncidentReview.WhatHappened) + "\"";
        var trails = (await db.AuditLog.AsNoTracking()
                .Where(a => a.EntityType == nameof(PostIncidentReview) && keys.Contains(a.EntityId!)
                            && (a.Action == AuditAction.Create || a.Action == AuditAction.Update)
                            && a.AfterJson != null && a.AfterJson.Contains(field))
                .Select(a => new { a.EntityId, a.Sequence, a.Action, a.AtUtc, a.BeforeJson, a.AfterJson })
                .ToListAsync(ct))
            .GroupBy(a => a.EntityId!, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.OrderBy(a => a.Sequence).ToList(), StringComparer.OrdinalIgnoreCase);

        var list = new List<(Guid CaseId, DateTimeOffset At)>();
        foreach (var r in rows)
        {
            if (!r.Recorded) continue;   // filled in once and cleared since: not a review recorded (BUG-324)
            DateTimeOffset? at;
            if (!trails.TryGetValue(r.Id.ToString(), out var trail)) at = r.Recorded ? r.CreatedAtUtc : null;
            else if (trail[0].Action == AuditAction.Create || !Filled(trail[0].BeforeJson))
                at = trail.FirstOrDefault(a => Filled(a.AfterJson)) is { } first
                    ? (first.Action == AuditAction.Create ? r.CreatedAtUtc : first.AtUtc)
                    : null;
            else at = r.CreatedAtUtc;   // filled in before the trail began
            if (at is { } t) list.Add((r.CaseId, t));
        }
        return list;
    }

    // Whether an audit entry's JSON holds a non-blank "What happened".
    private static bool Filled(string? json)
    {
        if (string.IsNullOrEmpty(json)) return false;
        try
        {
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.ValueKind == JsonValueKind.Object
                   && doc.RootElement.TryGetProperty(nameof(PostIncidentReview.WhatHappened), out var v)
                   && v.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(v.GetString());
        }
        catch (JsonException) { return false; }
    }

    private sealed record CaseRow(Guid Id, Classification? Classification, Severity Severity, CasePhase Phase,
        DateTimeOffset CreatedAtUtc, DateTimeOffset? OccurredAtUtc, DateTimeOffset? DetectedAtUtc, DateTimeOffset? ContainedAtUtc,
        DateTimeOffset? ResolvedAtUtc, DateTimeOffset? ReportedAtUtc, DateTimeOffset? ClosedAtUtc, bool IsArchived);

    private sealed record ActionRow(DateTimeOffset CreatedAtUtc, DateTimeOffset? ClosedAtUtc, ImprovementActionStatus Status,
        DateTimeOffset? TargetDateUtc, string? RelatedArea, IReadOnlyList<(DateTimeOffset At, string Before)> Edits)
    {
        /// <summary>WF-80: the action as it stood just before <paramref name="t"/>: every edit made at or after it undone,
        /// newest first, from the values its audit entry records as before.</summary>
        public ActionRow At(DateTimeOffset t)
        {
            var a = this;
            foreach (var (at, before) in Edits)
            {
                if (at < t) break;
                try
                {
                    using var doc = JsonDocument.Parse(before);
                    var root = doc.RootElement;
                    if (root.TryGetProperty(nameof(Status), out var st) && st.TryGetInt32(out var s)) a = a with { Status = (ImprovementActionStatus)s };
                    if (root.TryGetProperty(nameof(ClosedAtUtc), out var cl)) a = a with { ClosedAtUtc = Instant(cl) };
                    if (root.TryGetProperty(nameof(TargetDateUtc), out var td)) a = a with { TargetDateUtc = Instant(td) };
                    if (root.TryGetProperty(nameof(RelatedArea), out var ra)) a = a with { RelatedArea = ra.ValueKind == JsonValueKind.String ? ra.GetString() : null };
                }
                catch (JsonException) { /* an entry it can't read leaves the fields as they are */ }
            }
            return a;

            static DateTimeOffset? Instant(JsonElement e) =>
                e.ValueKind == JsonValueKind.String && e.TryGetDateTimeOffset(out var v) ? v : null;
        }
    }

    // Everything is computed in memory: DateTimeOffset comparison and arithmetic stay off SQLite (F-08).
    private static ProgramSnapshot Snapshot(DateTimeOffset start, DateTimeOffset end, Loaded data)
    {
        var (rows, breachAt, reviews, actions, targets) = (data.Rows, data.BreachAt, data.Reviews, data.Actions, data.Targets);
        var history = data.History;
        bool In(DateTimeOffset? t) => t is { } v && v >= start && v < end;
        // WF-38: as the record stood at the quarter's end.
        bool ClosedInQuarter(CaseRow r) => history.ClosedIn(r.Id, start, end, r.ClosedAtUtc);
        Classification? ClassAtEnd(CaseRow r) => history.ClassAt(r.Id, end, r.Classification);
        Severity SevAtEnd(CaseRow r) => history.SevAt(r.Id, end, r.Severity);

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
        int cMet = 0, cMiss = 0, rMet = 0, rMiss = 0, dMet = 0, dMiss = 0, nMet = 0, nMiss = 0;
        var bySeverity = new Dictionary<Severity, (int Met, int Missed)>();
        foreach (var r in rows)
        {
            // WF-76: judged on the severity and classification the case had at the quarter's end, as it's bucketed, so a
            // later raise doesn't turn a past quarter's Met into Missed.
            // BUG-322: and against the target in force when it was contained, resolved or detected.
            var cont = SlaPolicy.Breakdown(SevAtEnd(r), r.Phase, r.DetectedAtUtc, r.ContainedAtUtc, r.ResolvedAtUtc,
                data.TargetsAt(r.ContainedAtUtc ?? end), end, ClassAtEnd(r)).Containment;
            var res = SlaPolicy.Breakdown(SevAtEnd(r), r.Phase, r.DetectedAtUtc, r.ContainedAtUtc, r.ResolvedAtUtc,
                data.TargetsAt(r.ResolvedAtUtc ?? end), end, ClassAtEnd(r)).Resolution;
            if (In(r.ContainedAtUtc) && cont.State is SlaState.Met or SlaState.Missed)
            {
                var met = cont.State == SlaState.Met;
                if (met) cMet++; else cMiss++;
                var sev = SevAtEnd(r);
                var (sm, sx) = bySeverity.GetValueOrDefault(sev);
                bySeverity[sev] = met ? (sm + 1, sx) : (sm, sx + 1);
            }
            if (In(r.ResolvedAtUtc)) { if (res.State == SlaState.Met) rMet++; else if (res.State == SlaState.Missed) rMiss++; }
            if (In(r.DetectedAtUtc))
            {
                var det = SlaPolicy.EvaluateDetection(SevAtEnd(r), r.OccurredAtUtc, r.DetectedAtUtc, data.TargetsAt(r.DetectedAtUtc ?? end));
                if (det.State == SlaState.Met) dMet++; else if (det.State == SlaState.Missed) dMiss++;
            }
        }

        // BUG-287: the notices given in the quarter, each judged on its own.
        foreach (var n in data.Notices.Where(n => In(n.At)))
            if (n.State == SlaState.Met) nMet++; else nMiss++;

        actions = actions.Where(a => a.CreatedAtUtc < end).Select(a => a.At(end)).ToList();   // WF-80: as they stood at the end
        var openAtEnd = actions.Where(a => a.CreatedAtUtc < end && (a.ClosedAtUtc is null || a.ClosedAtUtc >= end)).ToList();
        // REV-59: a review recorded by the end of the quarter, so one recorded later doesn't change a quarter already reported.
        var reviewed = reviews.Where(r => r.At < end).Select(r => r.CaseId).ToHashSet();

        static List<CountBy<string>> Areas(IEnumerable<ActionRow> list) => list
            .GroupBy(a => string.IsNullOrWhiteSpace(a.RelatedArea) ? "Unspecified" : a.RelatedArea.Trim(), StringComparer.OrdinalIgnoreCase)
            .Select(g => new CountBy<string>(g.First().RelatedArea?.Trim() is { Length: > 0 } s ? s : "Unspecified", g.Count()))
            .OrderByDescending(x => x.Count).ThenBy(x => x.Key, StringComparer.OrdinalIgnoreCase).Take(8).ToList();

        return new ProgramSnapshot(
            Opened: opened.Count,
            Closed: rows.Count(ClosedInQuarter),
            // BUG-211: an archived case that was never closed isn't open, as on the dashboard (BUG-55). WF-38: closed or open
            // as it stood at the quarter's end, so reopening it later doesn't move a quarter already reported.
            OpenAtEnd: rows.Count(r => r.CreatedAtUtc < end && !history.ClosedAt(r.Id, end, r.ClosedAtUtc)
                                       && !(r.IsArchived && !history.EverClosed(r.Id, r.ClosedAtUtc))),
            OpenedByClassification: opened.GroupBy(ClassAtEnd)
                .Select(g => new CountBy<Classification?>(g.Key, g.Count())).OrderBy(x => x.Key is null ? -1 : (int)x.Key).ToList(),
            OpenedBySeverity: opened.GroupBy(SevAtEnd)
                .Select(g => new CountBy<Severity>(g.Key, g.Count())).OrderByDescending(x => x.Key).ToList(),
            TimeToDetect: Span(rows.Select(r => (r.OccurredAtUtc, r.DetectedAtUtc))),
            TimeToContain: Span(rows.Select(r => (r.DetectedAtUtc, r.ContainedAtUtc))),
            TimeToResolve: Span(rows.Select(r => (r.DetectedAtUtc, r.ResolvedAtUtc))),
            Sla: [new(SlaClock.Detection, dMet, dMiss), new(SlaClock.Containment, cMet, cMiss), new(SlaClock.Resolution, rMet, rMiss)],
            BreachesOpened: breachAt.Values.Count(t => In(t)),
            ReportedToRegulators: rows.Count(r => In(r.ReportedAtUtc)),
            DetectToReport: Span(rows.Select(r => (r.DetectedAtUtc, r.ReportedAtUtc))),
            ReviewsRecorded: reviews.Count(r => In(r.At)),
            ActionsOpened: actions.Count(a => In(a.CreatedAtUtc)),
            ActionsCompleted: actions.Count(a => a.Status == ImprovementActionStatus.Completed && In(a.ClosedAtUtc)),
            ActionsNotPursued: actions.Count(a => a.Status == ImprovementActionStatus.NotPursued && In(a.ClosedAtUtc)),
            ActionsOpenAtEnd: openAtEnd.Count,
            // BUG-323: past target by the quarter's end, or by now for the quarter still running (its end hasn't come).
            ActionsPastTargetAtEnd: openAtEnd.Count(a => a.TargetDateUtc is { } t && t < (end < data.NowUtc ? end : data.NowUtc)),
            ActionAreas: Areas(actions.Where(a => In(a.CreatedAtUtc))),
            ContainmentBySeverity: Enum.GetValues<Severity>().OrderByDescending(v => v)
                .Select(v => new SeverityAttainment(v, data.TargetsAt(end < data.NowUtc ? end : data.NowUtc).HoursFor(SlaClock.Containment, v),   // as it stood at the end
                    bySeverity.GetValueOrDefault(v).Met, bySeverity.GetValueOrDefault(v).Missed)).ToList(),
            NoticesMet: nMet, NoticesMissed: nMiss,
            ClosedWithReview: rows.Count(r => ClosedInQuarter(r) && reviewed.Contains(r.Id)),
            OpenActionAreas: Areas(openAtEnd));
    }

    /// <summary>The report as a two-period CSV (metric, this quarter, previous quarter) for exam/board packs.</summary>
    public static string ToCsv(ProgramReport r, Func<Classification?, string> classLabel, Func<Severity, string> sevLabel)
    {
        var inv = CultureInfo.InvariantCulture;
        var sb = new StringBuilder();
        sb.Append("# CaseBook program report ").Append(r.Period.Label)
          .Append(r.IncludesExercises ? " (includes exercise cases)" : "")
          .Append(", ").Append(r.FirstDay.ToString("yyyy-MM-dd", inv)).Append(" to ").Append(r.LastDay.ToString("yyyy-MM-dd", inv))
          .Append(" (").Append(r.ZoneLabel).Append(')')
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
            Row("Timing (hours)", name + " (mean)", N(cur.MeanHours), N(prev.MeanHours));
            Row("Timing (hours)", name + " (median)", N(cur.MedianHours), N(prev.MedianHours));
        }
        foreach (var s in c.Sla)
        {
            var ps = p.Sla.First(x => x.Clock == s.Clock);
            Row("SLA attainment", $"{s.Clock} within target %", s.Percent?.ToString(inv) ?? "", ps.Percent?.ToString(inv) ?? "");
            Row("SLA attainment", $"{s.Clock} met / missed", $"{s.Met} / {s.Missed}", $"{ps.Met} / {ps.Missed}");
        }
        Row("Regulatory", "Cases classified as breach", c.BreachesOpened.ToString(inv), p.BreachesOpened.ToString(inv));
        Row("Regulatory", "Reported to regulators", c.ReportedToRegulators.ToString(inv), p.ReportedToRegulators.ToString(inv));
        // BUG-77: the figures the page shows, so the board or exam pack CSV has them too.
        Row("Regulatory", "Notices inside their window %", c.NoticesPercent?.ToString(inv) ?? "", p.NoticesPercent?.ToString(inv) ?? "");
        Row("Regulatory", "Notices inside / outside their window", $"{c.NoticesMet} / {c.NoticesMissed}", $"{p.NoticesMet} / {p.NoticesMissed}");
        foreach (var s in c.ContainmentBySeverity ?? [])
        {
            var ps = p.ContainmentBySeverity?.FirstOrDefault(x => x.Severity == s.Severity);
            Row("Containment by severity", $"{sevLabel(s.Severity)} met / missed" + (s.TargetHours is { } h ? $" (target {h} h)" : ""),
                $"{s.Met} / {s.Missed}", ps is null ? "" : $"{ps.Met} / {ps.Missed}");
        }
        Row("Post-incident", "Closed cases with a review", c.ClosedWithReview.ToString(inv), p.ClosedWithReview.ToString(inv));
        Row("Post-incident", "Reviews recorded", c.ReviewsRecorded.ToString(inv), p.ReviewsRecorded.ToString(inv));
        Row("Post-incident", "Improvement actions opened", c.ActionsOpened.ToString(inv), p.ActionsOpened.ToString(inv));
        Row("Post-incident", "Improvement actions completed", c.ActionsCompleted.ToString(inv), p.ActionsCompleted.ToString(inv));
        Row("Post-incident", "Improvement actions not pursued", c.ActionsNotPursued.ToString(inv), p.ActionsNotPursued.ToString(inv));
        Row("Post-incident", "Open at quarter end", c.ActionsOpenAtEnd.ToString(inv), p.ActionsOpenAtEnd.ToString(inv));
        Row("Post-incident", "Past target at quarter end", c.ActionsPastTargetAtEnd.ToString(inv), p.ActionsPastTargetAtEnd.ToString(inv));
        foreach (var a in c.ActionAreas)
            Row("Improvement areas (opened)", a.Key, a.Count.ToString(inv), "");
        foreach (var a in c.OpenActionAreas ?? [])
            Row("Improvement areas (open at quarter end)", a.Key, a.Count.ToString(inv), "");
        foreach (var t in r.TopTechniques)
            Row("ATT&CK techniques (cases)", $"{t.TechniqueId} {t.Name}", t.Cases.ToString(inv), "");
        return sb.ToString();
    }
}
