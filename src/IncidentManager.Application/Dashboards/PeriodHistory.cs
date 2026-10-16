using System.Text.Json;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Sla;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Dashboards;

/// <summary>
/// C11 (past-period stability): the shared as-of readers every period figure is computed from, so a closed period is
/// figured from values as they stood then, never from today's. Each rebuilds what a figure reads at an instant
/// (<c>asOf</c>, the period's end) from today's rows and the audit trail: every change recorded at or after it is
/// undone, newest first, from the values its audit entry records as before. The rules they share:
/// <list type="bullet">
/// <item>A case filed at or after the instant had no record then; its values today place it (BUG-499 follow-up: a
/// detected time filed as "now" and corrected back into the window still counts there).</item>
/// <item>A transition-time correction (INV-05b) made at or after the instant is undone (BUG-584).</item>
/// <item>A child row (a notice, a step, a tag) created at or after the instant wasn't there, unless the whole case was
/// filed afterwards; one deleted at or after it was, as its delete's before-image records it.</item>
/// </list>
/// PastPeriodFreezeTests holds every period figure to this against a catalogue of later mutations.
/// </summary>
public static class PeriodHistory
{
    /// <summary>Calls <paramref name="field"/> for each property of an audit entry's JSON object (none when unreadable).</summary>
    public static void Fields(string? json, Action<string, JsonElement> field)
    {
        if (string.IsNullOrEmpty(json)) return;
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return;
            foreach (var p in doc.RootElement.EnumerateObject()) field(p.Name, p.Value);
        }
        catch (JsonException) { /* an entry it can't read changes nothing */ }
    }

    public static DateTimeOffset? Instant(JsonElement e) =>
        e.ValueKind == JsonValueKind.String && e.TryGetDateTimeOffset(out var t) ? t : null;

    public static int? Int(JsonElement e) => e.ValueKind == JsonValueKind.Number && e.TryGetInt32(out var i) ? i : null;

    public static Guid? Id(JsonElement e) => e.ValueKind == JsonValueKind.String && e.TryGetGuid(out var g) ? g : null;

    public static string? Text(JsonElement e) => e.ValueKind == JsonValueKind.String ? e.GetString() : null;

    /// <summary>One audit entry of an entity, for undoing it.</summary>
    public sealed record Entry(string EntityId, AuditAction Action, DateTimeOffset AtUtc, long Sequence, string? BeforeJson, string? AfterJson);

    /// <summary>
    /// The updates (and, with <paramref name="deletes"/>, every delete) of <paramref name="entityType"/> rows, newest first per
    /// row. Updates are read for <paramref name="ids"/> only; deletes for every row of the type (the caller narrows them by
    /// the case in the before-image). Compared in memory: DateTimeOffset stays off SQLite (F-08).
    /// </summary>
    public static async Task<Dictionary<string, List<Entry>>> TrailsAsync(IAppDbContext db, string entityType,
        IReadOnlyCollection<string> ids, bool deletes, CancellationToken ct)
    {
        List<Entry> updates = ids.Count == 0 ? [] : await db.AuditLog.AsNoTracking()
            .Where(a => a.EntityType == entityType && a.Action == AuditAction.Update && a.BeforeJson != null
                        && a.EntityId != null && ids.Contains(a.EntityId))
            .Select(a => new Entry(a.EntityId!, a.Action, a.AtUtc, a.Sequence, a.BeforeJson, a.AfterJson))
            .ToListAsync(ct);
        if (deletes)
            updates.AddRange(await db.AuditLog.AsNoTracking()
                .Where(a => a.EntityType == entityType && a.Action == AuditAction.Delete && a.BeforeJson != null && a.EntityId != null)
                .Select(a => new Entry(a.EntityId!, a.Action, a.AtUtc, a.Sequence, a.BeforeJson, a.AfterJson))
                .ToListAsync(ct));
        return updates.GroupBy(e => e.EntityId, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.OrderByDescending(e => e.Sequence).ToList(), StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>The creates and deletes of <paramref name="entityType"/> rows (small rows, such as a step's tactics).</summary>
    public static async Task<List<Entry>> CreatesAndDeletesAsync(IAppDbContext db, string entityType, CancellationToken ct) =>
        await db.AuditLog.AsNoTracking()
            .Where(a => a.EntityType == entityType && (a.Action == AuditAction.Create || a.Action == AuditAction.Delete) && a.EntityId != null)
            .Select(a => new Entry(a.EntityId!, a.Action, a.AtUtc, a.Sequence, a.BeforeJson, a.AfterJson))
            .ToListAsync(ct);

    /// <summary>
    /// The quarter-end a milestone reached at <paramref name="t"/> is reported at (BUG-588): the end of the calendar quarter
    /// it falls in, in <paramref name="zone"/>. At the calendar's edges (a mistyped year), <paramref name="t"/> itself.
    /// </summary>
    public static DateTimeOffset QuarterEnd(DateTimeOffset t, TimeZoneInfo zone) =>
        t.Year is > 1 and < 9999 ? ProgramPeriod.Containing(t, zone).EndUtc(zone) : t;
}

/// <summary>BUG-499: the milestone stamps a period reads, rebuilt together as the record stood at its end.</summary>
public sealed record CaseStamps(DateTimeOffset? OccurredAtUtc, DateTimeOffset? DetectedAtUtc, DateTimeOffset? ContainedAtUtc,
    bool ContainmentNotNeeded, DateTimeOffset? ResolvedAtUtc, DateTimeOffset? ReportedAtUtc)
{
    /// <summary>BUG-165: a case that didn't need containment has no time to contain and no containment target outcome.</summary>
    public DateTimeOffset? ContainedIfNeeded => ContainmentNotNeeded ? null : ContainedAtUtc;

    /// <summary>The stamps just before an edit: the fields its audit entry records as before take those values.</summary>
    public CaseStamps Before(JsonElement before)
    {
        var s = this;
        if (before.TryGetProperty(nameof(Case.OccurredAtUtc), out var v)) s = s with { OccurredAtUtc = PeriodHistory.Instant(v) };
        if (before.TryGetProperty(nameof(Case.DetectedAtUtc), out v)) s = s with { DetectedAtUtc = PeriodHistory.Instant(v) };
        if (before.TryGetProperty(nameof(Case.ContainedAtUtc), out v)) s = s with { ContainedAtUtc = PeriodHistory.Instant(v) };
        if (before.TryGetProperty(nameof(Case.ContainmentNotNeededReason), out v))
            s = s with { ContainmentNotNeeded = v.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(v.GetString()) };
        if (before.TryGetProperty(nameof(Case.ResolvedAtUtc), out v)) s = s with { ResolvedAtUtc = PeriodHistory.Instant(v) };
        if (before.TryGetProperty(nameof(Case.ReportedAtUtc), out v)) s = s with { ReportedAtUtc = PeriodHistory.Instant(v) };
        return s;
    }
}

/// <summary>
/// BUG-374, BUG-499: each case's milestone stamps as the record stood at any instant (StampsAt), from today's and the
/// case's audited stamp edits. One read for every case.
/// </summary>
public sealed class StampHistory
{
    private readonly Dictionary<Guid, (DateTimeOffset CreatedAtUtc, CaseStamps Now)> _cases;
    private readonly Dictionary<Guid, List<(DateTimeOffset At, CaseStamps Before)>> _edits;

    private StampHistory(Dictionary<Guid, (DateTimeOffset, CaseStamps)> cases, Dictionary<Guid, List<(DateTimeOffset, CaseStamps)>> edits)
    {
        _cases = cases;
        _edits = edits;
    }

    /// <summary>Today's stamps only (no trail read): every instant reads as now.</summary>
    public static StampHistory Today(IEnumerable<(Guid Id, DateTimeOffset CreatedAtUtc, CaseStamps Now)> rows) =>
        new(rows.ToDictionary(r => r.Id, r => (r.CreatedAtUtc, r.Now)), []);

    public static async Task<StampHistory> LoadAsync(IAppDbContext db, IReadOnlyCollection<(Guid Id, DateTimeOffset CreatedAtUtc, CaseStamps Now)> rows,
        CancellationToken ct)
    {
        var keys = rows.Select(r => r.Id.ToString()).ToList();
        static string F(string name) => "\"" + name + "\"";
        var (occurred, detected, contained) = (F(nameof(Case.OccurredAtUtc)), F(nameof(Case.DetectedAtUtc)), F(nameof(Case.ContainedAtUtc)));
        var (notNeeded, resolved, reported) = (F(nameof(Case.ContainmentNotNeededReason)), F(nameof(Case.ResolvedAtUtc)), F(nameof(Case.ReportedAtUtc)));
        var edits = await db.AuditLog.AsNoTracking()
            .Where(x => x.EntityType == nameof(Case) && x.Action == AuditAction.Update && x.BeforeJson != null
                        && (x.BeforeJson.Contains(occurred) || x.BeforeJson.Contains(detected) || x.BeforeJson.Contains(contained)
                            || x.BeforeJson.Contains(notNeeded) || x.BeforeJson.Contains(resolved) || x.BeforeJson.Contains(reported))
                        && x.EntityId != null && keys.Contains(x.EntityId))
            .Select(x => new { x.EntityId, x.AtUtc, x.Sequence, x.BeforeJson })
            .ToListAsync(ct);
        var byId = rows.ToDictionary(r => r.Id, r => (r.CreatedAtUtc, r.Now));
        var map = new Dictionary<Guid, List<(DateTimeOffset At, CaseStamps Before)>>();
        foreach (var g in edits.GroupBy(x => x.EntityId!, StringComparer.OrdinalIgnoreCase))
        {
            if (!Guid.TryParse(g.Key, out var id) || !byId.TryGetValue(id, out var row)) continue;
            var list = new List<(DateTimeOffset At, CaseStamps Before)>();
            var stamps = row.Now;
            foreach (var x in g.OrderByDescending(x => x.Sequence))
            {
                try
                {
                    using var doc = JsonDocument.Parse(x.BeforeJson!);
                    if (doc.RootElement.ValueKind != JsonValueKind.Object) continue;
                    var before = stamps.Before(doc.RootElement);
                    if (before == stamps) continue;   // none of the stamps moved (another field, or a new "not needed" reason)
                    list.Add((x.AtUtc, stamps = before));
                }
                catch (JsonException) { /* an entry it can't read is skipped */ }
            }
            list.Reverse();
            if (list.Count > 0) map[id] = list;
        }
        return new StampHistory(byId, map);
    }

    /// <summary>
    /// BUG-374: the reported time as the record stood at <paramref name="end"/> (every later change undone), so a case made
    /// unreported again later or reported again doesn't move a period already reported. Unreported then, a report recorded
    /// afterwards but dated before the end (Legal often reports before it is entered) is that period's: the time it settled
    /// on. BUG-499: likewise every milestone stamp, so moving a case back into Containment later doesn't move a period
    /// already reported. Whether containment was needed goes with the contained time it was recorded with.
    /// </summary>
    public CaseStamps At(Guid id, DateTimeOffset end)
    {
        var (created, now) = _cases[id];
        if (created >= end) return now;
        if (_edits.GetValueOrDefault(id) is not { Count: > 0 } edits) return now;
        var i = edits.FindIndex(e => e.At >= end);
        if (i < 0) return now;
        var s = edits[i].Before;
        if (s.ReportedAtUtc is null && Settled(x => x.ReportedAtUtc) is { } rep) s = s with { ReportedAtUtc = rep.ReportedAtUtc };
        if (s.ContainedAtUtc is null && Settled(x => x.ContainedAtUtc) is { } con)
            s = s with { ContainedAtUtc = con.ContainedAtUtc, ContainmentNotNeeded = con.ContainmentNotNeeded };
        if (s.ResolvedAtUtc is null && Settled(x => x.ResolvedAtUtc) is { } res) s = s with { ResolvedAtUtc = res.ResolvedAtUtc };
        if (s.DetectedAtUtc is null && Settled(x => x.DetectedAtUtc) is { } det) s = s with { DetectedAtUtc = det.DetectedAtUtc };
        if (s.OccurredAtUtc is null && Settled(x => x.OccurredAtUtc) is { } occ) s = s with { OccurredAtUtc = occ.OccurredAtUtc };
        return s;

        // Empty at the end: the record as it stood once the stamp was set afterwards (until it was next cleared), when the
        // time it settled on is before the end.
        CaseStamps? Settled(Func<CaseStamps, DateTimeOffset?> field)
        {
            CaseStamps? settled = null;
            for (var j = i; j < edits.Count; j++)
            {
                var after = j + 1 < edits.Count ? edits[j + 1].Before : now;
                if (field(after) == field(edits[j].Before)) continue;   // an edit to another stamp
                if (field(after) is null) break;
                settled = after;
            }
            return settled is { } st && field(st) < end ? st : null;
        }
    }
}

public sealed record PhaseChangeRow(Guid Id, Guid CaseId, CasePhase? From, CasePhase To, DateTimeOffset EffectiveAt, DateTimeOffset ChangedAtUtc);
public sealed record ClassChangeRow(Guid Id, Guid CaseId, Classification? From, Classification To, DateTimeOffset EffectiveAt, DateTimeOffset ChangedAtUtc);
public sealed record SeverityChangeRow(Guid Id, Guid CaseId, Severity? From, Severity To, DateTimeOffset EffectiveAt, DateTimeOffset ChangedAtUtc);
public sealed record CorrectionRow(Guid ChangeId, DateTimeOffset FromEffectiveUtc, DateTimeOffset CreatedAtUtc);

/// <summary>
/// WF-38: each case's phase, classification and severity changes, in the order they were recorded (WF-97: the order the
/// states followed each other), so a period is figured as the record stood then (owner's decision: past quarters are
/// frozen). BUG-584: each change's effective time as it stood then too: a transition-time correction made at or after
/// the instant is undone (the correction row keeps the time it moved from), so re-dating a change later doesn't move a
/// past quarter's phase, class, severity or breach figures.
/// </summary>
public sealed class TransitionHistory
{
    private readonly Dictionary<Guid, List<PhaseChangeRow>> _phases;
    private readonly Dictionary<Guid, List<ClassChangeRow>> _classes;
    private readonly Dictionary<Guid, List<SeverityChangeRow>> _severities;
    private readonly Dictionary<Guid, List<CorrectionRow>> _corrections;

    public TransitionHistory(IEnumerable<PhaseChangeRow> phases, IEnumerable<ClassChangeRow> classes,
        IEnumerable<SeverityChangeRow> severities, IEnumerable<CorrectionRow> corrections)
    {
        _phases = phases.GroupBy(x => x.CaseId).ToDictionary(g => g.Key, g => g.OrderBy(x => x.ChangedAtUtc).ToList());
        _classes = classes.GroupBy(x => x.CaseId).ToDictionary(g => g.Key, g => g.OrderBy(x => x.ChangedAtUtc).ToList());
        _severities = severities.GroupBy(x => x.CaseId).ToDictionary(g => g.Key, g => g.OrderBy(x => x.ChangedAtUtc).ToList());
        _corrections = corrections.GroupBy(x => x.ChangeId).ToDictionary(g => g.Key, g => g.OrderBy(x => x.CreatedAtUtc).ToList());
    }

    /// <summary>The history of every case in <paramref name="ids"/>, in one read per table.</summary>
    public static async Task<TransitionHistory> LoadAsync(IAppDbContext db, IQueryable<Guid> ids, CancellationToken ct)
    {
        var phases = await db.StatusChanges.AsNoTracking().Where(x => ids.Contains(x.CaseId))
            .Select(x => new PhaseChangeRow(x.Id, x.CaseId, x.From, x.To, x.EffectiveAtUtc ?? x.ChangedAtUtc, x.ChangedAtUtc)).ToListAsync(ct);
        var classes = await db.ClassificationChanges.AsNoTracking().Where(x => ids.Contains(x.CaseId))
            .Select(x => new ClassChangeRow(x.Id, x.CaseId, x.From, x.To, x.EffectiveAtUtc ?? x.ChangedAtUtc, x.ChangedAtUtc)).ToListAsync(ct);
        var severities = await db.SeverityChanges.AsNoTracking().Where(x => ids.Contains(x.CaseId))
            .Select(x => new SeverityChangeRow(x.Id, x.CaseId, x.From, x.To, x.EffectiveAtUtc ?? x.ChangedAtUtc, x.ChangedAtUtc)).ToListAsync(ct);
        var corrections = await db.TransitionTimeCorrections.AsNoTracking().Where(x => ids.Contains(x.CaseId))
            .Select(x => new CorrectionRow(x.ChangeId, x.FromEffectiveUtc, x.CreatedAtUtc)).ToListAsync(ct);
        return new TransitionHistory(phases, classes, severities, corrections);
    }

    /// <summary>A change's effective time as it stood at <paramref name="asOf"/>: the time the first correction made at or
    /// after it moved it from, else its time today.</summary>
    private DateTimeOffset At(Guid changeId, DateTimeOffset effectiveNow, DateTimeOffset asOf)
    {
        if (!_corrections.TryGetValue(changeId, out var list)) return effectiveNow;
        var i = list.FindIndex(c => c.CreatedAtUtc >= asOf);
        return i < 0 ? effectiveNow : list[i].FromEffectiveUtc;
    }

    // A case's closures and reopenings, when the record has them; one closed without a phase change (data from before phase
    // changes were recorded) is judged by its closed time, as before.
    private List<PhaseChangeRow>? Closures(Guid id) =>
        _phases.TryGetValue(id, out var ph) && ph.Any(x => x.To == CasePhase.Closed || x.From == CasePhase.Closed) ? ph : null;

    /// <summary>Closed at <paramref name="t"/>, as the record stood then.</summary>
    public bool ClosedAt(Guid id, DateTimeOffset t, DateTimeOffset? closedNow) =>
        Closures(id) is { } ph
            ? ph.Where(x => At(x.Id, x.EffectiveAt, t) < t).Select(x => (CasePhase?)x.To).LastOrDefault() == CasePhase.Closed
            : closedNow is { } c && c < t;

    /// <summary>Closed in [<paramref name="start"/>, <paramref name="end"/>), as the record stood at the end.</summary>
    public bool ClosedIn(Guid id, DateTimeOffset start, DateTimeOffset end, DateTimeOffset? closedNow) =>
        ClosedTimes(id, end, closedNow).Any(c => c >= start && c < end);

    /// <summary>When it was closed (each closure), as the record stood at <paramref name="asOf"/>.</summary>
    public IEnumerable<DateTimeOffset> ClosedTimes(Guid id, DateTimeOffset asOf, DateTimeOffset? closedNow) =>
        Closures(id) is { } ph ? ph.Where(x => x.To == CasePhase.Closed).Select(x => At(x.Id, x.EffectiveAt, asOf))
        : closedNow is { } c ? [c] : [];

    public bool EverClosed(Guid id, DateTimeOffset? closedNow) => closedNow is not null || Closures(id) is not null;

    /// <summary>The classification at <paramref name="t"/> (a change at exactly <paramref name="t"/> counts only when
    /// <paramref name="inclusive"/>), as the record stood at <paramref name="asOf"/> (by default, then).</summary>
    public Classification? ClassAt(Guid id, DateTimeOffset t, Classification? now, bool inclusive = false, DateTimeOffset? asOf = null)
    {
        if (!_classes.TryGetValue(id, out var ch) || ch.Count == 0) return now;
        var stood = asOf ?? t;
        bool Before(ClassChangeRow x) => At(x.Id, x.EffectiveAt, stood) is var at && (inclusive ? at <= t : at < t);
        return ch.LastOrDefault(Before) is { } last ? last.To : ch[0].From;
    }

    public Severity SevAt(Guid id, DateTimeOffset t, Severity now)
    {
        if (!_severities.TryGetValue(id, out var ch) || ch.Count == 0) return now;
        return ch.LastOrDefault(x => At(x.Id, x.EffectiveAt, t) < t) is { } last ? last.To : ch[0].From ?? now;
    }

    /// <summary>When the case first became a Breach, as the record stood at <paramref name="asOf"/>; null if it never did.</summary>
    public DateTimeOffset? BreachAt(Guid id, DateTimeOffset asOf) =>
        _classes.TryGetValue(id, out var ch) && ch.Where(x => x.To == Classification.Breach).Select(x => At(x.Id, x.EffectiveAt, asOf)).ToList()
            is { Count: > 0 } times ? times.Min() : null;

    /// <summary>The cases that were ever a Breach.</summary>
    public IEnumerable<Guid> EverBreach => _classes.Where(kv => kv.Value.Any(x => x.To == Classification.Breach)).Select(kv => kv.Key);
}

/// <summary>
/// BUG-587 (owner's decision: past quarters' ATT&amp;CK top techniques freeze at quarter end) and BUG-583: each case's event
/// steps and technique tags as they stood at any instant. A step is there once created and until retracted; its technique,
/// tactics, environment, actor/target and stated time are rebuilt from its audited edits and its tactics' adds/removes; a
/// tag is there once created and until removed, with the tactic it had.
/// </summary>
public sealed class AttackHistory
{
    /// <summary>An event step's fields a period reads.</summary>
    public sealed record Step(Guid Id, Guid CaseId, DateTimeOffset CreatedAtUtc, DateTimeOffset? RetractedAtUtc, bool IsCurrent,
        DateTimeOffset OccurredAtUtc, TimePrecision? OccurredPrecision, DateTimeOffset? OccurredUntilUtc, int? StepOrder,
        string? TechniqueId, Guid? ActorEntityId, Guid? TargetEntityId, StepEnvironment? Environment,
        IReadOnlyList<(Guid Id, MitreTactic Tactic)> Tactics);

    /// <summary>A technique tag's fields a period reads.</summary>
    public sealed record Tag(Guid Id, Guid CaseId, string TechniqueId, MitreTactic Tactic, DateTimeOffset CreatedAtUtc);

    private readonly Dictionary<Guid, DateTimeOffset> _caseCreated;
    private readonly List<Step> _steps;
    private readonly Dictionary<string, List<PeriodHistory.Entry>> _stepEdits;
    // BUG-612: by step, once (each window rebuilds every step; a scan of the whole trail per step was steps x trail).
    private readonly ILookup<Guid, (Guid StepId, Guid TacticId, MitreTactic Tactic, AuditAction Action, DateTimeOffset At)> _tacticTrail;
    private readonly List<Tag> _tags;
    private readonly Dictionary<string, List<PeriodHistory.Entry>> _tagTrail;

    private AttackHistory(Dictionary<Guid, DateTimeOffset> caseCreated, List<Step> steps, Dictionary<string, List<PeriodHistory.Entry>> stepEdits,
        List<(Guid, Guid, MitreTactic, AuditAction, DateTimeOffset)> tacticTrail, List<Tag> tags, Dictionary<string, List<PeriodHistory.Entry>> tagTrail)
    {
        (_caseCreated, _steps, _stepEdits, _tags, _tagTrail) = (caseCreated, steps, stepEdits, tags, tagTrail);
        _tacticTrail = tacticTrail.ToLookup(t => t.Item1);
    }

    /// <param name="cases">The visible cases, with when each was filed.</param>
    /// <param name="withTrails">False for figures that read only today's (the trail isn't read).</param>
    public static async Task<AttackHistory> LoadAsync(IAppDbContext db, IQueryable<Case> cases, bool withTrails, CancellationToken ct)
    {
        var ids = cases.Select(c => c.Id);
        var created = await cases.Select(c => new { c.Id, c.CreatedAtUtc }).ToDictionaryAsync(c => c.Id, c => c.CreatedAtUtc, ct);
        // Retracted steps too: a step retracted after the instant was still on the record then.
        var steps = (await db.TimelineEntries.AsNoTracking().Where(e => ids.Contains(e.CaseId) && e.Kind == TimelineKind.Event)
                .Select(e => new
                {
                    e.Id, e.CaseId, e.CreatedAtUtc, e.RetractedAtUtc, e.IsCurrent, e.OccurredAtUtc, e.OccurredPrecision, e.OccurredUntilUtc,
                    e.StepOrder, e.TechniqueId, e.ActorEntityId, e.TargetEntityId, e.Environment,
                    Tactics = e.Tactics.Select(t => new { t.Id, t.Tactic }).ToList()
                }).ToListAsync(ct))
            .Select(e => new Step(e.Id, e.CaseId, e.CreatedAtUtc, e.RetractedAtUtc, e.IsCurrent, e.OccurredAtUtc, e.OccurredPrecision,
                e.OccurredUntilUtc, e.StepOrder, e.TechniqueId, e.ActorEntityId, e.TargetEntityId, e.Environment,
                e.Tactics.Select(t => (t.Id, t.Tactic)).ToList()))
            .ToList();
        var tags = await db.CaseTechniques.AsNoTracking().Where(t => ids.Contains(t.CaseId))
            .Select(t => new Tag(t.Id, t.CaseId, t.TechniqueId, t.Tactic, t.CreatedAtUtc)).ToListAsync(ct);
        if (!withTrails) return new AttackHistory(created, steps, [], [], tags, []);

        var stepEdits = await PeriodHistory.TrailsAsync(db, nameof(TimelineEntry), steps.Select(s => s.Id.ToString()).ToList(), deletes: false, ct);
        var stepIds = steps.Select(s => s.Id).ToHashSet();
        var tacticTrail = new List<(Guid, Guid, MitreTactic, AuditAction, DateTimeOffset)>();
        foreach (var e in await PeriodHistory.CreatesAndDeletesAsync(db, nameof(EventStepTactic), ct))
        {
            Guid? step = null;
            MitreTactic? tactic = null;
            PeriodHistory.Fields(e.Action == AuditAction.Create ? e.AfterJson : e.BeforeJson, (name, v) =>
            {
                if (name == nameof(EventStepTactic.TimelineEntryId)) step = PeriodHistory.Id(v);
                else if (name == nameof(EventStepTactic.Tactic) && PeriodHistory.Int(v) is { } i) tactic = (MitreTactic)i;
            });
            if (step is { } s && stepIds.Contains(s) && tactic is { } t && Guid.TryParse(e.EntityId, out var tid))
                tacticTrail.Add((s, tid, t, e.Action, e.AtUtc));
        }
        var tagTrail = await PeriodHistory.TrailsAsync(db, nameof(CaseTechnique), tags.Select(t => t.Id.ToString()).ToList(), deletes: true, ct);
        // A deleted tag is known only from its delete's before-image; kept when it was on a visible case.
        var tagIds = tags.Select(t => t.Id).ToHashSet();
        foreach (var (id, trail) in tagTrail)
        {
            if (trail.FirstOrDefault(x => x.Action == AuditAction.Delete) is not { } del || !Guid.TryParse(id, out var tagId)
                || tagIds.Contains(tagId)) continue;
            Guid? caseId = null; string? technique = null; MitreTactic tactic = MitreTactic.Unspecified; DateTimeOffset? at = null;
            PeriodHistory.Fields(del.BeforeJson, (name, v) =>
            {
                switch (name)
                {
                    case nameof(CaseTechnique.CaseId): caseId = PeriodHistory.Id(v); break;
                    case nameof(CaseTechnique.TechniqueId): technique = PeriodHistory.Text(v); break;
                    case nameof(CaseTechnique.Tactic): tactic = PeriodHistory.Int(v) is { } i ? (MitreTactic)i : tactic; break;
                    case nameof(CaseTechnique.CreatedAtUtc): at = PeriodHistory.Instant(v); break;
                }
            });
            if (caseId is { } cid && created.ContainsKey(cid) && technique is not null && at is { } createdAt)
                tags.Add(new Tag(tagId, cid, technique, tactic, createdAt));
        }
        return new AttackHistory(created, steps, stepEdits, tacticTrail, tags, tagTrail);
    }

    private bool FiledAfter(Guid caseId, DateTimeOffset asOf) => !_caseCreated.TryGetValue(caseId, out var c) || c >= asOf;

    /// <summary>The current (not retracted) event steps of each case as they stood at <paramref name="asOf"/>.</summary>
    public ILookup<Guid, Step> StepsAt(DateTimeOffset asOf)
    {
        var list = new List<Step>();
        foreach (var s in _steps)
        {
            if (FiledAfter(s.CaseId, asOf)) { if (s.IsCurrent) list.Add(s); continue; }
            if (s.CreatedAtUtc >= asOf) continue;
            if (s.RetractedAtUtc is { } r ? r < asOf : !s.IsCurrent) continue;
            list.Add(Rebuilt(s, asOf));
        }
        return list.ToLookup(s => s.CaseId);
    }

    private Step Rebuilt(Step s, DateTimeOffset asOf)
    {
        var step = s;
        foreach (var e in _stepEdits.GetValueOrDefault(s.Id.ToString()) ?? [])
        {
            if (e.AtUtc < asOf) break;
            PeriodHistory.Fields(e.BeforeJson, (name, v) =>
            {
                step = name switch
                {
                    nameof(TimelineEntry.OccurredAtUtc) when PeriodHistory.Instant(v) is { } at => step with { OccurredAtUtc = at },
                    nameof(TimelineEntry.OccurredPrecision) => step with { OccurredPrecision = PeriodHistory.Int(v) is { } p ? (TimePrecision)p : null },
                    nameof(TimelineEntry.OccurredUntilUtc) => step with { OccurredUntilUtc = PeriodHistory.Instant(v) },
                    nameof(TimelineEntry.StepOrder) => step with { StepOrder = PeriodHistory.Int(v) },
                    nameof(TimelineEntry.TechniqueId) => step with { TechniqueId = PeriodHistory.Text(v) },
                    nameof(TimelineEntry.ActorEntityId) => step with { ActorEntityId = PeriodHistory.Id(v) },
                    nameof(TimelineEntry.TargetEntityId) => step with { TargetEntityId = PeriodHistory.Id(v) },
                    nameof(TimelineEntry.Environment) => step with { Environment = PeriodHistory.Int(v) is { } env ? (StepEnvironment)env : null },
                    _ => step
                };
            });
        }
        var tactics = s.Tactics.ToList();
        foreach (var t in _tacticTrail[s.Id].Where(t => t.At >= asOf))
            if (t.Action == AuditAction.Create) tactics.RemoveAll(x => x.Id == t.TacticId);
            else if (tactics.All(x => x.Id != t.TacticId)) tactics.Add((t.TacticId, t.Tactic));
        return step with { Tactics = tactics };
    }

    /// <summary>Each case's technique tags as they stood at <paramref name="asOf"/>.</summary>
    public IEnumerable<Tag> TagsAt(DateTimeOffset asOf)
    {
        foreach (var t in _tags)
        {
            var trail = _tagTrail.GetValueOrDefault(t.Id.ToString()) ?? [];
            var deleted = trail.FirstOrDefault(x => x.Action == AuditAction.Delete);
            if (FiledAfter(t.CaseId, asOf)) { if (deleted is null) yield return t; continue; }
            if (t.CreatedAtUtc >= asOf || deleted is { } d && d.AtUtc < asOf) continue;
            var tag = t;
            foreach (var e in trail.Where(x => x.Action == AuditAction.Update && x.AtUtc >= asOf))   // newest first
                PeriodHistory.Fields(e.BeforeJson, (name, v) =>
                {
                    if (name == nameof(CaseTechnique.Tactic) && PeriodHistory.Int(v) is { } i) tag = tag with { Tactic = (MitreTactic)i };
                });
            yield return tag;
        }
    }

    /// <summary>
    /// ST-04 / BUG-583: the cases whose "activity began" is approximate at <paramref name="asOf"/> (its first attack step's
    /// time is, StepTime.ActivityBeganCaveat), given each case's origin and recorded start then. Nothing is measured from
    /// such a start: no time to detect and no detection target outcome.
    /// </summary>
    public HashSet<Guid> ApproximateStarts(DateTimeOffset asOf, IReadOnlyDictionary<Guid, CaseOrigin> origins,
        Func<Guid, DateTimeOffset?> occurredAt)
    {
        var result = new HashSet<Guid>();
        foreach (var g in StepsAt(asOf))
            if (g.Any(s => s.OccurredPrecision is { } p && p != TimePrecision.Exact) && origins.TryGetValue(g.Key, out var origin)
                && StepTime.ActivityBeganCaveat(origin, occurredAt(g.Key), g.Select(ToEntry)) is not null)
                result.Add(g.Key);
        return result;
    }

    /// <summary>A step as a detached timeline entry, for the rules that read one (EventSteps, StepTime).</summary>
    public static TimelineEntry ToEntry(Step s) => new()
    {
        Id = s.Id, CaseId = s.CaseId, Kind = TimelineKind.Event, IsCurrent = true, CreatedAtUtc = s.CreatedAtUtc,
        OccurredAtUtc = s.OccurredAtUtc, OccurredPrecision = s.OccurredPrecision, OccurredUntilUtc = s.OccurredUntilUtc, StepOrder = s.StepOrder,
        TechniqueId = s.TechniqueId, ActorEntityId = s.ActorEntityId, TargetEntityId = s.TargetEntityId, Environment = s.Environment,
        Tactics = s.Tactics.Select(t => new EventStepTactic { Id = t.Id, TimelineEntryId = s.Id, Tactic = t.Tactic }).ToList()
    };
}

/// <summary>
/// BUG-322, WF-76, BUG-583, BUG-588: how a period judges one case's SLA milestones. Each milestone reached in the period is
/// judged on the severity and classification the case had at the period's end (as it's bucketed), against the targets in
/// force when it was reached. The detection clock isn't judged when the start is approximate (ST-04). The program report
/// and the dashboard's all-time figure share it, so both agree.
/// </summary>
public static class PeriodSla
{
    public static (SlaStatus Containment, SlaStatus Resolution, SlaStatus Detection) Judge(Severity severity, Classification? classification,
        CasePhase phase, CaseStamps s, Func<DateTimeOffset, SlaTargets> targetsAt, DateTimeOffset end, bool approximateStart)
    {
        var contained = s.ContainedIfNeeded;
        var cont = SlaPolicy.Breakdown(severity, phase, s.DetectedAtUtc, contained, s.ResolvedAtUtc,
            targetsAt(contained ?? end), end, classification).Containment;
        var res = SlaPolicy.Breakdown(severity, phase, s.DetectedAtUtc, contained, s.ResolvedAtUtc,
            targetsAt(s.ResolvedAtUtc ?? end), end, classification).Resolution;
        var det = approximateStart
            ? SlaStatus.None with { Clock = SlaClock.Detection }
            : SlaPolicy.EvaluateDetection(severity, s.OccurredAtUtc, s.DetectedAtUtc, targetsAt(s.DetectedAtUtc ?? end));
        return (cont, res, det);
    }
}
