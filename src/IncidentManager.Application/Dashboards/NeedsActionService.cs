using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Compliance;
using IncidentManager.Application.Sla;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Dashboards;

public enum NeedsActionKind
{
    /// <summary>A regulatory notice at risk of, or past, its jurisdiction's window.</summary>
    Notify,
    /// <summary>An open case at risk of, or past, its containment or resolution target.</summary>
    Sla,
    /// <summary>The case's brief predates a decision, handoff, phase, classification or materiality change.</summary>
    Brief,
    /// <summary>A case's tasks past their due date.</summary>
    Tasks,
    /// <summary>Improvement actions past their target date (across the program).</summary>
    Actions
}

/// <summary>One thing on the Program overview that needs someone to act. <see cref="DueAtUtc"/> is when it falls (or
/// fell) due; <see cref="Over"/> says it already has. A null case is a program-wide item.</summary>
public sealed record NeedsActionItem(NeedsActionKind Kind, Guid? CaseId, string? CaseNumber, string What,
    DateTimeOffset DueAtUtc, bool Over, int Count = 1, string? Href = null);

/// <summary>A running regulatory-notification clock: the case's most urgent jurisdiction.</summary>
public sealed record NotificationClock(Guid CaseId, string CaseNumber, string Jurisdiction, int WindowHours,
    double ElapsedHours, DateTimeOffset DueAtUtc, SlaState State);

public sealed record NeedsAction(IReadOnlyList<NeedsActionItem> Items, IReadOnlyList<NotificationClock> Clocks,
    bool NotifyDeadlinesEnabled);

/// <summary>
/// The Program overview's "Needs action" list and notification clocks: notices, response targets, briefs behind
/// the record, overdue tasks and improvement actions past target, on the caller's visible cases. Read-only; it only
/// points at work, and a person does it.
/// </summary>
public sealed class NeedsActionService
{
    // An entry version's type and links, without its text.
    private static readonly System.Linq.Expressions.Expression<Func<TimelineEntry, TimelineEntry>> LinkOnly = e => new TimelineEntry
        { Id = e.Id, CaseId = e.CaseId, Type = e.Type, IsCurrent = e.IsCurrent, SupersedesEntryId = e.SupersedesEntryId, CreatedAtUtc = e.CreatedAtUtc };

    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;
    private readonly ISlaTargetsProvider _sla;
    private readonly INotificationDeadlineSettingsProvider _notify;
    private readonly Admin.NotificationRuleService _rules;

    public NeedsActionService(IAppDbContextFactory factory, ICurrentUser user, IClock clock, ISlaTargetsProvider sla,
        INotificationDeadlineSettingsProvider notify, Admin.NotificationRuleService rules)
    {
        _factory = factory;
        _user = user;
        _clock = clock;
        _sla = sla;
        _notify = notify;
        _rules = rules;
    }

    public async Task<NeedsAction> GetAsync(bool includeExercises = false, CancellationToken ct = default) =>
        await GetAsync(includeExercises, TeamScope.Any, ct);

    /// <summary>As above, for one team's cases (CAP-36), after need-to-know.</summary>
    public async Task<NeedsAction> GetAsync(bool includeExercises, TeamScope team, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var now = _clock.UtcNow;
        var cases = db.Cases.AsNoTracking().ForUser(_user).InTeam(team).Where(c => !c.IsArchived);
        if (!includeExercises) cases = cases.ExcludingExercises();
        var items = new List<NeedsActionItem>();

        // Regulatory notices: every running clock goes on the clocks panel; at risk or past due also needs action.
        // Closed cases count (INV-43): closing a case doesn't answer its notification.
        var clocks = new List<NotificationClock>();
        var nd = _notify.Current;
        if (nd.Enabled)
        {
            var ruleSet = await _rules.LoadRuleSetAsync(nd.DefaultWindowHours, ct);
            var heads = await NotificationDeadlineService.OpenHeadlinesAsync(db, cases, nd, ruleSet, now, ct);
            var numbers = await CaseNumbersAsync(cases, heads.Keys, ct);
            foreach (var (id, h) in heads)
            {
                if (h.DueAtUtc is not { } due || !h.IsActive) continue;
                clocks.Add(new(id, numbers[id], h.JurisdictionLabel, h.WindowHours, h.ElapsedHours ?? 0, due, h.State));
                if (h.NeedsAttention)
                    items.Add(new(NeedsActionKind.Notify, id, numbers[id], $"Notify {h.JurisdictionLabel}: {h.WindowHours} h window",
                        due, h.State == SlaState.Breached));
            }
        }

        // Response targets on open cases: the earliest running clock, as the case list's SLA filter judges it.
        var targets = _sla.Current;
        var open = await cases.Where(c => c.Phase != CasePhase.Closed)
            .Select(c => new { c.Id, c.CaseNumber, c.Severity, c.Phase, c.Classification, c.Origin, c.DetectedAtUtc, c.ContainedAtUtc, c.ResolvedAtUtc })
            .ToListAsync(ct);
        foreach (var c in open)
        {
            var s = SlaPolicy.Evaluate(c.Severity, c.Phase, c.DetectedAtUtc, c.ContainedAtUtc, c.ResolvedAtUtc, targets, now, c.Classification,
                origin: c.Origin);
            if (s.State is not (SlaState.Breached or SlaState.AtRisk) || s.DueAtUtc is not { } due) continue;
            var verb = s.Clock == SlaClock.Resolution ? "resolved" : "contained";
            items.Add(new(NeedsActionKind.Sla, c.Id, c.CaseNumber, s.State == SlaState.Breached
                    ? $"Not {verb} within its {s.TargetHours} h target"
                    : $"To be {verb} within its {s.TargetHours} h target", due, s.State == SlaState.Breached));
        }

        // Briefs behind the record: the latest decision, handoff, phase, classification or materiality change was
        // recorded after the current brief was written or last confirmed (what the case page prompts on).
        var openIds = open.Select(c => c.Id).ToList();
        // BUG-407: judged as the case page's brief card judges it (BriefFreshness): from the version last written or confirmed,
        // stepping back over versions CaseBook appended (WF-30), and an entry dated by when it was first recorded, so an
        // edited decision isn't a new one (BUG-301). Every version of each, without their text.
        var versions = (await db.CaseBriefs.AsNoTracking().Where(b => openIds.Contains(b.CaseId))
                .Select(b => new CaseBrief { Id = b.Id, CaseId = b.CaseId, Version = b.Version, IsCurrent = b.IsCurrent,
                    SupersedesBriefId = b.SupersedesBriefId, Appended = b.Appended, CreatedAtUtc = b.CreatedAtUtc,
                    ConfirmedAtUtc = b.ConfirmedAtUtc })
                .ToListAsync(ct))
            .GroupBy(b => b.CaseId).ToDictionary(g => g.Key, g => g.ToList());
        var briefs = versions.Values.SelectMany(v => v.Where(b => b.IsCurrent)).ToList();
        if (briefs.Count > 0)
        {
            var ids = briefs.Select(b => b.CaseId).ToList();
            // The current decisions and handoffs, then each one's earlier versions (to date it by its first). BUG-444: fetched
            // by their links, whatever their type, since an edit can change it (an analysis edited into a decision).
            var entries = (await db.TimelineEntries.AsNoTracking()
                    .Where(e => ids.Contains(e.CaseId) && e.IsCurrent
                                && (e.Type == TimelineEntryType.Decision || e.Type == TimelineEntryType.Handoff))
                    .Select(LinkOnly)
                    .ToListAsync(ct))
                .ToDictionary(e => e.Id);
            var earlier = entries.Values.Select(e => e.SupersedesEntryId).OfType<Guid>().ToList();
            for (var guard = 0; earlier.Count > 0 && guard < 1000; guard++)   // as BriefFreshness.FirstRecorded's guard
            {
                var found = await db.TimelineEntries.AsNoTracking().Where(e => earlier.Contains(e.Id)).Select(LinkOnly)
                    .ToListAsync(ct);
                foreach (var e in found) entries.TryAdd(e.Id, e);
                earlier = found.Select(e => e.SupersedesEntryId).OfType<Guid>().Where(id => !entries.ContainsKey(id)).ToList();
            }
            var changes = entries.Values
                .Where(e => e.IsCurrent && e.Type is TimelineEntryType.Decision or TimelineEntryType.Handoff)
                .Select(e => (e.CaseId, At: BriefFreshness.FirstRecorded(e, entries),
                    What: e.Type == TimelineEntryType.Decision ? "a decision" : "a handoff"))
                .Concat((await db.StatusChanges.AsNoTracking().Where(x => ids.Contains(x.CaseId))
                    .Select(x => new { x.CaseId, x.ChangedAtUtc }).ToListAsync(ct)).Select(x => (x.CaseId, At: x.ChangedAtUtc, What: "a phase change")))
                .Concat((await db.ClassificationChanges.AsNoTracking().Where(x => ids.Contains(x.CaseId))
                    .Select(x => new { x.CaseId, x.ChangedAtUtc }).ToListAsync(ct)).Select(x => (x.CaseId, At: x.ChangedAtUtc, What: "a classification change")))
                .Concat((await db.MaterialityChanges.AsNoTracking().Where(x => ids.Contains(x.CaseId))
                    .Select(x => new { x.CaseId, x.ChangedAtUtc }).ToListAsync(ct)).Select(x => (x.CaseId, At: x.ChangedAtUtc, What: "a materiality decision")))
                .GroupBy(x => x.CaseId).ToDictionary(g => g.Key, g => g.MaxBy(x => x.At));
            var numbers = open.ToDictionary(c => c.Id, c => c.CaseNumber);
            foreach (var b in briefs)
            {
                var asOf = BriefFreshness.Baseline(versions[b.CaseId], b);
                if (changes.TryGetValue(b.CaseId, out var latest) && latest.At > asOf)
                    items.Add(new(NeedsActionKind.Brief, b.CaseId, numbers[b.CaseId],
                        $"Brief v{b.Version} predates {latest.What}", latest.At, false));
            }
        }

        // Overdue tasks, one row per case. BUG-163: open cases only, as on the dashboard and in the reminders and agenda
        // (BUG-12, BUG-103): a closed case's leftover task isn't something to act on here.
        var visible = cases.Select(c => c.Id);
        var overdue = (await db.ActionItems.AsNoTracking()
                .Where(a => openIds.Contains(a.CaseId) && a.DueAtUtc != null
                            && a.Status != ActionItemStatus.Done && a.Status != ActionItemStatus.Cancelled)
                .Select(a => new { a.CaseId, Due = a.DueAtUtc!.Value }).ToListAsync(ct))
            .Where(a => a.Due < now).GroupBy(a => a.CaseId).ToList();
        var taskCases = await CaseNumbersAsync(cases, overdue.Select(g => g.Key), ct);
        foreach (var g in overdue)
        {
            var n = g.Count();
            items.Add(new(NeedsActionKind.Tasks, g.Key, taskCases[g.Key], $"{n} overdue task{(n == 1 ? "" : "s")}",
                g.Min(a => a.Due), true, n));
        }

        // Improvement actions past target: one program-wide row pointing at the register.
        var ids2 = visible;
        var pastTarget = (await db.ImprovementActions.AsNoTracking()
                .Where(a => ids2.Contains(a.CaseId) && a.TargetDateUtc != null
                            && (a.Status == ImprovementActionStatus.Open || a.Status == ImprovementActionStatus.InProgress))
                .Select(a => a.TargetDateUtc!.Value).ToListAsync(ct))
            .Where(t => t < now).ToList();
        if (pastTarget.Count > 0)
            items.Add(new(NeedsActionKind.Actions, null, null,
                $"{pastTarget.Count} improvement action{(pastTarget.Count == 1 ? "" : "s")} past target date",
                pastTarget.Min(), true, pastTarget.Count, "program/improvement-actions"));

        // Notices first (a legal clock), then whatever fell due earliest.
        return new NeedsAction(
            items.OrderBy(i => i.Kind == NeedsActionKind.Notify ? 0 : 1).ThenBy(i => i.Over ? 0 : 1).ThenBy(i => i.DueAtUtc).ToList(),
            clocks.OrderBy(c => c.DueAtUtc).ToList(), nd.Enabled);
    }

    private static async Task<Dictionary<Guid, string>> CaseNumbersAsync(IQueryable<Domain.Entities.Case> cases,
        IEnumerable<Guid> ids, CancellationToken ct)
    {
        var list = ids.ToList();
        return list.Count == 0 ? [] : await cases.Where(c => list.Contains(c.Id)).ToDictionaryAsync(c => c.Id, c => c.CaseNumber, ct);
    }
}
