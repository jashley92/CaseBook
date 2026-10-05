using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Compliance;
using IncidentManager.Application.Sla;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Work;

/// <summary>Why a task exists, as the Desk shows it beside the task.</summary>
public enum DeskWhy { None, Question, Decision, Entry, Entity, Evidence, Note, Notify, Investigate, Contain, Eradicate, Recover }

/// <summary>One of the caller's cases: their part in it, the next thing for them, and what changed since they looked.</summary>
public sealed record DeskCase(
    Guid Id, string CaseNumber, string Title, Classification? Classification, Severity Severity, CasePhase Phase,
    DateTimeOffset PhaseSinceUtc, CaseAssignmentRole? Role, bool IsRestricted,
    string? NextForYou, DateTimeOffset? NextDueUtc, DateTimeOffset? LastViewedUtc,
    int ChangesSince, IReadOnlyList<string> ChangedBy);

/// <summary>A task the caller owns, with why it exists.</summary>
public sealed record DeskTask(
    Guid Id, Guid CaseId, string CaseNumber, string CaseTitle, string Title, DateTimeOffset? DueAtUtc,
    TaskKind Kind, DeskWhy Why, string? WhyDetail);

public enum DeskNeedKind { Notify, Overdue, Mention, Assigned, DueSoon }

/// <summary>Something that needs the caller, in order of consequence.</summary>
public sealed record DeskNeed(
    DeskNeedKind Kind, Guid CaseId, string CaseNumber, string Title, string? Detail, DateTimeOffset? AtUtc,
    string? ByUserId = null, Guid? TaskId = null, Guid? NoteId = null);

/// <summary>A running clock on one of the caller's cases: a notification deadline or an SLA clock.</summary>
public sealed record DeskClock(Guid CaseId, string CaseNumber, NotificationDeadlineStatus? Notify, SlaStatus? Sla);

/// <summary>The caller's Desk (RD-16).</summary>
public sealed record Desk(
    IReadOnlyList<DeskNeed> Needs,
    IReadOnlyList<DeskCase> Cases,
    IReadOnlyList<DeskTask> Next,
    IReadOnlyList<DeskClock> Clocks,
    int ChangesSince,
    IReadOnlyList<string> ChangedBy,
    IReadOnlyList<Escalation> RecentEscalations);

/// <summary>
/// RD-16: the analyst's home. Builds on <see cref="MyWorkService"/> (the caller's open cases and tasks, need-to-know
/// scoped) and adds, per case, the caller's part and what others changed since the caller last opened it; what
/// needs the caller, ordered by consequence (a running notification clock, overdue work, a mention, being added to a
/// case, work due within a day); the caller's tasks with why each exists; and the clocks running on their cases.
/// Read only.
/// </summary>
public sealed class DeskService
{
    /// <summary>How far back "since you looked" reaches for a case the caller has never opened.</summary>
    public const int SinceWindowDays = 14;

    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;
    private readonly MyWorkService _work;
    private readonly NotificationDeadlineService _deadlines;
    private readonly ISlaTargetsProvider _sla;

    public DeskService(IAppDbContextFactory factory, ICurrentUser user, IClock clock, MyWorkService work,
        NotificationDeadlineService deadlines, ISlaTargetsProvider sla)
    {
        _factory = factory;
        _user = user;
        _clock = clock;
        _work = work;
        _deadlines = deadlines;
        _sla = sla;
    }

    public async Task<Desk> GetAsync(CancellationToken ct = default)
    {
        var work = await _work.GetAsync(ct);
        var now = _clock.UtcNow;
        var me = _user.UserId;
        var ids = work.OpenCases.Select(c => c.Id).ToList();
        var numbers = work.OpenCases.Select(c => c.CaseNumber).ToList();

        using var db = _factory.CreateDbContext();

        var roles = await db.Assignments.AsNoTracking()
            .Where(a => ids.Contains(a.CaseId) && a.UserId == me)
            .Select(a => new { a.CaseId, a.Role, a.AssignedAtUtc, a.AssignedBy })
            .ToListAsync(ct);
        var phaseChanges = await db.StatusChanges.AsNoTracking()
            .Where(s => ids.Contains(s.CaseId))
            .Select(s => new { s.CaseId, s.To, s.EffectiveAtUtc, s.ChangedAtUtc })
            .ToListAsync(ct);
        var viewed = (await db.CaseAccessEvents.AsNoTracking()
                .Where(e => e.ActorUserId == me && e.AccessType == AccessType.CaseOpen && e.CaseId != null && ids.Contains(e.CaseId.Value))
                .Select(e => new { CaseId = e.CaseId!.Value, e.LastSeenUtc })
                .ToListAsync(ct))
            .GroupBy(e => e.CaseId).ToDictionary(g => g.Key, g => g.Max(e => e.LastSeenUtc));

        DateTimeOffset SinceFor(Guid caseId) => viewed.TryGetValue(caseId, out var v) ? v : now.AddDays(-SinceWindowDays);

        // What others changed on each case since the caller last opened it (from the audit log).
        var floor = now.AddDays(-SinceWindowDays);
        var audit = await db.AuditLog.AsNoTracking()
            .Where(a => a.CaseNumber != null && numbers.Contains(a.CaseNumber) && a.Actor != me && a.AtUtc > floor)
            .Select(a => new { a.CaseNumber, a.Actor, a.AtUtc })
            .ToListAsync(ct);

        // My own tasks, with what's needed to say why each exists.
        var mine = work.Tasks.Where(t => t.OwnedByMe).ToList();
        var mineIds = mine.Select(t => t.Id).ToList();
        var taskInfo = await db.ActionItems.AsNoTracking()
            .Where(a => mineIds.Contains(a.Id))
            .Select(a => new { a.Id, a.Kind, a.RaisedFromBriefId, a.AboutRef })
            .ToDictionaryAsync(a => a.Id, ct);
        var abouts = taskInfo.Values.Select(t => ParseAbout(t.AboutRef)).Where(a => a is not null).Select(a => a!.Value).ToList();
        var entryIds = abouts.Where(a => a.Kind == ActionItem.AboutEntry).Select(a => a.Id).ToList();
        var entityIds = abouts.Where(a => a.Kind == ActionItem.AboutEntity).Select(a => a.Id).ToList();
        var evidenceIds = abouts.Where(a => a.Kind == ActionItem.AboutEvidence).Select(a => a.Id).ToList();
        var entryTypes = await db.TimelineEntries.AsNoTracking().Where(e => entryIds.Contains(e.Id))
            .Select(e => new { e.Id, e.Type }).ToDictionaryAsync(e => e.Id, e => e.Type, ct);
        var entityNames = await db.CaseEntities.AsNoTracking().Where(e => entityIds.Contains(e.Id))
            .Select(e => new { e.Id, Name = e.Label ?? e.Value }).ToDictionaryAsync(e => e.Id, e => e.Name, ct);
        var evidenceNames = await db.Evidence.AsNoTracking().Where(e => evidenceIds.Contains(e.Id))
            .Select(e => new { e.Id, e.OriginalFileName }).ToDictionaryAsync(e => e.Id, e => e.OriginalFileName, ct);

        var titles = work.OpenCases.ToDictionary(c => c.Id, c => c.Title);
        var next = mine.Select(t =>
        {
            var info = taskInfo.GetValueOrDefault(t.Id);
            var (why, detail) = info is null ? (DeskWhy.None, (string?)null) : Why(info.Kind, info.RaisedFromBriefId, ParseAbout(info.AboutRef),
                entryTypes, entityNames, evidenceNames);
            return new DeskTask(t.Id, t.CaseId, t.CaseNumber, titles.GetValueOrDefault(t.CaseId) ?? "", t.Title, t.DueAtUtc,
                info?.Kind ?? TaskKind.General, why, detail);
        }).ToList();

        var cases = work.OpenCases.Select(c =>
        {
            var since = SinceFor(c.Id);
            var changes = audit.Where(a => a.CaseNumber == c.CaseNumber && a.AtUtc > since).ToList();
            var role = roles.FirstOrDefault(r => r.CaseId == c.Id)?.Role
                ?? (c.IncidentCommander == me ? CaseAssignmentRole.IncidentCommander : null);
            var phaseSince = phaseChanges.Where(s => s.CaseId == c.Id && s.To == c.Phase)
                .Select(s => s.EffectiveAtUtc ?? s.ChangedAtUtc).DefaultIfEmpty(c.CreatedAtUtc).Max();
            var mineHere = next.Where(t => t.CaseId == c.Id).OrderBy(t => t.DueAtUtc ?? DateTimeOffset.MaxValue).FirstOrDefault();
            return new DeskCase(c.Id, c.CaseNumber, c.Title, c.Classification, c.Severity, c.Phase, phaseSince, role, c.IsRestricted,
                mineHere?.Title, mineHere?.DueAtUtc, viewed.TryGetValue(c.Id, out var v) ? v : null,
                changes.Count, changes.Select(a => a.Actor).Distinct().ToList());
        }).ToList();

        // --- What needs me, by consequence ---
        var needs = new List<DeskNeed>();
        var clocks = new List<DeskClock>();
        var targets = _sla.Current;
        foreach (var c in work.OpenCases)
        {
            var d = await _deadlines.EvaluateAsync(c.Id, ct);
            if (d.Headline is { IsActive: true } h && d.ReportedAtUtc is null)
            {
                needs.Add(new DeskNeed(DeskNeedKind.Notify, c.Id, c.CaseNumber, $"Notify {h.JurisdictionLabel}", c.Title, h.DueAtUtc));
                clocks.Add(new DeskClock(c.Id, c.CaseNumber, h, null));
            }
            var (contain, resolve) = SlaPolicy.Breakdown(c.Severity, c.Phase, c.DetectedAtUtc, c.ContainedAtUtc, c.ResolvedAtUtc,
                targets, now, c.Classification);
            foreach (var s in new[] { contain, resolve }.Where(s => s.IsActive))
                clocks.Add(new DeskClock(c.Id, c.CaseNumber, null, s));
        }
        foreach (var t in next.Where(t => t.DueAtUtc is { } due && due < now).OrderBy(t => t.DueAtUtc))
            needs.Add(new DeskNeed(DeskNeedKind.Overdue, t.CaseId, t.CaseNumber, t.Title, t.CaseTitle, t.DueAtUtc, TaskId: t.Id));

        var notes = await db.Notes.AsNoTracking()
            .Where(n => ids.Contains(n.CaseId) && n.IsCurrent && n.CreatedBy != me && n.MentionsCsv != "")
            .Select(n => new { n.Id, n.CaseId, n.Body, n.MentionsCsv, n.CreatedBy, n.CreatedAtUtc })
            .ToListAsync(ct);
        foreach (var n in notes.Where(n => n.MentionsCsv.Split(',', StringSplitOptions.TrimEntries).Contains(me, StringComparer.OrdinalIgnoreCase)
                                           && n.CreatedAtUtc > SinceFor(n.CaseId))
                               .OrderByDescending(n => n.CreatedAtUtc))
        {
            var c = work.OpenCases.First(x => x.Id == n.CaseId);
            needs.Add(new DeskNeed(DeskNeedKind.Mention, c.Id, c.CaseNumber, Excerpt(n.Body), c.Title, n.CreatedAtUtc, n.CreatedBy, NoteId: n.Id));
        }
        foreach (var r in roles.Where(r => r.AssignedBy != me && r.AssignedAtUtc > SinceFor(r.CaseId)).OrderByDescending(r => r.AssignedAtUtc))
        {
            var c = work.OpenCases.First(x => x.Id == r.CaseId);
            needs.Add(new DeskNeed(DeskNeedKind.Assigned, c.Id, c.CaseNumber, c.Title, r.Role.ToString(), r.AssignedAtUtc, r.AssignedBy));
        }
        foreach (var t in next.Where(t => t.DueAtUtc is { } due && due >= now && due < now.AddDays(1)).OrderBy(t => t.DueAtUtc))
            needs.Add(new DeskNeed(DeskNeedKind.DueSoon, t.CaseId, t.CaseNumber, t.Title, t.CaseTitle, t.DueAtUtc, TaskId: t.Id));

        var changedBy = cases.SelectMany(c => c.ChangedBy).Distinct().ToList();
        return new Desk(needs, cases, next.OrderBy(t => t.DueAtUtc ?? DateTimeOffset.MaxValue).ThenBy(t => t.Title).ToList(),
            clocks.OrderBy(k => k.Notify is null).ThenBy(k => (k.Notify?.DueAtUtc ?? k.Sla?.DueAtUtc) ?? DateTimeOffset.MaxValue).ToList(),
            cases.Sum(c => c.ChangesSince), changedBy, work.RecentEscalations);
    }

    private static (string Kind, Guid Id)? ParseAbout(string? aboutRef)
    {
        if (string.IsNullOrEmpty(aboutRef)) return null;
        var i = aboutRef.IndexOf(':');
        return i > 0 && Guid.TryParse(aboutRef.AsSpan(i + 1), out var id) ? (aboutRef[..i], id) : null;
    }

    // The first reason that applies: the question it answers, the decision it carries out, what it's about, the
    // obligation it feeds, or the phase its kind belongs to (the same order as the case's Next).
    private static (DeskWhy, string?) Why(TaskKind kind, Guid? fromBrief, (string Kind, Guid Id)? about,
        IReadOnlyDictionary<Guid, TimelineEntryType> entryTypes, IReadOnlyDictionary<Guid, string> entities,
        IReadOnlyDictionary<Guid, string> evidence)
    {
        if (fromBrief is not null) return (DeskWhy.Question, null);
        if (about is { } a)
        {
            switch (a.Kind)
            {
                case ActionItem.AboutEntry:
                    return entryTypes.TryGetValue(a.Id, out var type) && type == TimelineEntryType.Decision
                        ? (DeskWhy.Decision, null) : (DeskWhy.Entry, null);
                case ActionItem.AboutEntity when entities.TryGetValue(a.Id, out var name):
                    return (DeskWhy.Entity, name);
                case ActionItem.AboutEvidence when evidence.TryGetValue(a.Id, out var file):
                    return (DeskWhy.Evidence, file);
                case ActionItem.AboutNote:
                    return (DeskWhy.Note, null);
            }
        }
        return kind switch
        {
            TaskKind.Notify => (DeskWhy.Notify, null),
            TaskKind.Investigate => (DeskWhy.Investigate, null),
            TaskKind.Contain => (DeskWhy.Contain, null),
            TaskKind.Eradicate => (DeskWhy.Eradicate, null),
            TaskKind.Recover => (DeskWhy.Recover, null),
            _ => (DeskWhy.None, null)
        };
    }

    private static string Excerpt(string body)
    {
        var t = body.Replace('\n', ' ').Trim();
        return t.Length <= 140 ? t : t[..137] + "…";
    }
}
