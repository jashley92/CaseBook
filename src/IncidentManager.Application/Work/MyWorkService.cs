using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Work;

/// <summary>An open after-action task the current user is responsible for (overdue or upcoming).</summary>
public sealed record MyTask(
    Guid CaseId, string CaseNumber, string Title, string? Owner,
    DateTimeOffset? DueAtUtc, bool OwnedByMe);

/// <summary>A recent upward classification transition (escalation) on a case the user can see.</summary>
public sealed record Escalation(
    Guid CaseId, string CaseNumber, string Title,
    Classification From, Classification To, string ChangedBy, DateTimeOffset ChangedAtUtc);

/// <summary>Everything the analyst "My Work" landing needs, computed for the current user.</summary>
public sealed record MyWork(
    IReadOnlyList<CaseListItem> OpenCases,
    IReadOnlyList<MyTask> Tasks,
    IReadOnlyList<Escalation> RecentEscalations);

/// <summary>
/// The analyst-facing daily driver (U-25): a personal view over the caller's own work — open cases,
/// overdue after-action tasks, recent escalations, and other cases that share an indicator they added.
/// Every read is need-to-know scoped via <see cref="CaseQueryExtensions.ForUser"/>; complements, not
/// replaces, the leadership dashboard.
/// </summary>
public sealed class MyWorkService
{
    /// <summary>How far back "recently escalated" looks.</summary>
    public const int EscalationWindowDays = 14;

    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;

    public MyWorkService(IAppDbContextFactory factory, ICurrentUser user, IClock clock)
    {
        _factory = factory;
        _user = user;
        _clock = clock;
    }

    public async Task<MyWork> GetAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var uid = _user.UserId;
        var now = _clock.UtcNow;
        var visible = db.Cases.AsNoTracking().ForUser(_user);

        // Cases I own or am assigned to that are still open. My daily worklist.
        var openCases = await visible
            .Where(c => c.Phase != CasePhase.Closed && !c.IsArchived)
            .Where(c => c.IncidentCommander == uid || c.Assignments.Any(a => a.UserId == uid))
            .OrderByDescending(c => c.Severity)
            .ThenByDescending(c => c.CreatedAtUtc)
            .Select(c => new CaseListItem(
                c.Id, c.CaseNumber, c.Title, c.Classification, c.Phase, c.Severity, c.Origin,
                c.IsRestricted, c.LegalReferral.IsReferred, c.CreatedAtUtc, c.IncidentCommander,
                c.DetectedAtUtc, c.ContainedAtUtc, c.ResolvedAtUtc))
            .ToListAsync(ct);

        // My open after-action tasks on cases I can see — overdue *and* upcoming, so this is a
        // worklist, not just a late list. "Mine" = a task I own, or one on a case I own/am assigned to.
        var taskRows = await (
            from a in db.ActionItems.AsNoTracking()
            where a.Status != ActionItemStatus.Done && a.Status != ActionItemStatus.Cancelled
            join c in visible on a.CaseId equals c.Id
            select new
            {
                a.CaseId,
                c.CaseNumber,
                a.Title,
                a.Owner,
                a.DueAtUtc,
                IsMyCase = c.IncidentCommander == uid || c.Assignments.Any(x => x.UserId == uid)
            }).ToListAsync(ct);

        var tasks = taskRows
            .Select(t => new { Row = t, Owned = OwnedByMe(t.Owner) })
            .Where(t => t.Owned || t.Row.IsMyCase)
            // Soonest due first; undated tasks sink to the bottom. (Sorted in memory to keep the
            // DateTimeOffset comparison off SQLite, which doesn't translate it.)
            .OrderBy(t => t.Row.DueAtUtc ?? DateTimeOffset.MaxValue)
            .ThenBy(t => t.Row.Title)
            .Select(t => new MyTask(t.Row.CaseId, t.Row.CaseNumber, t.Row.Title, t.Row.Owner, t.Row.DueAtUtc, t.Owned))
            .ToList();

        // Upward classification transitions across my visible set in the recent window (situational
        // awareness for the shift). From/To comparison and the date filter run in memory.
        var since = now.AddDays(-EscalationWindowDays);
        var escRows = await (
            from cc in db.ClassificationChanges.AsNoTracking()
            where cc.From != null
            join c in visible on cc.CaseId equals c.Id
            select new { c.Id, c.CaseNumber, c.Title, cc.From, cc.To, cc.ChangedBy, cc.ChangedAtUtc })
            .ToListAsync(ct);

        var recentEscalations = escRows
            .Where(e => e.ChangedAtUtc >= since && e.To > e.From!.Value)
            .OrderByDescending(e => e.ChangedAtUtc)
            .Take(10)
            .Select(e => new Escalation(e.Id, e.CaseNumber, e.Title, e.From!.Value, e.To, e.ChangedBy, e.ChangedAtUtc))
            .ToList();

        return new MyWork(openCases, tasks, recentEscalations);
    }

    /// <summary>
    /// An action item's <c>Owner</c> is free text (AD id, UPN, display name, or email). Match it against
    /// any of the current user's identifiers so "my tasks" resolves regardless of which was entered.
    /// </summary>
    private bool OwnedByMe(string? owner)
    {
        if (string.IsNullOrWhiteSpace(owner)) return false;
        var o = owner.Trim();
        return Same(o, _user.UserId) || Same(o, _user.UserPrincipalName)
            || Same(o, _user.DisplayName) || Same(o, _user.Email);

        static bool Same(string a, string? b) => !string.IsNullOrWhiteSpace(b)
            && string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
    }
}
