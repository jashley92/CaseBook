using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Import;

/// <summary>CAP-01: how many submissions wait for review (at most the cap asked for) and when the oldest arrived.</summary>
public sealed record PendingImportCount(int Count, bool More, DateTimeOffset? OldestUtc)
{
    public static readonly PendingImportCount None = new(0, false, null);
}

/// <summary>
/// CAP-01: raised when the import queue changes (a submission arrives, or one is claimed, applied, rejected or put back),
/// so the open pages' Import badges count again. One per process, as CaseBook runs as one instance.
/// </summary>
public sealed class PendingImportSignal
{
    public event Action? Changed;

    /// <summary>Tells each listener; one that fails (a page closing as it's told) never fails the queue change.</summary>
    public void Raise()
    {
        if (Changed is not { } changed) return;
        foreach (var listener in changed.GetInvocationList().Cast<Action>())
        {
            try { listener(); }
            catch (Exception ex) when (ex is ObjectDisposedException or InvalidOperationException)
            {
                // That page is going; the others still count again.
            }
        }
    }
}

/// <summary>
/// CAP-01: the import review queue as reviewers are told of it: the Desk's "needs you" item, the Import badge in the
/// sidebar and the line in the work digest. Read only. Every count goes through <see cref="Visible"/>, the scope the
/// queue itself uses, so a submission into a restricted case is counted only for that case's audience.
/// </summary>
public sealed class PendingImportQueue(IAppDbContextFactory factory, ICurrentUser user)
{
    /// <summary>The most the badge and the Desk count; more shows as "99+".</summary>
    public const int CountCap = 99;

    /// <summary>How long a count may take before the badge gives up and shows nothing (it renders on every page).</summary>
    public static readonly TimeSpan CountTimeout = TimeSpan.FromSeconds(3);

    /// <summary>
    /// The queued submissions <paramref name="user"/> may see: need-to-know scoped on the target case, because the queue
    /// shows the submitter, origin and a summary naming the target's case number. A submission into an existing case the
    /// caller can't see (<see cref="CaseQueryExtensions.ForUser"/>) is left out; one with no target, or whose target no
    /// longer exists (it previews as a new case), is visible to every reviewer.
    /// </summary>
    public static IQueryable<PendingImport> Visible(IAppDbContext db, ICurrentUser user)
    {
        var visible = db.Cases.ForUser(user).Select(c => c.Id);
        return db.PendingImports.Where(p => p.TargetCaseId == null
            || visible.Contains(p.TargetCaseId.Value)
            || !db.Cases.Any(c => c.Id == p.TargetCaseId));
    }

    /// <summary>Whether the current user reviews imports: whoever can confirm one on the Import page (EditCases).</summary>
    public bool Reviews => user.Has(Permission.EditCases);

    /// <summary>
    /// The submissions waiting for the current user's review, counted up to <see cref="CountCap"/>, with the oldest's
    /// arrival. Nothing for someone who doesn't review imports. Null when the count took longer than
    /// <see cref="CountTimeout"/>: the badge then shows nothing rather than hold up the page.
    /// </summary>
    public async Task<PendingImportCount?> WaitingAsync(CancellationToken ct = default)
    {
        if (!Reviews) return PendingImportCount.None;
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(ct);
        limit.CancelAfter(CountTimeout);
        try
        {
            using var db = factory.CreateDbContext();
            var times = await Visible(db, user).AsNoTracking()
                .Where(p => p.Status == PendingImportStatus.Pending)
                .OrderBy(p => p.SubmittedAtUtc)
                .Select(p => p.SubmittedAtUtc)
                .Take(CountCap + 1)
                .ToListAsync(limit.Token);
            return times.Count == 0 ? PendingImportCount.None
                : new PendingImportCount(Math.Min(times.Count, CountCap), times.Count > CountCap, times[0]);
        }
        // CAP-01 review: SQL Server reports a query cancelled by the time limit as a SqlException ("Operation cancelled by
        // user"), not an OperationCanceledException; either is the count running out of time.
        catch (Exception ex) when (ex is OperationCanceledException or System.Data.Common.DbException
                                   && limit.IsCancellationRequested && !ct.IsCancellationRequested)
        {
            return null;
        }
    }

    /// <summary>
    /// CAP-01: for <paramref name="userId"/>'s work digest, the submissions waiting longer than <paramref name="olderThan"/>
    /// that they would see in the queue (up to <see cref="CountCap"/>): none unless they review imports, and one into a
    /// restricted case only when they could see that case (<see cref="Notifications.ReminderAudience"/>).
    /// </summary>
    /// <remarks>Static, with the factory passed in: the digest runs in a background scope, with no person signed in.</remarks>
    public static async Task<PendingImportCount> WaitingForAsync(IAppDbContextFactory factory, string userId, TimeSpan olderThan,
        DateTimeOffset nowUtc, IUserDirectory? users, IRoleDirectory? roles, Notifications.ReminderAudience audience,
        CancellationToken ct = default)
    {
        if (olderThan <= TimeSpan.Zero || users?.Resolve(userId) is not { } who || roles is null) return PendingImportCount.None;
        var held = roles.PermissionsForRoles(Domain.Common.RoleList.Split(who.RolesCsv, roles.IsRole));
        if (!held.Contains(Permission.EditCases)) return PendingImportCount.None;

        using var db = factory.CreateDbContext();
        var cutoff = nowUtc - olderThan;
        var waiting = await db.PendingImports.AsNoTracking()
            .Where(p => p.Status == PendingImportStatus.Pending && p.SubmittedAtUtc < cutoff)
            .OrderBy(p => p.SubmittedAtUtc)
            .Select(p => new { p.TargetCaseId, p.SubmittedAtUtc })
            .Take(500)
            .ToListAsync(ct);
        if (waiting.Count == 0) return PendingImportCount.None;
        var targetIds = waiting.Where(w => w.TargetCaseId != null).Select(w => w.TargetCaseId!.Value).Distinct().ToList();
        var targets = await db.Cases.AsNoTracking().Where(c => targetIds.Contains(c.Id))
            .Select(c => new { c.Id, c.IsRestricted, c.IncidentCommander, Team = c.Assignments.Select(a => a.UserId).ToList() })
            .ToDictionaryAsync(c => c.Id, ct);

        var seen = new List<DateTimeOffset>();
        foreach (var w in waiting)
        {
            // As Visible: no target, or one that's gone, is every reviewer's; a restricted one is its audience's.
            if (w.TargetCaseId is { } t && targets.TryGetValue(t, out var c) && c.IsRestricted
                && !await audience.CanSeeAsync(userId, true, c.IncidentCommander, c.Team, ct))
                continue;
            seen.Add(w.SubmittedAtUtc);
            if (seen.Count > CountCap) break;
        }
        return seen.Count == 0 ? PendingImportCount.None
            : new PendingImportCount(Math.Min(seen.Count, CountCap), seen.Count > CountCap, seen[0]);
    }
}
