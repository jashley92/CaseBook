using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Compliance;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace IncidentManager.Application.Admin;

/// <summary>A removed case, for Administration's list: restorable until <see cref="RestorableUntilUtc"/>, or purged.</summary>
public sealed record RemovedCaseRow(Guid CaseId, string Number, string? Title, string RemovedBy, DateTimeOffset RemovedAtUtc,
    string Reason, DateTimeOffset? RestorableUntilUtc, DateTimeOffset? PurgedAtUtc, bool LegalHold)
{
    public bool Purged => PurgedAtUtc is not null;
}

/// <summary>
/// An administrator's removal of an archived case opened by mistake, or a bad import. Removed, it's left out of everything
/// (the context's filter): lists, search, lookup by number, IOC matching, related cases, counts and exports. For
/// <see cref="UndoDays"/> it can be restored; then (or at once, with <see cref="PurgeNowAsync"/>) its content is purged:
/// every row filed under it is deleted, its evidence files' bytes too (their records and custody stay), its reports' files,
/// and the case is left a stub that the audit trail and the chain of custody point to (who removed it, when, why, its
/// former number). The number is free from then: the next case takes it if it was the latest, and any case can be given it.
/// Administer only; each step is in the audit trail and the SIEM (5520 to 5522). Never on a case under a legal hold.
/// </summary>
public sealed class CaseRemovalService(
    IAppDbContextFactory factory,
    ICurrentUser user,
    IClock clock,
    ICaseContentPurger purger,
    IOptionsMonitor<CaseRetentionOptions>? options = null,
    IEvidenceStore? evidenceStore = null,
    IReportStore? reportStore = null,
    ISecurityEventSink? siem = null)
{
    /// <summary>The audit trail's reason on the purge's save.</summary>
    public const string PurgeReason = "Removed case purged";

    public const int MaxUndoDays = 365;

    /// <summary>How long a removed case can be restored (<c>Retention:RemovedCaseDays</c>, default 30); 0 purges it at the
    /// next nightly run.</summary>
    public int UndoDays => Math.Clamp(options?.CurrentValue.RemovedCaseDays ?? 30, 0, MaxUndoDays);

    public async Task<IReadOnlyList<RemovedCaseRow>> ListAsync(CancellationToken ct = default)
    {
        AdminActionPermissions.Require<CaseRemovalService>(user, siem);
        using var db = factory.CreateDbContext();
        var rows = await db.Cases.AsNoTracking().IgnoreQueryFilters().Where(c => c.RemovedAtUtc != null)
            .Select(c => new { c.Id, c.RemovedNumber, c.Title, c.RemovedBy, c.RemovedAtUtc, c.RemovedReason, c.PurgedAtUtc, c.LegalHold })
            .ToListAsync(ct);
        var days = UndoDays;
        return rows
            .Select(r => new RemovedCaseRow(r.Id, r.RemovedNumber ?? "", r.PurgedAtUtc is null ? r.Title : null, r.RemovedBy ?? "",
                r.RemovedAtUtc!.Value, r.RemovedReason ?? "", r.PurgedAtUtc is null ? Common.Instants.AddClamped(r.RemovedAtUtc.Value, TimeSpan.FromDays(days)) : null,
                r.PurgedAtUtc, r.LegalHold))
            .OrderBy(r => r.Purged).ThenByDescending(r => r.RemovedAtUtc).ToList();
    }

    /// <summary>Removes an archived case: the number typed to confirm, and a reason. It can be restored for
    /// <see cref="UndoDays"/>.</summary>
    public async Task RemoveAsync(Guid caseId, string typedNumber, string reason, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<CaseRemovalService>(user, siem);
        using var db = factory.CreateDbContext();
        var c = await db.Cases.IgnoreQueryFilters().Include(x => x.DataElements).FirstOrDefaultAsync(x => x.Id == caseId, ct)
                ?? throw new InvalidOperationException("That case wasn't found.");
        c.Remove(reason, typedNumber, user.UserId, clock.UtcNow);
        db.PendingChangeReason = c.RemovedReason;
        await db.SaveChangesAsync(ct);
        var subject = new CaseSubject(c.CaseNumber, c.DetectionCaseId, c.IsExercise);
        SecurityEventEmit.EmitSafely(siem, () => SecurityEvents.CaseRemoved(subject, user.UserId, user.UserPrincipalName));
    }

    /// <summary>Puts a removed case back, archived as it was, while its content hasn't been purged.</summary>
    public async Task RestoreAsync(Guid caseId, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<CaseRemovalService>(user, siem);
        using var db = factory.CreateDbContext();
        var c = await db.Cases.IgnoreQueryFilters().Include(x => x.DataElements).FirstOrDefaultAsync(x => x.Id == caseId, ct)
                ?? throw new InvalidOperationException("That case wasn't found.");
        // Its number may have been given to another case meanwhile only if it was purged, which RestoreRemoved refuses.
        c.RestoreRemoved(user.UserId, clock.UtcNow);
        db.PendingChangeReason = "Removal undone";
        await db.SaveChangesAsync(ct);
        var subject = new CaseSubject(c.CaseNumber, c.DetectionCaseId, c.IsExercise);
        SecurityEventEmit.EmitSafely(siem, () => SecurityEvents.CaseRemovalUndone(subject, user.UserId, user.UserPrincipalName));
    }

    /// <summary>
    /// Purges a removed case now, without waiting out <see cref="UndoDays"/> (to take its number back at once, say): its
    /// former number typed to confirm. Returns what couldn't be deleted from the stores (null when everything was).
    /// </summary>
    public async Task<string?> PurgeNowAsync(Guid caseId, string typedNumber, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<CaseRemovalService>(user, siem);
        using (var db = factory.CreateDbContext())
        {
            var c = await db.Cases.AsNoTracking().IgnoreQueryFilters().FirstOrDefaultAsync(x => x.Id == caseId, ct)
                    ?? throw new InvalidOperationException("That case wasn't found.");
            if (!c.IsRemoved) throw new InvalidOperationException("Only a removed case can be purged.");
            if (!string.Equals((typedNumber ?? "").Trim(), c.RemovedNumber, StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException($"Type the case number ({c.RemovedNumber}) to confirm.");
        }
        return await PurgeCoreAsync(caseId, user.UserId, user.UserPrincipalName, ct);
    }

    /// <summary>The nightly run: purges every case removed more than <see cref="UndoDays"/> ago. Returns how many were
    /// purged. A case put under a legal hold meanwhile is left.</summary>
    public async Task<int> PurgeDueAsync(CancellationToken ct = default)
    {
        var cutoff = clock.UtcNow.AddDays(-UndoDays);
        List<Guid> due;
        using (var db = factory.CreateDbContext())
            due = await db.Cases.AsNoTracking().IgnoreQueryFilters()
                .Where(c => c.RemovedAtUtc != null && c.PurgedAtUtc == null && !c.LegalHold && c.RemovedAtUtc <= cutoff)
                .Select(c => c.Id).ToListAsync(ct);
        foreach (var id in due) await PurgeCoreAsync(id, "system", null, ct);
        return due.Count;
    }

    private async Task<string?> PurgeCoreAsync(Guid caseId, string actor, string? actorUpn, CancellationToken ct)
    {
        var now = clock.UtcNow;
        List<string> evidencePaths, reportPaths;
        CaseSubject subject;
        using (var db = factory.CreateDbContext())
        {
            var c = await db.Cases.IgnoreQueryFilters().Include(x => x.DataElements).FirstOrDefaultAsync(x => x.Id == caseId, ct)
                    ?? throw new InvalidOperationException("That case wasn't found.");
            if (!c.IsRemoved) throw new InvalidOperationException("Only a removed case can be purged.");
            if (c.LegalHold) throw new InvalidOperationException("This case is under legal hold, so nothing on it can be purged.");
            if (c.IsPurged) return null;   // purged already (a second click, or the nightly run got there first)
            subject = new CaseSubject(c.RemovedNumber ?? c.CaseNumber, c.DetectionCaseId, c.IsExercise);
            // Every file's bytes go; its record, SHA-256 and custody stay (withdrawn, then purged, each a custody event).
            var why = Common.TextFit.Cap($"Case removed: {c.RemovedReason}", Domain.Entities.Evidence.MaxWithdrawnReasonLength, "");
            var files = await db.Evidence.IgnoreQueryFilters().Include(e => e.CustodyEvents)
                .Where(e => e.CaseId == caseId && e.PurgedAtUtc == null).ToListAsync(ct);
            foreach (var ev in files)
            {
                if (!ev.IsWithdrawn) ev.Withdraw(why, actor, now);
                ev.Purge(why, actor, now, reinstatableUntil: null, legalHold: false);
            }
            evidencePaths = files.Select(f => f.StoragePath).ToList();
            reportPaths = await db.Reports.IgnoreQueryFilters().Where(r => r.CaseId == caseId).Select(r => r.StoragePath).ToListAsync(ct);
            // Everything filed under it, deleted in the same save as the stub: one transaction, each deletion in the trail.
            await purger.RemoveContentAsync(db, caseId, ct);
            c.MarkPurged(actor, now);
            db.PendingChangeReason = PurgeReason;
            await db.SaveChangesAsync(ct);
        }

        var problems = new List<string>();
        foreach (var path in evidencePaths)
            await DeleteFileAsync(() => evidenceStore?.PurgeAsync(path, ct) ?? Task.CompletedTask, "evidence", path, problems);
        foreach (var path in reportPaths)
            await DeleteFileAsync(() => reportStore?.DeleteAsync(path, ct) ?? Task.CompletedTask, "report", path, problems);
        SecurityEventEmit.EmitSafely(siem, () => SecurityEvents.CasePurged(subject, actor, actorUpn));
        return problems.Count == 0 ? null
            : $"The case is purged, but {problems.Count} file{(problems.Count == 1 ? "" : "s")} couldn't be deleted from the store: " +
              string.Join("; ", problems.Take(5)) + ". Delete them by hand.";
    }

    private static async Task DeleteFileAsync(Func<Task> delete, string what, string path, List<string> problems)
    {
        try { await delete(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            problems.Add($"{what} {path} ({ex.Message})");
        }
    }
}
