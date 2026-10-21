using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Integrity;

/// <summary>
/// A case number given up by a removed case's purge can be taken again, but the audit trail (append-only) keeps the
/// entries written under it, and the trail is read by number (a case's Audit tab, the activity feed, the Desk's changes,
/// whether a number is taken). An entry written under a number at or before a purge released it belongs to the removed
/// case: never to the number's next holder. The purge's own entries are written under the stub's number, so the line is
/// exact.
/// </summary>
public static class ReleasedNumbers
{
    /// <summary>The entries whose number still means the case holding it now (or that no case gave up since).</summary>
    public static IQueryable<AuditLogEntry> HeldNow(this IQueryable<AuditLogEntry> entries, IAppDbContext db) =>
        entries.Where(a => !db.Cases.IgnoreQueryFilters()
            .Any(c => c.PurgedAtUtc != null && c.RemovedNumber == a.CaseNumber && a.AtUtc <= c.PurgedAtUtc));
}
