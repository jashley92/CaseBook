using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace IncidentManager.Application.Access;

/// <summary>
/// PROD-52: deletes access-log entries (who opened a case, downloaded evidence or a report, exported) last seen longer
/// ago than <c>Retention:AccessLogYears</c>, so the log stops growing without limit. Entries for a case under a legal
/// hold are kept whatever their age (they may be needed as evidence of who saw what), and so are entries whose case is
/// on hold through a pending release request. Each prune that deletes anything is recorded in the audit trail, so the
/// removal itself is evidenced. The log is outside the audit chain, so nothing else refers to its rows.
/// </summary>
public sealed class AccessLogRetention(IAppDbContextFactory factory, IAuditWriter audit, IClock clock,
    ILogger<AccessLogRetention>? logger = null)
{
    /// <summary>Rows deleted per statement, so a first prune of years of log doesn't hold one long transaction.</summary>
    internal const int Batch = 5_000;

    /// <summary>The audit trail's name for the log in the prune's entry.</summary>
    public const string AuditEntityType = "AccessLog";

    /// <summary>
    /// Deletes entries last seen before <paramref name="years"/> years ago, except those of cases under a legal hold, and
    /// returns how many. 0 years (or less) keeps everything.
    /// </summary>
    public async Task<int> PruneAsync(int years, CancellationToken ct = default)
    {
        if (years <= 0) return 0;
        var cutoff = clock.UtcNow.AddYears(-years);
        var deleted = 0;
        using (var db = factory.CreateDbContext())
        {
            while (true)
            {
                ct.ThrowIfCancellationRequested();
                var n = await db.CaseAccessEvents
                    .Where(e => e.LastSeenUtc < cutoff
                                && !db.Cases.IgnoreQueryFilters().Any(c => c.Id == e.CaseId && c.LegalHold))
                    .OrderBy(e => e.LastSeenUtc)
                    .Take(Batch)
                    .ExecuteDeleteAsync(ct);
                deleted += n;
                if (n < Batch) break;
            }
        }
        if (deleted == 0) return 0;

        await audit.RecordAsync(AuditAction.Delete, AuditEntityType, null, null,
            $"Access log retention: deleted {deleted:N0} entries last seen before {cutoff:yyyy-MM-dd} UTC " +
            $"({years} year{(years == 1 ? "" : "s")}). Entries for cases under a legal hold were kept.", ct);
        logger?.LogInformation("Access log retention deleted {Count} entries last seen before {Cutoff:u} ({Years} years).",
            deleted, cutoff, years);
        return deleted;
    }
}
