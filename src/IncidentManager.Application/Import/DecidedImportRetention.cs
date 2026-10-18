using System.Globalization;
using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace IncidentManager.Application.Import;

/// <summary>
/// CAP-31: clears the stored documents of imports decided longer ago than <c>Retention:DecidedImportDays</c>: the
/// submitted JSON (<c>RawJson</c>, up to 5 MiB each) and a part-way apply's saved preview (<c>ResumeJson</c>), which
/// nothing reads once the import is applied or rejected. The decision row stays: who sent it and when, its summary, the
/// document's SHA-256, who decided, when, why, and the case it went into, so the queue's history and the API's status
/// answer (CAP-13) are unchanged. Only decided rows are touched: rejected ones, and applied ones with their case recorded.
/// One still waiting, or claimed and being applied (applied with no case yet, which WF-18 can put back in the queue), keeps
/// its document. Each run that clears anything is recorded in the audit trail, as PROD-52's access-log prune is. The
/// staging rows are outside the audit chain, so nothing else refers to their text.
/// </summary>
public sealed class DecidedImportRetention(IAppDbContextFactory factory, IAuditWriter audit, IClock clock,
    ILogger<DecidedImportRetention>? logger = null)
{
    /// <summary>Rows cleared per statement, so a first run over years of imports doesn't hold one long transaction.</summary>
    internal const int Batch = 500;

    /// <summary>The audit trail's name for the import queue in the run's entry.</summary>
    public const string AuditEntityType = "PendingImport";

    /// <summary>The longest the setting allows (ten years).</summary>
    public const int MaxDays = 3650;

    /// <summary>
    /// Clears the documents of imports decided before <paramref name="days"/> days ago and returns how many. 0 days (or
    /// less) keeps everything.
    /// </summary>
    public async Task<int> ClearAsync(int days, CancellationToken ct = default)
    {
        if (days <= 0) return 0;
        days = Math.Min(days, MaxDays);
        var cutoff = clock.UtcNow.AddDays(-days);
        var cleared = 0;
        using (var db = factory.CreateDbContext())
        {
            while (true)
            {
                ct.ThrowIfCancellationRequested();
                var n = await db.PendingImports
                    .Where(p => p.DecidedAtUtc != null && p.DecidedAtUtc < cutoff
                                && (p.Status == PendingImportStatus.Rejected
                                    || (p.Status == PendingImportStatus.Applied && p.ResolvedCaseId != null))
                                && (p.RawJson != "" || p.ResumeJson != null))
                    .OrderBy(p => p.DecidedAtUtc)
                    .Take(Batch)
                    .ExecuteUpdateAsync(s => s
                        .SetProperty(p => p.RawJson, "")
                        .SetProperty(p => p.ResumeJson, (string?)null), ct);
                cleared += n;
                if (n < Batch) break;
            }
        }
        if (cleared == 0) return 0;

        // BUG-531: saved text, so the invariant calendar and digits.
        await audit.RecordAsync(AuditAction.Update, AuditEntityType, null, null, string.Create(CultureInfo.InvariantCulture,
            $"Import retention: cleared the stored documents of {cleared:N0} decided imports (decided before {cutoff:yyyy-MM-dd} UTC, " +
            $"{days} day{(days == 1 ? "" : "s")}). Who sent each, who decided and the case it went into are kept."), ct);
        logger?.LogInformation("Import retention cleared the documents of {Count} imports decided before {Cutoff:u} ({Days} days).",
            cleared, cutoff, days);
        return cleared;
    }
}
