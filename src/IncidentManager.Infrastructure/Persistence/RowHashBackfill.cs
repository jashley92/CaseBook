using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Common;
using IncidentManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Infrastructure.Persistence;

/// <summary>
/// BUG-70: gives the rows of tables that became hashable their row hash, at startup after the migrations. Only rows the
/// audit trail records are filled: the record check reads a hashed row the trail never recorded as added outside
/// CaseBook. The hash is written directly, not as an audited change, so the upgrade adds nothing to the trail; it covers
/// each row as it stands, and catches a direct edit from then on. Rows that already have a hash are left alone, so once
/// every row is filled this does nothing.
/// </summary>
public static class RowHashBackfill
{
    public static async Task<int> RunAsync(AppDbContext db, IHashChainService hasher, CancellationToken ct = default) =>
        await FillAsync(db, db.ClassificationChanges, hasher, ct)
        + await FillAsync(db, db.StatusChanges, hasher, ct)
        + await FillAsync(db, db.MaterialityChanges, hasher, ct)
        + await FillAsync(db, db.SeverityChanges, hasher, ct)
        + await FillAsync(db, db.AssignmentChanges, hasher, ct)
        + await FillAsync(db, db.EntityVerdictChanges, hasher, ct)
        + await FillAsync(db, db.Assignments, hasher, ct)
        + await FillAsync(db, db.EvidenceCitations, hasher, ct);

    private static async Task<int> FillAsync<T>(AppDbContext db, DbSet<T> set, IHashChainService hasher, CancellationToken ct)
        where T : Entity, IHashableEntity
    {
        var rows = await set.AsNoTracking().Where(x => x.RowHash == null).ToListAsync(ct);
        if (rows.Count == 0) return 0;

        var type = typeof(T).Name;
        var recorded = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var chunk in rows.Select(r => r.Id.ToString()).Chunk(500))
            recorded.UnionWith(await db.AuditLog.AsNoTracking()
                .Where(a => a.EntityType == type && a.EntityId != null && chunk.Contains(a.EntityId))
                .Select(a => a.EntityId!).Distinct().ToListAsync(ct));

        var filled = 0;
        foreach (var row in rows.Where(r => recorded.Contains(r.Id.ToString())))
        {
            var hash = hasher.ComputeRowHash(row);
            filled += await set.Where(x => x.Id == row.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.RowHash, hash), ct);
        }
        return filled;
    }
}
