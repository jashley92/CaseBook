using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Common;
using IncidentManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Infrastructure.Persistence;

/// <summary>
/// BUG-70: gives the rows of tables that became hashable their row hash, at startup after the migrations. Only rows the
/// audit trail records are filled: the record check reads a hashed row the trail never recorded as added outside
/// CaseBook. BUG-153: the hash is saved as an audited change, so the chain holds it. A hash written only to the row could
/// be recomputed by whoever edited the row, and a row deleted outright left nothing to miss. v1.5.2 wrote the hashes
/// directly, so a row it filled whose latest entry holds no hash is recorded too, as long as it still matches its hash
/// (one that doesn't is left for the check to report). Once every row is recorded this does nothing.
/// </summary>
public static class RowHashBackfill
{
    private const int Batch = 500;

    public static async Task<int> RunAsync(AppDbContext db, IHashChainService hasher, CancellationToken ct = default) =>
        await FillAsync(db, db.ClassificationChanges, hasher, ct)
        + await FillAsync(db, db.StatusChanges, hasher, ct)
        + await FillAsync(db, db.MaterialityChanges, hasher, ct)
        + await FillAsync(db, db.SeverityChanges, hasher, ct)
        + await FillAsync(db, db.AssignmentChanges, hasher, ct)
        + await FillAsync(db, db.EntityVerdictChanges, hasher, ct)
        + await FillAsync(db, db.Assignments, hasher, ct)
        + await FillAsync(db, db.EvidenceCitations, hasher, ct)
        // REV-05: tokens issued before they were chained have the service's own Create (and Revoke) entries, without a
        // hash: each such token is recorded with its hash. A token row no entry names gets none, and the check flags it.
        + await FillAsync(db, db.ApiTokens, hasher, ct);

    private static async Task<int> FillAsync<T>(AppDbContext db, DbSet<T> set, IHashChainService hasher, CancellationToken ct)
        where T : Entity, IHashableEntity
    {
        var type = typeof(T).Name;
        // What the trail records of this type, and which of those its entries already give a hash for.
        var entries = await db.AuditLog.AsNoTracking()
            .Where(a => a.EntityType == type && a.EntityId != null)
            .Select(a => new { a.EntityId, a.Sequence, a.Action, Hashed = a.AfterJson != null && a.AfterJson.Contains("\"RowHash\"") })
            .ToListAsync(ct);
        if (entries.Count == 0) return 0;
        // A row whose latest entry is a removal is one put back outside CaseBook: the check reports it, so it isn't recorded.
        var needsHash = entries.GroupBy(e => e.EntityId!, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.MaxBy(e => e.Sequence)!)
            .Where(e => !e.Hashed && e.Action != Domain.Enums.AuditAction.Delete)
            .Select(e => e.EntityId!).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (needsHash.Count == 0) return 0;

        var ids = await set.AsNoTracking().Select(x => x.Id).ToListAsync(ct);
        var todo = ids.Where(id => needsHash.Contains(id.ToString())).ToList();

        var recorded = 0;
        foreach (var chunk in todo.Chunk(Batch))
        {
            db.ChangeTracker.Clear();
            var rows = await set.Where(x => chunk.Contains(x.Id)).ToListAsync(ct);
            foreach (var row in rows)
            {
                if (row.RowHash is { } stored && !hasher.RowHashMatches(row, stored)) continue;   // changed since: reported
                row.RowHash = hasher.ComputeRowHash(row);
                db.Entry(row).Property(x => x.RowHash).IsModified = true;   // an audited update that records the hash
                recorded++;
            }
            await db.SaveChangesAsync(ct);
        }
        db.ChangeTracker.Clear();
        return recorded;
    }
}
