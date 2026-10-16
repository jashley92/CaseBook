using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Integrity;
using IncidentManager.Domain.Common;
using IncidentManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Infrastructure.Persistence;

/// <summary>
/// C18: the start-up upgrade that makes the record check strict. Until now a record with no hash and no trail entry was
/// taken for one from before row hashes in most tables (BUG-620), a record last updated before v1.5.1 had no hash in its
/// trail to compare with (BUG-629), a migration's cleared hashes excused a whole table (BUG-621), and values format 4
/// brought in weren't in any hash. Once, at start-up, every record in every hashed table is looked at:
/// <list type="bullet">
/// <item>one with no hash, or whose latest entry records none, gets its hash recorded (an audited update, CaseBook's
/// upkeep) when it agrees with what its trail last recorded (<see cref="TrailSnapshot.Agrees"/>), its child rows (a
/// case's data elements, a step's tactics) are in the trail too, or, with no trail, when it holds what a released
/// migration wrote (<see cref="MigrationSeededRows"/>);</item>
/// <item>one whose hash doesn't cover what it holds (a value format 4 brought in) is re-hashed in format 4 the same way,
/// only when it agrees with its trail;</item>
/// <item>anything else (it disagrees with its trail, it's in none, its hash was cleared or no longer matches) is left as
/// it is and named in the result, and the check reports it.</item>
/// </list>
/// Then it writes the marker (<see cref="RowIntegrityVerifier.UpgradeMarkerKey"/>) that makes the check strict. If any
/// step fails, nothing is marked and the check stays as it was; what was recorded stays recorded (each is an ordinary
/// audited change), and the next start carries on. BUG-641: a row whose hash won't save is named in the result and the
/// others are still recorded, but nothing is marked while there's one. Once marked it does nothing.
/// </summary>
public static class RowHashUpgrade
{
    private const int Batch = 200;

    /// <summary>What the upgrade did: how many records it recorded, the ones it left (each "Type id: why"), and whether it
    /// marked the check strict (false when it had already).</summary>
    public sealed record Result(int Recorded, IReadOnlyList<string> Left, bool Marked);

    public static async Task<Result> RunAsync(AppDbContext db, IHashChainService hasher, IClock clock, CancellationToken ct = default)
    {
        if (await RowIntegrityVerifier.UpgradedAsync(db, ct)) return new Result(0, [], false);

        // Each record's latest entry, as the check reads them.
        var records = new RowIntegrityVerifier.ChainRecords();
        await foreach (var e in db.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).AsAsyncEnumerable().WithCancellation(ct))
            records.Add(e);
        var gates = await db.StageGates.AsNoTracking().ToDictionaryAsync(g => g.Id, g => (int)g.Trigger, ct);
        var lookup = new MigrationSeededRows.Lookup(
            async (type, id) => (await TrailSnapshot.ForAsync(db, type, [id.ToString()], ct)).GetValueOrDefault(id.ToString()), gates);

        var recorded = 0;
        var left = new List<string>();
        var unsaved = new List<string>();
        foreach (var table in RowIntegrityVerifier.Tables(db))
        {
            var type = table.ElementType.Name;
            var tableName = db.Model.FindEntityType(table.ElementType)?.GetTableName() ?? type;
            var todo = new List<(IHashableEntity Row, Need Need)>();
            await foreach (var row in table.AsAsyncEnumerable().WithCancellation(ct))
                if (Assess(row, records, hasher) is { } need) todo.Add((row, need));
            if (todo.Count == 0) continue;

            var trails = await TrailSnapshot.ForAsync(db, type, todo.Select(t => ((Entity)t.Row).Id.ToString()).ToList(), ct);
            var ok = new List<Guid>();
            foreach (var (row, need) in todo)
            {
                var id = ((Entity)row).Id;
                var trail = trails.GetValueOrDefault(id.ToString());
                var why = need switch
                {
                    Need.Seeded or Need.ClearedByMigration =>
                        await MigrationSeededRows.HoldsWhatAMigrationWroteAsync(tableName, row, need == Need.Seeded ? null : trail, lookup)
                            ? null
                            : need == Need.Seeded ? "in no audit entry, and not as a released migration wrote it"
                            : "its hash was cleared, and it isn't as the migration that cleared it wrote it",
                    _ when trail is null || !trail.Agrees(row) => "it doesn't agree with its audit trail",
                    _ => null,
                };
                why ??= ChildOutsideTheTrail(row, records);
                if (why is null) ok.Add(id);
                else left.Add($"{type} {id}: {why}");
            }
            recorded += await RecordAsync(db, table, type, ok, unsaved, ct);
        }

        // BUG-641: a row that agrees with its trail but whose hash couldn't be saved would be reported as changed outside
        // CaseBook once the check is strict, and the upgrade wouldn't run again to record it. So nothing is marked while
        // there's one: what was recorded stays recorded, and the next start tries the rest.
        left.AddRange(unsaved);
        if (unsaved.Count > 0) return new Result(recorded, left, false);

        db.ChangeTracker.Clear();
        db.AppSettings.Add(new AppSetting
        {
            Key = RowIntegrityVerifier.UpgradeMarkerKey, Value = RowIntegrityVerifier.UpgradeMarkerValue,
            UpdatedAtUtc = clock.UtcNow, UpdatedBy = "system",
        });
        await db.SaveChangesAsync(ct);
        return new Result(recorded, left, true);
    }

    private enum Need { Seeded, ClearedByMigration, NotRecorded, NotCovered }

    // What a record needs before the check can be strict, or null when it's ready (or something the check reports, which
    // the upgrade leaves alone).
    private static Need? Assess(IHashableEntity row, RowIntegrityVerifier.ChainRecords records, IHashChainService hasher)
    {
        var known = records.TryGet((row.GetType().Name, ((Entity)row).Id.ToString()), out var last);
        if (known && last.Deleted) return null;   // removed, then put back outside CaseBook
        if (row.RowHash is not { Length: > 0 } stored)
            return !known ? Need.Seeded : last.Hash is null ? Need.NotRecorded : Need.ClearedByMigration;
        if (!known || !hasher.RowHashMatches(row, stored)) return null;   // added or changed outside CaseBook
        if (last.Hash is null) return Need.NotRecorded;   // BUG-629: last updated before v1.5.1
        if (!string.Equals(last.Hash, stored, StringComparison.OrdinalIgnoreCase)) return null;   // rewritten outside CaseBook
        return Canonical.Covers(Canonical.FormatOf(stored), row.BuildCanonicalContent) ? null : Need.NotCovered;
    }

    /// <summary>The child rows a record's hash covers that aren't hashed on their own (a case's data elements, a step's tactics).</summary>
    internal static IEnumerable<Entity> HashedChildren(IHashableEntity row) => row switch
    {
        Case c => c.DataElements,
        TimelineEntry t => t.Tactics,
        _ => [],
    };

    // A case's data elements and a step's tactics are in its hash, not hashed on their own: each must be one the trail
    // records (CaseBook audits every one), or a row planted under the case would be signed off with it (BUG-639: the
    // upkeep guard asks the same).
    internal static string? ChildOutsideTheTrail(IHashableEntity row, RowIntegrityVerifier.ChainRecords records)
    {
        foreach (var child in HashedChildren(row))
            if (!records.TryGet((child.GetType().Name, child.Id.ToString()), out var last) || last.Deleted)
                return $"its {child.GetType().Name} {child.Id} is in no audit entry";
        return null;
    }

    // Records each row's hash as an audited update (CaseBook's upkeep): the interceptor computes it in format 4 and the
    // entry carries it. The hash is marked changed, so the entry is written even when it was already the format-4 one.
    // BUG-641: a batch whose save fails is saved one row at a time, so one row that won't save doesn't stop every other
    // being recorded; each that still fails is named in <paramref name="unsaved"/>.
    private static async Task<int> RecordAsync(AppDbContext db, IQueryable<IHashableEntity> table, string type, List<Guid> ids,
        List<string> unsaved, CancellationToken ct)
    {
        var done = 0;
        foreach (var chunk in ids.Chunk(Batch))
        {
            try { done += await SaveAsync(db, table, chunk, ct); }
            catch (Exception e) when (IsRowFailure(e))
            {
                foreach (var id in chunk)
                {
                    try { done += await SaveAsync(db, table, [id], ct); }
                    catch (Exception one) when (IsRowFailure(one))
                    {
                        unsaved.Add($"{type} {id}: its hash couldn't be saved ({one.Message}); it's tried again at the next start, "
                                    + "and the check isn't made strict until it is");
                    }
                }
            }
        }
        db.ChangeTracker.Clear();
        return done;
    }

    // What a save of some rows can fail with because of a row (as the start-up back-fills catch); cancellation isn't one.
    private static bool IsRowFailure(Exception e) =>
        e is DbUpdateException or ConcurrentEditException or ArgumentException or InvalidOperationException;

    private static async Task<int> SaveAsync(AppDbContext db, IQueryable<IHashableEntity> table, Guid[] ids, CancellationToken ct)
    {
        db.ChangeTracker.Clear();
        var rows = await table.AsTracking().Where(r => ids.Contains(((Entity)(object)r).Id)).ToListAsync(ct);
        foreach (var row in rows) db.Entry(row).Property(nameof(IHashableEntity.RowHash)).IsModified = true;
        db.PendingUpkeep = true;
        try { await db.SaveChangesAsync(ct); }
        finally { db.PendingUpkeep = false; }
        return rows.Count;
    }
}
