using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Common;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
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
public static partial class RowHashBackfill
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
        + await FillAsync(db, db.ApiTokens, hasher, ct, TokenMatchesTrail);

    /// <summary>
    /// WF-43: a token whose row disagrees with what its trail says is left unhashed, so the record check flags it, rather
    /// than being signed off as clean: a revoked token switched back on in the database, or one whose roles or expiry
    /// differ from its Create entry (owner's decision). Entries older than these summaries say nothing checkable and pass.
    /// A swapped secret (TokenHash) can't be told either way: the trail never recorded it.
    /// </summary>
    internal static bool TokenMatchesTrail(ApiToken row, IReadOnlyList<(AuditAction Action, string? Summary)> trail)
    {
        if (trail.Count > 0 && trail[^1] is { Summary: { } last } && last.StartsWith("Revoked ", StringComparison.Ordinal) && row.RevokedAtUtc is null)
            return false;
        var created = trail.FirstOrDefault(e => e.Action == AuditAction.Create && e.Summary is not null).Summary;
        if (created is null) return true;
        var m = CreatedSummary().Match(created);
        if (!m.Success) return true;
        var roles = m.Groups["roles"].Value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (!roles.SetEquals(row.GetRoles())) return false;
        return !DateTimeOffset.TryParse(m.Groups["expires"].Value, System.Globalization.CultureInfo.InvariantCulture,
                   System.Globalization.DateTimeStyles.AssumeUniversal, out var expires)
               || Math.Abs((expires - row.ExpiresAtUtc).TotalSeconds) < 1;
    }

    [System.Text.RegularExpressions.GeneratedRegex(@"\(roles: (?<roles>[^;]*); expires (?<expires>[^)]+)\)")]
    private static partial System.Text.RegularExpressions.Regex CreatedSummary();

    private static async Task<int> FillAsync<T>(AppDbContext db, DbSet<T> set, IHashChainService hasher, CancellationToken ct,
        Func<T, IReadOnlyList<(AuditAction Action, string? Summary)>, bool>? matchesTrail = null)
        where T : Entity, IHashableEntity
    {
        var type = typeof(T).Name;
        // What the trail records of this type, and which of those its entries already give a hash for.
        var entries = await db.AuditLog.AsNoTracking()
            .Where(a => a.EntityType == type && a.EntityId != null)
            .Select(a => new { a.EntityId, a.Sequence, a.Action, a.Summary, Hashed = a.AfterJson != null && a.AfterJson.Contains("\"RowHash\"") })
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
                if (matchesTrail is not null && !matchesTrail(row, entries.Where(e => string.Equals(e.EntityId, row.Id.ToString(), StringComparison.OrdinalIgnoreCase))
                        .OrderBy(e => e.Sequence).Select(e => (e.Action, e.Summary)).ToList()))
                    continue;   // WF-43: disagrees with its trail: left for the check to report
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
