using System.Text.Json;
using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Common;
using IncidentManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Integrity;

/// <summary>
/// BUG-06: checks the records themselves, not only the audit chain. Every hashable row carries a hash of its content,
/// and every audited write records that hash in the chain. A row passes when its content still produces its stored
/// hash (catches an edit made directly in the database) and that hash is the one the chain last recorded for it
/// (catches an edit whose author also recomputed the row hash, since the chain is linked and can be keyed and sealed).
/// Rows from before row hashes existed, and rows whose chain entries predate them, are skipped rather than flagged.
/// BUG-64/65: a row whose hash was cleared while the chain holds one, a row the chain last recorded as deleted, a hashed
/// row the chain never recorded, and a row the chain recorded that is no longer there are all flagged too.
/// </summary>
public static class RowIntegrityVerifier
{
    /// <summary>The first record that fails, or null when every checked record matches.</summary>
    public sealed record RowMismatch(string EntityType, Guid Id, long? LastSequence, string Detail);

    /// <summary>The hashable tables checked, each loaded with what its hash covers (a case's data elements, a step's tactics).</summary>
    public static IEnumerable<IQueryable<IHashableEntity>> Tables(IAppDbContext db) =>
    [
        db.Cases.AsNoTracking().Include(c => c.DataElements),
        db.TimelineEntries.AsNoTracking().Include(t => t.Tactics),
        db.Notes.AsNoTracking(),
        db.Evidence.AsNoTracking(),
        db.ActionItems.AsNoTracking(),
        db.ActionItemComments.AsNoTracking(),
        db.CaseEntities.AsNoTracking(),
        db.EntityRelationships.AsNoTracking(),
        db.CaseTechniques.AsNoTracking(),
        db.CaseLinks.AsNoTracking(),
        db.CaseBriefs.AsNoTracking(),
        db.CaseOutcomes.AsNoTracking(),
        db.PostIncidentReviews.AsNoTracking(),
        db.ImprovementActions.AsNoTracking(),
        db.TransitionTimeCorrections.AsNoTracking(),
        db.JurisdictionNotices.AsNoTracking(),
        db.CaseTemplates.AsNoTracking(),
        db.CaseTemplateSteps.AsNoTracking(),
        db.StageGates.AsNoTracking(),
        db.StageGateRequirements.AsNoTracking(),
        db.GatePassages.AsNoTracking(),
        db.ReportProfiles.AsNoTracking(),
        db.ReportTemplates.AsNoTracking(),
        db.DataElements.AsNoTracking(),
        db.NotificationRules.AsNoTracking(),
        db.AppSettings.AsNoTracking(),
        db.Roles.AsNoTracking(),
        db.RoleMappings.AsNoTracking(),
        // BUG-70: when things happened and who could see a case, which were outside the check before.
        db.ClassificationChanges.AsNoTracking(),
        db.StatusChanges.AsNoTracking(),
        db.MaterialityChanges.AsNoTracking(),
        db.SeverityChanges.AsNoTracking(),
        db.AssignmentChanges.AsNoTracking(),
        db.EntityVerdictChanges.AsNoTracking(),
        db.Assignments.AsNoTracking(),
        db.EvidenceCitations.AsNoTracking(),
        // REV-05: who the API lets in. A token row inserted in the database would otherwise be an admin identity no
        // check flagged.
        db.ApiTokens.AsNoTracking(),
    ];

    /// <summary>
    /// Checks every hashable record against its own hash and against the hash the chain last recorded for it.
    /// <paramref name="chain"/> is the full audit log in sequence order (the caller has already verified its links).
    /// </summary>
    public static Task<RowMismatch?> VerifyAsync(IAppDbContext db, IHashChainService hasher,
        IReadOnlyList<AuditLogEntry> chain, CancellationToken ct = default)
    {
        var recorded = new ChainRecords();
        foreach (var e in chain) recorded.Add(e);
        return VerifyAsync(db, hasher, recorded, ct: ct);
    }

    /// <summary>
    /// BUG-194: how a record that looks wrong is looked at again. The chain is read before the tables, so a save that
    /// lands in between makes its record look added, changed or removed outside CaseBook. <see cref="CatchUp"/> reads
    /// the entries written since into the records (checking their links). The records are re-read once the scan is done.
    /// </summary>
    public sealed record Recheck(Func<CancellationToken, Task> CatchUp);

    // A save in progress settles in one catch-up; a record still failing after a few is what's stored.
    private const int Catchups = 3;

    /// <summary>
    /// The same check against <paramref name="recorded"/>, which the caller built while streaming the chain (BUG-195), so
    /// the audit log is never held in memory. With <paramref name="recheck"/>, a record that fails is checked again
    /// against the entries written since (BUG-194), and reported only if it still fails.
    /// </summary>
    public static async Task<RowMismatch?> VerifyAsync(IAppDbContext db, IHashChainService hasher,
        ChainRecords recorded, Recheck? recheck = null, CancellationToken ct = default)
    {
        var tables = Tables(db).ToList();
        var tableOf = new Dictionary<string, int>(StringComparer.Ordinal);
        var present = new HashSet<(string, string)>();
        var suspects = new List<(int Table, Guid Id, RowMismatch Bad)>();
        for (var i = 0; i < tables.Count; i++)
        {
            tableOf[tables[i].ElementType.Name] = i;
            await foreach (var row in tables[i].AsAsyncEnumerable().WithCancellation(ct))
            {
                var entity = (Entity)row;
                present.Add((row.GetType().Name, entity.Id.ToString()));
                if (Check(row, recorded, hasher) is not { } bad) continue;
                if (recheck is null) return bad;
                suspects.Add((i, entity.Id, bad));   // looked at again once the scan is done
            }
        }

        // A record the chain last recorded as created or changed (with a row hash, so after row hashes existed) that is
        // no longer in its table was deleted outside CaseBook: the app records every removal.
        var missing = recorded.All.Where(r => IsMissing(r.Key, r.Value, tableOf, present)).Select(r => r.Key).ToList();
        if (recheck is null)
            return missing.Select(k => Missing(k, recorded)).FirstOrDefault();

        // BUG-194: each catch-up reads the entries written since, then re-reads what still looks wrong. A save in
        // progress settles; a record still failing after the last is what's stored.
        for (var n = 0; n < Catchups && (suspects.Count > 0 || missing.Count > 0); n++)
        {
            await recheck.CatchUp(ct);
            var still = new List<(int Table, Guid Id, RowMismatch Bad)>();
            foreach (var (table, id, _) in suspects)
                if (await Reread(db, table, id, ct) is { } again && Check(again, recorded, hasher) is { } bad)   // gone since: the removal decides
                    still.Add((table, id, bad));
            suspects = still;
            var gone = new List<(string Type, string Id)>();
            foreach (var key in missing)
                if (recorded.TryGet(key, out var last) && IsMissing(key, last, tableOf, present)
                    && (!Guid.TryParse(key.Id, out var gid) || await Reread(db, tableOf[key.Type], gid, ct) is null))
                    gone.Add(key);
            missing = gone;
        }
        return suspects.Count > 0 ? suspects[0].Bad : missing.Select(k => Missing(k, recorded)).FirstOrDefault();
    }

    private static RowMismatch Missing((string Type, string Id) key, ChainRecords recorded)
    {
        recorded.TryGet(key, out var last);
        return new RowMismatch(key.Type, Guid.TryParse(key.Id, out var g) ? g : Guid.Empty, last.Sequence,
            $"{key.Type} {key.Id} is missing: the audit trail records it (entry {last.Sequence}) but it was deleted outside CaseBook.");
    }

    // BUG-153: in the tables made hashable later, every row is in the trail, so a missing one counts even when its latest
    // entry predates row hashes.
    private static bool IsMissing((string Type, string Id) key, (string? Hash, long Sequence, bool Deleted) last,
        Dictionary<string, int> tableOf, HashSet<(string, string)> present) =>
        !last.Deleted && (last.Hash is not null || HashedFromUpgrade.Contains(key.Type)) && tableOf.ContainsKey(key.Type)
        && !present.Contains(key);

    // One record re-read by id from its table (index into Tables), with what its hash covers.
    private static Task<IHashableEntity?> Reread(IAppDbContext db, int table, Guid id, CancellationToken ct) =>
        Tables(db).ElementAt(table).Where(r => ((Entity)(object)r).Id == id).FirstOrDefaultAsync(ct);

    private static RowMismatch? Check(IHashableEntity row, ChainRecords recorded, IHashChainService hasher)
    {
        var entity = (Entity)row;
        var type = row.GetType().Name;
        var known = recorded.TryGet((type, entity.Id.ToString()), out var last);

        if (known && last.Deleted)
            return new RowMismatch(type, entity.Id, last.Sequence,
                $"{type} {entity.Id} was removed (audit entry {last.Sequence}) and put back outside CaseBook.");
        if (row.RowHash is not { Length: > 0 } stored)
        {
            // BUG-70: in the tables made hashable later, a row the trail records was given its hash at upgrade; one
            // without a hash that the trail never recorded was added outside CaseBook (an assignment, say).
            if (!known && HashedFromUpgrade.Contains(type))
                return new RowMismatch(type, entity.Id, null,
                    $"{type} {entity.Id} isn't in the audit trail: it was added outside CaseBook.");
            if (last.Hash is not null && !HashClearedByMigration.Contains(type))
                return new RowMismatch(type, entity.Id, last.Sequence,
                    $"{type} {entity.Id} had its hash removed outside CaseBook (audit entry {last.Sequence} recorded one).");
            // BUG-153: the start-up back-fill gives every recorded row in these tables a hash, so one without is a
            // hash cleared outside CaseBook (to be re-hashed from edited content at the next start).
            if (HashedFromUpgrade.Contains(type))
                return new RowMismatch(type, entity.Id, last.Sequence,
                    $"{type} {entity.Id} had its hash removed outside CaseBook (every recorded row has one since the upgrade).");
            return null;   // written before row hashes existed
        }
        if (!known)
            return new RowMismatch(type, entity.Id, null,
                $"{type} {entity.Id} isn't in the audit trail: it was added outside CaseBook.");

        if (!hasher.RowHashMatches(row, stored))   // BUG-24: in the format the hash was written in
            return new RowMismatch(type, entity.Id, last.Sequence,
                $"{type} {entity.Id} was changed outside CaseBook: its content no longer matches its hash.");
        if (last.Hash is { } chained && !string.Equals(chained, stored, StringComparison.OrdinalIgnoreCase))
            return new RowMismatch(type, entity.Id, last.Sequence,
                $"{type} {entity.Id} doesn't match its last recorded change (audit entry {last.Sequence}): it was rewritten outside CaseBook.");
        return null;
    }

    /// <summary>
    /// Types a released migration rewrote and cleared the row hash of (ClosureGateHonestChecks, on stage-gate
    /// requirements), so a cleared hash there isn't a sign of tampering. A migration that clears row hashes must add its
    /// type here.
    /// </summary>
    private static readonly HashSet<string> HashClearedByMigration = new(StringComparer.Ordinal) { nameof(StageGateRequirement) };

    /// <summary>
    /// BUG-70: tables made hashable after release, whose existing rows the startup back-fill (RowHashBackfill) gives a
    /// hash when the trail records them. Every row in them is in the trail, so one with neither is flagged.
    /// </summary>
    private static readonly HashSet<string> HashedFromUpgrade = new(StringComparer.Ordinal)
    {
        nameof(ClassificationChange), nameof(StatusChange), nameof(MaterialityChange), nameof(SeverityChange),
        nameof(AssignmentChange), nameof(EntityVerdictChange), nameof(CaseAssignment), nameof(EvidenceCitation),
        nameof(ApiToken),   // REV-05: every token CaseBook issued has a Create entry, so one with neither was added outside it
    };

    /// <summary>
    /// Per record (type, id), the row hash its latest audit entry recorded, that entry's sequence, and whether it was a
    /// removal. BUG-195: built one entry at a time as the chain is read, keeping only these, not the entries.
    /// </summary>
    public sealed class ChainRecords
    {
        private readonly Dictionary<(string Type, string Id), (string? Hash, long Sequence, bool Deleted)> _last = new();

        /// <summary>The last entry added: what the record check is up to date with.</summary>
        public long? Head { get; private set; }

        /// <summary>BUG-257: that entry's hash, so a later cycle can tell the chain still runs through it.</summary>
        public string? HeadHash { get; private set; }

        public void Add(AuditLogEntry e)
        {
            Head = e.Sequence;
            HeadHash = e.EntryHash;
            if (e.EntityId is not { } id) return;
            var type = string.Intern(e.EntityType);   // a few dozen names, repeated across every entry
            if (e.Action == Domain.Enums.AuditAction.Delete) { _last[(type, id)] = (null, e.Sequence, true); return; }
            if (e.AfterJson is not { } after) return;
            // The latest entry decides. Entries written before every update recorded the row hash don't carry it, and
            // a record whose latest entry is one of those is checked against its own hash only.
            string? hash = null;
            if (after.Contains("\"RowHash\"", StringComparison.Ordinal))
            {
                try
                {
                    using var doc = JsonDocument.Parse(after);
                    if (doc.RootElement.TryGetProperty("RowHash", out var h) && h.ValueKind == JsonValueKind.String) hash = h.GetString();
                }
                catch (JsonException) { /* not a snapshot this check reads; the chain check covers the entry itself */ }
            }
            _last[(type, id)] = (hash, e.Sequence, false);
        }

        internal bool TryGet((string Type, string Id) key, out (string? Hash, long Sequence, bool Deleted) last) =>
            _last.TryGetValue(key, out last);

        internal IEnumerable<KeyValuePair<(string Type, string Id), (string? Hash, long Sequence, bool Deleted)>> All => _last;
    }
}
