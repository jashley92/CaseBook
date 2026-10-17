using System.Buffers;
using System.Buffers.Binary;
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
        db.AccountDirectorySnapshots.AsNoTracking(),   // BUG-416
        db.Assignments.AsNoTracking(),
        db.EvidenceCitations.AsNoTracking(),
        // REV-05: who the API lets in. A token row inserted in the database would otherwise be an admin identity no
        // check flagged.
        db.ApiTokens.AsNoTracking(),
        // BUG-633: who generated a report (the approver must be someone else), whether it's the approved final, its version.
        db.Reports.AsNoTracking(),
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
        ChainRecords recorded, Recheck? recheck = null, IntegrityCycleCounts? counts = null, CancellationToken ct = default)
    {
        var tables = Tables(db).ToList();
        var tableOf = new Dictionary<string, int>(StringComparer.Ordinal);
        var present = new HashSet<(int Type, Guid Id)>();   // keyed as ChainRecords keys them (a type the trail names)
        var suspects = new List<(int Table, Guid Id, RowMismatch Bad)>();
        var strict = await UpgradedAsync(db, ct);   // C18
        for (var i = 0; i < tables.Count; i++)
        {
            tableOf[tables[i].ElementType.Name] = i;
            await foreach (var row in tables[i].AsAsyncEnumerable().WithCancellation(ct))
            {
                var entity = (Entity)row;
                counts?.RecordRead(tables[i].ElementType.Name);
                if (recorded.PresentKey(row.GetType().Name, entity.Id) is { } key) present.Add(key);
                if (Check(row, recorded, hasher, strict) is not { } bad) continue;
                if (recheck is null) return bad;
                suspects.Add((i, entity.Id, bad));   // looked at again once the scan is done
            }
        }

        // A record the chain last recorded as created or changed (with a row hash, so after row hashes existed) that is
        // no longer in its table was deleted outside CaseBook: the app records every removal.
        var missing = recorded.NotPresent(present, (type, last) => MayBeMissing(type, last, tableOf, strict));
        var lineage = await LineageAsync(db, strict, ct);
        if (recheck is null)
            return missing.Select(k => Missing(k, recorded)).FirstOrDefault() ?? lineage;

        // BUG-194: each catch-up reads the entries written since, then re-reads what still looks wrong. A save in
        // progress settles; a record still failing after the last is what's stored.
        for (var n = 0; n < Catchups && (suspects.Count > 0 || missing.Count > 0); n++)
        {
            await recheck.CatchUp(ct);
            var still = new List<(int Table, Guid Id, RowMismatch Bad)>();
            foreach (var (table, id, _) in suspects)
                if (await Reread(db, table, id, ct) is { } again && Check(again, recorded, hasher, strict) is { } bad)   // gone since: the removal decides
                    still.Add((table, id, bad));
            suspects = still;
            var gone = new List<(string Type, string Id)>();
            foreach (var key in missing)
                if (recorded.TryGetEntry(key, out var last) && MayBeMissing(key.Type, last, tableOf, strict) && !recorded.Present(key, present)
                    && (!Guid.TryParse(key.Id, out var gid) || await Reread(db, tableOf[key.Type], gid, ct) is null))
                    gone.Add(key);
            missing = gone;
        }
        if (suspects.Count > 0) return suspects[0].Bad;
        if (missing.Count > 0) return Missing(missing[0], recorded);
        if (lineage is null) return null;
        await recheck.CatchUp(ct);   // a save in progress settles before a lineage is called wrong
        return await LineageAsync(db, strict, ct);
    }

    /// <summary>
    /// C18: the AppSetting the start-up upgrade (RowHashUpgrade) writes once it has recorded the hash of every record that
    /// matches its trail and moved every record its hash didn't cover to format 4. From then on the check is strict
    /// (<see cref="Check"/>): no record may lack a hash or a trail entry recording it, a hash must cover what its record
    /// holds, and no migration's cleared hash is excused. Until it's written (an upgrade that failed part way, say) the
    /// check is as it was. Audited and hashed like any setting, so removing or changing it is itself flagged; the settings
    /// provider skips the key.
    /// </summary>
    public const string UpgradeMarkerKey = "Integrity:RowHashFormat";

    /// <summary>The marker's value: the format the upgrade brought every record to.</summary>
    public const string UpgradeMarkerValue = "4";

    /// <summary>Whether the upgrade's marker is written (the check is strict).</summary>
    public static Task<bool> UpgradedAsync(IAppDbContext db, CancellationToken ct = default) =>
        db.AppSettings.AsNoTracking().AnyAsync(s => s.Key == UpgradeMarkerKey && s.Value == UpgradeMarkerValue, ct);

    /// <summary>
    /// BUG-315: which version of a note, an investigation entry or the brief is the current one isn't in any row's hash
    /// (IsCurrent changes when the next version is written), so setting an earlier version current in the database, and the
    /// latest not, showed the old wording everywhere while every row still matched its hash. CaseBook only ever makes a
    /// version not current by writing the one that replaces it, so a replaced version marked current was changed outside
    /// it. (The other way round, a latest version not current, isn't flagged: it hides the text rather than changing it,
    /// and older releases could leave a lineage like that, so it would raise alarms nobody caused.)
    /// </summary>
    // Read as a join from each later version to the one it replaced (later versions are few), not a load of every row:
    // this runs with every check, about every ten minutes.
    private static async Task<RowMismatch?> LineageAsync(IAppDbContext db, bool strict, CancellationToken ct) =>
        await ReplacedButCurrentAsync(db, ct) ?? (strict ? await HiddenAsync(db, ct) : null);

    /// <summary>
    /// BUG-634 (owner's decision): a note or timeline entry marked not current that no later version replaced and that
    /// wasn't retracted has dropped out of the case and every report, and CaseBook never does that: a version stops
    /// being current only when the next one is written, or when it's retracted. Checked once the upgrade has run (strict),
    /// so the trail it records first is the baseline.
    /// </summary>
    private static async Task<RowMismatch?> HiddenAsync(IAppDbContext db, CancellationToken ct) =>
        Hidden(nameof(AnalystNote), await db.Notes.AsNoTracking()
            .Where(n => !n.IsCurrent && !db.Notes.Any(later => later.SupersedesNoteId == n.Id))
            .Select(n => n.Id).FirstOrDefaultAsync(ct))
        ?? Hidden(nameof(TimelineEntry), await db.TimelineEntries.AsNoTracking()
            .Where(t => !t.IsCurrent && t.RetractedAtUtc == null && !db.TimelineEntries.Any(later => later.SupersedesEntryId == t.Id))
            .Select(t => t.Id).FirstOrDefaultAsync(ct));

    private static RowMismatch? Hidden(string type, Guid id) =>
        id == Guid.Empty ? null
            : new RowMismatch(type, id, null,
                $"{type} {id} is marked not current, but no later version replaced it and it wasn't retracted: hidden outside CaseBook.");

    private static async Task<RowMismatch?> ReplacedButCurrentAsync(IAppDbContext db, CancellationToken ct) =>
        Lineage(nameof(AnalystNote), await (from later in db.Notes.AsNoTracking() where later.SupersedesNoteId != null
                                            join earlier in db.Notes.AsNoTracking() on later.SupersedesNoteId equals (Guid?)earlier.Id
                                            where earlier.IsCurrent select earlier.Id).FirstOrDefaultAsync(ct))
        ?? Lineage(nameof(TimelineEntry), await (from later in db.TimelineEntries.AsNoTracking() where later.SupersedesEntryId != null
                                                 join earlier in db.TimelineEntries.AsNoTracking() on later.SupersedesEntryId equals (Guid?)earlier.Id
                                                 where earlier.IsCurrent select earlier.Id).FirstOrDefaultAsync(ct))
        ?? Lineage(nameof(CaseBrief), await (from later in db.CaseBriefs.AsNoTracking() where later.SupersedesBriefId != null
                                             join earlier in db.CaseBriefs.AsNoTracking() on later.SupersedesBriefId equals (Guid?)earlier.Id
                                             where earlier.IsCurrent select earlier.Id).FirstOrDefaultAsync(ct))
        // BUG-421: retracting an entry makes it not current in the same change, and nothing makes it current again, so a
        // retracted entry marked current (back on the timeline and in every report) was changed outside CaseBook.
        ?? RetractedButCurrent(await db.TimelineEntries.AsNoTracking().Where(t => t.RetractedAtUtc != null && t.IsCurrent)
            .Select(t => t.Id).FirstOrDefaultAsync(ct));

    private static RowMismatch? Lineage(string type, Guid replacedButCurrent) =>
        replacedButCurrent == Guid.Empty ? null
            : new RowMismatch(type, replacedButCurrent, null,
                $"{type} {replacedButCurrent} is marked current though a later version replaced it: changed outside CaseBook.");

    private static RowMismatch? RetractedButCurrent(Guid id) =>
        id == Guid.Empty ? null
            : new RowMismatch(nameof(TimelineEntry), id, null,
                $"{nameof(TimelineEntry)} {id} is marked current though it was retracted: changed outside CaseBook.");

    private static RowMismatch Missing((string Type, string Id) key, ChainRecords recorded)
    {
        recorded.TryGet(key, out var last);
        return new RowMismatch(key.Type, Guid.TryParse(key.Id, out var g) ? g : Guid.Empty, last.Sequence,
            $"{key.Type} {key.Id} is missing: the audit trail records it (entry {last.Sequence}) but it was deleted outside CaseBook.");
    }

    // BUG-153: in the tables made hashable later, every row is in the trail, so a missing one counts even when its latest
    // entry predates row hashes. BUG-648: and in every table once the check is strict: CaseBook records every removal
    // (each delete of a hashed row, and of the rows under it, is a tracked one), so a record whose latest entry predates
    // row hashes and that is gone was deleted outside it.
    // Whether a record with this latest entry, if it's not in its table, was deleted outside CaseBook.
    private static bool MayBeMissing(string type, ChainRecords.Entry last, Dictionary<string, int> tableOf, bool strict) =>
        !last.Deleted && (strict || last.HasHash || HashedFromUpgrade.Contains(type)) && tableOf.ContainsKey(type);

    // One record re-read by id from its table (index into Tables), with what its hash covers.
    private static Task<IHashableEntity?> Reread(IAppDbContext db, int table, Guid id, CancellationToken ct) =>
        Tables(db).ElementAt(table).Where(r => ((Entity)(object)r).Id == id).FirstOrDefaultAsync(ct);

    private static RowMismatch? Check(IHashableEntity row, ChainRecords recorded, IHashChainService hasher, bool strict)
    {
        var entity = (Entity)row;
        var type = row.GetType().Name;
        var known = recorded.TryGetEntry(type, entity.Id, out var last);

        if (known && last.Deleted)
            return new RowMismatch(type, entity.Id, last.Sequence,
                $"{type} {entity.Id} was removed (audit entry {last.Sequence}) and put back outside CaseBook.");
        // BUG-620/621: once the upgrade has recorded every record's hash (and those its migrations wrote), a record
        // without one was added or had its hash cleared outside CaseBook, in every table and whatever the trail says.
        if (strict && row.RowHash is not { Length: > 0 })
            return new RowMismatch(type, entity.Id, known ? last.Sequence : null,
                $"{type} {entity.Id} has no hash, and every record has had one since the upgrade: it was added or changed outside CaseBook.");
        if (row.RowHash is not { Length: > 0 } stored)
        {
            // BUG-422: a table hashed from its first row has no row from before row hashes, so one without a hash was
            // added (or had its hash cleared) outside CaseBook, whatever the trail says.
            if (HashedSinceCreation.Contains(type))
                return new RowMismatch(type, entity.Id, known ? last.Sequence : null,
                    $"{type} {entity.Id} has no hash, and every record of its kind has had one: it was added or changed outside CaseBook.");
            // BUG-70: in the tables made hashable later, a row the trail records was given its hash at upgrade; one
            // without a hash that the trail never recorded was added outside CaseBook (an assignment, say).
            if (!known && HashedFromUpgrade.Contains(type))
                return new RowMismatch(type, entity.Id, null,
                    $"{type} {entity.Id} isn't in the audit trail: it was added outside CaseBook.");
            if (last.HasHash && !HashClearedByMigration.Contains(type))
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
        if (last.HasHash && !last.HashEquals(stored))
            return new RowMismatch(type, entity.Id, last.Sequence,
                $"{type} {entity.Id} doesn't match its last recorded change (audit entry {last.Sequence}): it was rewritten outside CaseBook.");
        if (!strict) return null;
        // BUG-629: the upgrade recorded the hash of every record whose latest entry (from before v1.5.1) didn't, so one
        // like that now was rewritten, its hash recomputed to match, outside CaseBook.
        if (!last.HasHash)
            return new RowMismatch(type, entity.Id, last.Sequence,
                $"{type} {entity.Id}'s last recorded change (audit entry {last.Sequence}) doesn't record its hash, and every record's has since the upgrade: it was rewritten outside CaseBook.");
        // C18: and moved every record its hash didn't cover to format 4, so a value an older hash leaves out was set since,
        // outside CaseBook (a kept deadline, a release request, a version link).
        if (!Canonical.Covers(Canonical.FormatOf(stored), row.BuildCanonicalContent))
            return new RowMismatch(type, entity.Id, last.Sequence,
                $"{type} {entity.Id} holds a value its hash (format {Canonical.FormatOf(stored)}) doesn't cover, and every record has been hashed with what it holds since the upgrade: it was changed outside CaseBook.");
        return null;
    }

    /// <summary>
    /// Types a released migration rewrote and cleared the row hash of (ClosureGateHonestChecks, on stage-gate
    /// requirements), so a cleared hash there isn't a sign of tampering. A migration that clears row hashes must add its
    /// type here. BUG-621: only until the upgrade, which records the hash of each row that still holds what the migration
    /// wrote (<see cref="MigrationSeededRows"/>); after it a cleared hash is flagged there too (strict).
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
    /// BUG-422: tables that were hashable from the release that added them, so none of their rows predates row hashes.
    /// A table added later belongs here, not in <see cref="HashedFromUpgrade"/>.
    /// </summary>
    private static readonly HashSet<string> HashedSinceCreation = new(StringComparer.Ordinal) { nameof(AccountDirectorySnapshot) };

    /// <summary>
    /// Per record (type, id), the row hash its latest audit entry recorded, that entry's sequence, and whether it was a
    /// removal. BUG-195: built one entry at a time as the chain is read, keeping only these, not the entries.
    /// The monitor keeps this between cycles, one entry per record the trail has ever named, so it's held compactly: a
    /// record whose id is a GUID as CaseBook writes it is keyed by its type's index and the GUID, and a hash as CaseBook
    /// writes it (an optional "vN:" prefix and 64 lower-case hex digits) is kept as its 32 bytes. Anything else (an id or
    /// hash written some other way, as an edit outside CaseBook might) is kept as written, so nothing reads differently.
    /// </summary>
    public sealed class ChainRecords
    {
        private readonly Dictionary<string, int> _typeIndex = new(StringComparer.Ordinal);
        private readonly List<string> _types = [];
        private readonly Dictionary<(int Type, Guid Id), Entry> _byGuid = new();
        private readonly Dictionary<(string Type, string Id), Entry> _other = new();

        /// <summary>The last entry added: what the record check is up to date with.</summary>
        public long? Head { get; private set; }

        /// <summary>BUG-257: that entry's hash, so a later cycle can tell the chain still runs through it.</summary>
        public string? HeadHash { get; private set; }

        /// <summary>How many records are kept (one per record the trail has mentioned).</summary>
        public int Count => _byGuid.Count + _other.Count;

        public void Add(AuditLogEntry e)
        {
            Head = e.Sequence;
            HeadHash = e.EntryHash;
            if (e.EntityId is not { } id) return;
            if (e.Action == Domain.Enums.AuditAction.Delete) { Set(e.EntityType, id, Entry.Removed(e.Sequence)); return; }
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
            Set(e.EntityType, id, Entry.Of(hash, e.Sequence));
        }

        private void Set(string type, string id, Entry entry)
        {
            if (CanonicalGuid(id) is { } g) _byGuid[(IndexOf(type), g)] = entry;
            else _other[(type, id)] = entry;
        }

        private int IndexOf(string type)
        {
            if (_typeIndex.TryGetValue(type, out var i)) return i;
            _types.Add(type);
            return _typeIndex[type] = _types.Count - 1;
        }

        public bool TryGet((string Type, string Id) key, out (string? Hash, long Sequence, bool Deleted) last)
        {
            if (TryGetEntry(key, out var entry))
            {
                last = (entry.Hash, entry.Sequence, entry.Deleted);
                return true;
            }
            last = default;
            return false;
        }

        internal bool TryGetEntry((string Type, string Id) key, out Entry entry)
        {
            if (CanonicalGuid(key.Id) is { } g) return TryGetEntry(key.Type, g, out entry);
            return _other.TryGetValue(key, out entry);
        }

        /// <summary>A record by its type and GUID id, as the check reads it from its table (no text key made).</summary>
        internal bool TryGetEntry(string type, Guid id, out Entry entry)
        {
            if (_typeIndex.TryGetValue(type, out var t) && _byGuid.TryGetValue((t, id), out entry)) return true;
            entry = default;
            return false;
        }

        /// <summary>The key a row read from its table has in the present set, or null for a type the trail never named.</summary>
        internal (int Type, Guid Id)? PresentKey(string type, Guid id) =>
            _typeIndex.TryGetValue(type, out var t) ? (t, id) : null;

        /// <summary>Whether a kept record was read from its table this cycle.</summary>
        internal bool Present((string Type, string Id) key, HashSet<(int Type, Guid Id)> present) =>
            CanonicalGuid(key.Id) is { } g && _typeIndex.TryGetValue(key.Type, out var t) && present.Contains((t, g));

        /// <summary>Every kept record whose entry passes <paramref name="keep"/> and that wasn't read from its table.</summary>
        internal List<(string Type, string Id)> NotPresent(HashSet<(int Type, Guid Id)> present, Func<string, Entry, bool> keep)
        {
            var result = new List<(string Type, string Id)>();
            foreach (var ((t, id), entry) in _byGuid)
                if (keep(_types[t], entry) && !present.Contains((t, id))) result.Add((_types[t], id.ToString()));
            foreach (var (key, entry) in _other)
                if (keep(key.Type, entry)) result.Add(key);   // never read from a table: rows' ids are GUIDs
            return result;
        }

        // The GUID an id names, when it's written as CaseBook writes one (Guid.ToString(): lower case, hyphenated), so
        // turning it back into text gives the same id.
        private static Guid? CanonicalGuid(string id)
        {
            if (id.Length != 36 || !Guid.TryParseExact(id, "D", out var g)) return null;
            Span<char> again = stackalloc char[36];
            return g.TryFormat(again, out var n, "D") && n == 36 && again.SequenceEqual(id) ? g : null;
        }

        /// <summary>
        /// A record's latest entry: its sequence, whether it was a removal, and the row hash it recorded (null when it
        /// recorded none). The hash is kept as its 32 bytes and format when CaseBook wrote it, else as written.
        /// </summary>
        internal readonly struct Entry
        {
            private const byte NoHash = 0, Bare = 1, AsWritten = 255;   // otherwise the format N of a "vN:" prefix (2-9)

            private readonly ulong _h0, _h1, _h2, _h3;
            private readonly string? _written;
            private readonly byte _kind;

            public long Sequence { get; }
            public bool Deleted { get; }

            private Entry(long sequence, bool deleted, byte kind, ReadOnlySpan<byte> bytes, string? written)
            {
                Sequence = sequence;
                Deleted = deleted;
                _kind = kind;
                _written = written;
                if (bytes.Length != 32) return;
                _h0 = BinaryPrimitives.ReadUInt64BigEndian(bytes);
                _h1 = BinaryPrimitives.ReadUInt64BigEndian(bytes[8..]);
                _h2 = BinaryPrimitives.ReadUInt64BigEndian(bytes[16..]);
                _h3 = BinaryPrimitives.ReadUInt64BigEndian(bytes[24..]);
            }

            public static Entry Removed(long sequence) => new(sequence, true, NoHash, default, null);

            public static Entry Of(string? hash, long sequence)
            {
                if (hash is null) return new(sequence, false, NoHash, default, null);
                Span<byte> bytes = stackalloc byte[32];
                return Parse(hash, bytes, lowerCaseOnly: true) is { } kind
                    ? new(sequence, false, kind, bytes, null)
                    : new(sequence, false, AsWritten, default, hash);
            }

            /// <summary>Whether it recorded a row hash.</summary>
            public bool HasHash => _kind != NoHash;

            /// <summary>The recorded row hash as written (made on each read; the check compares with <see cref="HashEquals"/>).</summary>
            public string? Hash
            {
                get
                {
                    if (_kind == NoHash) return null;
                    if (_kind == AsWritten) return _written;
                    Span<byte> b = stackalloc byte[32];
                    Write(b);
                    return (_kind == Bare ? "" : $"v{_kind}:") + Convert.ToHexStringLower(b);
                }
            }

            /// <summary>Whether the recorded hash is <paramref name="stored"/>, ignoring case, without making text.</summary>
            public bool HashEquals(string stored)
            {
                if (_kind == NoHash) return false;
                if (_kind == AsWritten) return string.Equals(_written, stored, StringComparison.OrdinalIgnoreCase);
                Span<byte> mine = stackalloc byte[32];
                Span<byte> other = stackalloc byte[32];
                Write(mine);
                return Parse(stored, other, lowerCaseOnly: false) == _kind && mine.SequenceEqual(other);
            }

            private void Write(Span<byte> b)
            {
                BinaryPrimitives.WriteUInt64BigEndian(b, _h0);
                BinaryPrimitives.WriteUInt64BigEndian(b[8..], _h1);
                BinaryPrimitives.WriteUInt64BigEndian(b[16..], _h2);
                BinaryPrimitives.WriteUInt64BigEndian(b[24..], _h3);
            }

            // The format of a hash written "vN:" (N 2-9) or bare, then 64 hex digits, with its digits into bytes; else null.
            // With lowerCaseOnly, only a lower-case prefix and digits (as CaseBook writes them), so the text is rebuilt exactly.
            private static byte? Parse(string hash, Span<byte> bytes, bool lowerCaseOnly)
            {
                var kind = Bare;
                var hex = hash.AsSpan();
                if (hash.Length == 67 && (hash[0] == 'v' || (!lowerCaseOnly && hash[0] == 'V')) && hash[1] is >= '2' and <= '9' && hash[2] == ':')
                {
                    kind = (byte)(hash[1] - '0');
                    hex = hex[3..];
                }
                if (hex.Length != 64) return null;
                foreach (var c in hex)
                    if (!(char.IsAsciiDigit(c) || c is >= 'a' and <= 'f' || (!lowerCaseOnly && c is >= 'A' and <= 'F'))) return null;
                return Convert.FromHexString(hex, bytes, out _, out var written) == OperationStatus.Done && written == 32 ? kind : null;
            }
        }
    }
}
