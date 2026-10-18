using System.Text.Json;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Integrity;
using IncidentManager.Domain.Common;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Metadata;

namespace IncidentManager.Infrastructure.Persistence.Interceptors;

/// <summary>
/// On every save: (1) recomputes the row hash of changed hashable entities, and (2) appends
/// tamper-evident, hash-chained <see cref="AuditLogEntry"/> rows describing each change, in the
/// same transaction. This is the spine of the system's integrity guarantees.
/// </summary>
public sealed class AuditChainInterceptor : SaveChangesInterceptor
{
    private static readonly HashSet<Type> NotAudited =
    [
        typeof(AuditLogEntry), typeof(IntegritySeal), typeof(AppUser), typeof(ChainOfCustodyEvent),
        typeof(EntityLayout), // cosmetic graph positions — deliberately outside the tamper-evident chain
        typeof(CaseAccessEvent), // C-05 read/access telemetry — high-volume, out of the tamper-evident chain
        typeof(NotificationMark), // BUG-95 what the scans sent — operational state, not case data
        typeof(AlertDelivery), // BUG-101 failed alert emails awaiting retry — operational state, not case data
        typeof(HeldEmail), // BUG-617 user-action emails awaiting the relay — operational state, not case data
        typeof(SavedView), // PROD-09 personal/shared case-queue filter sets — user convenience state, not case data
        typeof(PinnedCase), // PROD-20 per-user pinned favourites — convenience state, not case data
        typeof(OpenCaseTab), // RD-21 per-user open workspace tabs — convenience state, not case data
        typeof(PendingImport), // PROD-33 inbound import staging queue — the apply writes are audited, not the draft
        typeof(UserNotificationPreference), // PROD-39 per-user digest cadence — personal preference, not case data
        typeof(UserDisplayPreference) // per-user theme / sidebar / time / density — display preference, not case data
    ];

    /// <summary>C18: whether saves of <paramref name="type"/> are audited (a writer that goes around the interceptor
    /// leaves no trail of them, so AuditedWriterBypassTests refuses one).</summary>
    public static bool IsAudited(Type type) => typeof(Entity).IsAssignableFrom(type) && !NotAudited.Contains(type);

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = false };

    // BUG-113: a case whose only change is its concurrency token (renewed because something on it changed) isn't a change
    // to the case: nothing to audit or hash, and the live update names what did change.
    // BUG-392: nor when one of its owned value objects changed (they're tracked as their own entries, so the case's own
    // columns can show only the token): dropping it would skip the case's new row hash and its audit line.
    private static bool OnlyEditVersionBumped(EntityEntry e, IReadOnlyList<EntityEntry> removedOwned) =>
        e.Entity is Case && e.State == EntityState.Modified
        && e.Properties.Where(p => p.IsModified).All(p => p.Metadata.Name == AppDbContext.CaseEditVersion)
        && !e.References.Any(r => r.TargetEntry is { } t && t.Metadata.IsOwned()
                                  && t.State is EntityState.Added or EntityState.Modified or EntityState.Deleted)
        && !removedOwned.Any(d => OwnedBy(d, e));

    // REV-05: every token-authenticated API call stamps LastUsedAtUtc, which the token's row hash leaves out. Drop that
    // save here rather than in Apply's touch skip, so it never waits on the process-wide gate or reads the chain head.
    private static bool OnlyTokenUseStamped(EntityEntry e) =>
        e.Entity is ApiToken && e.State == EntityState.Modified
        && e.Properties.Where(p => p.IsModified).All(p => p.Metadata.Name == nameof(ApiToken.LastUsedAtUtc));

    // Freshness stamps bumped by a "touch". An update whose ONLY changed columns are these carries no
    // forensic value — see the skip in Apply.
    // REV-05: an API token's per-call last-used time too: a token is chained now, and every API call stamps it.
    private static bool IsTouchOnly(string field) => field is "ModifiedAtUtc" or "ModifiedBy" or nameof(ApiToken.LastUsedAtUtc);

    // REV-05: the trail records a token's hash (its row hash covers it), not the hash itself, which is the lookup key for
    // the secret and would otherwise travel in every audit export.
    private static object? Shown(Microsoft.EntityFrameworkCore.Metadata.IProperty p, object? value) =>
        p.DeclaringType.ClrType == typeof(ApiToken) && p.Name == nameof(ApiToken.TokenHash) ? "(not recorded)" : value;

    private readonly IHashChainService _hasher;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;
    private readonly ICaseChangeNotifier _notifier;

    // BUG-27: per-save state, kept per context. The scoped factory gives every context it makes in a circuit this one
    // interceptor, and those saves can interleave at an await, so one shared field let an unaudited save clear another
    // save's pending broadcast or release the gate it held. A context runs one save at a time.
    private sealed class SaveState
    {
        // Cases touched by the in-flight save, with what changed on each (RD-22), captured before commit and
        // broadcast once it succeeds.
        public readonly Dictionary<Guid, List<CaseChangeItem>> PendingCaseIds = new();

        // REL-05: true when this save acquired the process-wide audit-chain gate in SavingChanges and must release
        // it on completion (success, failure, or cancellation).
        public bool GateHeld;
    }

    private readonly System.Runtime.CompilerServices.ConditionalWeakTable<DbContext, SaveState> _states = new();

    private SaveState StateOf(DbContext ctx) => _states.GetOrCreateValue(ctx);

    public AuditChainInterceptor(IHashChainService hasher, ICurrentUser user, IClock clock, ICaseChangeNotifier notifier)
    {
        _hasher = hasher;
        _user = user;
        _clock = clock;
        _notifier = notifier;
    }

    public override int SavedChanges(SaveChangesCompletedEventData eventData, int result)
    {
        ReleaseGate(eventData.Context);
        PublishPending(eventData.Context);
        return base.SavedChanges(eventData, result);
    }

    public override ValueTask<int> SavedChangesAsync(
        SaveChangesCompletedEventData eventData, int result, CancellationToken ct = default)
    {
        ReleaseGate(eventData.Context);
        PublishPending(eventData.Context);
        return base.SavedChangesAsync(eventData, result, ct);
    }

    // REL-05: a failed or cancelled save never reaches SavedChanges, so release the gate here too (and
    // drop the pending broadcast — nothing committed).
    public override void SaveChangesFailed(DbContextErrorEventData eventData)
    {
        ReleaseGate(eventData.Context);
        Drop(eventData.Context);
        base.SaveChangesFailed(eventData);
    }

    public override Task SaveChangesFailedAsync(DbContextErrorEventData eventData, CancellationToken ct = default)
    {
        ReleaseGate(eventData.Context);
        Drop(eventData.Context);
        return base.SaveChangesFailedAsync(eventData, ct);
    }

    // BUG-01: a concurrency conflict (e.g. two people removing the same row) is reported here, not through
    // SaveChangesFailed, so the gate must be released here as well.
    public override InterceptionResult ThrowingConcurrencyException(ConcurrencyExceptionEventData eventData, InterceptionResult result)
    {
        ReleaseGate(eventData.Context);
        Drop(eventData.Context);
        return base.ThrowingConcurrencyException(eventData, result);
    }

    public override ValueTask<InterceptionResult> ThrowingConcurrencyExceptionAsync(
        ConcurrencyExceptionEventData eventData, InterceptionResult result, CancellationToken ct = default)
    {
        ReleaseGate(eventData.Context);
        Drop(eventData.Context);
        return base.ThrowingConcurrencyExceptionAsync(eventData, result, ct);
    }

    public override void SaveChangesCanceled(DbContextEventData eventData)
    {
        ReleaseGate(eventData.Context);
        Drop(eventData.Context);
        base.SaveChangesCanceled(eventData);
    }

    public override Task SaveChangesCanceledAsync(DbContextEventData eventData, CancellationToken ct = default)
    {
        ReleaseGate(eventData.Context);
        Drop(eventData.Context);
        return base.SaveChangesCanceledAsync(eventData, ct);
    }

    // BUG-01: EF calls SavingChanges before the save's own error handling, so an exception while appending (the
    // chain-head read timing out, say) reaches none of the completion callbacks. Release the gate here.
    private void AppendOrRelease(DbContext context, PreparedAudit prepared)
    {
        try { AppendChain(context, prepared); }
        catch
        {
            ReleaseGate(context);
            Drop(context);
            throw;
        }
    }

    private void ReleaseGate(DbContext? ctx)
    {
        if (ctx is null || !_states.TryGetValue(ctx, out var st) || !st.GateHeld) return;
        st.GateHeld = false;
        AuditChainGate.Exit();
    }

    private void Drop(DbContext? ctx)
    {
        if (ctx is not null && _states.TryGetValue(ctx, out var st)) st.PendingCaseIds.Clear();
    }

    private void PublishPending(DbContext? ctx)
    {
        if (ctx is null || !_states.TryGetValue(ctx, out var st)) return;
        // The actor is whoever this unit of work belongs to — used by viewers to attribute the change (U-30).
        var actorId = _user.UserId;
        foreach (var (id, items) in st.PendingCaseIds) _notifier.Publish(new CaseChange(id, actorId, items));
        st.PendingCaseIds.Clear();
    }

    public override InterceptionResult<int> SavingChanges(DbContextEventData eventData, InterceptionResult<int> result)
    {
        if (eventData.Context is { } ctx)
        {
            // BUG-657: an upkeep save is vouched for under the gate (see PrepareUnderGateOrRelease).
            if (IsUpkeep(ctx)) HoldGate(ctx);
            var prepared = PrepareUnderGateOrRelease(ctx);
            if (prepared is not null)
            {
                // REL-05: hold the gate from the head read through commit (released in the completion
                // callbacks) so a concurrent append can't read the same head and fork the chain.
                if (!StateOf(ctx).GateHeld) HoldGate(ctx);
                AppendOrRelease(ctx, prepared);
            }
        }
        return result;
    }

    public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(
        DbContextEventData eventData, InterceptionResult<int> result, CancellationToken ct = default)
    {
        if (eventData.Context is { } ctx)
        {
            if (IsUpkeep(ctx)) await HoldGateAsync(ctx, ct);
            var prepared = PrepareUnderGateOrRelease(ctx);
            if (prepared is not null)
            {
                if (!StateOf(ctx).GateHeld) await HoldGateAsync(ctx, ct);
                AppendOrRelease(ctx, prepared);
            }
        }
        return result;
    }

    private static bool IsUpkeep(DbContext ctx) => ctx is AppDbContext { PendingUpkeep: true };

    private void HoldGate(DbContext ctx)
    {
        AuditChainGate.Enter();
        StateOf(ctx).GateHeld = true;
    }

    private async Task HoldGateAsync(DbContext ctx, CancellationToken ct)
    {
        await AuditChainGate.EnterAsync(ct);
        StateOf(ctx).GateHeld = true;
    }

    // BUG-657: an upkeep save reads its rows, then vouches for them as read. Vouched for before the gate, a change to one
    // that another save was committing meanwhile was overwritten by a hash of the row as the upkeep read it: a false
    // tamper alarm (rows other than a case have no concurrency token). Under the gate, every audited save that started
    // before has committed, and none can commit until this one has. A save with nothing to append lets the gate go.
    private PreparedAudit? PrepareUnderGateOrRelease(DbContext ctx)
    {
        PreparedAudit? prepared;
        try { prepared = Prepare(ctx); }
        catch
        {
            ReleaseGate(ctx);
            throw;
        }
        if (prepared is null) ReleaseGate(ctx);
        return prepared;
    }

    /// <summary>
    /// Phase 1 (no gate): detect changes, snapshot which cases the save touches, consume the change
    /// reason, and refresh row hashes (each independent of the chain head). Returns the auditable
    /// entries + context needed to append, or null when the save carries no forensic change.
    /// </summary>
    private PreparedAudit? Prepare(DbContext ctx)
    {
        ctx.ChangeTracker.DetectChanges();
        if (ctx is AppDbContext { PendingUpkeep: true } kept) RefuseUnvouchedUpkeep(kept);   // BUG-639

        var actor = _user.IsAuthenticated ? _user.UserId : "system";
        var now = _clock.UtcNow;

        // BUG-333: a replaced owned value object is tracked as the new instance (Added) plus the old one (Deleted). The old
        // ones are taken now, while change detection is current, so the update's diff can read the real before-values.
        var replacedOwned = ctx.ChangeTracker.Entries()
            .Where(x => x.Metadata.IsOwned() && x.State == EntityState.Deleted).ToList();

        var auditable = ctx.ChangeTracker.Entries()
            .Where(e => e.Entity is Entity
                        && !e.Metadata.IsOwned()
                        && !NotAudited.Contains(e.Entity.GetType())
                        && e.State is EntityState.Added or EntityState.Modified or EntityState.Deleted
                        && !OnlyEditVersionBumped(e, replacedOwned)
                        && !OnlyTokenUseStamped(e))
            .ToList();

        // Map cases by id so child-entity audit lines can carry the case number.
        var (caseNumbers, evidenceCases) = CaseNumbersFor(ctx, auditable);

        // Record which cases this save touches, to broadcast once it commits (SavedChanges).
        var pending = StateOf(ctx).PendingCaseIds;
        pending.Clear();
        var upkeepSave = ctx is AppDbContext { PendingUpkeep: true };
        foreach (var e in auditable)
        {
            // BUG-658: upkeep that only records a row's hash changes nothing a viewer sees, so nobody is told to reload.
            if (upkeepSave && e.State == EntityState.Modified && !ChangesContent(e)) continue;
            var cid = e.Entity is Case cse ? cse.Id : TryGetCaseId(e);
            if (cid is not { } id) continue;
            if (!pending.TryGetValue(id, out var items)) pending[id] = items = [];
            items.Add(new CaseChangeItem(e.Entity.GetType().Name, ((Entity)e.Entity).Id, e.State switch
            {
                EntityState.Added => CaseChangeOp.Added, EntityState.Deleted => CaseChangeOp.Deleted, _ => CaseChangeOp.Modified
            }));
        }

        // CAP-12 review: entries for an act that changes no audited row (a package's hand-over), taken now so a retry of a
        // failed save never sends them twice; chained after the save's own, in its transaction.
        List<AuditNote> notes = [];
        if (ctx is AppDbContext { PendingAuditNotes.Count: > 0 } noted)
        {
            notes.AddRange(noted.PendingAuditNotes);
            noted.PendingAuditNotes.Clear();
        }

        if (auditable.Count == 0 && notes.Count == 0) return null;

        // Consume the analyst's optional "reason for change" for this unit of work, then clear it so a
        // later save on the same context doesn't inherit it. Only Update entries carry it (a correction).
        string? reason = null;
        if (ctx is AppDbContext app)
        {
            reason = string.IsNullOrWhiteSpace(app.PendingChangeReason) ? null : app.PendingChangeReason.Trim();
            app.PendingChangeReason = null;
            var upkeep = app.PendingUpkeep;
            app.PendingUpkeep = false;
            // C18: upkeep is left out of every view of who changed what, so a reason typed to read like it is refused.
            if (IntegrityUpkeep.Mimics(reason))
                throw new ArgumentException("That reason is reserved for CaseBook's own upkeep. Word it differently. Nothing was saved.");
            if (upkeep) reason = IntegrityUpkeep.Reason;
            // REV-03: the audit lines are added after ColumnLengthGuard has run, so their reason is checked here: SQLite
            // would keep a longer one and SQL Server would refuse the whole save.
            if (reason is { Length: > MaxReason })
                throw new ArgumentException(
                    $"Keep the reason for the change to {MaxReason:N0} characters or fewer (it's {reason.Length:N0}). Nothing was saved.");
        }

        // BUG-25: store every time in UTC. Canonicals print times with their offset, and SQLite reads them back as UTC,
        // so a time saved with another offset would hash differently once reloaded. Owned value objects are included.
        foreach (var e in ctx.ChangeTracker.Entries().Where(x => x.State is EntityState.Added or EntityState.Modified))
            foreach (var p in e.Properties)
                if (p.CurrentValue is DateTimeOffset t && t.Offset != TimeSpan.Zero)
                    p.CurrentValue = t.ToUniversalTime();

        // Refresh row hashes for changed hashable entities (before snapshotting for audit). These are
        // per-row canonicals, independent of the chain head, so they don't need the gate.
        foreach (var e in auditable)
        {
            if (e.State is EntityState.Added or EntityState.Modified && e.Entity is IHashableEntity hashable)
                hashable.RowHash = _hasher.ComputeRowHash(hashable);
        }

        return new PreparedAudit(auditable, caseNumbers, evidenceCases, actor, now, reason, replacedOwned, notes);
    }

    /// <summary>
    /// BUG-639: upkeep re-hashes the rows it fills in, and its entry records the new hash, so a row changed outside CaseBook
    /// (any field) whose derived value was cleared too would be filled in and signed off clean. So each hashable row an
    /// upkeep save changes must be vouched for as it was read: it matches its stored hash and that hash is the one its trail
    /// last recorded; or, where the trail records none (a row from before v1.5.1, or from before row hashes), it agrees
    /// with its trail and its child rows are in it, as the upgrade requires (RowHashUpgrade), and the check isn't strict
    /// yet. A row that isn't is put back as read, so nothing of it is saved: the writer skips it and the record check
    /// reports it. The upgrade's own saves change only the hash, and it has vouched for each row itself (some, a row a
    /// migration wrote, have no trail to vouch for them here).
    /// </summary>
    private void RefuseUnvouchedUpkeep(AppDbContext ctx)
    {
        PutBackChangedSinceRead(ctx);
        var changed = ctx.ChangeTracker.Entries()
            .Where(e => e.State == EntityState.Modified && e.Entity is IHashableEntity && !e.Metadata.IsOwned() && ChangesContent(e))
            .ToList();
        if (changed.Count == 0) return;
        var replacedOwned = ctx.ChangeTracker.Entries().Where(x => x.Metadata.IsOwned() && x.State == EntityState.Deleted).ToList();
        var strict = new Lazy<bool>(() => ctx.AppSettings.AsNoTracking()
            .Any(s => s.Key == RowIntegrityVerifier.UpgradeMarkerKey && s.Value == RowIntegrityVerifier.UpgradeMarkerValue));
        foreach (var group in changed.GroupBy(e => e.Entity.GetType()))
        {
            var records = new RowIntegrityVerifier.ChainRecords();
            var trails = new Dictionary<string, TrailSnapshot>(StringComparer.OrdinalIgnoreCase);
            ReadTrail(ctx, group.Key.Name, group.Select(e => ((Entity)e.Entity).Id.ToString()).ToList(), records, trails);
            foreach (var e in group)
            {
                if (Vouched(ctx, e, AsRead(e, replacedOwned), records, trails, strict)) continue;
                if (e.References.Any(r => r.TargetEntry is { State: EntityState.Added or EntityState.Deleted } t && t.Metadata.IsOwned()))
                    throw new InvalidOperationException("CaseBook's upkeep doesn't replace a record's details. Nothing was saved.");
                foreach (var r in e.References)
                    if (r.TargetEntry is { State: EntityState.Modified } t && t.Metadata.IsOwned()) PutBackAsRead(t);
                PutBackAsRead(e);
            }
        }
    }

    /// <summary>
    /// BUG-657: a row an upkeep save changes (its hash alone, as the upgrade and the hash back-fill do, or a value) whose
    /// stored hash isn't the one it was read with was saved by someone since: its hash, computed from the row as read,
    /// would overwrite theirs. It's put back as read and left for the next start. Run under the gate, so no audited save
    /// can land between this read and the commit (as an UPDATE guarded by WHERE RowHash = the hash read).
    /// </summary>
    private static void PutBackChangedSinceRead(AppDbContext ctx)
    {
        var rows = ctx.ChangeTracker.Entries()
            .Where(e => e.State == EntityState.Modified && e.Entity is IHashableEntity && !e.Metadata.IsOwned())
            .ToList();
        foreach (var group in rows.GroupBy(e => e.Metadata.ClrType))
        {
            var ids = group.Select(e => ((Entity)e.Entity).Id).ToArray();
            // BUG-660: unwrapped, so a database timeout surfaces as itself (the start-up fills and the upgrade catch it).
            var now = StoredHashesOf.MakeGenericMethod(group.Key)
                .Invoke(null, System.Reflection.BindingFlags.DoNotWrapExceptions, null, [ctx, ids], null) as Dictionary<Guid, string?> ?? [];
            foreach (var e in group)
            {
                var read = e.Property(nameof(IHashableEntity.RowHash)).OriginalValue as string;
                if (now.TryGetValue(((Entity)e.Entity).Id, out var stored) && string.Equals(stored, read, StringComparison.Ordinal)) continue;
                foreach (var r in e.References)
                    if (r.TargetEntry is { State: EntityState.Modified } t && t.Metadata.IsOwned()) PutBackAsRead(t);
                PutBackAsRead(e);
            }
        }
    }

    private static readonly System.Reflection.MethodInfo StoredHashesOf =
        typeof(AuditChainInterceptor).GetMethod(nameof(StoredHashes), System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;

    private static Dictionary<Guid, string?> StoredHashes<T>(DbContext ctx, Guid[] ids) where T : Entity, IHashableEntity
    {
        var result = new Dictionary<Guid, string?>();
        foreach (var chunk in ids.Chunk(500))
            foreach (var row in ctx.Set<T>().AsNoTracking().IgnoreQueryFilters().Where(r => chunk.Contains(r.Id))
                         .Select(r => new { r.Id, RowHash = EF.Property<string?>(r, nameof(IHashableEntity.RowHash)) }).ToList())
                result[row.Id] = row.RowHash;
        return result;
    }

    private bool Vouched(AppDbContext ctx, EntityEntry e, IHashableEntity asRead, RowIntegrityVerifier.ChainRecords records,
        Dictionary<string, TrailSnapshot> trails, Lazy<bool> strict)
    {
        var id = ((Entity)e.Entity).Id.ToString();
        var stored = e.Property(nameof(IHashableEntity.RowHash)).OriginalValue as string;
        if (!records.TryGet((e.Entity.GetType().Name, id), out var last) || last.Deleted) return false;
        if (stored is { Length: > 0 } && !_hasher.RowHashMatches(asRead, stored)) return false;
        trails.TryGetValue(id, out var trail);
        if (last.Hash is not null)
            // BUG-646: a hash in an older format leaves out values format 4 brought in (a case's kept jurisdictions), so a
            // row matching it may still have been changed there; it must agree with its trail too, as the upgrade asks.
            // CAP-07: from format 4 on, the hash vouches when it covers what the row holds; no row hashed before format 5
            // can hold a value format 5 brought in (how a regulator was notified), as CaseBook hashes it with what it sets.
            return stored is { Length: > 0 } && string.Equals(last.Hash, stored, StringComparison.OrdinalIgnoreCase)
                   && Canonical.Covers(Math.Max(Canonical.FormatOf(stored), 4), asRead.BuildCanonicalContent)
                   && (Canonical.FormatOf(stored) >= 4 || trail?.Agrees(asRead) == true);
        if (strict.Value || trail is null || !trail.Agrees(asRead)) return false;
        var children = RowHashUpgrade.HashedChildren(asRead).ToList();
        if (children.Count == 0) return true;
        var childRecords = new RowIntegrityVerifier.ChainRecords();
        foreach (var g in children.GroupBy(c => c.GetType().Name))
            ReadTrail(ctx, g.Key, g.Select(c => c.Id.ToString()).ToList(), childRecords, null);
        return RowHashUpgrade.ChildOutsideTheTrail(asRead, childRecords) is null;
    }

    // Each record's entries, in sequence order, into its latest recorded hash and (when asked) what its trail describes.
    private static void ReadTrail(DbContext ctx, string type, List<string> ids, RowIntegrityVerifier.ChainRecords records,
        Dictionary<string, TrailSnapshot>? trails)
    {
        foreach (var chunk in ids.Chunk(500))
            foreach (var a in ctx.Set<AuditLogEntry>().AsNoTracking()
                         .Where(a => a.EntityType == type && a.EntityId != null && chunk.Contains(a.EntityId))
                         .OrderBy(a => a.Sequence).ToList())
            {
                records.Add(a);
                if (trails is null) continue;
                if (!trails.TryGetValue(a.EntityId!, out var trail)) trails[a.EntityId!] = trail = new TrailSnapshot();
                trail.Add(a.Action, a.AfterJson);
            }
    }

    private static bool ChangesContent(EntityEntry e) =>
        e.Properties.Any(p => p.IsModified && !p.Metadata.IsShadowProperty() && p.Metadata.Name != nameof(IHashableEntity.RowHash))
        || e.References.Any(r => r.TargetEntry is { State: EntityState.Added or EntityState.Modified or EntityState.Deleted } t
                                 && t.Metadata.IsOwned());

    // A copy of the row as it was read: its changed values (and its changed or replaced value objects') put back.
    private static IHashableEntity AsRead(EntityEntry e, IReadOnlyList<EntityEntry> replacedOwned)
    {
        var copy = TrailSnapshot.CopyOf((IHashableEntity)e.Entity);
        WithOriginals(e, copy);
        foreach (var r in e.References)
        {
            if (r.TargetEntry is not { } t || !t.Metadata.IsOwned()) continue;
            if (t.State == EntityState.Modified && r.Metadata.GetGetter().GetClrValueUsingContainingEntity(copy) is { } owned)
                WithOriginals(t, owned);   // the copy's own copy of the value object
            else if (t.State == EntityState.Added)
                SetClr(r.Metadata, copy, ReplacedBy(t, e, replacedOwned)?.Entity);
        }
        return copy;
    }

    private static void WithOriginals(EntityEntry e, object target)
    {
        foreach (var p in e.Properties)
            if (p.IsModified && !p.Metadata.IsShadowProperty())
                SetClr(p.Metadata, target, p.OriginalValue);
    }

    // As EF sets it: through the property (its setter may be private), else its backing field.
    private static void SetClr(IPropertyBase p, object target, object? value)
    {
        if (p.PropertyInfo is { CanWrite: true } prop) prop.SetValue(target, value);
        else p.FieldInfo?.SetValue(target, value);
    }

    private static void PutBackAsRead(EntityEntry e)
    {
        e.CurrentValues.SetValues(e.OriginalValues);
        e.State = EntityState.Unchanged;
    }

    /// <summary>
    /// Phase 2 (under the gate): read the current chain head and append the chained audit lines. Called
    /// only while <see cref="AuditChainGate"/> is held, so the head read and the append are atomic
    /// against other writers.
    /// </summary>
    private void AppendChain(DbContext ctx, PreparedAudit p)
    {
        var (auditable, caseNumbers, evidenceCases, actor, now, reason, replacedOwned, notes) = p;

        var head = ctx.Set<AuditLogEntry>().AsNoTracking().OrderByDescending(a => a.Sequence).FirstOrDefault();
        var newEntries = new List<AuditLogEntry>(auditable.Count);
        // BUG-167: the time is taken before the gate and the sequence under it, so a save that waited could follow one
        // that prepared later. An entry is never earlier than the one before it, so a time range (a compliance bundle's
        // day or quarter) is a run of consecutive sequence numbers with no gap at its edges.
        if (head is not null && head.AtUtc > now) now = head.AtUtc;

        foreach (var e in auditable)
        {
            var entity = (Entity)e.Entity;
            var type = e.Entity.GetType().Name;
            var (action, before, after, changedFields) = Describe(e, replacedOwned);

            // Skip a pure "touch": an update whose only changed columns are the freshness stamps
            // (ModifiedAtUtc/ModifiedBy). It never alters the tamper-evident canonical (RowHash stays put),
            // and the substantive action that caused it — e.g. adding an assignment, note, or timeline entry —
            // is recorded by its own audit entry. Logging the touch on the parent only adds noise.
            if (action == AuditAction.Update && changedFields.All(IsTouchOnly))
                continue;

            string? caseNumber = entity is Case c ? c.CaseNumber
                : CaseIdOf(e, evidenceCases) is { } cid && caseNumbers.TryGetValue(cid, out var cn) ? cn
                : null;

            var entry = new AuditLogEntry
            {
                AtUtc = now,
                Actor = actor,
                Action = action,
                EntityType = type,
                EntityId = entity.Id.ToString(),
                CaseNumber = caseNumber,
                // A human identity for the changed thing, captured now so the trail reads "Update ActionItem —
                // Rotate exposed credentials" instead of an opaque type + GUID (folded into the hash only when set).
                EntityLabel = Cap(LabelFor(entity), MaxEntityLabel),
                // Name the fields that actually moved (e.g. "Update Case — Legal hold") so the trail reads as
                // what changed, not just that "something" did. The full before/after is in the JSON below.
                Summary = Cap(AuditChangeDetail.ComposeSummary(action, type, changedFields), MaxSummary),
                BeforeJson = before,
                AfterJson = after,
                // A correction reason only makes sense against an in-place update, not a create/delete.
                Reason = action == AuditAction.Update ? reason : null
            };
            _hasher.ChainAppend(entry, head);
            head = entry;
            newEntries.Add(entry);
        }

        // CAP-12 review: as AuditWriter writes one, but in this save's transaction.
        foreach (var n in notes)
        {
            var entry = new AuditLogEntry
            {
                AtUtc = now, Actor = actor, Action = n.Action, EntityType = n.EntityType, EntityId = n.EntityId,
                CaseNumber = n.CaseNumber, Summary = Cap(n.Summary, MaxSummary)!
            };
            _hasher.ChainAppend(entry, head);
            head = entry;
            newEntries.Add(entry);
        }

        ctx.Set<AuditLogEntry>().AddRange(newEntries);
    }

    /// <summary>Carries the phase-1 snapshot from <see cref="Prepare"/> to the gated <see cref="AppendChain"/>.</summary>
    private sealed record PreparedAudit(
        IReadOnlyList<EntityEntry> Auditable,
        IReadOnlyDictionary<Guid, string> CaseNumbers,
        IReadOnlyDictionary<Guid, Guid> EvidenceCases,
        string Actor,
        DateTimeOffset Now,
        string? Reason,
        IReadOnlyList<EntityEntry> ReplacedOwned,
        IReadOnlyList<AuditNote> Notes);

    private static readonly string[] NoFields = Array.Empty<string>();

    private static (AuditAction action, string? before, string? after, IReadOnlyList<string> changedFields) Describe(EntityEntry e,
        IReadOnlyList<EntityEntry> replacedOwned)
    {
        switch (e.State)
        {
            case EntityState.Added:
                return (AuditAction.Create, null, Snapshot(e, current: true), NoFields);
            case EntityState.Deleted:
                return (AuditAction.Delete, Snapshot(e, current: false), null, NoFields);
            default:
                return DescribeUpdate(e, replacedOwned);
        }
    }

    /// <summary>
    /// Builds the before/after diff for an update. Owned value objects (LegalReferral / Materiality /
    /// ThirdParty) share the owner's row but are tracked as separate, excluded entries — so their changes are
    /// folded into the owner's diff here, keyed "Nav.Prop" (e.g. "Materiality.Status"). Without this, a
    /// referral or materiality determination shows only as an empty "Update Case" (just the row-hash/touch).
    /// </summary>
    private static (AuditAction, string?, string?, IReadOnlyList<string>) DescribeUpdate(EntityEntry e,
        IReadOnlyList<EntityEntry> replacedOwned)
    {
        var before = new Dictionary<string, object?>();
        var after = new Dictionary<string, object?>();
        var names = new List<string>();

        foreach (var p in e.Properties.Where(p => p.IsModified && !p.Metadata.IsShadowProperty()))
        {
            before[p.Metadata.Name] = Shown(p.Metadata, p.OriginalValue);
            after[p.Metadata.Name] = Shown(p.Metadata, p.CurrentValue);
            names.Add(p.Metadata.Name);
        }

        foreach (var reference in e.References)
        {
            var target = reference.TargetEntry;
            if (target is null || !target.Metadata.IsOwned()) continue;
            if (target.State is not (EntityState.Added or EntityState.Modified or EntityState.Deleted)) continue;

            var nav = reference.Metadata.Name;
            // BUG-333: replacing the whole VO tracks the new instance as Added; its before-values are the replaced
            // instance's (the Deleted entry of the same owned navigation and owner).
            var replaced = target.State == EntityState.Added ? ReplacedBy(target, e, replacedOwned) : null;
            foreach (var p in target.Properties)
            {
                if (p.Metadata.IsShadowProperty()) continue; // owner FK / key
                var moved = target.State is EntityState.Added or EntityState.Deleted || p.IsModified;
                if (!moved) continue;
                var key = $"{nav}.{p.Metadata.Name}";
                // A true first time (nothing replaced) reads from the type's default — "No" / "Undetermined" — rather
                // than an "absent" dash.
                var was = target.State != EntityState.Added ? p.OriginalValue
                    : replaced is not null ? replaced.Property(p.Metadata.Name).OriginalValue
                    : DefaultOf(p.Metadata.ClrType);
                var now = target.State == EntityState.Deleted ? null : p.CurrentValue;
                if (Equals(was, now)) continue; // BUG-333: only what actually moved
                before[key] = was;
                after[key] = now;
                names.Add(key);
            }
        }

        // BUG-06: the row hash is set after change detection ran, so it never shows as modified. Record it on every
        // update (the integrity check compares a record with the hash its latest entry holds), and count a change to
        // it as a real change: a case whose data elements changed has only a touched row, but a new hash.
        if (e.Entity is IHashableEntity hashable && e.Metadata.FindProperty(nameof(IHashableEntity.RowHash)) is not null)
        {
            var was = e.OriginalValues[nameof(IHashableEntity.RowHash)] as string;
            after[nameof(IHashableEntity.RowHash)] = hashable.RowHash;
            if (!string.Equals(was, hashable.RowHash, StringComparison.Ordinal) && !names.Contains(nameof(IHashableEntity.RowHash)))
            {
                before[nameof(IHashableEntity.RowHash)] = was;
                names.Add(nameof(IHashableEntity.RowHash));
            }
        }

        return (AuditAction.Update,
            JsonSerializer.Serialize(before, Json),
            JsonSerializer.Serialize(after, Json),
            names);
    }

    // BUG-333: the owned instance an Added one replaced: the Deleted entry of the same owned type (one per navigation)
    // whose owner key is this owner's.
    private static EntityEntry? ReplacedBy(EntityEntry added, EntityEntry owner, IReadOnlyList<EntityEntry> replacedOwned) =>
        replacedOwned.FirstOrDefault(d => d.Metadata == added.Metadata && OwnedBy(d, owner));

    // Whether an owned entry belongs to this owner (its ownership key is the owner's key).
    private static bool OwnedBy(EntityEntry owned, EntityEntry owner)
    {
        if (owned.Metadata.FindOwnership() is not { } ownership || ownership.PrincipalEntityType.ClrType != owner.Metadata.ClrType)
            return false;
        var fk = ownership.Properties;
        var pk = ownership.PrincipalKey.Properties;
        return Enumerable.Range(0, fk.Count).All(i => Equals(owned.Property(fk[i].Name).CurrentValue, owner.Property(pk[i].Name).CurrentValue));
    }

    /// <summary>
    /// BUG-392: a Create (current values) or Delete (original values) snapshot with the owned value objects folded in,
    /// keyed "Nav.Prop" as <see cref="DescribeUpdate"/> keys them. They're tracked as their own (unaudited) entries, so a
    /// third-party case's vendor details, or a referral made at creation, never reached the trail.
    /// </summary>
    private static string Snapshot(EntityEntry e, bool current)
    {
        var values = current ? e.CurrentValues : e.OriginalValues;
        var map = new Dictionary<string, object?>();
        foreach (var p in values.Properties)
        {
            if (p.IsShadowProperty()) continue;
            map[p.Name] = Shown(p, values[p.Name]);
        }
        foreach (var reference in e.References)
        {
            if (reference.TargetEntry is not { } target || !target.Metadata.IsOwned()) continue;
            var owned = current ? target.CurrentValues : target.OriginalValues;
            foreach (var p in owned.Properties)
            {
                if (p.IsShadowProperty()) continue;   // owner FK / key
                map[$"{reference.Metadata.Name}.{p.Name}"] = owned[p.Name];
            }
        }
        return JsonSerializer.Serialize(map, Json);
    }

    // The "empty" prior value for a property whose owned VO was added wholesale: the zero of a value type
    // (false, Undetermined, 0), or null for strings / nullable types.
    private static object? DefaultOf(Type clrType) =>
        clrType.IsValueType && Nullable.GetUnderlyingType(clrType) is null ? Activator.CreateInstance(clrType) : null;


    /// <summary>
    /// REV-02: the case number for every case this save's entries belong to. Cases tracked by the save are read from
    /// the tracker; any other (a service that checked the case without tracking it, such as an evidence upload or a
    /// report) is looked up, so the line still carries its case number and appears in that case's trail. A chain-of-
    /// custody event belongs to its evidence's case.
    /// </summary>
    private static (Dictionary<Guid, string> Numbers, Dictionary<Guid, Guid> EvidenceCases) CaseNumbersFor(
        DbContext ctx, IReadOnlyList<EntityEntry> auditable)
    {
        var numbers = ctx.ChangeTracker.Entries<Case>().ToDictionary(e => e.Entity.Id, e => e.Entity.CaseNumber);
        var evidenceCases = ctx.ChangeTracker.Entries<Evidence>().ToDictionary(e => e.Entity.Id, e => e.Entity.CaseId);
        if (auditable.Count == 0) return (numbers, evidenceCases);

        var unknownEvidence = auditable.Select(e => e.Entity).OfType<ChainOfCustodyEvent>().Select(c => c.EvidenceId)
            .Where(id => !evidenceCases.ContainsKey(id)).Distinct().ToList();
        if (unknownEvidence.Count > 0)
            foreach (var row in ctx.Set<Evidence>().AsNoTracking().IgnoreQueryFilters().Where(v => unknownEvidence.Contains(v.Id))
                         .Select(v => new { v.Id, v.CaseId }).ToList())
                evidenceCases[row.Id] = row.CaseId;

        var unknownCases = auditable.Where(e => e.Entity is not Case).Select(e => CaseIdOf(e, evidenceCases)).OfType<Guid>()
            .Where(id => !numbers.ContainsKey(id)).Distinct().ToList();
        if (unknownCases.Count > 0)
            foreach (var row in ctx.Set<Case>().AsNoTracking().IgnoreQueryFilters().Where(c => unknownCases.Contains(c.Id))
                         .Select(c => new { c.Id, c.CaseNumber }).ToList())
                numbers[row.Id] = row.CaseNumber;
        return (numbers, evidenceCases);
    }

    private static Guid? CaseIdOf(EntityEntry e, IReadOnlyDictionary<Guid, Guid> evidenceCases) =>
        TryGetCaseId(e) ?? (e.Entity is ChainOfCustodyEvent c && evidenceCases.TryGetValue(c.EvidenceId, out var id) ? id : null);

    private static Guid? TryGetCaseId(EntityEntry e)
    {
        var prop = e.Metadata.FindProperty("CaseId");
        if (prop is null) return null;
        var val = e.CurrentValues[prop];
        return val is Guid g ? g : null;
    }

    /// <summary>
    /// A short human identity for the changed entity, captured at write time so an audit line names <em>what</em>
    /// was changed. Structured records use their natural key (a task's title, an IOC's value); free-text records
    /// use their opening words. Entities with no cheap self-label (e.g. a relationship between two IDs) return
    /// null and are still identified by the resolved reference values in the diff.
    /// </summary>
    // BUG-02: the label column is nvarchar(300). It's set before the entry is hashed, so the stored label is the hashed one.
    private const int MaxEntityLabel = 300;
    private const int MaxSummary = 2000;   // REV-03: AuditLog column lengths
    internal const int MaxReason = 2000;

    private static string? Cap(string? s, int max) => s is null || s.Length <= max ? s : s[..(max - 1)] + "…";

    private static string? LabelFor(Entity entity) => entity switch
    {
        Case c => c.Title,
        ActionItem a => a.Title,
        ActionItemComment aic => Snippet(aic.Body),
        TimelineEntry t => Snippet(t.Description),
        AnalystNote n => Snippet(n.Body),
        ImprovementAction ia => ia.Title,
        PostIncidentReview => "Post-incident review",
        CaseEntity ce => string.IsNullOrWhiteSpace(ce.Label) ? ce.Value : $"{ce.Label} ({ce.Value})",
        Evidence ev => ev.OriginalFileName,
        CaseAssignment asg => string.IsNullOrWhiteSpace(asg.UserDisplayName) ? asg.UserId : asg.UserDisplayName,
        CaseTechnique tech => tech.TechniqueId,
        JurisdictionNotice n => $"Notice to {n.Jurisdiction}",
        CaseParty p => p.Name,   // CAP-34
        ApiToken t => $"{t.Name} ({t.Kind})",   // REV-05
        _ => null
    };

    // First line of a free-text body, trimmed to a headline length (fits the audit column and the label column).
    private static string? Snippet(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var firstLine = text.TrimStart().Split('\n', 2)[0].Trim();
        const int max = 120;
        return firstLine.Length <= max ? firstLine : firstLine[..(max - 1)] + "…";
    }
}
