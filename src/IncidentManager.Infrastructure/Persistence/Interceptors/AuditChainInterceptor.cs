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
        if (eventData.Context is not null)
        {
            var prepared = Prepare(eventData.Context);
            if (prepared is not null)
            {
                // REL-05: hold the gate from the head read through commit (released in the completion
                // callbacks) so a concurrent append can't read the same head and fork the chain.
                AuditChainGate.Enter();
                StateOf(eventData.Context).GateHeld = true;
                AppendOrRelease(eventData.Context, prepared);
            }
        }
        return result;
    }

    public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(
        DbContextEventData eventData, InterceptionResult<int> result, CancellationToken ct = default)
    {
        if (eventData.Context is not null)
        {
            var prepared = Prepare(eventData.Context);
            if (prepared is not null)
            {
                await AuditChainGate.EnterAsync(ct);
                StateOf(eventData.Context).GateHeld = true;
                AppendOrRelease(eventData.Context, prepared);
            }
        }
        return result;
    }

    /// <summary>
    /// Phase 1 (no gate): detect changes, snapshot which cases the save touches, consume the change
    /// reason, and refresh row hashes (each independent of the chain head). Returns the auditable
    /// entries + context needed to append, or null when the save carries no forensic change.
    /// </summary>
    private PreparedAudit? Prepare(DbContext ctx)
    {
        ctx.ChangeTracker.DetectChanges();

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
        foreach (var e in auditable)
        {
            var cid = e.Entity is Case cse ? cse.Id : TryGetCaseId(e);
            if (cid is not { } id) continue;
            if (!pending.TryGetValue(id, out var items)) pending[id] = items = [];
            items.Add(new CaseChangeItem(e.Entity.GetType().Name, ((Entity)e.Entity).Id, e.State switch
            {
                EntityState.Added => CaseChangeOp.Added, EntityState.Deleted => CaseChangeOp.Deleted, _ => CaseChangeOp.Modified
            }));
        }

        if (auditable.Count == 0) return null;

        // Consume the analyst's optional "reason for change" for this unit of work, then clear it so a
        // later save on the same context doesn't inherit it. Only Update entries carry it (a correction).
        string? reason = null;
        if (ctx is AppDbContext app)
        {
            reason = string.IsNullOrWhiteSpace(app.PendingChangeReason) ? null : app.PendingChangeReason.Trim();
            app.PendingChangeReason = null;
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

        return new PreparedAudit(auditable, caseNumbers, evidenceCases, actor, now, reason, replacedOwned);
    }

    /// <summary>
    /// Phase 2 (under the gate): read the current chain head and append the chained audit lines. Called
    /// only while <see cref="AuditChainGate"/> is held, so the head read and the append are atomic
    /// against other writers.
    /// </summary>
    private void AppendChain(DbContext ctx, PreparedAudit p)
    {
        var (auditable, caseNumbers, evidenceCases, actor, now, reason, replacedOwned) = p;

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
        IReadOnlyList<EntityEntry> ReplacedOwned);

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
