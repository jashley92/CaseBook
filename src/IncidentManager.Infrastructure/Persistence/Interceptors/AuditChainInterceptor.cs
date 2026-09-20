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
        typeof(SavedView), // PROD-09 personal/shared case-queue filter sets — user convenience state, not case data
        typeof(PinnedCase), // PROD-20 per-user pinned favourites — convenience state, not case data
        typeof(PendingImport), // PROD-33 inbound import staging queue — the apply writes are audited, not the draft
        typeof(ApiToken), // PROD-34 API tokens — create/revoke are audited explicitly; per-call last-used isn't chained
        typeof(UserNotificationPreference) // PROD-39 per-user digest cadence — personal preference, not case data
    ];

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = false };

    // Freshness stamps bumped by a "touch". An update whose ONLY changed columns are these carries no
    // forensic value — see the skip in Apply.
    private static bool IsTouchOnly(string field) => field is "ModifiedAtUtc" or "ModifiedBy";

    private readonly IHashChainService _hasher;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;
    private readonly ICaseChangeNotifier _notifier;

    // Cases touched by the in-flight save, captured before commit and broadcast once it succeeds.
    private readonly HashSet<Guid> _pendingCaseIds = new();

    // REL-05: true when this save acquired the process-wide audit-chain gate in SavingChanges and must
    // release it on completion (success, failure, or cancellation). The interceptor is scoped, so a
    // context runs one save at a time — a single instance field is enough.
    private bool _gateHeld;

    public AuditChainInterceptor(IHashChainService hasher, ICurrentUser user, IClock clock, ICaseChangeNotifier notifier)
    {
        _hasher = hasher;
        _user = user;
        _clock = clock;
        _notifier = notifier;
    }

    public override int SavedChanges(SaveChangesCompletedEventData eventData, int result)
    {
        ReleaseGate();
        PublishPending();
        return base.SavedChanges(eventData, result);
    }

    public override ValueTask<int> SavedChangesAsync(
        SaveChangesCompletedEventData eventData, int result, CancellationToken ct = default)
    {
        ReleaseGate();
        PublishPending();
        return base.SavedChangesAsync(eventData, result, ct);
    }

    // REL-05: a failed or cancelled save never reaches SavedChanges, so release the gate here too (and
    // drop the pending broadcast — nothing committed).
    public override void SaveChangesFailed(DbContextErrorEventData eventData)
    {
        ReleaseGate();
        _pendingCaseIds.Clear();
        base.SaveChangesFailed(eventData);
    }

    public override Task SaveChangesFailedAsync(DbContextErrorEventData eventData, CancellationToken ct = default)
    {
        ReleaseGate();
        _pendingCaseIds.Clear();
        return base.SaveChangesFailedAsync(eventData, ct);
    }

    public override void SaveChangesCanceled(DbContextEventData eventData)
    {
        ReleaseGate();
        _pendingCaseIds.Clear();
        base.SaveChangesCanceled(eventData);
    }

    public override Task SaveChangesCanceledAsync(DbContextEventData eventData, CancellationToken ct = default)
    {
        ReleaseGate();
        _pendingCaseIds.Clear();
        return base.SaveChangesCanceledAsync(eventData, ct);
    }

    private void ReleaseGate()
    {
        if (!_gateHeld) return;
        _gateHeld = false;
        AuditChainGate.Exit();
    }

    private void PublishPending()
    {
        // The actor is whoever this unit of work belongs to — used by viewers to attribute the change (U-30).
        var actorId = _user.UserId;
        foreach (var id in _pendingCaseIds) _notifier.Publish(id, actorId);
        _pendingCaseIds.Clear();
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
                _gateHeld = true;
                AppendChain(eventData.Context, prepared);
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
                _gateHeld = true;
                AppendChain(eventData.Context, prepared);
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

        // Map tracked cases by id so child-entity audit lines can carry the case number.
        var caseNumbers = ctx.ChangeTracker.Entries<Case>()
            .ToDictionary(e => e.Entity.Id, e => e.Entity.CaseNumber);

        var auditable = ctx.ChangeTracker.Entries()
            .Where(e => e.Entity is Entity
                        && !e.Metadata.IsOwned()
                        && !NotAudited.Contains(e.Entity.GetType())
                        && e.State is EntityState.Added or EntityState.Modified or EntityState.Deleted)
            .ToList();

        // Record which cases this save touches, to broadcast once it commits (SavedChanges).
        _pendingCaseIds.Clear();
        foreach (var e in auditable)
        {
            var cid = e.Entity is Case cse ? cse.Id : TryGetCaseId(e);
            if (cid is { } id) _pendingCaseIds.Add(id);
        }

        if (auditable.Count == 0) return null;

        // Consume the analyst's optional "reason for change" for this unit of work, then clear it so a
        // later save on the same context doesn't inherit it. Only Update entries carry it (a correction).
        string? reason = null;
        if (ctx is AppDbContext app)
        {
            reason = string.IsNullOrWhiteSpace(app.PendingChangeReason) ? null : app.PendingChangeReason.Trim();
            app.PendingChangeReason = null;
        }

        // Refresh row hashes for changed hashable entities (before snapshotting for audit). These are
        // per-row canonicals, independent of the chain head, so they don't need the gate.
        foreach (var e in auditable)
        {
            if (e.State is EntityState.Added or EntityState.Modified && e.Entity is IHashableEntity hashable)
                hashable.RowHash = _hasher.ComputeRowHash(hashable);
        }

        return new PreparedAudit(auditable, caseNumbers, actor, now, reason);
    }

    /// <summary>
    /// Phase 2 (under the gate): read the current chain head and append the chained audit lines. Called
    /// only while <see cref="AuditChainGate"/> is held, so the head read and the append are atomic
    /// against other writers.
    /// </summary>
    private void AppendChain(DbContext ctx, PreparedAudit p)
    {
        var (auditable, caseNumbers, actor, now, reason) = p;

        var head = ctx.Set<AuditLogEntry>().AsNoTracking().OrderByDescending(a => a.Sequence).FirstOrDefault();
        var newEntries = new List<AuditLogEntry>(auditable.Count);

        foreach (var e in auditable)
        {
            var entity = (Entity)e.Entity;
            var type = e.Entity.GetType().Name;
            var (action, before, after, changedFields) = Describe(e);

            // Skip a pure "touch": an update whose only changed columns are the freshness stamps
            // (ModifiedAtUtc/ModifiedBy). It never alters the tamper-evident canonical (RowHash stays put),
            // and the substantive action that caused it — e.g. adding an assignment, note, or timeline entry —
            // is recorded by its own audit entry. Logging the touch on the parent only adds noise.
            if (action == AuditAction.Update && changedFields.All(IsTouchOnly))
                continue;

            string? caseNumber = entity is Case c ? c.CaseNumber
                : TryGetCaseId(e) is { } cid && caseNumbers.TryGetValue(cid, out var cn) ? cn
                : null;

            var entry = new AuditLogEntry
            {
                AtUtc = now,
                Actor = actor,
                Action = action,
                EntityType = type,
                EntityId = entity.Id.ToString(),
                CaseNumber = caseNumber,
                // Name the fields that actually moved (e.g. "Update Case — Legal hold") so the trail reads as
                // what changed, not just that "something" did. The full before/after is in the JSON below.
                Summary = AuditChangeDetail.ComposeSummary(action, type, changedFields),
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
        string Actor,
        DateTimeOffset Now,
        string? Reason);

    private static readonly string[] NoFields = Array.Empty<string>();

    private static (AuditAction action, string? before, string? after, IReadOnlyList<string> changedFields) Describe(EntityEntry e)
    {
        switch (e.State)
        {
            case EntityState.Added:
                return (AuditAction.Create, null, Serialize(e.CurrentValues, e.CurrentValues.Properties), NoFields);
            case EntityState.Deleted:
                return (AuditAction.SoftDelete, Serialize(e.OriginalValues, e.OriginalValues.Properties), null, NoFields);
            default:
                return DescribeUpdate(e);
        }
    }

    /// <summary>
    /// Builds the before/after diff for an update. Owned value objects (LegalReferral / Materiality /
    /// ThirdParty) share the owner's row but are tracked as separate, excluded entries — so their changes are
    /// folded into the owner's diff here, keyed "Nav.Prop" (e.g. "Materiality.Status"). Without this, a
    /// referral or materiality determination shows only as an empty "Update Case" (just the row-hash/touch).
    /// </summary>
    private static (AuditAction, string?, string?, IReadOnlyList<string>) DescribeUpdate(EntityEntry e)
    {
        var before = new Dictionary<string, object?>();
        var after = new Dictionary<string, object?>();
        var names = new List<string>();

        foreach (var p in e.Properties.Where(p => p.IsModified && !p.Metadata.IsShadowProperty()))
        {
            before[p.Metadata.Name] = p.OriginalValue;
            after[p.Metadata.Name] = p.CurrentValue;
            names.Add(p.Metadata.Name);
        }

        foreach (var reference in e.References)
        {
            var target = reference.TargetEntry;
            if (target is null || !target.Metadata.IsOwned()) continue;
            if (target.State is not (EntityState.Added or EntityState.Modified or EntityState.Deleted)) continue;

            var nav = reference.Metadata.Name;
            foreach (var p in target.Properties)
            {
                if (p.Metadata.IsShadowProperty()) continue; // owner FK / key
                var moved = target.State is EntityState.Added or EntityState.Deleted || p.IsModified;
                if (!moved) continue;
                var key = $"{nav}.{p.Metadata.Name}";
                // Replacing the whole VO tracks it as Added (no original), so a first-time referral/materiality
                // reads from the type's default — "No" / "Undetermined" — rather than an "absent" dash.
                before[key] = target.State == EntityState.Added ? DefaultOf(p.Metadata.ClrType) : p.OriginalValue;
                after[key] = target.State == EntityState.Deleted ? null : p.CurrentValue;
                names.Add(key);
            }
        }

        return (AuditAction.Update,
            JsonSerializer.Serialize(before, Json),
            JsonSerializer.Serialize(after, Json),
            names);
    }

    // The "empty" prior value for a property whose owned VO was added wholesale: the zero of a value type
    // (false, Undetermined, 0), or null for strings / nullable types.
    private static object? DefaultOf(Type clrType) =>
        clrType.IsValueType && Nullable.GetUnderlyingType(clrType) is null ? Activator.CreateInstance(clrType) : null;

    private static string Serialize(PropertyValues values, IEnumerable<Microsoft.EntityFrameworkCore.Metadata.IProperty> props)
    {
        var map = new Dictionary<string, object?>();
        foreach (var p in props)
        {
            if (p.IsShadowProperty()) continue;
            map[p.Name] = values[p.Name];
        }
        return JsonSerializer.Serialize(map, Json);
    }

    private static Guid? TryGetCaseId(EntityEntry e)
    {
        var prop = e.Metadata.FindProperty("CaseId");
        if (prop is null) return null;
        var val = e.CurrentValues[prop];
        return val is Guid g ? g : null;
    }
}
