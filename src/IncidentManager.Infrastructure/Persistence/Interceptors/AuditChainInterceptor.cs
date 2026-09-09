using System.Text.Json;
using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Common;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
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
        typeof(CaseAccessEvent) // C-05 read/access telemetry — high-volume, out of the tamper-evident chain
    ];

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = false };

    private readonly IHashChainService _hasher;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;
    private readonly ICaseChangeNotifier _notifier;

    // Cases touched by the in-flight save, captured before commit and broadcast once it succeeds.
    private readonly HashSet<Guid> _pendingCaseIds = new();

    public AuditChainInterceptor(IHashChainService hasher, ICurrentUser user, IClock clock, ICaseChangeNotifier notifier)
    {
        _hasher = hasher;
        _user = user;
        _clock = clock;
        _notifier = notifier;
    }

    public override int SavedChanges(SaveChangesCompletedEventData eventData, int result)
    {
        PublishPending();
        return base.SavedChanges(eventData, result);
    }

    public override ValueTask<int> SavedChangesAsync(
        SaveChangesCompletedEventData eventData, int result, CancellationToken ct = default)
    {
        PublishPending();
        return base.SavedChangesAsync(eventData, result, ct);
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
        if (eventData.Context is not null) Apply(eventData.Context);
        return result;
    }

    public override ValueTask<InterceptionResult<int>> SavingChangesAsync(
        DbContextEventData eventData, InterceptionResult<int> result, CancellationToken ct = default)
    {
        if (eventData.Context is not null) Apply(eventData.Context);
        return ValueTask.FromResult(result);
    }

    private void Apply(DbContext ctx)
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

        if (auditable.Count == 0) return;

        // Consume the analyst's optional "reason for change" for this unit of work, then clear it so a
        // later save on the same context doesn't inherit it. Only Update entries carry it (a correction).
        string? reason = null;
        if (ctx is AppDbContext app)
        {
            reason = string.IsNullOrWhiteSpace(app.PendingChangeReason) ? null : app.PendingChangeReason.Trim();
            app.PendingChangeReason = null;
        }

        // 1) Refresh row hashes for changed hashable entities (before snapshotting for audit).
        foreach (var e in auditable)
        {
            if (e.State is EntityState.Added or EntityState.Modified && e.Entity is IHashableEntity hashable)
                hashable.RowHash = _hasher.ComputeRowHash(hashable);
        }

        // 2) Build audit lines and chain them onto the current head.
        var head = ctx.Set<AuditLogEntry>().AsNoTracking().OrderByDescending(a => a.Sequence).FirstOrDefault();
        var newEntries = new List<AuditLogEntry>(auditable.Count);

        foreach (var e in auditable)
        {
            var entity = (Entity)e.Entity;
            var type = e.Entity.GetType().Name;
            var (action, before, after) = Describe(e);

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
                Summary = $"{action} {type}",
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

    private static (AuditAction action, string? before, string? after) Describe(EntityEntry e)
    {
        switch (e.State)
        {
            case EntityState.Added:
                return (AuditAction.Create, null, Serialize(e.CurrentValues, e.CurrentValues.Properties));
            case EntityState.Deleted:
                return (AuditAction.SoftDelete, Serialize(e.OriginalValues, e.OriginalValues.Properties), null);
            default:
                var changed = e.Properties.Where(p => p.IsModified).Select(p => p.Metadata).ToList();
                return (AuditAction.Update,
                    Serialize(e.OriginalValues, changed),
                    Serialize(e.CurrentValues, changed));
        }
    }

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
