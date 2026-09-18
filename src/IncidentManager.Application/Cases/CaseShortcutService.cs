using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Cases;

/// <summary>
/// Quick-access shortcuts to cases for the current user (PROD-20): recently-opened cases (derived from the
/// C-05 access log) and pinned favourites. Every result is re-scoped through
/// <see cref="CaseQueryExtensions.ForUser"/> at read time, so a case that later became restricted or was
/// un-shared never leaks through a stale shortcut. Pins are per-user convenience state, out of the audit chain.
/// </summary>
public sealed class CaseShortcutService
{
    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;

    public CaseShortcutService(IAppDbContextFactory factory, ICurrentUser user, IClock clock)
    {
        _factory = factory;
        _user = user;
        _clock = clock;
    }

    /// <summary>The user's most-recently-opened cases (distinct, newest first), need-to-know scoped.</summary>
    public async Task<IReadOnlyList<CaseListItem>> RecentAsync(int take = 5, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var me = _user.UserId;

        // Case-open events newest first; dedup by case in memory (LINQ Distinct preserves first-seen order).
        var recent = await db.CaseAccessEvents.AsNoTracking()
            .Where(e => e.ActorUserId == me && e.AccessType == AccessType.CaseOpen && e.CaseId != null)
            .OrderByDescending(e => e.LastSeenUtc)
            .Select(e => e.CaseId!.Value)
            .Take(take * 8)
            .ToListAsync(ct);

        var ids = recent.Distinct().Take(take * 2).ToList();
        if (ids.Count == 0) return Array.Empty<CaseListItem>();

        var items = await ScopedItemsAsync(db, ids, ct);
        return Reorder(items, ids).Take(take).ToList();
    }

    /// <summary>The user's pinned cases (most-recently pinned first), need-to-know scoped.</summary>
    public async Task<IReadOnlyList<CaseListItem>> PinnedAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var me = _user.UserId;

        var pins = await db.PinnedCases.AsNoTracking()
            .Where(p => p.UserId == me)
            .OrderByDescending(p => p.PinnedAtUtc)
            .Select(p => p.CaseId)
            .ToListAsync(ct);
        if (pins.Count == 0) return Array.Empty<CaseListItem>();

        var items = await ScopedItemsAsync(db, pins, ct);
        return Reorder(items, pins).ToList();
    }

    public async Task<bool> IsPinnedAsync(Guid caseId, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var me = _user.UserId;
        return await db.PinnedCases.AsNoTracking().AnyAsync(p => p.UserId == me && p.CaseId == caseId, ct);
    }

    /// <summary>Pins or unpins a case for the current user; returns the new pinned state.</summary>
    public async Task<bool> TogglePinAsync(Guid caseId, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var me = _user.UserId;

        var existing = await db.PinnedCases.FirstOrDefaultAsync(p => p.UserId == me && p.CaseId == caseId, ct);
        if (existing is not null)
        {
            db.PinnedCases.Remove(existing);
            await db.SaveChangesAsync(ct);
            return false;
        }

        // Only a case the user can actually see may be pinned.
        var canSee = await db.Cases.AsNoTracking().ForUser(_user).AnyAsync(c => c.Id == caseId, ct);
        if (!canSee) throw new InvalidOperationException("Case not found.");

        db.PinnedCases.Add(new PinnedCase { UserId = me, CaseId = caseId, PinnedAtUtc = _clock.UtcNow });
        await db.SaveChangesAsync(ct);
        return true;
    }

    // Fetch the given ids as list items, need-to-know scoped (order restored by the caller).
    private Task<List<CaseListItem>> ScopedItemsAsync(IAppDbContext db, List<Guid> ids, CancellationToken ct) =>
        db.Cases.AsNoTracking().ForUser(_user)
            .Where(c => ids.Contains(c.Id))
            .Select(c => new CaseListItem(
                c.Id, c.CaseNumber, c.Title, c.Classification, c.Phase, c.Severity, c.Origin,
                c.IsRestricted, c.LegalReferral.IsReferred, c.LegalHold, c.CreatedAtUtc, c.IncidentCommander,
                c.DetectedAtUtc, c.ContainedAtUtc, c.ResolvedAtUtc))
            .ToListAsync(ct);

    // Restore the requested id order (scoping may drop some, and the DB returns rows unordered).
    private static IEnumerable<CaseListItem> Reorder(List<CaseListItem> items, List<Guid> order)
    {
        var rank = new Dictionary<Guid, int>(order.Count);
        for (var i = 0; i < order.Count; i++) rank[order[i]] = i;
        return items.OrderBy(c => rank.TryGetValue(c.Id, out var r) ? r : int.MaxValue);
    }
}
