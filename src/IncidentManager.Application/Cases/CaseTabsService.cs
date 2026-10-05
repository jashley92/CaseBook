using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Sla;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Cases;

/// <summary>
/// One open-case tab: only what the tab strip shows (the case's header state), never the case itself. A tab that
/// isn't in front holds nothing else; the case loads when it's opened.
/// </summary>
public sealed record CaseTab(Guid CaseId, string CaseNumber, string Title, Classification? Classification, Severity Severity,
    CasePhase Phase, bool IsPinned, SlaState Clock);

/// <summary>
/// RD-21: the cases a user has open as workspace tabs, restored when they sign in again. Pinned cases are tabs that stay
/// (first, in the order they were pinned); the rest are the cases the user opened, oldest first, up to
/// <see cref="MaxOpen"/> (opening another lets go of the one least recently looked at). Need-to-know scoped at read time,
/// so a case that became restricted drops out. Per-user convenience state, outside the audit chain; opening a case is
/// recorded in the access log as before.
/// </summary>
public sealed class CaseTabsService
{
    /// <summary>The most unpinned tabs kept.</summary>
    public const int MaxOpen = 8;

    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;
    private readonly ISlaTargetsProvider _sla;

    public CaseTabsService(IAppDbContextFactory factory, ICurrentUser user, IClock clock, ISlaTargetsProvider sla)
    {
        _factory = factory;
        _user = user;
        _clock = clock;
        _sla = sla;
    }

    public async Task<IReadOnlyList<CaseTab>> ListAsync(CancellationToken ct = default)
    {
        var me = _user.UserId;
        if (string.IsNullOrEmpty(me)) return [];
        using var db = _factory.CreateDbContext();
        var pinned = await db.PinnedCases.AsNoTracking().Where(p => p.UserId == me)
            .OrderBy(p => p.PinnedAtUtc).Select(p => p.CaseId).ToListAsync(ct);
        var open = await db.OpenCaseTabs.AsNoTracking().Where(t => t.UserId == me)
            .OrderBy(t => t.OpenedAtUtc).Select(t => t.CaseId).ToListAsync(ct);
        var order = pinned.Concat(open.Where(id => !pinned.Contains(id))).ToList();
        if (order.Count == 0) return [];

        var rows = await db.Cases.AsNoTracking().ForUser(_user).Where(c => order.Contains(c.Id))
            .Select(c => new { c.Id, c.CaseNumber, c.Title, c.Classification, c.Severity, c.Phase, c.DetectedAtUtc, c.ContainedAtUtc, c.ResolvedAtUtc })
            .ToListAsync(ct);
        var now = _clock.UtcNow;
        var targets = _sla.Current;
        return order
            .Select(id => rows.FirstOrDefault(r => r.Id == id))
            .Where(r => r is not null)
            .Select(r => new CaseTab(r!.Id, r.CaseNumber, r.Title, r.Classification, r.Severity, r.Phase, pinned.Contains(r.Id),
                SlaPolicy.Evaluate(r.Severity, r.Phase, r.DetectedAtUtc, r.ContainedAtUtc, r.ResolvedAtUtc, targets, now, r.Classification).State))
            .ToList();
    }

    /// <summary>Opens (or brings forward) a case as a tab. A case the caller can't see is ignored.</summary>
    public async Task OpenAsync(Guid caseId, CancellationToken ct = default)
    {
        var me = _user.UserId;
        if (string.IsNullOrEmpty(me)) return;
        using var db = _factory.CreateDbContext();
        if (!await db.Cases.AsNoTracking().ForUser(_user).AnyAsync(c => c.Id == caseId, ct)) return;

        var now = _clock.UtcNow;
        var tabs = await db.OpenCaseTabs.Where(t => t.UserId == me).ToListAsync(ct);
        if (tabs.FirstOrDefault(t => t.CaseId == caseId) is { } tab) tab.LastSeenAtUtc = now;
        else db.OpenCaseTabs.Add(new OpenCaseTab { UserId = me, CaseId = caseId, OpenedAtUtc = now, LastSeenAtUtc = now });

        // Keep at most MaxOpen tabs that aren't pinned; let go of the least recently seen.
        var pinned = await db.PinnedCases.AsNoTracking().Where(p => p.UserId == me).Select(p => p.CaseId).ToListAsync(ct);
        var unpinned = tabs.Where(t => t.CaseId != caseId && !pinned.Contains(t.CaseId)).OrderBy(t => t.LastSeenAtUtc).ToList();
        var over = unpinned.Count + (pinned.Contains(caseId) ? 0 : 1) - MaxOpen;
        if (over > 0) db.OpenCaseTabs.RemoveRange(unpinned.Take(over));

        try { await db.SaveChangesAsync(ct); }
        catch (DbUpdateException) { /* the same case opened in another window at the same moment: it's open either way */ }
    }

    /// <summary>Closes a tab. A pinned case stays a tab until it's unpinned.</summary>
    public async Task CloseAsync(Guid caseId, CancellationToken ct = default)
    {
        var me = _user.UserId;
        using var db = _factory.CreateDbContext();
        var tab = await db.OpenCaseTabs.FirstOrDefaultAsync(t => t.UserId == me && t.CaseId == caseId, ct);
        if (tab is null) return;
        db.OpenCaseTabs.Remove(tab);
        await db.SaveChangesAsync(ct);
    }
}
