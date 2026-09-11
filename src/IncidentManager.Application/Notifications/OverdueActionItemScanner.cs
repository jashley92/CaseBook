using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Notifications;

/// <summary>
/// Finds after-action items that have passed their due date and, for those newly overdue since the last
/// run, dispatches an overdue reminder through <see cref="ICaseNotifications"/> (E-03b). Read-only over the
/// data — it records nothing to the database, so it never touches the audit chain (the "ops telemetry out
/// of the chain" principle, like the H-04 backup-health reader and the F-17 verifier's reads). The
/// scheduled hosted service calls <see cref="ScanAndNotifyAsync"/> on a slow cadence.
/// </summary>
public sealed class OverdueActionItemScanner(
    IAppDbContextFactory factory,
    ICaseNotifications notifications,
    IOverdueActionItemTracker tracker,
    IClock clock)
{
    /// <summary>Scans for overdue items and notifies the newly-overdue ones. Returns how many were sent for.</summary>
    public async Task<int> ScanAndNotifyAsync(CancellationToken ct = default)
    {
        var now = clock.UtcNow;
        using var db = factory.CreateDbContext();

        // Join to the case so we can address the owner (else the incident commander) without a second load.
        var overdue = await (
            from a in db.ActionItems.AsNoTracking()
            where a.DueAtUtc != null && a.DueAtUtc < now
                  && a.Status != ActionItemStatus.Done && a.Status != ActionItemStatus.Cancelled
            join c in db.Cases.AsNoTracking() on a.CaseId equals c.Id
            select new OverdueActionItem(
                c.Id, c.CaseNumber, c.Title, c.IncidentCommander,
                a.Id, a.Title, a.DueAtUtc!.Value, a.Owner))
            .ToListAsync(ct);

        // Only alert on items not already reminded for this due date (once per episode).
        var newly = overdue.Where(i => tracker.TryMarkNotified(i.ActionItemId, i.DueAtUtc)).ToList();
        if (newly.Count > 0)
            await notifications.OnActionItemsOverdueAsync(newly, ct);

        return newly.Count;
    }
}
