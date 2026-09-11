using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Notifications;

/// <summary>
/// Finds after-action items whose due date falls inside the lead window (due, but not yet passed) and, for
/// those not already reminded for this due date, dispatches a "due soon" reminder through
/// <see cref="ICaseNotifications"/> (E-03d). The overdue scan handles items once they pass their due date;
/// this one fires <em>ahead</em> of the deadline. Read-only over the data — it records nothing, so it never
/// touches the audit chain (the "ops telemetry out of the chain" principle, like the overdue scanner). The
/// scheduled hosted service calls <see cref="ScanAndNotifyAsync"/> on a slow cadence with the lead window.
/// </summary>
public sealed class DueSoonActionItemScanner(
    IAppDbContextFactory factory,
    ICaseNotifications notifications,
    IDueSoonActionItemTracker tracker,
    IClock clock)
{
    /// <summary>
    /// Scans for items due within <paramref name="leadHours"/> and notifies the not-yet-reminded ones.
    /// Returns how many were sent for.
    /// </summary>
    public async Task<int> ScanAndNotifyAsync(double leadHours, CancellationToken ct = default)
    {
        var now = clock.UtcNow;
        var horizon = now.AddHours(leadHours > 0 ? leadHours : 24);
        using var db = factory.CreateDbContext();

        // Join to the case so we can address the owner (else the incident commander) without a second load.
        var dueSoon = await (
            from a in db.ActionItems.AsNoTracking()
            where a.DueAtUtc != null && a.DueAtUtc >= now && a.DueAtUtc <= horizon
                  && a.Status != ActionItemStatus.Done && a.Status != ActionItemStatus.Cancelled
            join c in db.Cases.AsNoTracking() on a.CaseId equals c.Id
            select new DueSoonActionItem(
                c.Id, c.CaseNumber, c.Title, c.IncidentCommander,
                a.Id, a.Title, a.DueAtUtc!.Value, a.Owner))
            .ToListAsync(ct);

        // Only alert on items not already reminded for this due date (once per approaching deadline).
        var newly = dueSoon.Where(i => tracker.TryMarkNotified(i.ActionItemId, i.DueAtUtc)).ToList();
        if (newly.Count > 0)
            await notifications.OnActionItemsDueSoonAsync(newly, (int)Math.Round(leadHours > 0 ? leadHours : 24), ct);

        return newly.Count;
    }
}
