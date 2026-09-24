using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Notifications;

/// <summary>
/// PROD-03: how long an item may stay overdue before its reminder widens. Hours are measured from the due
/// date; a value of 0 (or less) disables that tier.
/// </summary>
public sealed record OverdueEscalationPolicy(int IncidentCommanderAfterHours, int ManagersAfterHours);

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
    /// <summary>
    /// Scans for overdue items and notifies the newly-overdue ones; with an <paramref name="escalation"/> policy,
    /// also escalates items that have stayed overdue past each tier (PROD-03) — once per item, due date and tier.
    /// Notifications only: an escalation never reassigns, re-dates or otherwise changes the item or its case.
    /// Returns how many reminders and escalations were sent for.
    /// </summary>
    public async Task<int> ScanAndNotifyAsync(OverdueEscalationPolicy? escalation = null, CancellationToken ct = default)
    {
        var now = clock.UtcNow;
        using var db = factory.CreateDbContext();

        // Join to the case so we can address the owner (else the incident commander) without a second load.
        var overdue = await (
            from a in db.ActionItems.AsNoTracking()
            where a.DueAtUtc != null && a.DueAtUtc < now
                  && a.Status != ActionItemStatus.Done && a.Status != ActionItemStatus.Cancelled
            join c in db.Cases.AsNoTracking().ExcludingExercises() on a.CaseId equals c.Id // PROD-43: skip drills
            select new OverdueActionItem(
                c.Id, c.CaseNumber, c.Title, c.IncidentCommander,
                a.Id, a.Title, a.DueAtUtc!.Value, a.Owner))
            .ToListAsync(ct);

        // Only alert on items not already reminded for this due date (once per episode).
        var newly = overdue.Where(i => tracker.TryMarkNotified(i.ActionItemId, i.DueAtUtc)).ToList();
        if (newly.Count > 0)
            await notifications.OnActionItemsOverdueAsync(newly, ct);

        var escalated = escalation is null ? [] : Escalations(overdue, escalation, now);
        if (escalated.Count > 0)
            await notifications.OnActionItemsEscalatedAsync(escalated, ct);

        return newly.Count + escalated.Count;
    }

    /// <summary>Each item's newly reached tier(s). A lower tier not yet sent (e.g. the IC step, when the scan was
    /// off while it passed) goes out alongside the higher one, so the chain never skips a rung.</summary>
    private List<EscalatedActionItem> Escalations(IEnumerable<OverdueActionItem> overdue, OverdueEscalationPolicy policy,
        DateTimeOffset now)
    {
        var result = new List<EscalatedActionItem>();
        foreach (var item in overdue)
        {
            var hours = (now - item.DueAtUtc).TotalHours;
            foreach (var (tier, after) in new[]
            {
                (OverdueEscalationTier.IncidentCommander, policy.IncidentCommanderAfterHours),
                (OverdueEscalationTier.Managers, policy.ManagersAfterHours),
            })
            {
                if (after > 0 && hours >= after && tracker.TryMarkEscalated(item.ActionItemId, item.DueAtUtc, (int)tier))
                    result.Add(new EscalatedActionItem(item, tier, Math.Round(hours, 1)));
            }
        }
        return result;
    }
}
