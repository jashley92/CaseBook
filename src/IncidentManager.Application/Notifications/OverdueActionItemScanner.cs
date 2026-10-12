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
    IClock clock,
    IUserDirectory? users = null,
    IRoleDirectory? roles = null)
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
        var rows = await (
            from a in db.ActionItems.AsNoTracking()
            where a.DueAtUtc != null && a.DueAtUtc < now
                  && a.Status != ActionItemStatus.Done && a.Status != ActionItemStatus.Cancelled
            join c in db.Cases.AsNoTracking().ExcludingExercises() on a.CaseId equals c.Id // PROD-43: skip drills
            where c.Phase != CasePhase.Closed && !c.IsArchived // BUG-12: no reminders for a closed or archived case
            select new
            {
                Item = new OverdueActionItem(c.Id, c.CaseNumber, c.Title, c.IncidentCommander, a.Id, a.Title, a.DueAtUtc!.Value, a.Owner),
                c.IsRestricted, Team = c.Assignments.Select(x => x.UserId).ToList()
            })
            .ToListAsync(ct);
        // BUG-96: on a restricted case, an owner who can't see it isn't told about its task; the IC is instead.
        var overdue = rows.Select(r => r.Item with
        {
            OwnerUserId = TaskReminderAudience.Owner(r.IsRestricted, r.Item.IncidentCommanderUserId, r.Team, r.Item.OwnerUserId, users, roles)
        }).ToList();

        // Only alert on items not already reminded for this due date (once per episode).
        var newly = overdue.Where(i => tracker.TryMarkNotified(i.ActionItemId, i.DueAtUtc)).ToList();
        // BUG-08: a reminder or escalation that wasn't delivered is un-marked, so the next scan sends it again.
        if (newly.Count > 0)
        {
            using var watch = DeliveryWatch.Begin();
            await notifications.OnActionItemsOverdueAsync(newly, ct);
            if (watch.Failed)
            {
                foreach (var i in newly) tracker.ForgetNotified(i.ActionItemId, i.DueAtUtc);
                newly = [];
            }
        }

        var escalated = escalation is null ? [] : Escalations(overdue, escalation, now);
        if (escalated.Count > 0)
        {
            using var watch = DeliveryWatch.Begin();
            await notifications.OnActionItemsEscalatedAsync(escalated, ct);
            if (watch.Failed)
            {
                foreach (var e in escalated) tracker.ForgetEscalated(e.Item.ActionItemId, e.Item.DueAtUtc, (int)e.Tier);
                escalated = [];
            }
        }

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
