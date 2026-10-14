using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
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
    IClock clock,
    IUserDirectory? users = null,
    IRoleDirectory? roles = null)
{
    /// <summary>
    /// Scans for items due within <paramref name="leadHours"/> and notifies the not-yet-reminded ones.
    /// Returns how many were sent for.
    /// </summary>
    public async Task<int> ScanAndNotifyAsync(double leadHours, CancellationToken ct = default)
    {
        // BUG-262: a lead window from the server's settings file isn't checked; past the setting's limit it's the limit.
        leadHours = Math.Min(leadHours, Admin.SettingsCatalog.MaxWaitHours);
        var now = clock.UtcNow;
        var horizon = now.AddHours(leadHours > 0 ? leadHours : 24);
        using var db = factory.CreateDbContext();

        // Join to the case so we can address the owner (else the incident commander) without a second load.
        var rows = await (
            from a in db.ActionItems.AsNoTracking()
            where a.DueAtUtc != null && a.DueAtUtc >= now && a.DueAtUtc <= horizon
                  && a.Status != ActionItemStatus.Done && a.Status != ActionItemStatus.Cancelled
            join c in db.Cases.AsNoTracking().ExcludingExercises() on a.CaseId equals c.Id // PROD-43: skip drills
            where c.Phase != CasePhase.Closed && !c.IsArchived // BUG-12: no reminders for a closed or archived case
            select new
            {
                Item = new DueSoonActionItem(c.Id, c.CaseNumber, c.Title, c.IncidentCommander, a.Id, a.Title, a.DueAtUtc!.Value, a.Owner),
                c.IsRestricted, Team = c.Assignments.Select(x => x.UserId).ToList()
            })
            .ToListAsync(ct);
        // BUG-96: on a restricted case, an owner who can't see it isn't told about its task; the IC is instead.
        var dueSoon = rows.Select(r => r.Item with
        {
            OwnerUserId = TaskReminderAudience.Owner(r.IsRestricted, r.Item.IncidentCommanderUserId, r.Team, r.Item.OwnerUserId, users, roles)
        }).ToList();

        // Only alert on items not already reminded for this due date (once per approaching deadline). BUG-147: the
        // marks are kept only if the sends finish.
        using var marks = NotificationMarkBatch.Begin();
        var newly = dueSoon.Where(i => tracker.TryMarkNotified(i.ActionItemId, i.DueAtUtc)).ToList();
        if (newly.Count > 0)
        {
            // BUG-08: a reminder that wasn't delivered is un-marked, so the next scan sends it again.
            using var watch = DeliveryWatch.Begin();
            await notifications.OnActionItemsDueSoonAsync(newly, (int)Math.Round(leadHours > 0 ? leadHours : 24), ct);
            foreach (var i in newly.Where(i => watch.ShouldRetry(i.ActionItemId.ToString())).ToList())
            {
                tracker.Forget(i.ActionItemId, i.DueAtUtc);
                newly.Remove(i);
            }
        }

        marks.Complete();
        return newly.Count;
    }
}
