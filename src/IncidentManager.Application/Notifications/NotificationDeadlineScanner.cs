using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Compliance;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Notifications;

/// <summary>
/// Finds open cases whose <b>regulatory notification deadline</b> (PROD-07) is approaching or already passed
/// and, for those newly in that band since the last run, dispatches a reminder through
/// <see cref="ICaseNotifications"/> (PROD-37). This is the deadline-clock sibling of the overdue/due-soon
/// after-action scanners: the two of those watch <em>task</em> due dates; this one watches the far more
/// consequential regulatory clock, which had no reminder before. Read-only over case data — it records
/// nothing, so it never touches the audit chain (the "ops telemetry out of the chain" principle), and it
/// never mutates case state: a human still records the reported milestone. The scheduled hosted service calls
/// <see cref="ScanAndNotifyAsync"/> on a moderate cadence.
/// </summary>
public sealed class NotificationDeadlineScanner(
    IAppDbContextFactory factory,
    NotificationDeadlineService deadlines,
    INotificationDeadlineSettingsProvider settings,
    ICaseNotifications notifications,
    IDeadlineReminderTracker tracker,
    IUserDirectory? users = null,
    IRoleDirectory? roles = null,
    ApiTokens.ITokenOwnerCheck? owners = null)
{
    /// <summary>
    /// Scans open, un-reported ladder cases, evaluates each against the administered deadline rules, and
    /// reminds the newly at-risk / breached ones (once per band). Returns how many reminders were sent for.
    /// </summary>
    public async Task<int> ScanAndNotifyAsync(CancellationToken ct = default)
    {
        // Feature-gated by the same toggle the on-case countdown uses; skip all work when it's off.
        if (!settings.Current.Enabled) return 0;

        using var db = factory.CreateDbContext();

        // Candidate set = cases that could have a running clock: not archived, not yet reported, and
        // on the IRP ladder (a Complex Event can't have started a clock under either basis). The precise
        // start/trigger test is left to NotificationDeadlineService, the single source of truth — this is
        // just a cheap pre-filter. Elevated-events-only intake keeps this set small.
        var scope = db.Cases.AsNoTracking().ExcludingExercises() // PROD-43: no real-clock reminders for drills
            // INV-43: closed cases stay in — closing doesn't answer a notification, so reminders continue until
            // the reported time is recorded.
            .Where(c => !c.IsArchived && c.ReportedAtUtc == null && c.Classification != null);

        // BUG-11: every candidate's clock in one pass, then only the ones that need attention are loaded. BUG-191: every
        // jurisdiction's clock, not just the headline's, so a breached one can't hide another's.
        var due = (await deadlines.AllNowAsync(db, scope, ct))
            .Select(h => (h.Key, Statuses: h.Value.Where(s => s.NeedsAttention).ToList()))
            .Where(h => h.Statuses.Count > 0).ToDictionary(h => h.Key, h => h.Statuses);
        if (due.Count == 0) return 0;
        var ids = due.Keys.ToList();
        var candidates = await scope.Where(c => ids.Contains(c.Id))
            .Select(c => new Candidate(
                c.Id, c.CaseNumber, c.Title, c.Severity, c.IncidentCommander, c.IsRestricted,
                c.Assignments.Select(a => a.UserId).ToList()))
            .ToListAsync(ct);

        // BUG-147: the marks below are kept only if the sends finish.
        using var marks = NotificationMarkBatch.Begin();
        var reminders = new List<DeadlineReminder>();
        var audience = new ReminderAudience(users, roles, owners);
        foreach (var cand in candidates.OrderBy(c => c.CaseNumber, StringComparer.Ordinal))
        {
            var recipients = new List<string>();
            if (!string.IsNullOrWhiteSpace(cand.IncidentCommander)) recipients.Add(cand.IncidentCommander!);
            recipients.AddRange(cand.AssigneeUserIds.Where(id => !string.IsNullOrWhiteSpace(id)));
            // BUG-377: only people still entitled to the case (a leaver, or someone whose role no longer grants ViewCases,
            // is left off). With nobody left, the reminder is tried again on the next scan, as one with no one reachable is.
            var to = await audience.EntitledOnlyAsync(recipients.Distinct(StringComparer.OrdinalIgnoreCase),
                cand.IsRestricted, cand.IncidentCommander, cand.AssigneeUserIds, ct);

            // Jurisdictions on the same clock (band and deadline) share one reminder that names them all.
            foreach (var clock in due[cand.CaseId].GroupBy(s => (s.State, s.DueAtUtc)).OrderBy(g => g.Key.DueAtUtc))
            {
                // Once per band: a fresh reminder when it enters "at risk" and again if it enters "breached".
                if (!tracker.TryMarkNotified(cand.CaseId, clock.Key.State, clock.Key.DueAtUtc)) continue;
                reminders.Add(new DeadlineReminder(
                    cand.CaseId, cand.CaseNumber, cand.CaseTitle, cand.Severity, to,
                    clock.Key.State, string.Join(", ", clock.Select(s => s.JurisdictionLabel)), clock.Key.DueAtUtc,
                    clock.First().Remaining));
            }
        }

        if (reminders.Count > 0)
        {
            // BUG-08: a reminder that wasn't delivered is un-marked, so the next scan sends it again.
            using var watch = DeliveryWatch.Begin();
            await notifications.OnDeadlineApproachingAsync(reminders, ct);
            foreach (var r in reminders.Where(r => watch.ShouldRetry(r.CaseId.ToString())).ToList())
            {
                tracker.Forget(r.CaseId, r.State, r.DueAtUtc);
                reminders.Remove(r);
            }
        }

        marks.Complete();
        return reminders.Count;
    }

    private sealed record Candidate(
        Guid CaseId, string CaseNumber, string CaseTitle, Severity Severity,
        string? IncidentCommander, bool IsRestricted, List<string> AssigneeUserIds);
}
