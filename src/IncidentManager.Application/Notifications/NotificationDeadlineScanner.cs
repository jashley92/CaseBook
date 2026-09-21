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
    IDeadlineReminderTracker tracker)
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

        // Candidate set = cases that could have a running clock: open, not archived, not yet reported, and
        // on the IRP ladder (a Complex Event can't have started a clock under either basis). The precise
        // start/trigger test is left to NotificationDeadlineService, the single source of truth — this is
        // just a cheap pre-filter. Elevated-events-only intake keeps this set small.
        var candidates = await db.Cases.AsNoTracking().ExcludingExercises() // PROD-43: no real-clock reminders for drills
            .Where(c => !c.IsArchived && c.Phase != CasePhase.Closed
                        && c.ReportedAtUtc == null && c.Classification != null)
            .Select(c => new Candidate(
                c.Id, c.CaseNumber, c.Title, c.Severity, c.IncidentCommander,
                c.Assignments.Select(a => a.UserId).ToList()))
            .ToListAsync(ct);

        var reminders = new List<DeadlineReminder>();
        foreach (var cand in candidates)
        {
            var eval = await deadlines.EvaluateAsync(cand.CaseId, ct);
            var headline = eval.Headline;
            if (headline is null || !headline.NeedsAttention) continue;   // on track / already reported / no clock

            // Once per band: a fresh reminder when it enters "at risk" and again if it enters "breached".
            if (!tracker.TryMarkNotified(cand.CaseId, headline.State, headline.DueAtUtc)) continue;

            var recipients = new List<string>();
            if (!string.IsNullOrWhiteSpace(cand.IncidentCommander)) recipients.Add(cand.IncidentCommander!);
            recipients.AddRange(cand.AssigneeUserIds.Where(id => !string.IsNullOrWhiteSpace(id)));

            reminders.Add(new DeadlineReminder(
                cand.CaseId, cand.CaseNumber, cand.CaseTitle, cand.Severity,
                recipients.Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
                headline.State, headline.JurisdictionLabel, headline.DueAtUtc, headline.Remaining));
        }

        if (reminders.Count > 0)
            await notifications.OnDeadlineApproachingAsync(reminders, ct);

        return reminders.Count;
    }

    private sealed record Candidate(
        Guid CaseId, string CaseNumber, string CaseTitle, Severity Severity,
        string? IncidentCommander, List<string> AssigneeUserIds);
}
