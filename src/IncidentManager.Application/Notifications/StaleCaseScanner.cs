using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Notifications;

/// <summary>
/// Per-severity "how many days of quiet make a case stale" thresholds (PROD-38). A value of <c>0</c> (or
/// less) disables the nudge for that severity — so, e.g., Informational cases are never nudged by default.
/// A Critical going quiet matters much sooner than a Low, hence the per-severity scale.
/// </summary>
public sealed record StaleThresholdDays(int Informational, int Low, int Medium, int High, int Critical)
{
    public int For(Severity severity) => severity switch
    {
        Severity.Critical => Critical,
        Severity.High => High,
        Severity.Medium => Medium,
        Severity.Low => Low,
        _ => Informational,
    };
}

/// <summary>
/// Finds open cases that have gone quiet — no recorded activity for longer than their severity's threshold —
/// and nudges each case's incident commander + assignees (PROD-38). "Activity" is the most recent
/// tamper-evident audit entry for the case (which captures every note, timeline step, status/severity change,
/// entity edit, comment and action-item change), falling back to the case's creation instant. Read-only over
/// case data — it records nothing and never changes case state, so it stays out of the audit chain. Nudges
/// once per quiet spell (the tracker keys on the last-activity instant, so any new activity resets it). The
/// scheduled hosted service calls <see cref="ScanAndNotifyAsync"/> on a moderate cadence.
/// </summary>
public sealed class StaleCaseScanner(
    IAppDbContextFactory factory,
    ICaseNotifications notifications,
    IStaleCaseTracker tracker,
    IClock clock,
    IUserDirectory? users = null,
    IRoleDirectory? roles = null,
    ApiTokens.ITokenOwnerCheck? owners = null)
{
    /// <summary>
    /// Scans open cases and nudges the newly-stale ones per the supplied per-severity thresholds. Returns how
    /// many nudges were sent for. A no-op (returns 0) when every threshold is disabled.
    /// </summary>
    public async Task<int> ScanAndNotifyAsync(StaleThresholdDays thresholds, CancellationToken ct = default)
    {
        if (thresholds.Informational <= 0 && thresholds.Low <= 0 && thresholds.Medium <= 0
            && thresholds.High <= 0 && thresholds.Critical <= 0)
            return 0;

        var now = clock.UtcNow;
        using var db = factory.CreateDbContext();

        // Last activity = the newest audit entry for the case (denormalized CaseNumber), else its creation.
        // The audit chain records every unit of case work, so this is a complete "when did anything last
        // happen here" signal without enumerating each child collection. Elevated-events-only intake keeps
        // the open-case set small, so the correlated MAX is cheap on this cadence.
        var candidates = await db.Cases.AsNoTracking().ExcludingExercises() // PROD-43: no reminders for drills
            .Where(c => !c.IsArchived && c.Phase != CasePhase.Closed)
            .Select(c => new Candidate(
                c.Id, c.CaseNumber, c.Title, c.Severity, c.IncidentCommander, c.CreatedAtUtc,
                // C18: CaseBook's upkeep (a start-up fill, the row-hash upgrade) isn't activity on the case.
                db.AuditLog.Where(a => a.CaseNumber == c.CaseNumber && a.Reason != Integrity.IntegrityUpkeep.Reason).Max(a => (DateTimeOffset?)a.AtUtc),
                c.IsRestricted, c.Assignments.Select(a => a.UserId).ToList(), c.TeamId))
            .ToListAsync(ct);

        // BUG-147: the marks below are kept only if the sends finish.
        using var marks = NotificationMarkBatch.Begin();
        var reminders = new List<StaleCaseReminder>();
        var audience = new ReminderAudience(users, roles, owners);
        foreach (var cand in candidates)
        {
            var threshold = thresholds.For(cand.Severity);
            if (threshold <= 0) continue;   // this severity's nudge is disabled

            var lastActivity = cand.LastAuditAtUtc is { } a && a > cand.CreatedAtUtc ? a : cand.CreatedAtUtc;
            var daysInactive = (now - lastActivity).TotalDays;
            if (daysInactive < threshold) continue;

            // Once per quiet spell: any new activity advances lastActivity and so re-arms the nudge.
            if (!tracker.TryMarkNotified(cand.CaseId, lastActivity)) continue;

            var recipients = new List<string>();
            if (!string.IsNullOrWhiteSpace(cand.IncidentCommander)) recipients.Add(cand.IncidentCommander!);
            recipients.AddRange(cand.AssigneeUserIds.Where(id => !string.IsNullOrWhiteSpace(id)));

            reminders.Add(new StaleCaseReminder(
                cand.CaseId, cand.CaseNumber, cand.CaseTitle, cand.Severity,
                // BUG-377: only people still entitled to the case; with nobody left it's tried again next scan (WF-96).
                await audience.EntitledOnlyAsync(recipients.Distinct(StringComparer.OrdinalIgnoreCase),
                    cand.IsRestricted, cand.IncidentCommander, cand.AssigneeUserIds, ct),
                lastActivity, (int)Math.Floor(daysInactive), threshold, cand.TeamId));
        }

        if (reminders.Count > 0)
        {
            // BUG-08: a nudge that wasn't delivered is un-marked, so the next scan sends it again.
            using var watch = DeliveryWatch.Begin();
            await notifications.OnCasesStaleAsync(reminders, ct);
            foreach (var r in reminders.Where(r => watch.ShouldRetry(r.CaseId.ToString())).ToList())
            {
                tracker.Forget(r.CaseId, r.LastActivityAtUtc);
                reminders.Remove(r);
            }
        }

        marks.Complete();
        return reminders.Count;
    }

    private sealed record Candidate(
        Guid CaseId, string CaseNumber, string CaseTitle, Severity Severity, string? IncidentCommander,
        DateTimeOffset CreatedAtUtc, DateTimeOffset? LastAuditAtUtc, bool IsRestricted, List<string> AssigneeUserIds, Guid? TeamId);
}
