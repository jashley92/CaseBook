using IncidentManager.Application.Abstractions;
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
    IClock clock)
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
        var candidates = await db.Cases.AsNoTracking()
            .Where(c => !c.IsArchived && c.Phase != CasePhase.Closed)
            .Select(c => new Candidate(
                c.Id, c.CaseNumber, c.Title, c.Severity, c.IncidentCommander, c.CreatedAtUtc,
                db.AuditLog.Where(a => a.CaseNumber == c.CaseNumber).Max(a => (DateTimeOffset?)a.AtUtc),
                c.Assignments.Select(a => a.UserId).ToList()))
            .ToListAsync(ct);

        var reminders = new List<StaleCaseReminder>();
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
                recipients.Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
                lastActivity, (int)Math.Floor(daysInactive), threshold));
        }

        if (reminders.Count > 0)
            await notifications.OnCasesStaleAsync(reminders, ct);

        return reminders.Count;
    }

    private sealed record Candidate(
        Guid CaseId, string CaseNumber, string CaseTitle, Severity Severity, string? IncidentCommander,
        DateTimeOffset CreatedAtUtc, DateTimeOffset? LastAuditAtUtc, List<string> AssigneeUserIds);
}
