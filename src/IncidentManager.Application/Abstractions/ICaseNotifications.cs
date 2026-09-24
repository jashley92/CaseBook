using IncidentManager.Application.Sla;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Abstractions;

/// <summary>
/// A follow-up item that has passed its due date, flattened for notification (E-03b). Carries the owner id
/// and the case's incident commander so the notifier can resolve a recipient (owner, else IC) without
/// re-loading entities, plus the display fields for the email body.
/// </summary>
public sealed record OverdueActionItem(
    Guid CaseId,
    string CaseNumber,
    string CaseTitle,
    string? IncidentCommanderUserId,
    Guid ActionItemId,
    string Title,
    DateTimeOffset DueAtUtc,
    string? OwnerUserId);

/// <summary>Who an overdue follow-up item has escalated to (PROD-03). Values are the escalation order.</summary>
public enum OverdueEscalationTier
{
    /// <summary>The case's incident commander (skipped when they were the first reminder's recipient).</summary>
    IncidentCommander = 1,
    /// <summary>Everyone holding the Manager role in the user directory.</summary>
    Managers = 2,
}

/// <summary>
/// An overdue follow-up item that has stayed overdue long enough to escalate (PROD-03): the item, the tier it
/// has newly reached, and how long it has been overdue, for the email body.
/// </summary>
public sealed record EscalatedActionItem(OverdueActionItem Item, OverdueEscalationTier Tier, double HoursOverdue);

/// <summary>
/// A follow-up item whose due date is approaching but not yet passed (E-03d), flattened for notification.
/// Same shape as <see cref="OverdueActionItem"/> — carried as a distinct type so the "due soon" and
/// "overdue" notification paths (and their notify-once trackers) stay independent.
/// </summary>
public sealed record DueSoonActionItem(
    Guid CaseId,
    string CaseNumber,
    string CaseTitle,
    string? IncidentCommanderUserId,
    Guid ActionItemId,
    string Title,
    DateTimeOffset DueAtUtc,
    string? OwnerUserId);

/// <summary>
/// A case whose regulatory notification deadline (PROD-07) is approaching or already passed, flattened for
/// notification (PROD-37). Carries the resolved recipient user-ids (the incident commander plus the case's
/// assignees) so the notifier can address them without re-loading, plus the headline jurisdiction's standing
/// for the email body. <see cref="State"/> is always <see cref="SlaState.AtRisk"/> or
/// <see cref="SlaState.Breached"/> — the scanner only raises the attention-worthy bands.
/// </summary>
public sealed record DeadlineReminder(
    Guid CaseId,
    string CaseNumber,
    string CaseTitle,
    Severity Severity,
    IReadOnlyList<string> RecipientUserIds,
    SlaState State,
    string JurisdictionLabel,
    DateTimeOffset? DueAtUtc,
    TimeSpan? Remaining);

/// <summary>
/// An open case that has gone quiet — no recorded activity for longer than its severity's threshold —
/// flattened for notification (PROD-38). Carries the resolved recipient user-ids (incident commander +
/// assignees) and the quiet-spell facts for the email body.
/// </summary>
public sealed record StaleCaseReminder(
    Guid CaseId,
    string CaseNumber,
    string CaseTitle,
    Severity Severity,
    IReadOnlyList<string> RecipientUserIds,
    DateTimeOffset LastActivityAtUtc,
    int DaysInactive,
    int ThresholdDays);

/// <summary>One open, dated follow-up item on a user's work digest (PROD-39), flattened for the email body.</summary>
public sealed record DigestItem(string CaseNumber, string TaskTitle, Severity Severity, DateTimeOffset DueAtUtc);

/// <summary>
/// A single user's consolidated work digest (PROD-39): their open, dated follow-up items grouped into the
/// familiar agenda bands. Sent on the cadence they chose, in place of a scatter of per-item reminders.
/// </summary>
public sealed record UserDigest(
    string UserId,
    DigestCadence Cadence,
    IReadOnlyList<DigestItem> Overdue,
    IReadOnlyList<DigestItem> DueToday,
    IReadOnlyList<DigestItem> DueThisWeek)
{
    public int TotalItems => Overdue.Count + DueToday.Count + DueThisWeek.Count;
}

/// <summary>
/// Case-lifecycle notifications (who to tell, and how) — kept out of the use-case layer so recipient
/// configuration and the delivery channel live in Infrastructure. Implementations must not throw.
/// </summary>
public interface ICaseNotifications
{
    /// <summary>Called after a reclassification is persisted (e.g. to alert Legal on a Breach escalation).</summary>
    Task OnReclassifiedAsync(Case c, Classification? from, Classification to, CancellationToken ct = default);

    /// <summary>
    /// Called after a comment @mentioning teammates is posted (PROD-04). Emails each mentioned user (resolved
    /// via the user directory), skipping the comment's author. Best-effort and gated like the other triggers.
    /// A default no-op is provided so existing implementers (and test doubles) need not change; the real
    /// <c>CaseNotifications</c> overrides it.
    /// </summary>
    Task OnMentionedAsync(Case c, string byUserId, IReadOnlyCollection<string> mentionedUserIds,
        string commentExcerpt, CancellationToken ct = default) => Task.CompletedTask;

    /// <summary>
    /// Called after someone is assigned to a case (E-03b). Emails the assignee (resolved via the user
    /// directory) that they have a new case role. Skips self-assignments and is gated by config.
    /// </summary>
    Task OnAssignedAsync(Case c, string assigneeUserId, string assigneeDisplayName, CaseAssignmentRole role,
        string assignedByUserId, CancellationToken ct = default);

    /// <summary>
    /// Called by the scheduled overdue scan (E-03b) with the items that have <em>newly</em> become overdue.
    /// Resolves a recipient per item (its owner, else the case's incident commander), groups by recipient,
    /// and sends one reminder each. Gated by config; a no-op when no recipients resolve.
    /// </summary>
    Task OnActionItemsOverdueAsync(IReadOnlyList<OverdueActionItem> items, CancellationToken ct = default);

    /// <summary>
    /// Called by the scheduled due-soon scan (E-03d) with items whose due date falls within the lead window
    /// and that have <em>not</em> yet been reminded for this due date. Resolves a recipient per item (its
    /// owner, else the case's incident commander), groups by recipient, and sends one reminder each. Gated
    /// by config; a no-op when no recipients resolve.
    /// </summary>
    Task OnActionItemsDueSoonAsync(IReadOnlyList<DueSoonActionItem> items, int leadHours, CancellationToken ct = default);

    /// <summary>
    /// Called by the overdue scan (PROD-03) with items that have <em>newly</em> reached an escalation tier:
    /// still overdue after the configured hours, so the reminder widens from the owner to the incident
    /// commander, then to managers. Notifies only — nothing here changes the item or the case. A default no-op
    /// is provided so existing implementers (and test doubles) need not change.
    /// </summary>
    Task OnActionItemsEscalatedAsync(IReadOnlyList<EscalatedActionItem> items, CancellationToken ct = default)
        => Task.CompletedTask;

    /// <summary>
    /// Called by the scheduled regulatory-deadline scan (PROD-37) with the cases that have <em>newly</em>
    /// crossed into an at-risk or breached notification-deadline band and have not yet been reminded for it.
    /// Resolves each case's recipients (incident commander + assignees), groups by recipient, and sends one
    /// reminder each. A default no-op is provided so existing implementers (and test doubles) need not change;
    /// the real <c>CaseNotifications</c> overrides it. Gated by config; a no-op when no recipients resolve.
    /// Reminds only — a human still records the reported milestone; nothing here mutates case state.
    /// </summary>
    Task OnDeadlineApproachingAsync(IReadOnlyList<DeadlineReminder> reminders, CancellationToken ct = default)
        => Task.CompletedTask;

    /// <summary>
    /// Called by the scheduled stale-case scan (PROD-38) with the open cases that have <em>newly</em> gone
    /// quiet past their severity's threshold and have not yet been nudged for this quiet spell. Resolves each
    /// case's recipients (incident commander + assignees), groups by recipient, and sends one nudge each. A
    /// default no-op is provided so existing implementers (and test doubles) need not change; the real
    /// <c>CaseNotifications</c> overrides it. Gated by config; a no-op when no recipients resolve. Nudges
    /// only — nothing here mutates case state.
    /// </summary>
    Task OnCasesStaleAsync(IReadOnlyList<StaleCaseReminder> reminders, CancellationToken ct = default)
        => Task.CompletedTask;

    /// <summary>
    /// Called by the scheduled digest scan (PROD-39) with one user's consolidated work digest, on the cadence
    /// they opted into. Resolves the user's address and sends a single grouped summary — the one email that
    /// stands in for a scatter of per-item reminders. A default no-op is provided so existing implementers
    /// (and test doubles) need not change; the real <c>CaseNotifications</c> overrides it. A no-op when the
    /// user has no address on file. Reminds only — nothing here mutates case state.
    /// </summary>
    Task OnDigestAsync(UserDigest digest, CancellationToken ct = default) => Task.CompletedTask;

    /// <summary>
    /// PROD-15: the scheduled executive report — last quarter's program headline figures (E-31) for the managers,
    /// with a link to the full report. Default no-op so existing implementers and test doubles need not change.
    /// </summary>
    Task OnExecutiveReportAsync(IncidentManager.Application.Dashboards.ProgramReport report, CancellationToken ct = default)
        => Task.CompletedTask;
}
