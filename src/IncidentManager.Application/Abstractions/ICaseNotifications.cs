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
    /// Called by the scheduled regulatory-deadline scan (PROD-37) with the cases that have <em>newly</em>
    /// crossed into an at-risk or breached notification-deadline band and have not yet been reminded for it.
    /// Resolves each case's recipients (incident commander + assignees), groups by recipient, and sends one
    /// reminder each. A default no-op is provided so existing implementers (and test doubles) need not change;
    /// the real <c>CaseNotifications</c> overrides it. Gated by config; a no-op when no recipients resolve.
    /// Reminds only — a human still records the reported milestone; nothing here mutates case state.
    /// </summary>
    Task OnDeadlineApproachingAsync(IReadOnlyList<DeadlineReminder> reminders, CancellationToken ct = default)
        => Task.CompletedTask;
}
