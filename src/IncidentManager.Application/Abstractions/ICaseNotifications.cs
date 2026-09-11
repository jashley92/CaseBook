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
/// Case-lifecycle notifications (who to tell, and how) — kept out of the use-case layer so recipient
/// configuration and the delivery channel live in Infrastructure. Implementations must not throw.
/// </summary>
public interface ICaseNotifications
{
    /// <summary>Called after a reclassification is persisted (e.g. to alert Legal on a Breach escalation).</summary>
    Task OnReclassifiedAsync(Case c, Classification? from, Classification to, CancellationToken ct = default);

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
}
