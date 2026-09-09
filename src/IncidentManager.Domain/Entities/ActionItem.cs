using IncidentManager.Domain.Common;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Domain.Entities;

/// <summary>An after-action follow-up item tracked to completion.</summary>
public class ActionItem : AuditableEntity, IHashableEntity
{
    public Guid CaseId { get; set; }
    public string Title { get; set; } = string.Empty;
    public string? Description { get; set; }

    /// <summary>Assigned owner (AD UPN or display name).</summary>
    public string? Owner { get; set; }
    public DateTimeOffset? DueAtUtc { get; set; }
    public ActionItemStatus Status { get; set; } = ActionItemStatus.Open;
    public DateTimeOffset? CompletedAtUtc { get; set; }

    public bool IsOverdue(DateTimeOffset nowUtc) =>
        DueAtUtc is { } due && Status is not (ActionItemStatus.Done or ActionItemStatus.Cancelled) && due < nowUtc;

    public string? RowHash { get; set; }

    public string BuildCanonicalContent() => string.Join('|',
        CaseId, Title, Description, Owner, DueAtUtc?.ToString("o"), (int)Status, CompletedAtUtc?.ToString("o"));
}
