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

    /// <summary>INV-13: the kind of response work this is; General for a task not tied to a phase.</summary>
    public TaskKind Kind { get; set; } = TaskKind.General;

    /// <summary>INV-13: open (not done or cancelled).</summary>
    public bool IsOpen => Status is not (ActionItemStatus.Done or ActionItemStatus.Cancelled);
    public DateTimeOffset? CompletedAtUtc { get; set; }

    public bool IsOverdue(DateTimeOffset nowUtc) =>
        DueAtUtc is { } due && Status is not (ActionItemStatus.Done or ActionItemStatus.Cancelled) && due < nowUtc;

    public string? RowHash { get; set; }

    // INV-13: the kind is folded in only when it isn't General, so existing rows keep their exact hash.
    public string BuildCanonicalContent()
    {
        var content = string.Join('|',
            CaseId, Title, Description, Owner, DueAtUtc?.ToString("o"), (int)Status, CompletedAtUtc?.ToString("o"));
        return Kind == TaskKind.General ? content : string.Join('|', content, "kind", (int)Kind);
    }
}
