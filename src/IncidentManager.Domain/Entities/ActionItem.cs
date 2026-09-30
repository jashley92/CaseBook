using IncidentManager.Domain.Common;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Domain.Entities;

/// <summary>An after-action follow-up item tracked to completion.</summary>
public class ActionItem : AuditableEntity, IHashableEntity
{
    public const int MaxTitleLength = 400;

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

    /// <summary>INV-25: the brief version whose open question this task follows up, when it was raised from one.</summary>
    public Guid? RaisedFromBriefId { get; set; }

    /// <summary>
    /// INV-28: what the task is about, when it was started from it: "entity:&lt;id&gt;", "evidence:&lt;id&gt;" or
    /// "entry:&lt;id&gt;" (a timeline entry's first version, so the link survives edits). Null for a free-standing task.
    /// </summary>
    public string? AboutRef { get; set; }

    public const string AboutEntity = "entity", AboutEvidence = "evidence", AboutEntry = "entry";

    /// <summary>The kind and id of <see cref="AboutRef"/>, or null.</summary>
    public (string Kind, Guid Id)? About =>
        AboutRef?.Split(':', 2) is [var kind, var id] && Guid.TryParse(id, out var g) ? (kind, g) : null;

    public bool IsOverdue(DateTimeOffset nowUtc) =>
        DueAtUtc is { } due && Status is not (ActionItemStatus.Done or ActionItemStatus.Cancelled) && due < nowUtc;

    public string? RowHash { get; set; }

    // INV-13: the kind is folded in only when it isn't General, so existing rows keep their exact hash.
    // INV-25: likewise the brief a task was raised from, only when set.
    public string BuildCanonicalContent()
    {
        var content = string.Join('|',
            CaseId, Title, Description, Owner, DueAtUtc?.ToString("o"), (int)Status, CompletedAtUtc?.ToString("o"));
        if (Kind != TaskKind.General) content = string.Join('|', content, "kind", (int)Kind);
        if (RaisedFromBriefId is { } b) content = string.Join('|', content, "brief", b);
        // INV-28: likewise what it's about, only when set.
        return AboutRef is { } about ? string.Join('|', content, "about", about) : content;
    }
}
