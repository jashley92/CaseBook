using IncidentManager.Domain.Common;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// A durable, append-only commentary note on a single <see cref="ActionItem"/> — progress updates,
/// blockers, and hand-off context an analyst records as the follow-up is worked. It carries the owning
/// <see cref="CaseId"/> directly (like <see cref="CaseComment"/>) so the save interceptor audits and
/// hash-chains it, and so a change broadcasts to collaborators on that case. Never edited or deleted, so
/// the running commentary can't be silently rewritten.
/// </summary>
public class ActionItemComment : AuditableEntity, IHashableEntity
{
    public Guid ActionItemId { get; set; }

    /// <summary>The case the task belongs to — used for scoping, the audit case-number, and live-collab.</summary>
    public Guid CaseId { get; set; }

    public string Body { get; set; } = string.Empty;

    public string? RowHash { get; set; }

    public string BuildCanonicalContent() => string.Join('|',
        ActionItemId, CaseId, Body, CreatedBy, CreatedAtUtc.ToString("o"));
}
