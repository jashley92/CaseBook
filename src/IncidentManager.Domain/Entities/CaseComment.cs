using IncidentManager.Domain.Common;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// A durable, threaded discussion comment on a case (PROD-04). Unlike an <see cref="AnalystNote"/>
/// (an analyst's own investigation documentation), a comment is team conversation: a top-level comment
/// or a reply to one, optionally @mentioning teammates who are then notified through the notification
/// pipeline. Append-only — part of the case's tamper-evident record (audited + hash-chained), so a
/// handoff or decision discussion can never be silently rewritten.
/// </summary>
public class CaseComment : AuditableEntity, IHashableEntity
{
    public Guid CaseId { get; set; }

    /// <summary>The top-level comment this one replies to, or null for a new thread. One level of nesting.</summary>
    public Guid? ParentId { get; set; }

    public string Body { get; set; } = string.Empty;

    /// <summary>Comma-separated user ids @mentioned in this comment (notified on post). Empty when none.</summary>
    public string MentionsCsv { get; set; } = string.Empty;

    public string? RowHash { get; set; }

    public string BuildCanonicalContent() => string.Join('|',
        CaseId, ParentId, Body, MentionsCsv, CreatedBy, CreatedAtUtc.ToString("o"));
}
