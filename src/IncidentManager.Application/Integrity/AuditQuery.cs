using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Integrity;

/// <summary>
/// Filter over the hash-chained audit trail (E-24). All fields are optional and AND together; a
/// null/blank field is ignored. Dates are inclusive and interpreted in UTC — the stored truth (U-29).
/// </summary>
public sealed record AuditQueryFilter
{
    /// <summary>Restrict to one case number (the per-case Audit tab always sets this).</summary>
    public string? CaseNumber { get; init; }

    /// <summary>Actor user id (exact match — the UI resolves display names).</summary>
    public string? Actor { get; init; }

    public AuditAction? Action { get; init; }

    /// <summary>Entity type name as recorded (e.g. "Case", "Evidence", "TimelineEntry").</summary>
    public string? EntityType { get; init; }

    /// <summary>Inclusive lower bound (UTC).</summary>
    public DateTimeOffset? FromUtc { get; init; }

    /// <summary>Inclusive upper bound (UTC).</summary>
    public DateTimeOffset? ToUtc { get; init; }

    public bool IsEmpty =>
        string.IsNullOrWhiteSpace(Actor) && Action is null &&
        string.IsNullOrWhiteSpace(EntityType) && FromUtc is null && ToUtc is null;
}
