using IncidentManager.Domain.Entities;
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

    /// <summary>
    /// CAP-03: one administered setting's history (e.g. "Email:From"): the <c>AppSetting</c> entries for that key,
    /// across every row that has held it (a reset removes the row, and the next change adds a new one).
    /// </summary>
    public string? SettingKey { get; init; }

    public bool IsEmpty =>
        string.IsNullOrWhiteSpace(Actor) && Action is null &&
        string.IsNullOrWhiteSpace(EntityType) && FromUtc is null && ToUtc is null && string.IsNullOrWhiteSpace(SettingKey);
}

/// <summary>CAP-03: one page of the filtered trail, newest first, and whether older entries follow it.</summary>
public sealed record AuditPage(IReadOnlyList<AuditLogEntry> Entries, bool HasOlder);

/// <summary>CAP-03: an audit-trail CSV and how many entries it holds (at most the limit it was built with).</summary>
public sealed record AuditExport(string Csv, int Rows, bool Truncated);
