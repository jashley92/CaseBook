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

/// <summary>
/// CAP-03: one page of the filtered trail, newest first, whether older entries follow it and whether newer ones are
/// before it. CAP-03 review: <see cref="HasNewer"/> is false only on the newest page.
/// </summary>
public sealed record AuditPage(IReadOnlyList<AuditLogEntry> Entries, bool HasOlder, bool HasNewer = false);

/// <summary>
/// CAP-03 review: which page of the trail to read, by sequence rather than by offset (keyset paging), so entries written
/// while someone pages neither repeat nor go missing. <see cref="Newest"/> is the first page; <see cref="Older"/> the
/// entries below the last sequence shown; <see cref="Newer"/> the ones above the first shown.
/// </summary>
public readonly record struct AuditPageAt(long? OlderThan, long? NewerThan)
{
    public static AuditPageAt Newest => default;
    public static AuditPageAt Older(long lastShown) => new(lastShown, null);
    public static AuditPageAt Newer(long firstShown) => new(null, firstShown);
}

/// <summary>CAP-03: an audit-trail CSV and how many entries it holds (at most the limit it was built with).</summary>
public sealed record AuditExport(string Csv, int Rows, bool Truncated);
