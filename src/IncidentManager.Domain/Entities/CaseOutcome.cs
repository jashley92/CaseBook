using IncidentManager.Domain.Common;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// HR-01: what a case concluded when it closed (e.g. "Confirmed", "Policy violation", "False positive"). Admin-managed
/// reference data like <see cref="DataElement"/>: a case stores the outcome's stable <see cref="Key"/> (never renamed,
/// so case hashes keep verifying), while the label, description and order are editable display attributes. Built-in
/// outcomes can be relabelled, reordered and archived but not deleted; an outcome a case recorded is never deleted.
/// </summary>
public class CaseOutcome : AuditableEntity, IHashableEntity
{
    /// <summary>Stable machine key (e.g. "FalsePositive"): what a case stores. Assigned once and never changed.</summary>
    public string Key { get; set; } = string.Empty;

    /// <summary>Display label, shown in the close dialog, on the case, in lists and in the report.</summary>
    public string Label { get; set; } = string.Empty;

    /// <summary>One line on when to pick it, shown in the close dialog.</summary>
    public string? Description { get; set; }

    /// <summary>Display order (ascending); ties break on label.</summary>
    public int SortOrder { get; set; }

    /// <summary>Active outcomes are offered when closing. Archiving keeps it on cases that already recorded it.</summary>
    public bool IsActive { get; set; } = true;

    /// <summary>Seeded on first run; can be relabelled, reordered and archived but not deleted.</summary>
    public bool IsSystem { get; set; }

    public string? RowHash { get; set; }

    public string BuildCanonicalContent() => string.Join('|',
        Key, Label, Description, SortOrder, IsActive, IsSystem, CreatedBy, CreatedAtUtc.ToString("o"));
}
