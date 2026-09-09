using IncidentManager.Domain.Common;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// A category of personal / non-public information that may be affected in a case (X-03) — e.g.
/// "Social Security number", "Payment card", "Medical / health information". Formerly a fixed
/// <c>[Flags]</c> enum tuned for a NY P&amp;C insurer; now admin-managed reference data so a bank,
/// healthcare, or retail SOC can express its own PII categories without a code release.
///
/// <para>The tamper-evident hash canonical on a case stores each involved element by its stable
/// <see cref="Key"/> (see <see cref="CaseDataElement"/>) — never renamed, so old case hashes keep verifying —
/// while the <see cref="Label"/>, order, and attributes are display-only and freely editable, exactly like
/// the X-02 taxonomy layer stores a stable member name and varies only the shown label.</para>
///
/// Reference data — audited and hash-chained like <see cref="ReportProfile"/> and <see cref="StageGate"/>,
/// not case-scoped.
/// </summary>
public class DataElement : AuditableEntity, IHashableEntity
{
    /// <summary>Stable machine key (e.g. "SocialSecurityNumber") — the element's identity: the value a case
    /// stores, the tamper-evident canonical hashes, and imports match on. Assigned once and never changed.</summary>
    public string Key { get; set; } = string.Empty;

    /// <summary>Display label (editable, live) — the wording shown in the impact UI, reports, and exports.</summary>
    public string Label { get; set; } = string.Empty;

    /// <summary>Display order in the impact-assessment picker and reports (ascending); ties break on label.</summary>
    public int SortOrder { get; set; }

    /// <summary>Active elements are offered in the impact picker. Archiving one (<c>IsActive = false</c>) drops
    /// it from new selection but keeps it on cases that already recorded it — applies to built-in elements too,
    /// so a deprecated category never dangles a historical case and is never hard-deleted.</summary>
    public bool IsActive { get; set; } = true;

    /// <summary>The thirteen elements seeded on first run. System elements may be relabelled / reordered /
    /// archived but not deleted, so a stable baseline always exists.</summary>
    public bool IsSystem { get; set; }

    /// <summary>
    /// Optional comma-separated jurisdiction codes whose breach-notification law is triggered by this element
    /// (e.g. "US" for SSN, or specific states). Surfaced in the report's Business-Impact grouping (X-03). Free
    /// reference metadata — not control flow — so an IRP can express regulatory grouping without a release.
    /// </summary>
    public string? NotificationJurisdictions { get; set; }

    public string? RowHash { get; set; }

    public string BuildCanonicalContent() => string.Join('|',
        Key, Label, SortOrder, IsActive, IsSystem, NotificationJurisdictions,
        CreatedBy, CreatedAtUtc.ToString("o"));
}
