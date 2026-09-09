using IncidentManager.Domain.Common;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// An admin-authored, reusable <b>report profile</b> (E-28): a named section layout a case can be printed
/// with — e.g. an "Executive summary" (a curated subset) versus a "Full examiner pack" (every section) —
/// so the report body isn't locked to one global deployment setting. A case optionally picks a profile
/// (<see cref="Case.ReportProfileId"/>); when it does, the profile's <see cref="SectionLayout"/> overrides
/// the global <c>Reporting:SectionLayout</c> for that case's reports and its in-app preview.
///
/// Profiles are admin reference data — audited and hash-chained like <see cref="CaseTemplate"/> and
/// <see cref="StageGate"/>, not case-scoped. The layout string reuses the same token grammar as the global
/// setting (a comma-separated list of section tokens, each optionally '!'-prefixed to hide it), parsed by
/// the application's ReportLayout helper, so an unknown/missing token is tolerant and forward-compatible.
/// </summary>
public class ReportProfile : AuditableEntity, IHashableEntity
{
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }

    /// <summary>Inactive profiles are kept (for audit/history) but hidden from the case picker.</summary>
    public bool IsActive { get; set; } = true;

    /// <summary>Display order in the picker (ascending); ties break on name.</summary>
    public int SortOrder { get; set; }

    /// <summary>
    /// The report body section layout — the same comma-separated, optionally '!'-prefixed token grammar as
    /// the global <c>Reporting:SectionLayout</c> setting. Blank means "all sections in default order".
    /// </summary>
    public string? SectionLayout { get; set; }

    public string? RowHash { get; set; }

    public string BuildCanonicalContent() => string.Join('|',
        Name, Description, IsActive, SortOrder, SectionLayout, CreatedBy, CreatedAtUtc.ToString("o"));
}
