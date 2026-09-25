using IncidentManager.Domain.Common;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// A customer-designed Word (.docx) report template in the template library (PROD-47). Admins upload several;
/// a <see cref="ReportProfile"/> names one as its default (<see cref="ReportProfile.TemplateId"/>), and whoever
/// generates a Word report can pick another. The file itself lives in the report-template store, keyed by
/// <see cref="Entity.Id"/>. Admin reference data: audited and hash-chained like <see cref="ReportProfile"/>.
/// </summary>
public class ReportTemplate : AuditableEntity, IHashableEntity
{
    /// <summary>What admins and analysts pick it by, e.g. "Examiner pack" or "Board summary".</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>The uploaded file's original name, offered when an admin downloads it to edit.</summary>
    public string FileName { get; set; } = string.Empty;

    /// <summary>SHA-256 of the current file, so the audit trail and each generated report record exactly which file was used.</summary>
    public string Sha256 { get; set; } = string.Empty;

    public long SizeBytes { get; set; }

    /// <summary>Archived templates stay listed for admins (and in history) but can't be picked for new reports.</summary>
    public bool IsActive { get; set; } = true;

    public string? RowHash { get; set; }

    public string BuildCanonicalContent() => string.Join('|',
        Name, FileName, Sha256, SizeBytes, IsActive, CreatedBy, CreatedAtUtc.ToString("o"));
}
