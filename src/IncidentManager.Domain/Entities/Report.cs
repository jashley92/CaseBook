using IncidentManager.Domain.Common;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Domain.Entities;

/// <summary>A generated report (a Word document; earlier releases also produced PDFs, which stay readable): a
/// working draft until approved as the locked, hashed final.</summary>
public class Report : AuditableEntity
{
    public Guid CaseId { get; set; }
    public int Version { get; set; }

    /// <summary>Case report (default) or the separate lessons-learned report. Versions number per kind + format.</summary>
    public ReportKind Kind { get; set; } = ReportKind.Case;
    public ReportFormat Format { get; set; }
    public string FileName { get; set; } = string.Empty;
    public string StoragePath { get; set; } = string.Empty;

    /// <summary>SHA-256 of the generated file, embedded in the PDF and verifiable later.</summary>
    public string ContentSha256 { get; set; } = string.Empty;

    /// <summary>PROD-45: the TLP marking printed on this report (null for reports generated before markings).</summary>
    public TlpLevel? Tlp { get; set; }

    /// <summary>PROD-47: the Word template this report was filled from (name and SHA-256 at generation time), or
    /// null for the built-in layout. Kept by value so the record survives the template being replaced or deleted.</summary>
    public string? TemplateName { get; set; }
    public string? TemplateSha256 { get; set; }

    /// <summary>True for the locked, approved final; false for editable working drafts.</summary>
    public bool IsFinal { get; set; }
    public string? ApprovedBy { get; set; }
    public DateTimeOffset? ApprovedAtUtc { get; set; }

    /// <summary>
    /// Approves and finalizes this report (E-15): the locked final an examiner receives. The stored file and its
    /// recorded SHA-256 are the record; anyone needing a PDF saves the final as PDF in Word. Approved once.
    /// Separation-of-duties (approver ≠ generator) is enforced by the service, where the policy lives.
    /// </summary>
    public void Approve(string approver, DateTimeOffset nowUtc)
    {
        if (string.IsNullOrWhiteSpace(approver))
            throw new ArgumentException("An approver is required.", nameof(approver));
        if (IsFinal)
            throw new InvalidOperationException("This report is already approved and final.");

        IsFinal = true;
        ApprovedBy = approver;
        ApprovedAtUtc = nowUtc;
    }
}
