using IncidentManager.Domain.Common;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Domain.Entities;

/// <summary>A generated report artifact (Word working draft or locked/hashed final PDF).</summary>
public class Report : AuditableEntity
{
    public Guid CaseId { get; set; }
    public int Version { get; set; }
    public ReportFormat Format { get; set; }
    public string FileName { get; set; } = string.Empty;
    public string StoragePath { get; set; } = string.Empty;

    /// <summary>SHA-256 of the generated file, embedded in the PDF and verifiable later.</summary>
    public string ContentSha256 { get; set; } = string.Empty;

    /// <summary>True for the locked, approved final; false for editable working drafts.</summary>
    public bool IsFinal { get; set; }
    public string? ApprovedBy { get; set; }
    public DateTimeOffset? ApprovedAtUtc { get; set; }

    /// <summary>
    /// Approves and finalizes this report (E-15) — the locked PDF an examiner receives. Only a generated
    /// PDF can be finalized (a Word file is an editable working draft), and a report is approved once.
    /// Separation-of-duties (approver ≠ generator) is enforced by the service, where the policy lives.
    /// </summary>
    public void Approve(string approver, DateTimeOffset nowUtc)
    {
        if (string.IsNullOrWhiteSpace(approver))
            throw new ArgumentException("An approver is required.", nameof(approver));
        if (Format != ReportFormat.Pdf)
            throw new InvalidOperationException("Only a PDF report can be approved as the locked final — generate a PDF first.");
        if (IsFinal)
            throw new InvalidOperationException("This report is already approved and final.");

        IsFinal = true;
        ApprovedBy = approver;
        ApprovedAtUtc = nowUtc;
    }
}
