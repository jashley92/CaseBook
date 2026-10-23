using IncidentManager.Domain.Common;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Domain.Entities;

/// <summary>A generated report (a Word document; earlier releases also produced PDFs, which stay readable): a
/// working draft until approved as the locked, hashed final. BUG-633: a hashed record like the rest, since who generated
/// it (the approver must be someone else), whether it's the approved final and by whom, and its version decide what an
/// examiner receives; reports from before it get their hash at the upgrade (RowHashUpgrade).</summary>
public class Report : AuditableEntity, IHashableEntity
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

    /// <summary>BUG-712: whether the stored file was written encrypted (CBE1), so reading it never guesses from its own
    /// first bytes; null for a file stored before this was kept (decided from its bytes). Set to true, as CaseBook's
    /// upkeep, when PROD-57's conversion encrypts a plain file. Hashed from format 9, only when set.</summary>
    public bool? StoredEncrypted { get; set; }

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

    public string? RowHash { get; set; }

    /// <summary>BUG-633: hashed from format 4, the first a report was hashed in. The storage path is left out, as an
    /// evidence file's is: the file there is checked against <see cref="ContentSha256"/> on every download and approval.</summary>
    public string BuildCanonicalContent() => string.Join('|',
        CaseId, Version.ToString(System.Globalization.CultureInfo.InvariantCulture), Canonical.Num(Kind), Canonical.Num(Format),
        Canonical.Text(FileName), ContentSha256, Canonical.Num(Tlp), Canonical.Text(TemplateName), TemplateSha256, IsFinal,
        Canonical.Text(ApprovedBy), Canonical.Time(ApprovedAtUtc), Canonical.Text(CreatedBy), Canonical.Time(CreatedAtUtc))
        // BUG-712: from format 9, how the file is stored, only when it's recorded, so a report from before builds what it did.
        + Canonical.Since(9, StoredEncrypted is not null, () => "|encrypted|" + (StoredEncrypted == true ? "1" : "0"));

    /// <summary>
    /// Approves and finalizes this report (E-15): the locked final an examiner receives. The stored file and its
    /// recorded SHA-256 are the record; anyone needing a PDF saves the final as PDF in Word. Approved once.
    /// Separation-of-duties (approver ≠ generator) is enforced by the service, where the policy lives.
    /// </summary>
    public void Approve(string approver, DateTimeOffset nowUtc)
    {
        if (string.IsNullOrWhiteSpace(approver))
            throw new ArgumentException("An approver is required.");
        if (IsFinal)
            throw new InvalidOperationException("This report is already approved and final.");

        IsFinal = true;
        ApprovedBy = approver;
        ApprovedAtUtc = nowUtc;
    }
}
