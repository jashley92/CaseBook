namespace IncidentManager.Domain.Enums;

/// <summary>Application-wide roles, mapped from AD security groups.</summary>
public enum AppRole
{
    Analyst = 0,
    IncidentCommander = 1,
    Manager = 2,
    LegalPrivacy = 3,
    SysAdmin = 4
}

/// <summary>The kind of action captured in the tamper-evident audit log.</summary>
public enum AuditAction
{
    Create = 0,
    Update = 1,
    SoftDelete = 2,
    Access = 3,
    Login = 4,
    Logout = 5,
    ClassificationChanged = 6,
    StatusChanged = 7,
    EvidenceUploaded = 8,
    EvidenceDownloaded = 9,
    ReportGenerated = 10,
    ReportFinalized = 11,
    LegalReferral = 12,
    IntegritySeal = 13,
    IntegrityVerification = 14,
    Export = 15,
    /// <summary>PROD-13: an analyst attested a hand-off of evidence outside CaseBook.</summary>
    EvidenceTransferred = 16
}

/// <summary>
/// Which document a stored <see cref="Entities.Report"/> is. The case report is the examiner-facing record;
/// the lessons-learned report (E-26/PROD-41) is kept separate so it can be handled and shared on its own terms.
/// </summary>
public enum ReportKind
{
    Case = 0,
    LessonsLearned = 1
}

/// <summary>Output format of a generated report.</summary>
public enum ReportFormat
{
    Word = 0,
    Pdf = 1
}

/// <summary>
/// What kind of read/access a <c>CaseAccessEvent</c> records (C-05). Distinct from
/// <see cref="AuditAction"/>: these live in the out-of-chain access log, not the tamper-evident audit.
/// </summary>
public enum AccessType
{
    /// <summary>An authenticated, authorized open of a case detail view.</summary>
    CaseOpen = 0,
    /// <summary>A download of a case evidence file.</summary>
    EvidenceDownload = 1,
    /// <summary>A download of a generated case report (Word/PDF).</summary>
    ReportDownload = 2,
    /// <summary>A data export (metrics CSV, IOC feed, compliance bundle, audit CSV…).</summary>
    Export = 3
}
