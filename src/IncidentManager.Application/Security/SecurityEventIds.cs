namespace IncidentManager.Application.Security;

/// <summary>
/// Stable event-id catalog for the outbound SIEM stream (F-18). These numbers are a public
/// contract — SIEM correlation/detection rules pin to them, so <b>never renumber</b>; only append.
/// Extends the F-16 integrity alarm (<see cref="AuditChainBroken"/> = 5001).
///
/// Ranges: 50xx integrity · 51xx authentication · 52xx authorization · 53xx data access · 54xx
/// admin/config · 55xx case governance · 59xx diagnostics.
/// </summary>
public static class SecurityEventIds
{
    // 50xx — Integrity
    public const int AuditChainBroken = 5001; // owned by F-16; may also flow through the stream
    public const int RejectedSettingOverride = 5002; // a non-whitelisted AppSettings row ignored on load (S-02 tamper signal)
    public const int EvidenceIntegrityDrift = 5003; // evidence at rest no longer matches its recorded SHA-256 (F-17)
    public const int IntegritySealRecorded = 5004;  // a seal was recorded: its copy outside CaseBook (F-26)
    public const int SealExportFailed = 5005;       // a copy of a seal failed: export folder, email or timestamp (F-26/F-27)
    public const int EvidenceKeyUnavailable = 5006; // the evidence key can't be opened: evidence and reports paused (PROD-59)
    public const int EvidenceKeyChanged = 5007;     // the evidence key: created, available again, re-protected, shares issued, a drill, a recovery (PROD-59)

    // 51xx — Authentication
    public const int AuthenticationFailed = 5101;

    // 52xx — Authorization
    public const int AuthorizationDenied = 5201; // a 403 on a page/endpoint
    public const int ActionRefused = 5202;       // an in-app action refused at the service layer (S-19)

    // 53xx — Data access (sourced from the C-05 access log)
    public const int CaseOpened = 5301;
    public const int EvidenceDownloaded = 5302;
    public const int ReportDownloaded = 5303;
    public const int DataExported = 5304;
    public const int RestrictedCaseAccessed = 5305; // a read of a restricted case (elevated severity)
    public const int DownloadRateLimited = 5306; // a download/export request refused by the per-user rate limit (F-13)
    public const int EvidenceExportedOffline = 5307; // evidence written out decrypted by casebook-keytool export (PROD-59)

    // 54xx — Admin / configuration
    public const int RoleChanged = 5401;
    public const int AdGroupMappingChanged = 5402;
    public const int SettingChanged = 5403;
    public const int ApiTokenChanged = 5404; // an API token was created or revoked (PROD-34)
    public const int ReferenceDataChanged = 5405; // CAP-06: a gate, data element, deadline rule, template, outcome, taxonomy label, report profile or Word/email template

    // 55xx — Case governance
    public const int LegalHoldPlaced = 5501;
    public const int LegalHoldReleased = 5502;
    public const int BreachEscalated = 5503;
    public const int CaseRestricted = 5504;          // a case was limited to need-to-know (S-08)
    public const int CaseRestrictionLifted = 5505;   // a case's need-to-know restriction was lifted — widens exposure (S-08)
    // CAP-06: the case lifecycle. Each carries the case number, the actor and, when set, the detection platform's id.
    public const int CaseCreated = 5506;
    public const int CasePhaseChanged = 5507;        // a move between phases other than closing or reopening (5509, 5510)
    public const int CaseReclassified = 5508;        // any reclassification except an escalation to Breach (5503)
    public const int CaseClosed = 5509;
    public const int CaseReopened = 5510;
    public const int CaseArchived = 5511;            // archived, or restored from the archive (action CaseRestored)
    public const int MaterialityRecorded = 5512;
    public const int CaseReported = 5513;            // marked reported to regulators, or one regulator's notice recorded
    public const int ReportApproved = 5514;
    public const int ImportApplied = 5515;           // a case-import document applied to a case (PROD-31/33), by a reviewer

    // 59xx — Diagnostics
    public const int SiemTest = 5901; // an admin's "Send test event" from Diagnostics, to confirm the collector receives the stream
}
