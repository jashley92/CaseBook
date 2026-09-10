namespace IncidentManager.Application.Security;

/// <summary>
/// Stable event-id catalog for the outbound SIEM stream (F-18). These numbers are a public
/// contract — SIEM correlation/detection rules pin to them, so <b>never renumber</b>; only append.
/// Extends the F-16 integrity alarm (<see cref="AuditChainBroken"/> = 5001).
///
/// Ranges: 50xx integrity · 51xx authentication · 52xx authorization · 53xx data access · 54xx
/// admin/config · 55xx case governance.
/// </summary>
public static class SecurityEventIds
{
    // 50xx — Integrity
    public const int AuditChainBroken = 5001; // owned by F-16; may also flow through the stream
    public const int RejectedSettingOverride = 5002; // a non-whitelisted AppSettings row ignored on load (S-02 tamper signal)
    public const int EvidenceIntegrityDrift = 5003; // evidence at rest no longer matches its recorded SHA-256 (F-17)

    // 51xx — Authentication
    public const int AuthenticationFailed = 5101;

    // 52xx — Authorization
    public const int AuthorizationDenied = 5201; // a 403 on a page/endpoint

    // 53xx — Data access (sourced from the C-05 access log)
    public const int CaseOpened = 5301;
    public const int EvidenceDownloaded = 5302;
    public const int ReportDownloaded = 5303;
    public const int DataExported = 5304;
    public const int RestrictedCaseAccessed = 5305; // a read of a restricted case (elevated severity)
    public const int DownloadRateLimited = 5306; // a download/export request refused by the per-user rate limit (F-13)

    // 54xx — Admin / configuration
    public const int RoleChanged = 5401;
    public const int AdGroupMappingChanged = 5402;
    public const int SettingChanged = 5403;

    // 55xx — Case governance
    public const int LegalHoldPlaced = 5501;
    public const int LegalHoldReleased = 5502;
    public const int BreachEscalated = 5503;
}
