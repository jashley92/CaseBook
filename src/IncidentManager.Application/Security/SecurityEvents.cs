using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Security;

/// <summary>
/// Factories for the security events emitted to the SIEM stream (F-18), so call sites stay one-liners
/// and the id/category/action/severity mapping lives in one place. Carry only ids/labels — never PII.
/// </summary>
public static class SecurityEvents
{
    public static SecurityEvent CaseAccess(AccessType type, bool wasRestricted, string actor, string? actorUpn,
        string? caseNumber, Guid? targetId, string? label) => type switch
    {
        AccessType.CaseOpen => new SecurityEvent
        {
            EventId = wasRestricted ? SecurityEventIds.RestrictedCaseAccessed : SecurityEventIds.CaseOpened,
            Category = "DataAccess",
            Action = "CaseOpen",
            Outcome = SecurityOutcome.Success,
            Severity = wasRestricted ? SecuritySeverity.High : SecuritySeverity.Info,
            Actor = actor, ActorUpn = actorUpn, CaseNumber = caseNumber, TargetType = "Case"
        },
        AccessType.EvidenceDownload => Artifact(SecurityEventIds.EvidenceDownloaded, "EvidenceDownload", wasRestricted, actor, actorUpn, caseNumber, "Evidence", targetId, label),
        AccessType.ReportDownload => Artifact(SecurityEventIds.ReportDownloaded, "ReportDownload", wasRestricted, actor, actorUpn, caseNumber, "Report", targetId, label),
        _ => Artifact(SecurityEventIds.DataExported, "Export", wasRestricted, actor, actorUpn, caseNumber, "Export", targetId, label)
    };

    private static SecurityEvent Artifact(int id, string action, bool wasRestricted, string actor, string? actorUpn,
        string? caseNumber, string targetType, Guid? targetId, string? label) => new()
    {
        EventId = id,
        Category = "DataAccess",
        Action = action,
        Outcome = SecurityOutcome.Success,
        Severity = wasRestricted ? SecuritySeverity.High : SecuritySeverity.Info,
        Actor = actor, ActorUpn = actorUpn, CaseNumber = caseNumber,
        TargetType = targetType, TargetId = targetId?.ToString(), Detail = label
    };

    /// <summary>
    /// A download/export request was refused by the per-user rate limit (F-13) — the account exceeded the
    /// configured download budget, which on a legitimate user is a burst and on a compromised one is the
    /// first sign of bulk exfiltration. Carries the actor and the requested path only.
    /// </summary>
    public static SecurityEvent DownloadRateLimited(string actor, string? actorUpn, string path) => new()
    {
        EventId = SecurityEventIds.DownloadRateLimited,
        Category = "DataAccess",
        Action = "DownloadRateLimited",
        Outcome = SecurityOutcome.Deny,
        Severity = SecuritySeverity.Warning,
        Actor = actor, ActorUpn = actorUpn, Detail = path
    };

    public static SecurityEvent AuthenticationFailed(string? detail) => new()
    {
        EventId = SecurityEventIds.AuthenticationFailed,
        Category = "Authentication",
        Action = "AuthenticationFailed",
        Outcome = SecurityOutcome.Failure,
        Severity = SecuritySeverity.Warning,
        Actor = "anonymous",
        Detail = detail
    };

    public static SecurityEvent AuthorizationDenied(string actor, string? actorUpn, string path) => new()
    {
        EventId = SecurityEventIds.AuthorizationDenied,
        Category = "Authorization",
        Action = "AccessDenied",
        Outcome = SecurityOutcome.Deny,
        Severity = SecuritySeverity.Warning,
        Actor = actor, ActorUpn = actorUpn, Detail = path
    };

    public static SecurityEvent LegalHold(bool placed, string actor, string? actorUpn, string? caseNumber) => new()
    {
        EventId = placed ? SecurityEventIds.LegalHoldPlaced : SecurityEventIds.LegalHoldReleased,
        Category = "Governance",
        Action = placed ? "LegalHoldPlaced" : "LegalHoldReleased",
        Outcome = SecurityOutcome.Success,
        Severity = SecuritySeverity.Warning,
        Actor = actor, ActorUpn = actorUpn, CaseNumber = caseNumber, TargetType = "Case"
    };

    public static SecurityEvent BreachEscalated(string actor, string? actorUpn, string? caseNumber) => new()
    {
        EventId = SecurityEventIds.BreachEscalated,
        Category = "Governance",
        Action = "BreachEscalated",
        Outcome = SecurityOutcome.Success,
        Severity = SecuritySeverity.High,
        Actor = actor, ActorUpn = actorUpn, CaseNumber = caseNumber, TargetType = "Case"
    };

    public static SecurityEvent RoleChanged(string action, string actor, string? actorUpn, string detail) => new()
    {
        EventId = SecurityEventIds.RoleChanged,
        Category = "Admin",
        Action = action, // e.g. "RoleCreated", "RoleUpdated", "RoleDeleted"
        Outcome = SecurityOutcome.Success,
        Severity = SecuritySeverity.Warning,
        Actor = actor, ActorUpn = actorUpn, TargetType = "Role", Detail = detail
    };

    public static SecurityEvent MappingChanged(string action, string actor, string? actorUpn, string detail) => new()
    {
        EventId = SecurityEventIds.AdGroupMappingChanged,
        Category = "Admin",
        Action = action, // "AdGroupMappingAdded" / "AdGroupMappingRemoved"
        Outcome = SecurityOutcome.Success,
        Severity = SecuritySeverity.Warning,
        Actor = actor, ActorUpn = actorUpn, TargetType = "AdGroupMapping", Detail = detail
    };

    public static SecurityEvent SettingChanged(string key, string actor, string? actorUpn) => new()
    {
        EventId = SecurityEventIds.SettingChanged,
        Category = "Admin",
        Action = "SettingChanged",
        Outcome = SecurityOutcome.Success,
        Severity = SecuritySeverity.Warning,
        Actor = actor, ActorUpn = actorUpn, TargetType = "Setting", Detail = key
    };

    /// <summary>
    /// A row in the AppSettings table whose key is NOT an editable operational setting was found and
    /// ignored on configuration load (S-02). Such a row can't be written through <c>AdminSettingsService</c>,
    /// so its presence means the whitelist was bypassed out-of-band (DB tamper / restored backup) — a
    /// critical integrity signal. Carries only the key.
    /// </summary>
    public static SecurityEvent RejectedSettingOverride(string key) => new()
    {
        EventId = SecurityEventIds.RejectedSettingOverride,
        Category = "Integrity",
        Action = "RejectedSettingOverride",
        Outcome = SecurityOutcome.Deny,
        Severity = SecuritySeverity.Critical,
        Actor = "system", TargetType = "Setting", Detail = key
    };

    /// <summary>
    /// Evidence at rest failed re-verification (F-17): one or more stored files no longer match their
    /// recorded SHA-256, or are missing/unreadable — bit-rot or filesystem tampering under the evidence
    /// store. Carries only counts (no filenames/case content); the email alert carries the offender list.
    /// </summary>
    public static SecurityEvent EvidenceIntegrityDrift(int driftCount, int checkedCount) => new()
    {
        EventId = SecurityEventIds.EvidenceIntegrityDrift,
        Category = "Integrity",
        Action = "EvidenceIntegrityDrift",
        Outcome = SecurityOutcome.Failure,
        Severity = SecuritySeverity.Critical,
        Actor = "system", TargetType = "Evidence",
        Detail = $"{driftCount} of {checkedCount} evidence item(s) drifted from the recorded hash"
    };
}
