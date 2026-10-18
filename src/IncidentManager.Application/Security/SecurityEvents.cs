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

    /// <summary>
    /// S-19: an action refused at the service boundary for lack of a permission — the UI normally hides what a user
    /// can't do, so this fires when the UI and the user's rights disagree (a stale session after access was removed,
    /// or a UI bug). No HTTP 403 accompanies it (Blazor calls the service directly), so it's streamed here.
    /// </summary>
    public static SecurityEvent ActionRefused(string actor, string? actorUpn, Permission required, string? action) => new()
    {
        EventId = SecurityEventIds.ActionRefused,
        Category = "Authorization",
        Action = "ActionRefused",
        Outcome = SecurityOutcome.Deny,
        Severity = SecuritySeverity.Warning,
        Actor = actor, ActorUpn = actorUpn,
        Detail = $"{action ?? "action"} requires {required}"
    };

    /// <summary>S-19: a presented API token was unknown, expired or revoked. Carries only the token's display prefix.</summary>
    public static SecurityEvent ApiTokenRejected(string? tokenPrefix, string? remoteAddress) => new()
    {
        EventId = SecurityEventIds.AuthenticationFailed,
        Category = "Authentication",
        Action = "ApiTokenRejected",
        Outcome = SecurityOutcome.Failure,
        Severity = SecuritySeverity.Warning,
        Actor = "anonymous",
        Detail = $"API token {(string.IsNullOrEmpty(tokenPrefix) ? "(malformed)" : tokenPrefix + "…")} rejected"
                 + (string.IsNullOrEmpty(remoteAddress) ? "" : $" from {remoteAddress}")
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

    /// <summary>S-08: a case was restricted to need-to-know, or the restriction lifted (widening exposure).</summary>
    public static SecurityEvent CaseRestriction(bool restricted, string actor, string? actorUpn, string? caseNumber) => new()
    {
        EventId = restricted ? SecurityEventIds.CaseRestricted : SecurityEventIds.CaseRestrictionLifted,
        Category = "Authorization",
        Action = restricted ? "CaseRestricted" : "CaseRestrictionLifted",
        Outcome = SecurityOutcome.Success,
        Severity = restricted ? SecuritySeverity.Info : SecuritySeverity.Warning,
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

    public static SecurityEvent ApiTokenChanged(string action, string actor, string? actorUpn, string detail) => new()
    {
        EventId = SecurityEventIds.ApiTokenChanged,
        Category = "Admin",
        Action = action, // "ApiTokenCreated" / "ApiTokenRevoked"
        Outcome = SecurityOutcome.Success,
        Severity = SecuritySeverity.Warning,
        Actor = actor, ActorUpn = actorUpn, TargetType = "ApiToken", Detail = detail
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
    /// <summary>
    /// F-26: a seal was recorded. The SIEM keeps this copy apart from CaseBook's database and servers, so a later
    /// comparison with the seals in a compliance bundle shows any seal that was altered, re-signed or deleted.
    /// <see cref="SecurityEvent.TargetId"/> is the sealed sequence; <see cref="SecurityEvent.Detail"/> is
    /// <c>head=&lt;chain-head hash&gt; key=&lt;key id&gt; sealedAtUtc=&lt;ISO 8601&gt;</c>.
    /// </summary>
    public static SecurityEvent IntegritySealRecorded(long upToSequence, string chainHeadHash, string keyId,
        DateTimeOffset sealedAtUtc, string actor, long? keyedFrom = null) => new()
    {
        EventId = SecurityEventIds.IntegritySealRecorded,
        Category = "Integrity",
        Action = "IntegritySealRecorded",
        Outcome = SecurityOutcome.Success,
        Severity = SecuritySeverity.Info,
        Actor = actor, TargetType = "IntegritySeal",
        TargetId = upToSequence.ToString(System.Globalization.CultureInfo.InvariantCulture),
        Detail = $"head={chainHeadHash} key={keyId} sealedAtUtc={sealedAtUtc.UtcDateTime.ToString("o", System.Globalization.CultureInfo.InvariantCulture)}"
                 + (keyedFrom is { } k ? $" keyedFrom={k.ToString(System.Globalization.CultureInfo.InvariantCulture)}" : "")
    };

    /// <summary>
    /// PROD-59: the evidence key can't be opened, so evidence and reports are paused (the rest of CaseBook works).
    /// <see cref="SecurityEvent.Detail"/> is the reason, with no key material. Sent once per change of state.
    /// </summary>
    public static SecurityEvent EvidenceKeyUnavailable(string reason) => new()
    {
        EventId = SecurityEventIds.EvidenceKeyUnavailable,
        Category = "Integrity",
        Action = "EvidenceKeyUnavailable",
        Outcome = SecurityOutcome.Failure,
        Severity = SecuritySeverity.High,
        Actor = "system", TargetType = "EvidenceKey",
        Detail = Common.TextFit.Cap(reason, 300)
    };

    /// <summary>
    /// PROD-59: something happened to the evidence key. <paramref name="action"/> is one of KeyCreated, KeyAvailable,
    /// KeyProtectionChanged, SharesIssued, RecoveryDrill, KeyRecovered; <see cref="SecurityEvent.TargetId"/> is the key
    /// id (derived from the key, revealing nothing). A recovery onto another certificate is High: the key moved.
    /// </summary>
    public static SecurityEvent EvidenceKeyChanged(string action, string keyId, string detail, string actor = "system") => new()
    {
        EventId = SecurityEventIds.EvidenceKeyChanged,
        Category = "Integrity",
        Action = action,
        Outcome = SecurityOutcome.Success,
        Severity = action == "KeyRecovered" ? SecuritySeverity.High : SecuritySeverity.Info,
        Actor = actor, TargetType = "EvidenceKey", TargetId = keyId,
        Detail = Common.TextFit.Cap(detail, 300)
    };

    /// <summary>PROD-59: evidence written out decrypted by casebook-keytool export, by an administrator on the server
    /// (recorded when CaseBook next reads the key's envelope). Bulk decrypted evidence leaving the store is a Warning.</summary>
    public static SecurityEvent EvidenceExportedOffline(string actor, string? caseNumber, string detail) => new()
    {
        EventId = SecurityEventIds.EvidenceExportedOffline,
        Category = "DataAccess",
        Action = "EvidenceExportedOffline",
        Outcome = SecurityOutcome.Success,
        Severity = SecuritySeverity.Warning,
        Actor = actor, CaseNumber = caseNumber, TargetType = "Evidence",
        Detail = Common.TextFit.Cap(detail, 300)
    };

    /// <summary>F-26/F-27: a copy of a seal (export folder, email digest, timestamp) failed. The seal itself is recorded;
    /// <see cref="SecurityEvent.Detail"/> names the destination and the reason.</summary>
    public static SecurityEvent SealExportFailed(long upToSequence, string reason) => new()
    {
        EventId = SecurityEventIds.SealExportFailed,
        Category = "Integrity",
        Action = "SealExportFailed",
        Outcome = SecurityOutcome.Failure,
        Severity = SecuritySeverity.Warning,
        Actor = "system", TargetType = "IntegritySeal",
        TargetId = upToSequence.ToString(System.Globalization.CultureInfo.InvariantCulture),
        Detail = reason.Length > 200 ? reason[..200] : reason
    };

    /// <summary>
    /// CAP-06: an administrator created, changed or deleted reference data: a stage gate, data element, deadline rule,
    /// playbook, outcome, taxonomy label or order, report profile, Word template or email template.
    /// <see cref="SecurityEvent.TargetType"/> is the kind, <see cref="SecurityEvent.TargetId"/> the row's id when it has
    /// one, and <see cref="SecurityEvent.Detail"/> its name (a label or key, never a body).
    /// Severity: a stage gate or deadline rule decides what a case must show before it moves on and how long a regulator's
    /// clock runs, so any change to one is a Warning, as the role and setting changes (5401-5403) are; so is any delete,
    /// which can't be undone from the page. Adding or relabelling the rest is Info.
    /// </summary>
    public static SecurityEvent ReferenceDataChanged(string kind, string name, ReferenceDataAction action, string actor,
        string? actorUpn, Guid? id = null) => new()
    {
        EventId = SecurityEventIds.ReferenceDataChanged,
        Category = "Admin",
        Action = "ReferenceData" + action,   // ReferenceDataCreated / ReferenceDataChanged / ReferenceDataDeleted
        Outcome = SecurityOutcome.Success,
        Severity = action == ReferenceDataAction.Deleted || kind is ReferenceDataKinds.StageGate or ReferenceDataKinds.DeadlineRule
            ? SecuritySeverity.Warning : SecuritySeverity.Info,
        Actor = actor, ActorUpn = actorUpn, TargetType = kind, TargetId = id?.ToString(),
        Detail = Common.TextFit.Cap(name, 300)
    };

    // ── CAP-06: the case lifecycle (5506-5515) ─────────────────────────────────────────────────────────────────────
    // Each carries the case number, the actor and the detection platform's id (detection=…) when the case has one, so a
    // SOC rule can join CaseBook's record to the platform's incident. An exercise's detail starts EXERCISE:, as its breach
    // escalation's does (BUG-100); unlike that alert, these are activity records, so an exercise's are always sent.

    /// <summary>CAP-06: a case was filed. Info: filing is the everyday act (a case filed as a Breach also sends 5503).</summary>
    public static SecurityEvent CaseCreated(CaseSubject c, Domain.Enums.Classification? classification, Domain.Enums.Severity severity,
        string actor, string? actorUpn) =>
        Lifecycle(SecurityEventIds.CaseCreated, "CaseCreated", SecuritySeverity.Info, c, actor, actorUpn,
            $"classification={Rung(classification)} severity={severity}");

    /// <summary>CAP-06: a case moved between phases (closing and reopening have their own ids). Info: routine progress.</summary>
    public static SecurityEvent CasePhaseChanged(CaseSubject c, Domain.Enums.CasePhase from, Domain.Enums.CasePhase to,
        string actor, string? actorUpn) =>
        Lifecycle(SecurityEventIds.CasePhaseChanged, "CasePhaseChanged", SecuritySeverity.Info, c, actor, actorUpn, $"from={from} to={to}");

    /// <summary>
    /// CAP-06: a case was reclassified, other than escalated to Breach (5503). Raising it, or promoting a Complex Event,
    /// is Info. Lowering it is a Warning: a lowered case skips the higher rung's checks when it closes (WF-13), so it's the
    /// move a SOC rule watches for before a quiet close.
    /// </summary>
    public static SecurityEvent CaseReclassified(CaseSubject c, Domain.Enums.Classification? from, Domain.Enums.Classification to,
        string actor, string? actorUpn) =>
        Lifecycle(SecurityEventIds.CaseReclassified, from is { } f && to < f ? "CaseDowngraded" : "CaseReclassified",
            from is { } g && to < g ? SecuritySeverity.Warning : SecuritySeverity.Info, c, actor, actorUpn,
            $"from={Rung(from)} to={Rung(to)}");

    /// <summary>
    /// CAP-06: a case was closed, with the outcome's key. Closing past unmet gate requirements (an override with a written
    /// justification) is a Warning: it's the close an examiner asks about. A close that met its gate is Info.
    /// </summary>
    public static SecurityEvent CaseClosed(CaseSubject c, string? outcomeKey, bool gateOverridden, string actor, string? actorUpn) =>
        Lifecycle(SecurityEventIds.CaseClosed, "CaseClosed", gateOverridden ? SecuritySeverity.Warning : SecuritySeverity.Info,
            c, actor, actorUpn, $"outcome={Common.TextFit.Cap(outcomeKey ?? "none", 64, "")}" + (gateOverridden ? " gateOverridden=true" : ""));

    /// <summary>CAP-06: a closed case was reopened. Info: a reason is required and recorded on the case; it's routine.</summary>
    public static SecurityEvent CaseReopened(CaseSubject c, string actor, string? actorUpn) =>
        Lifecycle(SecurityEventIds.CaseReopened, "CaseReopened", SecuritySeverity.Info, c, actor, actorUpn, null);

    /// <summary>
    /// CAP-06: a case was archived or restored. Archiving is the end of a case's working life (Info). Restoring is a
    /// Warning: it brings a retained record back into the working set, it's rare, and only an administrator can do it.
    /// </summary>
    public static SecurityEvent CaseArchived(CaseSubject c, bool archived, string actor, string? actorUpn) =>
        Lifecycle(SecurityEventIds.CaseArchived, archived ? "CaseArchived" : "CaseRestored",
            archived ? SecuritySeverity.Info : SecuritySeverity.Warning, c, actor, actorUpn, null);

    /// <summary>
    /// CAP-06: a materiality determination was recorded, with its status. "Material" is a Warning: it's the call that
    /// can start a disclosure clock (an 8-K's four business days), so the SOC should see it the moment it's made.
    /// </summary>
    public static SecurityEvent MaterialityRecorded(CaseSubject c, Domain.Enums.MaterialityStatus status, string actor, string? actorUpn) =>
        Lifecycle(SecurityEventIds.MaterialityRecorded, "MaterialityRecorded",
            status == Domain.Enums.MaterialityStatus.Material ? SecuritySeverity.Warning : SecuritySeverity.Info,
            c, actor, actorUpn, $"status={status}");

    /// <summary>
    /// CAP-06: regulators were recorded as notified: the whole case (CaseReported) or one regulator's notice
    /// (RegulatorNoticeRecorded, with its jurisdiction code). Info: it records a notice given outside CaseBook.
    /// </summary>
    public static SecurityEvent CaseReported(CaseSubject c, string? jurisdiction, string actor, string? actorUpn) =>
        Lifecycle(SecurityEventIds.CaseReported, jurisdiction is null ? "CaseReported" : "RegulatorNoticeRecorded",
            SecuritySeverity.Info, c, actor, actorUpn,
            jurisdiction is null ? null : $"jurisdiction={Common.TextFit.Cap(jurisdiction, 32, "")}");

    /// <summary>CAP-06: a report was approved; the target is the report. Info: approval is the expected end of drafting.</summary>
    public static SecurityEvent ReportApproved(CaseSubject c, Guid reportId, string actor, string? actorUpn) =>
        Lifecycle(SecurityEventIds.ReportApproved, "ReportApproved", SecuritySeverity.Info, c, actor, actorUpn, null,
            "Report", reportId.ToString());

    /// <summary>
    /// CAP-06: a case-import document was applied by a reviewer, into a new case or an existing one; the target is the
    /// pending import when it came through the queue. Info: a person confirmed it (ADR 0004).
    /// </summary>
    public static SecurityEvent ImportApplied(CaseSubject c, Guid? pendingImportId, bool createdCase, string actor, string? actorUpn) =>
        Lifecycle(SecurityEventIds.ImportApplied, "ImportApplied", SecuritySeverity.Info, c, actor, actorUpn,
            createdCase ? "createdCase=true" : null,
            pendingImportId is null ? "Case" : "PendingImport", pendingImportId?.ToString());

    private static string Rung(Domain.Enums.Classification? k) => k?.ToString() ?? "ComplexEvent";

    private static SecurityEvent Lifecycle(int id, string action, SecuritySeverity severity, CaseSubject c, string actor,
        string? actorUpn, string? detail, string targetType = "Case", string? targetId = null)
    {
        var parts = new List<string>(2);
        if (!string.IsNullOrEmpty(detail)) parts.Add(detail);
        if (!string.IsNullOrWhiteSpace(c.DetectionCaseId)) parts.Add("detection=" + Common.TextFit.Cap(c.DetectionCaseId.Trim(), 100, ""));
        var text = (c.IsExercise ? Abstractions.ExerciseMarking.Prefix : "") + string.Join(' ', parts);
        return new SecurityEvent
        {
            EventId = id,
            Category = "Governance",
            Action = action,
            Outcome = SecurityOutcome.Success,
            Severity = severity,
            Actor = actor, ActorUpn = actorUpn, CaseNumber = c.CaseNumber,
            TargetType = targetType, TargetId = targetId,
            Detail = text.Length == 0 ? null : Common.TextFit.Cap(text.TrimEnd(), 300)
        };
    }

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
