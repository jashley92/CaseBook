namespace IncidentManager.Application.Security;

/// <summary>Whether the actioned attempt was permitted or refused / succeeded or failed.</summary>
public enum SecurityOutcome
{
    Allow,
    Deny,
    Success,
    Failure
}

/// <summary>Relative importance of a security event, for SIEM triage/rules.</summary>
public enum SecuritySeverity
{
    Info,
    Warning,
    High,
    Critical
}

/// <summary>
/// One structured security event for the outbound SIEM stream (F-18). Field names are a stable
/// parse contract — SIEM detection rules key off <see cref="EventId"/> and these fields, so rename with
/// care. Carries only ids/labels/actions — <b>never</b> case content, affected-individual PII, or
/// before/after field values. <see cref="AtUtc"/>, <see cref="Host"/> and <see cref="App"/> are stamped
/// by the sink at emit time, so call sites don't repeat them.
/// </summary>
public sealed record SecurityEvent
{
    /// <summary>Stable numeric id from <see cref="SecurityEventIds"/> (e.g. 5301 = case opened).</summary>
    public required int EventId { get; init; }

    /// <summary>Coarse grouping, e.g. "DataAccess", "Authorization", "Admin", "Governance".</summary>
    public required string Category { get; init; }

    /// <summary>Specific action, e.g. "CaseOpen", "EvidenceDownload", "LegalHoldPlaced".</summary>
    public required string Action { get; init; }

    public SecurityOutcome Outcome { get; init; } = SecurityOutcome.Success;
    public SecuritySeverity Severity { get; init; } = SecuritySeverity.Info;

    /// <summary>Acting user id (AD SID / dev id), or "anonymous"/"system" when there is no user.</summary>
    public string Actor { get; init; } = "system";
    public string? ActorUpn { get; init; }

    public string? CaseNumber { get; init; }
    public string? TargetType { get; init; }
    public string? TargetId { get; init; }

    /// <summary>Short, non-sensitive context (a filename, a setting key, a request path). No PII.</summary>
    public string? Detail { get; init; }

    // --- Stamped by the sink at emit time ---
    public DateTimeOffset AtUtc { get; init; }
    public string Host { get; init; } = "";
    public string App { get; init; } = "CaseBook";
}
