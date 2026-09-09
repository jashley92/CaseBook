using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Abstractions;

/// <summary>
/// Appends a single tamper-evident, hash-chained <c>AuditLogEntry</c> for an action that is not an
/// entity mutation — a privileged read or export — so it lands in the same append-only spine as every
/// other change. The audit-chain interceptor handles entity writes; this seam covers the things that
/// leave no row behind (e.g. generating a compliance evidence bundle).
/// </summary>
public interface IAuditWriter
{
    /// <summary>Records the action, chaining a new entry onto the current audit head, and saves it.</summary>
    Task RecordAsync(AuditAction action, string entityType, string? entityId, string? caseNumber,
        string summary, CancellationToken ct = default);
}
