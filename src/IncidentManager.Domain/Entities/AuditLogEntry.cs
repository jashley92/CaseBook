using IncidentManager.Domain.Common;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// One link in the tamper-evident, append-only audit chain. Each entry hashes its own
/// canonical content together with the previous entry's hash, so any retroactive edit,
/// insertion, or deletion breaks the chain and is detectable.
/// </summary>
public class AuditLogEntry : Entity
{
    /// <summary>Monotonic position in the chain (assigned by the hash-chain service).</summary>
    public long Sequence { get; set; }
    public DateTimeOffset AtUtc { get; set; }
    public string Actor { get; set; } = string.Empty;
    public AuditAction Action { get; set; }
    public string EntityType { get; set; } = string.Empty;
    public string? EntityId { get; set; }

    /// <summary>Denormalized case number for fast filtering of the audit trail.</summary>
    public string? CaseNumber { get; set; }

    /// <summary>
    /// A human identity for the changed thing, captured at write time (e.g. a task's title, a timeline
    /// entry's opening words, an IOC's value) so the trail reads "Update ActionItem — Rotate exposed
    /// credentials" rather than an opaque type + GUID. Self-contained: it reflects the entity as it was
    /// when the change happened and never depends on re-resolving mutable current state.
    /// </summary>
    public string? EntityLabel { get; set; }

    public string? Summary { get; set; }
    public string? BeforeJson { get; set; }
    public string? AfterJson { get; set; }

    /// <summary>
    /// Optional analyst-supplied reason for a change (why an IOC/timeline entry was corrected).
    /// Folded into the hash only when present, so existing reason-less entries never re-baseline.
    /// </summary>
    public string? Reason { get; set; }

    /// <summary>Hash of the previous entry (empty string for the genesis entry).</summary>
    public string PrevHash { get; set; } = string.Empty;

    /// <summary>SHA-256 over <see cref="BuildCanonicalContent"/> + <see cref="PrevHash"/>.</summary>
    public string EntryHash { get; set; } = string.Empty;

    public string BuildCanonicalContent()
    {
        var content = string.Join('|',
            Sequence, AtUtc.ToString("o"), Actor, (int)Action, EntityType, EntityId, CaseNumber, Summary, BeforeJson, AfterJson);
        // A reason is tamper-evident too, but only entries that carry one extend the canonical, so the
        // vast majority of (reason-less) historical entries hash exactly as before. The entity label extends
        // it the same way, appended after the reason — so a historical entry (no label, with or without a
        // reason) hashes exactly as it did before this field existed.
        if (Reason is not null) content = string.Join('|', content, Reason);
        if (EntityLabel is not null) content = string.Join('|', content, EntityLabel);
        return content;
    }
}
