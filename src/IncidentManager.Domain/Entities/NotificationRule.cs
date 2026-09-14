using IncidentManager.Domain.Common;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// A per-jurisdiction regulatory notification deadline (PROD-07): how long, after the clock-start instant,
/// the org has to notify a given jurisdiction of a reportable event (e.g. NY / NYDFS Part 500 = 72 hours).
/// Admin-managed reference data — audited and hash-chained like <see cref="DataElement"/> and
/// <see cref="StageGate"/>, so an IRP can set its own timers without a code release. The <see cref="Code"/>
/// is keyed to the same jurisdiction code space the impact assessment already uses on
/// <see cref="DataElement.NotificationJurisdictions"/>, so the deadline table and the report grouping stay
/// in lockstep. A jurisdiction that appears on a case but has no active rule falls back to the configured
/// default window, so a countdown always exists.
/// </summary>
public class NotificationRule : AuditableEntity, IHashableEntity
{
    /// <summary>Stable jurisdiction code (e.g. "NY", "US") — the element's identity and the value matched against
    /// <see cref="DataElement.NotificationJurisdictions"/>. Uppercased; assigned once and never changed.</summary>
    public string Code { get; set; } = string.Empty;

    /// <summary>Display label (editable), e.g. "New York (NYDFS Part 500)".</summary>
    public string Label { get; set; } = string.Empty;

    /// <summary>Hours from the clock-start instant within which this jurisdiction must be notified.</summary>
    public int WindowHours { get; set; }

    /// <summary>Active rules apply; an archived one is ignored (the default window covers its jurisdiction).</summary>
    public bool IsActive { get; set; } = true;

    /// <summary>The rules seeded on first run (may be relabelled / retimed / archived, but not deleted).</summary>
    public bool IsSystem { get; set; }

    public string? RowHash { get; set; }

    public string BuildCanonicalContent() => string.Join('|',
        Code, Label, WindowHours, IsActive, IsSystem, CreatedBy, CreatedAtUtc.ToString("o"));
}
