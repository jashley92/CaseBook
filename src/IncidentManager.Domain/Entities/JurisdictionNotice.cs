using IncidentManager.Domain.Common;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// BUG-09: when one regulator was notified about a case (a jurisdiction code such as "NY"). Each jurisdiction's
/// notification clock stops on its own notice; the case's <see cref="Case.ReportedAtUtc"/> is the time the last one
/// in play was notified. Hash-chained and audited like the rest of the record. A correction updates it in place.
/// </summary>
public class JurisdictionNotice : AuditableEntity, IHashableEntity
{
    public const int MaxJurisdictionLength = 50;

    public Guid CaseId { get; set; }

    /// <summary>The jurisdiction code, upper case, as the data elements name it.</summary>
    public string Jurisdiction { get; set; } = string.Empty;

    public DateTimeOffset NotifiedAtUtc { get; set; }

    /// <summary>
    /// WF-77: the regulator's deadline as it stood when the notice was recorded (the rule's window from the clock's start
    /// then), so whether the notice was on time doesn't change when a rule's window or the materiality decision changes
    /// later. Null where no clock ran, or for a notice recorded before it was kept (filled at start-up). BUG-630: it decides
    /// whether the notice was on time, so it's in the canonical from format 4 (when set), and the start-up fill is an
    /// audited change.
    /// </summary>
    public DateTimeOffset? DueAtUtc { get; set; }

    public string? RowHash { get; set; }

    public string BuildCanonicalContent() => string.Join('|',
        CaseId, Jurisdiction, NotifiedAtUtc.ToString("o"), CreatedBy, CreatedAtUtc.ToString("o"))
        + Canonical.Since(4, DueAtUtc is not null, () => "|due|" + Canonical.Time(DueAtUtc));
}
