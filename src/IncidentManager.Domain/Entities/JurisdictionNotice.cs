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

    public string? RowHash { get; set; }

    public string BuildCanonicalContent() => string.Join('|',
        CaseId, Jurisdiction, NotifiedAtUtc.ToString("o"), CreatedBy, CreatedAtUtc.ToString("o"));
}
