using IncidentManager.Domain.Common;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// A typed relationship between two cases (E-14): duplicate-of, related, or part of the same
/// campaign. The link is filed under <see cref="CaseId"/> (the "source" side) and points at
/// <see cref="RelatedCaseId"/>; filing it under one case lets the audit-chain interceptor attribute
/// and broadcast the change to that case like any other child record. Symmetric types (RelatedTo,
/// PartOfCampaign) are stored once and shown from both cases; DuplicateOf is directional.
/// </summary>
public class CaseLink : AuditableEntity, IHashableEntity
{
    /// <summary>The case the link is filed under (the source side; also drives audit attribution).</summary>
    public Guid CaseId { get; set; }

    /// <summary>The other case this one is linked to (the target side).</summary>
    public Guid RelatedCaseId { get; set; }

    public CaseLinkType Type { get; set; }

    /// <summary>Optional analyst note on why the cases are linked.</summary>
    public string? Description { get; set; }

    public string? RowHash { get; set; }

    public string BuildCanonicalContent() => string.Join('|',
        CaseId, RelatedCaseId, (int)Type, Description, CreatedBy, CreatedAtUtc.ToString("o"));
}
