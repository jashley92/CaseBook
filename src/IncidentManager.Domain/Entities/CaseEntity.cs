using IncidentManager.Domain.Common;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// An artifact / indicator of compromise (IOC) associated with a case: an account, host,
/// IP, domain, URL, file hash, etc. Entities are the nodes of a case's investigation graph;
/// <see cref="EntityRelationship"/> forms the edges between them.
/// </summary>
public class CaseEntity : AuditableEntity, IHashableEntity
{
    public Guid CaseId { get; set; }
    public EntityType Type { get; set; }

    /// <summary>The canonical observable value (e.g. the IP, the SHA-256, the username, the URL).</summary>
    public string Value { get; set; } = string.Empty;

    /// <summary>Optional friendly label (e.g. a hostname's owner, an account's display name).</summary>
    public string? Label { get; set; }

    public EntityDisposition Disposition { get; set; } = EntityDisposition.Unknown;
    public string? Description { get; set; }

    /// <summary>Where this entity came from, e.g. "SIEM", "VirusTotal", analyst name.</summary>
    public string? Source { get; set; }

    public string? RowHash { get; set; }

    public string BuildCanonicalContent() => string.Join('|',
        CaseId, (int)Type, Value, Label, (int)Disposition, Description, Source, CreatedBy, CreatedAtUtc.ToString("o"));
}

/// <summary>
/// A directed relationship between two of a case's entities (source → target), such as
/// account <c>LoggedInTo</c> host or host <c>CommunicatedWith</c> IP.
/// </summary>
public class EntityRelationship : AuditableEntity, IHashableEntity
{
    public Guid CaseId { get; set; }
    public Guid SourceEntityId { get; set; }
    public Guid TargetEntityId { get; set; }
    public EntityRelationshipType Type { get; set; }
    public string? Description { get; set; }

    public string? RowHash { get; set; }

    public string BuildCanonicalContent() => string.Join('|',
        CaseId, SourceEntityId, TargetEntityId, (int)Type, Description, CreatedBy, CreatedAtUtc.ToString("o"));
}
