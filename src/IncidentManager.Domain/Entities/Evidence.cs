using IncidentManager.Domain.Common;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// A piece of evidence attached to a case. Immutable once attached: the file bytes are
/// hashed (SHA-256), stored outside the web root under a randomized name, and never executed.
/// </summary>
public class Evidence : AuditableEntity, IHashableEntity
{
    public Guid CaseId { get; set; }
    public string OriginalFileName { get; set; } = string.Empty;
    public string ContentType { get; set; } = "application/octet-stream";
    public long SizeBytes { get; set; }

    /// <summary>Lower-case hex SHA-256 of the stored bytes.</summary>
    public string Sha256 { get; set; } = string.Empty;

    /// <summary>Relative path within the evidence store (randomized name, not the original).</summary>
    public string StoragePath { get; set; } = string.Empty;
    public string? Description { get; set; }

    public List<ChainOfCustodyEvent> CustodyEvents { get; set; } = new();

    public string? RowHash { get; set; }

    public string BuildCanonicalContent() => string.Join('|',
        CaseId, OriginalFileName, ContentType, SizeBytes, Sha256, CreatedBy, CreatedAtUtc.ToString("o"));
}

/// <summary>An access/transfer event in an evidence item's chain of custody.</summary>
public class ChainOfCustodyEvent : Entity
{
    public Guid EvidenceId { get; set; }
    public DateTimeOffset AtUtc { get; set; }
    public string Actor { get; set; } = string.Empty;

    /// <summary>e.g. Uploaded, Downloaded, Viewed, Transferred.</summary>
    public string Action { get; set; } = string.Empty;
    public string? Details { get; set; }
}
