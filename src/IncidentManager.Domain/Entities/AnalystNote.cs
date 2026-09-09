using IncidentManager.Domain.Common;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// An analyst note. Edits create a new version rather than overwriting, so the record
/// of what was known and when is never lost.
/// </summary>
public class AnalystNote : AuditableEntity, IHashableEntity
{
    public Guid CaseId { get; set; }
    public string Body { get; set; } = string.Empty;
    public int Version { get; set; } = 1;

    /// <summary>The prior version this note supersedes, if it is an edit.</summary>
    public Guid? SupersedesNoteId { get; set; }

    /// <summary>False once a newer version supersedes this one.</summary>
    public bool IsCurrent { get; set; } = true;

    public string? RowHash { get; set; }

    public string BuildCanonicalContent() => string.Join('|',
        CaseId, Version, Body, CreatedBy, CreatedAtUtc.ToString("o"));
}
