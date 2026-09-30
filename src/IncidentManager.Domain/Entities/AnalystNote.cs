using IncidentManager.Domain.Common;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// An analyst note. Edits create a new version rather than overwriting, so the record
/// of what was known and when is never lost. INV-37: a note can @mention teammates to point them at it (there's no
/// thread and no reply: the conversation itself happens in the team's chat).
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

    /// <summary>INV-37: comma-separated user ids this version @mentions (empty when none).</summary>
    public string MentionsCsv { get; set; } = string.Empty;

    /// <summary>The user ids this version @mentions.</summary>
    public IReadOnlyList<string> Mentions =>
        MentionsCsv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    public string? RowHash { get; set; }

    // INV-37: mentions are folded in only when there are some, so existing notes keep their exact hash.
    public string BuildCanonicalContent()
    {
        var content = string.Join('|', CaseId, Version, Body, CreatedBy, CreatedAtUtc.ToString("o"));
        return MentionsCsv.Length == 0 ? content : string.Join('|', content, "mentions", MentionsCsv);
    }
}
