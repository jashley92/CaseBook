using IncidentManager.Domain.Common;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// INV-09: one version of a case's brief — where the case stands, in five short parts, so anyone picking the
/// case up can see it without reading every note. Each save is a new version (the supersede pattern notes use),
/// so "what did the team believe at T+24h?" can be answered from the record. Each part is Markdown and optional.
/// <para>
/// INV-36: the first part is the case summary. <see cref="Case.Summary"/> stays the field the report, the close
/// gate and import read; each version records the summary as it stood, so the summary is versioned with the
/// brief. The other parts are working understanding, not findings: the wording is neutral ("working
/// assessment", "open questions"), and they stay out of the case report unless its layout turns the brief on.
/// </para>
/// </summary>
public class CaseBrief : AuditableEntity, IHashableEntity
{
    public const int MaxPartLength = 8000;

    public Guid CaseId { get; set; }
    public int Version { get; set; } = 1;
    public Guid? SupersedesBriefId { get; set; }
    public bool IsCurrent { get; set; } = true;

    /// <summary>INV-36: the case summary as it stood at this version (the column was the brief's "situation",
    /// which the summary replaced).</summary>
    public string? Summary { get; set; }
    /// <summary>What the team currently thinks is happening, and how confident it is.</summary>
    public string? WorkingAssessment { get; set; }
    /// <summary>What is established, ideally with where it comes from.</summary>
    public string? Known { get; set; }
    /// <summary>What the team still needs to find out.</summary>
    public string? OpenQuestions { get; set; }
    /// <summary>What happens next, and who is doing it. INV-25: the case's open tasks are its next steps; each
    /// version records them as they stood when it was saved (a snapshot, not edited as text).</summary>
    public string? NextSteps { get; set; }

    public bool IsEmpty =>
        string.IsNullOrWhiteSpace(Summary) && string.IsNullOrWhiteSpace(WorkingAssessment) &&
        string.IsNullOrWhiteSpace(Known) && string.IsNullOrWhiteSpace(OpenQuestions) && string.IsNullOrWhiteSpace(NextSteps);

    public string? RowHash { get; set; }

    public string BuildCanonicalContent() => string.Join('|',
        CaseId, Version, SupersedesBriefId, Summary, WorkingAssessment, Known, OpenQuestions, NextSteps,
        CreatedBy, CreatedAtUtc.ToString("o"));
}
