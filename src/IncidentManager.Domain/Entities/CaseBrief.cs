using IncidentManager.Domain.Common;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// INV-09: one version of a case's brief — the team's current understanding in five short parts, so anyone
/// picking the case up can see where it stands without reading every note. Each save is a new version (the
/// supersede pattern notes use), so "what did the team believe at T+24h?" can be answered from the record.
/// Each part is Markdown and optional, but a version must say something.
/// <para>
/// The brief is working understanding, not a finding: the wording is neutral ("working assessment", "open
/// questions"), and it stays out of the examiner-facing case report.
/// </para>
/// </summary>
public class CaseBrief : AuditableEntity, IHashableEntity
{
    public const int MaxPartLength = 8000;

    public Guid CaseId { get; set; }
    public int Version { get; set; } = 1;
    public Guid? SupersedesBriefId { get; set; }
    public bool IsCurrent { get; set; } = true;

    /// <summary>What is going on, in a few sentences.</summary>
    public string? Situation { get; set; }
    /// <summary>What the team currently thinks is happening, and how confident it is.</summary>
    public string? WorkingAssessment { get; set; }
    /// <summary>What is established, ideally with where it comes from.</summary>
    public string? Known { get; set; }
    /// <summary>What the team still needs to find out.</summary>
    public string? OpenQuestions { get; set; }
    /// <summary>What happens next, and who is doing it.</summary>
    public string? NextSteps { get; set; }

    public bool IsEmpty =>
        string.IsNullOrWhiteSpace(Situation) && string.IsNullOrWhiteSpace(WorkingAssessment) &&
        string.IsNullOrWhiteSpace(Known) && string.IsNullOrWhiteSpace(OpenQuestions) && string.IsNullOrWhiteSpace(NextSteps);

    public string? RowHash { get; set; }

    public string BuildCanonicalContent() => string.Join('|',
        CaseId, Version, SupersedesBriefId, Situation, WorkingAssessment, Known, OpenQuestions, NextSteps,
        CreatedBy, CreatedAtUtc.ToString("o"));
}
