using System.Text.RegularExpressions;
using IncidentManager.Domain.Common;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// A MITRE ATT&amp;CK technique (or sub-technique) tagged on a case, e.g. <c>T1566.001</c>
/// "Spearphishing Attachment". Captures the adversary TTPs behind the case for after-action
/// reporting and trend analysis. Audited and hash-chained like other case data.
/// </summary>
public partial class CaseTechnique : AuditableEntity, IHashableEntity
{
    public Guid CaseId { get; set; }

    /// <summary>ATT&amp;CK technique ID, normalised upper-case, e.g. "T1566" or "T1566.001".</summary>
    public string TechniqueId { get; set; } = string.Empty;

    /// <summary>Human-readable technique name, e.g. "Phishing: Spearphishing Attachment".</summary>
    public string Name { get; set; } = string.Empty;

    public MitreTactic Tactic { get; set; } = MitreTactic.Unspecified;

    public string? RowHash { get; set; }

    public string BuildCanonicalContent() => string.Join('|',
        CaseId, TechniqueId, Name, (int)Tactic, CreatedBy, CreatedAtUtc.ToString("o"));

    /// <summary>Matches an ATT&amp;CK technique ID like T1566 or a sub-technique like T1566.001.</summary>
    [GeneratedRegex(@"^T\d{4}(\.\d{3})?$")]
    public static partial Regex IdPattern();

    /// <summary>Normalises and validates a technique ID, throwing if it is not a valid ATT&amp;CK ID.</summary>
    public static string NormaliseId(string techniqueId)
    {
        var id = (techniqueId ?? string.Empty).Trim().ToUpperInvariant();
        if (!IdPattern().IsMatch(id))
            throw new ArgumentException($"'{techniqueId}' is not a valid ATT&CK technique ID (expected e.g. T1566 or T1566.001).", nameof(techniqueId));
        return id;
    }
}
