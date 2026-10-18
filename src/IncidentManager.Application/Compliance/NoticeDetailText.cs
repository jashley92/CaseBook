using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Compliance;

/// <summary>
/// CAP-07: how a regulator was notified, in words: one wording for the Briefing, the timeline milestone and the report, so
/// they can't disagree.
/// </summary>
public static class NoticeDetailText
{
    /// <summary>What a file shows as when the notice names one that isn't among the case's evidence any more.</summary>
    public const string MissingFile = "(not in the case's evidence)";

    public static string Label(NoticeMethod m) => m switch
    {
        NoticeMethod.Portal => "Portal",
        NoticeMethod.Letter => "Letter",
        NoticeMethod.Email => "Email",
        NoticeMethod.Phone => "Phone",
        _ => "Other",
    };

    /// <summary>"by portal", "by letter", and so on, as a phrase.</summary>
    public static string Phrase(NoticeMethod m) => m == NoticeMethod.Other ? "by another method" : "by " + Label(m).ToLowerInvariant();

    /// <summary>The name of the file a notice names, from the case's evidence, or <see cref="MissingFile"/>.</summary>
    public static string? FileName(JurisdictionNotice n, IEnumerable<Domain.Entities.Evidence> evidence) =>
        n.EvidenceId is not { } id ? null : evidence.FirstOrDefault(e => e.Id == id)?.OriginalFileName ?? MissingFile;

    /// <summary>
    /// "By portal, reference NYDFS-114, notified by Pat Lee, notice file ack.pdf": what's recorded, in that order; null
    /// when none of it is.
    /// </summary>
    public static string? Summary(NoticeMethod? method, string? reference, string? notifiedBy, string? fileName)
    {
        var parts = new List<string>(4);
        if (method is { } m) parts.Add(Phrase(m));
        if (!string.IsNullOrWhiteSpace(reference)) parts.Add("reference " + reference.Trim());
        if (!string.IsNullOrWhiteSpace(notifiedBy)) parts.Add("notified by " + notifiedBy.Trim());
        if (!string.IsNullOrWhiteSpace(fileName)) parts.Add("notice file " + fileName);
        if (parts.Count == 0) return null;
        var text = string.Join(", ", parts);
        return char.ToUpperInvariant(text[0]) + text[1..];
    }

    /// <summary>The summary of one notice, its file named from <paramref name="evidence"/>.</summary>
    public static string? Summary(JurisdictionNotice n, IEnumerable<Domain.Entities.Evidence> evidence) =>
        Summary(n.Method, n.Reference, n.NotifiedBy, FileName(n, evidence));
}
