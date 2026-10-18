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

    /// <summary>
    /// CAP-38: where the case stands with its regulators, in one wording for the case page, the Briefing, the report and the
    /// register: "Partly reported: NY notified 2026-10-02 14:00, CA due 2026-10-05 09:00." until every jurisdiction in play
    /// has its notice, then "Reported to every regulator in play: …". Never a bare "Reported" while a clock runs.
    /// <paramref name="dueOf"/> gives an outstanding jurisdiction's deadline (null when none is tracked: "CA not yet
    /// notified"); <paramref name="time"/> formats an instant for the sink. Null when nothing is in play or notified.
    /// </summary>
    public static string? Standing(NoticeStanding s, Func<string, DateTimeOffset?> dueOf, Func<DateTimeOffset, string> time)
    {
        // The jurisdictions in play, then any notice given to one no longer in play (it was still given).
        var notified = s.InPlay.Where(j => s.NotifiedAt(j) is not null)
            .Concat(s.Notices.Keys.Where(k => !s.InPlay.Contains(k, StringComparer.OrdinalIgnoreCase)).OrderBy(k => k, StringComparer.Ordinal))
            .Select(j => $"{j} notified {time(s.NotifiedAt(j)!.Value)}").ToList();
        var outstanding = s.Outstanding.Select(j => dueOf(j) is { } due ? $"{j} due {time(due)}" : $"{j} not yet notified").ToList();
        if (s.IsFullyReported)
            return s.InPlay.Count == 0 && s.WholeReportUtc is { } whole ? $"Reported to regulators {time(whole)}."
                : s.InPlay.Count == 0 ? $"Reported to regulators: {string.Join(", ", notified)}."
                : $"Reported to every regulator in play: {string.Join(", ", notified)}.";
        if (outstanding.Count == 0) return null;
        return s.IsPartlyReported
            ? $"Partly reported: {string.Join(", ", notified.Concat(outstanding))}."
            : $"Not yet reported: {string.Join(", ", outstanding)}.";
    }

    /// <summary>CAP-38: <see cref="Standing(NoticeStanding, Func{string, DateTimeOffset?}, Func{DateTimeOffset, string})"/>
    /// for an evaluated case, each outstanding regulator's deadline taken from its clock.</summary>
    public static string? Standing(CaseNotificationDeadlines d, Func<DateTimeOffset, string> time) =>
        Standing(d.Standing, code => d.Statuses.FirstOrDefault(x => string.Equals(x.JurisdictionCode, code, StringComparison.OrdinalIgnoreCase))?.DueAtUtc,
            time);
}
