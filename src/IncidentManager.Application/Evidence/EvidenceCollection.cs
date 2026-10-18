using System.Globalization;

namespace IncidentManager.Application.Evidence;

/// <summary>
/// CAP-08: when, where from and by whom an evidence file was collected, as given on upload or in the evidence panel.
/// Each part is optional; <see cref="Domain.Entities.Evidence.CheckCollection"/> validates and trims them.
/// </summary>
public sealed record EvidenceCollection(DateTimeOffset? AtUtc, string? From, string? By)
{
    public static readonly EvidenceCollection None = new(null, null, null);

    /// <summary>The collection facts a record holds.</summary>
    public static EvidenceCollection Of(Domain.Entities.Evidence ev) => new(ev.CollectedAtUtc, ev.CollectedFrom, ev.CollectedBy);

    public bool IsEmpty => AtUtc is null && string.IsNullOrWhiteSpace(From) && string.IsNullOrWhiteSpace(By);

    /// <summary>
    /// "from mail01 by J. Smith" (either part alone, or null when neither is recorded), for a sentence that has said
    /// when: the evidence row, the panel, the "Evidence added" milestone and the report.
    /// </summary>
    public static string? Source(Domain.Entities.Evidence ev) => Source(ev.CollectedFrom, ev.CollectedBy);

    public static string? Source(string? from, string? by) =>
        (string.IsNullOrWhiteSpace(from), string.IsNullOrWhiteSpace(by)) switch
        {
            (false, false) => $"from {from!.Trim()} by {by!.Trim()}",
            (false, true) => $"from {from!.Trim()}",
            (true, false) => $"by {by!.Trim()}",
            _ => null
        };

    /// <summary>The collection as one line for the report's evidence index: "2026-10-01 09:30 UTC, from mail01 by J. Smith".</summary>
    public static string Line(DateTimeOffset? atUtc, string? from, string? by)
    {
        var when = atUtc is { } at ? at.UtcDateTime.ToString("yyyy-MM-dd HH:mm 'UTC'", CultureInfo.InvariantCulture) : null;
        return string.Join(", ", new[] { when, Source(from, by) }.Where(s => s is not null));
    }
}
