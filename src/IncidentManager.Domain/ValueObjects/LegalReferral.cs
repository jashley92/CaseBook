namespace IncidentManager.Domain.ValueObjects;

/// <summary>
/// Records a hand-off to Legal/Privacy. The tool captures the referral and the data Legal
/// needs (supporting NYDFS 23 NYCRR Part 500 / GLBA recordkeeping) but never tracks
/// notification deadlines &mdash; Legal owns the actual notification decision and timing.
/// </summary>
public class LegalReferral
{
    public bool IsReferred { get; set; }
    public DateTimeOffset? ReferredAtUtc { get; set; }
    public string? ReferredBy { get; set; }
    public string? ReferredToContact { get; set; }

    /// <summary>Free-text note on why regulatory relevance is suspected (e.g., NPI of NY residents involved).</summary>
    public string? RegulatoryRelevanceNote { get; set; }

    public string ToCanonical() =>
        $"{IsReferred}|{ReferredAtUtc:o}|{ReferredBy}|{ReferredToContact}|{RegulatoryRelevanceNote}";
}
