using IncidentManager.Domain.Common;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// A piece of evidence attached to a case. Immutable once attached: the file bytes are
/// hashed (SHA-256), stored outside the web root under a randomized name, and never executed.
/// CAP-08: when, where from and by whom it was collected are metadata about its acquisition, not the bytes, so they
/// may be set on upload or later; a later change is an audited update like any other.
/// </summary>
public class Evidence : AuditableEntity, IHashableEntity
{
    /// <summary>CAP-08: the column lengths of <see cref="CollectedFrom"/> and <see cref="CollectedBy"/>.</summary>
    public const int MaxCollectedFromLength = 300, MaxCollectedByLength = 200;

    public Guid CaseId { get; set; }
    public string OriginalFileName { get; set; } = string.Empty;
    public string ContentType { get; set; } = "application/octet-stream";
    public long SizeBytes { get; set; }

    /// <summary>Lower-case hex SHA-256 of the stored bytes.</summary>
    public string Sha256 { get; set; } = string.Empty;

    /// <summary>Relative path within the evidence store (randomized name, not the original).</summary>
    public string StoragePath { get; set; } = string.Empty;
    public string? Description { get; set; }

    /// <summary>CAP-08: when the file was collected (acquired from its source), when known. Null: taken to be the upload
    /// time (<see cref="AuditableEntity.CreatedAtUtc"/>), as before.</summary>
    public DateTimeOffset? CollectedAtUtc { get; set; }

    /// <summary>CAP-08: where it was collected from: a host, a mailbox, a system or a vendor, as written.</summary>
    public string? CollectedFrom { get; set; }

    /// <summary>CAP-08: who collected it: a person or a team, as written (not necessarily a CaseBook user).</summary>
    public string? CollectedBy { get; set; }

    /// <summary>CAP-08: when it was collected, or when it was uploaded when that isn't recorded.</summary>
    public DateTimeOffset CollectedOrUploadedAtUtc => CollectedAtUtc ?? CreatedAtUtc;

    /// <summary>CAP-08: whether any of the collection facts is recorded.</summary>
    public bool HasCollection => CollectedAtUtc is not null || CollectedFrom is not null || CollectedBy is not null;

    public List<ChainOfCustodyEvent> CustodyEvents { get; set; } = new();

    public string? RowHash { get; set; }

    /// <summary>
    /// CAP-08: checks the collection facts and returns them as they're stored (trimmed; blank is none). When it was
    /// collected is held to the rules a time recorded after the fact follows (R4): not in the future, and not before the
    /// case's activity began (<paramref name="activityBeganUtc"/>: its initial-activity time, or its detected time when
    /// that isn't recorded), compared to the minute; nor after the file was uploaded (<paramref name="uploadedAtUtc"/>;
    /// now, for an upload), since the bytes were in hand by then.
    /// </summary>
    public static (DateTimeOffset? At, string? From, string? By) CheckCollection(DateTimeOffset? collectedAtUtc,
        string? collectedFrom, string? collectedBy, DateTimeOffset nowUtc, DateTimeOffset? activityBeganUtc, DateTimeOffset uploadedAtUtc)
    {
        var from = Clean(collectedFrom);
        var by = Clean(collectedBy);
        if (from is { Length: > MaxCollectedFromLength })
            throw new ArgumentException($"Keep where it was collected from to {MaxCollectedFromLength} characters or fewer.");
        if (by is { Length: > MaxCollectedByLength })
            throw new ArgumentException($"Keep who collected it to {MaxCollectedByLength} characters or fewer.");
        if (collectedAtUtc is { } at)
        {
            if (Case.ToMinute(at) > Case.ToMinute(nowUtc))
                throw new ArgumentException("When it was collected can't be in the future.");
            if (Case.ToMinute(at) > Case.ToMinute(uploadedAtUtc))
                throw new ArgumentException("When it was collected can't be after it was uploaded.");
            if (activityBeganUtc is { } began && Case.ToMinute(at) < Case.ToMinute(began))
                throw new ArgumentException(
                    $"When it was collected can't be before the case's activity began ({began.UtcDateTime:yyyy-MM-dd HH:mm} UTC).");
        }
        return (collectedAtUtc, from, by);
    }

    private static string? Clean(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();

    public string BuildCanonicalContent()
    {
        var content = string.Join('|',
            CaseId, Canonical.Text(OriginalFileName), Canonical.Text(ContentType), SizeBytes, Sha256, CreatedBy, CreatedAtUtc.ToString("o"));
        // BUG-316: and its description (C18: an earlier format falls short only of one that's set).
        return content + Canonical.From(3, Description is not null, () => "|" + Canonical.Text(Description))
            // CAP-08: from format 4, when, where from and by whom it was collected, each only when set (R7), so a file
            // without them builds what it always did.
            + Canonical.Since(4, CollectedAtUtc is not null, () => "|collectedat|" + Canonical.Time(CollectedAtUtc))
            + Canonical.Since(4, CollectedFrom is not null, () => "|collectedfrom|" + Canonical.Text(CollectedFrom))
            + Canonical.Since(4, CollectedBy is not null, () => "|collectedby|" + Canonical.Text(CollectedBy));
    }
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
