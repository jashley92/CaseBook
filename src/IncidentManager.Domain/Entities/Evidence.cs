using IncidentManager.Domain.Common;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// A piece of evidence attached to a case. Its bytes are immutable once attached: hashed (SHA-256), stored outside the
/// web root under a randomized name, and never executed.
/// CAP-08: when, where from and by whom it was collected are metadata about its acquisition, not the bytes, so they
/// may be set on upload or later; a later change is an audited update like any other.
/// CAP-21: a file filed on the wrong case can be withdrawn, with a reason. Like a retracted timeline entry (BUG-413) it
/// stays (R3): its bytes, hash and chain of custody are kept and it can still be downloaded, but it leaves the record
/// (the report, the gates, citing and packaging). A withdrawal is final.
/// </summary>
public class Evidence : AuditableEntity, IHashableEntity
{
    /// <summary>CAP-08: the column lengths of <see cref="CollectedFrom"/> and <see cref="CollectedBy"/>.</summary>
    public const int MaxCollectedFromLength = 300, MaxCollectedByLength = 200;

    /// <summary>CAP-21: the column length of <see cref="WithdrawnReason"/>.</summary>
    public const int MaxWithdrawnReasonLength = 2000;

    /// <summary>CAP-21: the custody action a withdrawal records.</summary>
    public const string WithdrawnAction = "Withdrawn";

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

    // ---- CAP-21: a withdrawn file (never deleted, R3). ----

    /// <summary>CAP-21: when it was withdrawn; null while it stands.</summary>
    public DateTimeOffset? WithdrawnAtUtc { get; set; }

    /// <summary>CAP-21: who withdrew it.</summary>
    public string? WithdrawnBy { get; set; }

    /// <summary>CAP-21: why it was withdrawn (required).</summary>
    public string? WithdrawnReason { get; set; }

    /// <summary>CAP-21: true once the file has been withdrawn.</summary>
    public bool IsWithdrawn => WithdrawnAtUtc is not null;

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

    /// <summary>
    /// CAP-21: takes the file off the record without deleting it (R3): who, when and why, and a "Withdrawn" custody event
    /// with the reason. The bytes and the custody record stay. There's no way back, as with a retraction (BUG-413): a file
    /// withdrawn by mistake is uploaded again, as a new record with its own custody.
    /// </summary>
    public ChainOfCustodyEvent Withdraw(string reason, string actor, DateTimeOffset nowUtc)
    {
        reason = (reason ?? "").Trim();
        if (reason.Length == 0) throw new ArgumentException("Say why the file is being withdrawn.");
        if (reason.Length > MaxWithdrawnReasonLength)
            throw new ArgumentException($"Keep the reason to {MaxWithdrawnReasonLength:N0} characters or fewer.");
        if (IsWithdrawn) throw new InvalidOperationException("That file has already been withdrawn.");
        (WithdrawnAtUtc, WithdrawnBy, WithdrawnReason) = (nowUtc, actor, reason);
        (ModifiedBy, ModifiedAtUtc) = (actor, nowUtc);
        var custody = new ChainOfCustodyEvent { EvidenceId = Id, AtUtc = nowUtc, Actor = actor, Action = WithdrawnAction, Details = reason };
        CustodyEvents.Add(custody);
        return custody;
    }

    public string BuildCanonicalContent()
    {
        var content = string.Join('|',
            CaseId, Canonical.Text(OriginalFileName), Canonical.Text(ContentType), SizeBytes, Sha256, CreatedBy, CreatedAtUtc.ToString("o"));
        // BUG-316: and its description (C18: an earlier format falls short only of one that's set).
        return content + Canonical.From(3, Description is not null, () => "|" + Canonical.Text(Description))
            // CAP-08: from format 5, when, where from and by whom it was collected, each only when set (R7), so a file
            // without them builds what it always did.
            + Canonical.Since(5, CollectedAtUtc is not null, () => "|collectedat|" + Canonical.Time(CollectedAtUtc))
            + Canonical.Since(5, CollectedFrom is not null, () => "|collectedfrom|" + Canonical.Text(CollectedFrom))
            + Canonical.Since(5, CollectedBy is not null, () => "|collectedby|" + Canonical.Text(CollectedBy))
            // CAP-21: from format 5 too, a withdrawal: when, by whom and why, each only when set, so a file that stands
            // builds what it did.
            + Canonical.Since(5, WithdrawnAtUtc is not null, () => "|withdrawnat|" + Canonical.Time(WithdrawnAtUtc))
            + Canonical.Since(5, WithdrawnBy is not null, () => "|withdrawnby|" + Canonical.Text(WithdrawnBy))
            + Canonical.Since(5, WithdrawnReason is not null, () => "|withdrawnwhy|" + Canonical.Text(WithdrawnReason));
    }
}

/// <summary>An access/transfer event in an evidence item's chain of custody.</summary>
public class ChainOfCustodyEvent : Entity
{
    public Guid EvidenceId { get; set; }
    public DateTimeOffset AtUtc { get; set; }
    public string Actor { get; set; } = string.Empty;

    /// <summary>e.g. Uploaded, Downloaded, Viewed, Transferred, Withdrawn (CAP-21).</summary>
    public string Action { get; set; } = string.Empty;
    public string? Details { get; set; }
}
