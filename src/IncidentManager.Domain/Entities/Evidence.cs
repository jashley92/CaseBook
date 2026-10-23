using IncidentManager.Domain.Common;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// A piece of evidence attached to a case. Its bytes are immutable once attached: hashed (SHA-256), stored outside the
/// web root under a randomized name, and never executed.
/// CAP-08: when, where from and by whom it was collected are metadata about its acquisition, not the bytes, so they
/// may be set on upload or later; a later change is an audited update like any other.
/// CAP-21: a file filed on the wrong case can be withdrawn, with a reason. Like a retracted timeline entry (BUG-413) it
/// stays (R3): its bytes, hash and chain of custody are kept and it can still be downloaded, but it leaves the record
/// (the report, the gates, citing and packaging). It can be reinstated, with a reason, within the period an
/// administrator sets (Evidence:ReinstateWithinDays); it can be moved to the right case instead; and, once that period is
/// over, an administrator can purge its bytes, for content that must not be kept, leaving its record, hash and custody.
/// </summary>
public class Evidence : AuditableEntity, IHashableEntity
{
    /// <summary>CAP-08: the column lengths of <see cref="CollectedFrom"/> and <see cref="CollectedBy"/>.</summary>
    public const int MaxCollectedFromLength = 300, MaxCollectedByLength = 200;

    /// <summary>CAP-21: the column length of <see cref="WithdrawnReason"/>.</summary>
    public const int MaxWithdrawnReasonLength = 2000;

    /// <summary>CAP-21: the custody action a withdrawal records.</summary>
    public const string WithdrawnAction = "Withdrawn";

    /// <summary>The custody actions of a reinstatement, a move (on the file left behind, and on the copy on the right
    /// case) and a purge.</summary>
    public const string ReinstatedAction = "Reinstated", MovedOutAction = "MovedOut", MovedInAction = "MovedIn", PurgedAction = "Purged";

    public Guid CaseId { get; set; }
    public string OriginalFileName { get; set; } = string.Empty;
    public string ContentType { get; set; } = "application/octet-stream";
    public long SizeBytes { get; set; }

    /// <summary>Lower-case hex SHA-256 of the stored bytes.</summary>
    public string Sha256 { get; set; } = string.Empty;

    /// <summary>Relative path within the evidence store (randomized name, not the original).</summary>
    public string StoragePath { get; set; } = string.Empty;

    /// <summary>BUG-712: whether the stored file was written encrypted (CBE1), so reading it never guesses from its own
    /// first bytes; null for a file stored before this was kept (decided from its bytes). Set to true, as CaseBook's
    /// upkeep, when PROD-57's conversion encrypts a plain file. Hashed from format 9, only when set.</summary>
    public bool? StoredEncrypted { get; set; }
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

    // ---- A purged file: its bytes deleted from the store by an administrator; the record stays. ----

    /// <summary>When its bytes were purged; null while they're held.</summary>
    public DateTimeOffset? PurgedAtUtc { get; set; }
    public string? PurgedBy { get; set; }
    public string? PurgedReason { get; set; }

    /// <summary>True once the file's bytes have been purged: it can't be downloaded, checked or reinstated.</summary>
    public bool IsPurged => PurgedAtUtc is not null;

    /// <summary>True when the file was moved to another case (its custody says so): the copy there is the record now.</summary>
    public bool WasMovedOut => CustodyEvents.Any(c => c.Action == MovedOutAction);

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

    /// <summary>
    /// Puts a withdrawn file back on the record, with a reason, while <paramref name="reinstatableUntil"/> (the end of the
    /// period an administrator set, worked out by the caller; null when reinstating is off) hasn't passed. The withdrawal is
    /// cleared on the file, and both it and the reinstatement stay in the chain of custody and the audit trail. Not for a
    /// file moved to another case (the copy there is the record) or one whose bytes were purged.
    /// </summary>
    public ChainOfCustodyEvent Reinstate(string reason, string actor, DateTimeOffset nowUtc, DateTimeOffset? reinstatableUntil)
    {
        reason = CheckReason(reason, "reinstated");
        if (!IsWithdrawn) throw new InvalidOperationException("That file hasn't been withdrawn.");
        if (IsPurged) throw new InvalidOperationException("That file's contents were purged, so it can't be put back.");
        if (WasMovedOut) throw new InvalidOperationException("That file was moved to another case, where it's on the record; it can't be put back here too.");
        if (reinstatableUntil is not { } until)
            throw new InvalidOperationException("Withdrawn files can't be reinstated on this server (an administrator has turned it off).");
        if (nowUtc > until)
            throw new InvalidOperationException($"The time to reinstate this file ended {until.UtcDateTime:yyyy-MM-dd HH:mm} UTC, so its " +
                                                "withdrawal is final. Upload it again if it belongs here.");
        (WithdrawnAtUtc, WithdrawnBy, WithdrawnReason) = (null, null, null);
        (ModifiedBy, ModifiedAtUtc) = (actor, nowUtc);
        var custody = new ChainOfCustodyEvent { EvidenceId = Id, AtUtc = nowUtc, Actor = actor, Action = ReinstatedAction, Details = reason };
        CustodyEvents.Add(custody);
        return custody;
    }

    /// <summary>
    /// Records that a withdrawn file's bytes are purged (deleted from the store, by the caller, once this is saved): who,
    /// when and why, and a "Purged" custody event. Only a withdrawn file whose time to be reinstated is over
    /// (<paramref name="reinstatableUntil"/> passed, or reinstating off), and never on a case under a legal hold. The
    /// record, its SHA-256 and its custody stay, so what was held and what became of it is known.
    /// </summary>
    public ChainOfCustodyEvent Purge(string reason, string actor, DateTimeOffset nowUtc, DateTimeOffset? reinstatableUntil, bool legalHold)
    {
        reason = CheckReason(reason, "purged");
        if (!IsWithdrawn) throw new InvalidOperationException("Withdraw the file first: only a file off the record can be purged.");
        if (IsPurged) throw new InvalidOperationException("That file's contents were purged already.");
        if (legalHold) throw new InvalidOperationException("The case is under a legal hold, so nothing on it can be purged. The hold has to be released first.");
        if (reinstatableUntil is { } until && nowUtc <= until)
            throw new InvalidOperationException($"This file can still be reinstated until {until.UtcDateTime:yyyy-MM-dd HH:mm} UTC; it can be purged after that.");
        (PurgedAtUtc, PurgedBy, PurgedReason) = (nowUtc, actor, reason);
        (ModifiedBy, ModifiedAtUtc) = (actor, nowUtc);
        var custody = new ChainOfCustodyEvent { EvidenceId = Id, AtUtc = nowUtc, Actor = actor, Action = PurgedAction, Details = reason };
        CustodyEvents.Add(custody);
        return custody;
    }

    private static string CheckReason(string? reason, string what)
    {
        reason = (reason ?? "").Trim();
        if (reason.Length == 0) throw new ArgumentException($"Say why the file is being {what}.");
        if (reason.Length > MaxWithdrawnReasonLength)
            throw new ArgumentException($"Keep the reason to {MaxWithdrawnReasonLength:N0} characters or fewer.");
        return reason;
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
            + Canonical.Since(5, WithdrawnReason is not null, () => "|withdrawnwhy|" + Canonical.Text(WithdrawnReason))
            // From format 6, a purge, each only when set, so a file that wasn't purged builds what it did.
            + Canonical.Since(6, PurgedAtUtc is not null, () => "|purgedat|" + Canonical.Time(PurgedAtUtc))
            + Canonical.Since(6, PurgedBy is not null, () => "|purgedby|" + Canonical.Text(PurgedBy))
            + Canonical.Since(6, PurgedReason is not null, () => "|purgedwhy|" + Canonical.Text(PurgedReason))
            // BUG-712: from format 9, how the file is stored, only when it's recorded, so a row from before builds what it did.
            + Canonical.Since(9, StoredEncrypted is not null, () => "|encrypted|" + (StoredEncrypted == true ? "1" : "0"));
    }
}

/// <summary>An access/transfer event in an evidence item's chain of custody.</summary>
public class ChainOfCustodyEvent : Entity
{
    public Guid EvidenceId { get; set; }
    public DateTimeOffset AtUtc { get; set; }
    public string Actor { get; set; } = string.Empty;

    /// <summary>e.g. Uploaded, Downloaded, Viewed, Transferred, Withdrawn (CAP-21), Reinstated, MovedOut, MovedIn, Purged.</summary>
    public string Action { get; set; } = string.Empty;
    public string? Details { get; set; }
}
