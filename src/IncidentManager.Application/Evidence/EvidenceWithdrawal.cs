namespace IncidentManager.Application.Evidence;

/// <summary>
/// A withdrawn file's afterlife: it can be reinstated for <see cref="EvidenceStorageOptions.ReinstateWithinDays"/> after its
/// withdrawal (unless it was moved or purged), and an administrator can purge its bytes once that time is over.
/// </summary>
public static class EvidenceWithdrawal
{
    /// <summary>The period in force, kept within 0 (reinstating off) and <see cref="EvidenceStorageOptions.MaxReinstateWithinDays"/>.</summary>
    public static int WindowDays(EvidenceStorageOptions o) => Math.Clamp(o.ReinstateWithinDays, 0, EvidenceStorageOptions.MaxReinstateWithinDays);

    /// <summary>Until when a withdrawn file can be reinstated; null when it can't be (it stands, was moved or purged, or
    /// reinstating is off).</summary>
    public static DateTimeOffset? ReinstatableUntil(Domain.Entities.Evidence e, int windowDays) =>
        e.WithdrawnAtUtc is { } at && windowDays > 0 && !e.IsPurged && !e.WasMovedOut
            ? Common.Instants.AddClamped(at, TimeSpan.FromDays(windowDays))
            : null;

    /// <summary>Whether an administrator can purge it now: withdrawn, not purged, and past its time to be reinstated.</summary>
    public static bool Purgeable(Domain.Entities.Evidence e, int windowDays, DateTimeOffset nowUtc) =>
        e.IsWithdrawn && !e.IsPurged && (ReinstatableUntil(e, windowDays) is not { } until || nowUtc > until);
}

/// <summary>A withdrawn file, as the administrator's pane lists it.</summary>
public sealed record WithdrawnEvidenceRow(Guid EvidenceId, Guid CaseId, string CaseNumber, bool LegalHold, string FileName, long SizeBytes,
    string Sha256, string? WithdrawnBy, DateTimeOffset WithdrawnAtUtc, string? WithdrawnReason, DateTimeOffset? ReinstatableUntil,
    bool MovedOut, bool Purgeable);
