using IncidentManager.Domain.Common;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// One coalesced access/read event (C-05): who opened a case or pulled a sensitive artifact, and how
/// many times within a rolling view-session window.
///
/// Deliberately OUT of the tamper-evident hash chain — like <see cref="EntityLayout"/> and
/// <c>ChainOfCustodyEvent</c>, this is high-volume operational telemetry, not a case mutation, and is
/// prunable independently of the immutable audit record. A restricted-case read is a fast filter over
/// this one log (<see cref="WasRestricted"/>), never a separate path.
/// </summary>
public class CaseAccessEvent : Entity
{
    public string ActorUserId { get; set; } = string.Empty;

    /// <summary>The case accessed, or <c>null</c> for a cross-case export (metrics / IOC feed / bundle).</summary>
    public Guid? CaseId { get; set; }
    public string? CaseNumber { get; set; }

    public AccessType AccessType { get; set; }

    /// <summary>The specific artifact accessed (evidence / report id), where applicable.</summary>
    public Guid? TargetId { get; set; }

    /// <summary>Human label for the target — a filename or export name.</summary>
    public string? TargetLabel { get; set; }

    /// <summary>Whether the case was restricted at access time (snapshot), so restricted reads filter fast.</summary>
    public bool WasRestricted { get; set; }

    public DateTimeOffset FirstSeenUtc { get; set; }
    public DateTimeOffset LastSeenUtc { get; set; }

    /// <summary>Number of accesses folded into this session.</summary>
    public int Count { get; set; }

    /// <summary>Begins a new view-session row at <paramref name="now"/>.</summary>
    public static CaseAccessEvent Start(string actor, Guid? caseId, string? caseNumber, AccessType type,
        Guid? targetId, string? label, bool wasRestricted, DateTimeOffset now) => new()
    {
        ActorUserId = actor,
        CaseId = caseId,
        CaseNumber = caseNumber,
        AccessType = type,
        TargetId = targetId,
        TargetLabel = label,
        WasRestricted = wasRestricted,
        FirstSeenUtc = now,
        LastSeenUtc = now,
        Count = 1
    };

    /// <summary>Folds another access at <paramref name="now"/> into this session.</summary>
    public void Touch(DateTimeOffset now)
    {
        LastSeenUtc = now;
        Count++;
    }
}
