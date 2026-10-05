using IncidentManager.Domain.Common;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// RD-21: a case a user has open as a workspace tab, so the cases they're on are restored when they sign in again.
/// Opening a case adds it; closing the tab removes it. Pinned cases (<see cref="PinnedCase"/>) are tabs that stay.
///
/// Per-user convenience state, deliberately NOT audited or hash-chained (see the interceptor's NotAudited set), like
/// <see cref="PinnedCase"/>. Opening a case is already recorded in the access log.
/// </summary>
public class OpenCaseTab : Entity
{
    /// <summary>The user whose tab this is (their stable id).</summary>
    public string UserId { get; set; } = "";

    public Guid CaseId { get; set; }

    /// <summary>When the tab was first opened (the strip's order).</summary>
    public DateTimeOffset OpenedAtUtc { get; set; }

    /// <summary>When the user last had the case in front of them (the least recent tab is the one let go).</summary>
    public DateTimeOffset LastSeenAtUtc { get; set; }
}
