using IncidentManager.Domain.Common;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// A case a user has pinned for quick access (PROD-20): the pinned cases surface atop the command palette
/// and on My Work so the handful a person is actively working are one keystroke away.
///
/// Per-user convenience state — deliberately NOT audited or hash-chained (see the interceptor's NotAudited
/// set), like <see cref="SavedView"/> and <see cref="EntityLayout"/>.
/// </summary>
public class PinnedCase : Entity
{
    /// <summary>The user who pinned the case (their pins are private to them).</summary>
    public string UserId { get; set; } = "";

    public Guid CaseId { get; set; }

    public DateTimeOffset PinnedAtUtc { get; set; }
}
