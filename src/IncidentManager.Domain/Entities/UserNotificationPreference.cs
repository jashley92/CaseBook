using IncidentManager.Domain.Common;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// A user's personal notification preferences (PROD-39). Today it carries the consolidated-work-digest
/// cadence (off / daily / weekly); it is the seam a future per-user opt-down of the individual reminder
/// types (PROD-16) extends. One row per user, created on first opt-in.
///
/// Per-user convenience/preference state — deliberately NOT audited or hash-chained (see the interceptor's
/// NotAudited set), like <see cref="SavedView"/> and <see cref="PinnedCase"/>.
/// </summary>
public class UserNotificationPreference : Entity
{
    /// <summary>The user these preferences belong to (their stable id — the same value used as an actor).</summary>
    public string UserId { get; set; } = "";

    /// <summary>How often to send the consolidated work digest. <see cref="DigestCadence.Off"/> = no digest.</summary>
    public DigestCadence DigestCadence { get; set; } = DigestCadence.Off;

    public DateTimeOffset UpdatedAtUtc { get; set; }
}
