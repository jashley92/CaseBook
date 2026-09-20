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

    // --- Per-type opt-down of personal email notifications (PROD-16). Default false = the user receives them
    // (the current behaviour). An admin can mark a type mandatory, which overrides an opt-out. These gate only
    // the personal EMAIL path — never the compliance breach→Legal distribution, and never the chat broadcast. ---

    /// <summary>Opt out of the "you've been assigned to a case" email.</summary>
    public bool SuppressAssignment { get; set; }

    /// <summary>Opt out of per-item overdue after-action reminders (e.g. when relying on the digest).</summary>
    public bool SuppressOverdue { get; set; }

    /// <summary>Opt out of per-item due-soon after-action reminders (e.g. when relying on the digest).</summary>
    public bool SuppressDueSoon { get; set; }

    public DateTimeOffset UpdatedAtUtc { get; set; }
}
