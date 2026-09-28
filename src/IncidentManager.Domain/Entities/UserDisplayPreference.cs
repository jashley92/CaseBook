using IncidentManager.Domain.Common;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// A user's display preferences: theme, sidebar, on-screen time zone, clock format and list density. Stored per
/// account so they follow the analyst to any workstation or shared console, not just the browser they set them in.
/// One row per user, created the first time any of them is saved.
///
/// Per-user convenience state, deliberately NOT audited or hash-chained (see the interceptor's NotAudited set),
/// like <see cref="UserNotificationPreference"/>, <see cref="SavedView"/> and <see cref="PinnedCase"/>.
/// </summary>
public class UserDisplayPreference : Entity
{
    /// <summary>The user these preferences belong to (their stable id, the same value used as an actor).</summary>
    public string UserId { get; set; } = "";

    /// <summary>True for the dark theme, false for light.</summary>
    public bool DarkTheme { get; set; }

    /// <summary>The desktop sidebar is collapsed to icons.</summary>
    public bool NavCollapsed { get; set; }

    /// <summary>On-screen times in the viewer's local zone rather than UTC. Records and exports stay UTC.</summary>
    public bool LocalTime { get; set; }

    /// <summary>12-hour clock rather than 24-hour.</summary>
    public bool TwelveHourClock { get; set; }

    /// <summary>Compact list rows rather than comfortable.</summary>
    public bool CompactRows { get; set; }

    public DateTimeOffset UpdatedAtUtc { get; set; }
}
