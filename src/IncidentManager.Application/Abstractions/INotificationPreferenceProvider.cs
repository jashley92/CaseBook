namespace IncidentManager.Application.Abstractions;

/// <summary>
/// Which personal email notifications a user has opted out of (PROD-16). Flags are effective suppressions —
/// the digest overlay is already folded in (a digest subscriber's per-item overdue/due-soon are treated as
/// suppressed, since the digest covers them). Admin "mandatory" policy is applied by the caller, not here.
/// </summary>
public sealed record NotificationSuppression(bool Assignment, bool Overdue, bool DueSoon)
{
    public static readonly NotificationSuppression None = new(false, false, false);
}

/// <summary>
/// Resolves a user's effective notification suppressions (PROD-16) for the notifier, which is a singleton —
/// so this is implemented as a singleton over the preference table (mirroring <see cref="IUserDirectory"/>).
/// Reads only; a user with no stored preference suppresses nothing.
/// </summary>
public interface INotificationPreferenceProvider
{
    Task<NotificationSuppression> GetAsync(string userId, CancellationToken ct = default);
}
