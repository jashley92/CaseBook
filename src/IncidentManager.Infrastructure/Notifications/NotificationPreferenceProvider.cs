using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace IncidentManager.Infrastructure.Notifications;

/// <summary>
/// Singleton lookup of a user's effective notification suppressions (PROD-16), read from the
/// <c>UserNotificationPreferences</c> table on demand within a short-lived scope (the <see cref="IUserDirectory"/>
/// pattern) so it can be injected into the singleton notifier. A digest subscriber's per-item overdue/due-soon
/// are folded in as suppressed here, since the digest already covers them (PROD-39). No preference row ⇒
/// nothing suppressed (the current behaviour). Never throws into the caller — a lookup failure suppresses
/// nothing.
/// </summary>
public sealed class NotificationPreferenceProvider : INotificationPreferenceProvider
{
    private readonly IServiceScopeFactory _scopes;

    public NotificationPreferenceProvider(IServiceScopeFactory scopes) => _scopes = scopes;

    public async Task<NotificationSuppression> GetAsync(string userId, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(userId)) return NotificationSuppression.None;
        try
        {
            using var scope = _scopes.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var p = await db.UserNotificationPreferences.AsNoTracking()
                .FirstOrDefaultAsync(x => x.UserId == userId, ct);
            if (p is null) return NotificationSuppression.None;

            var onDigest = p.DigestCadence != DigestCadence.Off; // the digest replaces per-item reminders
            return new NotificationSuppression(
                Assignment: p.SuppressAssignment,
                Overdue: p.SuppressOverdue || onDigest,
                DueSoon: p.SuppressDueSoon || onDigest);
        }
        catch
        {
            return NotificationSuppression.None; // schema not present yet / transient — don't drop notifications
        }
    }
}
