using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
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
    private readonly IConfiguration? _config;

    public NotificationPreferenceProvider(IServiceScopeFactory scopes, IConfiguration? config = null)
    {
        _scopes = scopes;
        _config = config;
    }

    // BUG-97: a digest only replaces the per-item reminders while digests are being sent (off by default).
    private bool DigestsOn => _config?.GetValue<bool>("Notifications:DigestScan:Enabled") == true;

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

            var onDigest = p.DigestCadence != DigestCadence.Off && DigestsOn; // the digest replaces per-item reminders
            return new NotificationSuppression(
                Assignment: p.SuppressAssignment,
                Overdue: p.SuppressOverdue || onDigest,
                DueSoon: p.SuppressDueSoon || onDigest,
                Escalation: p.SuppressOverdue);
        }
        catch
        {
            return NotificationSuppression.None; // schema not present yet / transient — don't drop notifications
        }
    }
}
