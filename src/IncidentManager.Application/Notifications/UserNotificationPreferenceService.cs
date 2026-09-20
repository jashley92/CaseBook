using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Notifications;

/// <summary>An opted-in user and the digest cadence they chose (PROD-39) — the scanner's work list.</summary>
public sealed record DigestSubscriber(string UserId, DigestCadence Cadence);

/// <summary>
/// Reads and writes a user's personal notification preferences (PROD-39): today, the consolidated-work-digest
/// cadence. Each user manages only their own row (self-service), created on first opt-in. The scanner uses
/// <see cref="ListSubscribersAsync"/> to find who wants a digest. This is the seam a future per-user opt-down
/// of the individual reminder types (PROD-16) extends.
/// </summary>
public sealed class UserNotificationPreferenceService
{
    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;

    public UserNotificationPreferenceService(IAppDbContextFactory factory, ICurrentUser user, IClock clock)
    {
        _factory = factory;
        _user = user;
        _clock = clock;
    }

    /// <summary>The current user's digest cadence (<see cref="DigestCadence.Off"/> when they've never set one).</summary>
    public async Task<DigestCadence> GetMyDigestCadenceAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var pref = await db.UserNotificationPreferences.AsNoTracking()
            .FirstOrDefaultAsync(p => p.UserId == _user.UserId, ct);
        return pref?.DigestCadence ?? DigestCadence.Off;
    }

    /// <summary>Sets the current user's digest cadence, upserting their single preference row.</summary>
    public async Task SetMyDigestCadenceAsync(DigestCadence cadence, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var pref = await db.UserNotificationPreferences
            .FirstOrDefaultAsync(p => p.UserId == _user.UserId, ct);
        if (pref is null)
        {
            db.UserNotificationPreferences.Add(new UserNotificationPreference
            {
                UserId = _user.UserId, DigestCadence = cadence, UpdatedAtUtc = _clock.UtcNow
            });
        }
        else
        {
            pref.DigestCadence = cadence;
            pref.UpdatedAtUtc = _clock.UtcNow;
        }
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Everyone who has opted in to a digest (cadence not Off) — the scanner's work list.</summary>
    public async Task<IReadOnlyList<DigestSubscriber>> ListSubscribersAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        return await db.UserNotificationPreferences.AsNoTracking()
            .Where(p => p.DigestCadence != DigestCadence.Off)
            .Select(p => new DigestSubscriber(p.UserId, p.DigestCadence))
            .ToListAsync(ct);
    }
}
