using System.Collections.Concurrent;
using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace IncidentManager.Infrastructure.Security;

/// <summary>
/// Singleton, in-memory mirror of the <c>AppUser</c> directory. Reads the table once (and again on
/// <see cref="Invalidate"/>), answering id→name/email lookups from memory. Users self-populate on
/// sign-in via <see cref="TouchAsync"/>, which is throttled so an active session doesn't write per
/// request. <c>AppUser</c> is excluded from the audit chain, so mirror upkeep never disturbs integrity.
/// </summary>
public sealed class UserDirectory : IUserDirectory
{
    private static readonly TimeSpan RefreshWindow = TimeSpan.FromMinutes(30);

    private readonly IServiceScopeFactory _scopes;
    private volatile IReadOnlyDictionary<string, UserSummary> _byId =
        new Dictionary<string, UserSummary>(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DateTimeOffset> _lastTouched = new(StringComparer.OrdinalIgnoreCase);

    public UserDirectory(IServiceScopeFactory scopes)
    {
        _scopes = scopes;
        Invalidate();
    }

    public void Invalidate()
    {
        try
        {
            using var scope = _scopes.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var users = db.Users.AsNoTracking().ToList();
            _byId = users.ToDictionary(
                u => u.Sid,
                u => new UserSummary(u.Sid, u.DisplayName, u.UserPrincipalName, u.Email, u.RolesCsv),
                StringComparer.OrdinalIgnoreCase);
        }
        catch
        {
            // Schema not present yet (first run, pre-migration). Rebuilt after the seeder runs.
        }
    }

    public async Task TouchAsync(string userId, string displayName, string? upn, string? email, string rolesCsv,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(userId) || string.Equals(userId, "system", StringComparison.OrdinalIgnoreCase))
            return;

        // Cheap in-memory throttle: skip the database when we've recorded this user recently.
        if (_lastTouched.TryGetValue(userId, out var last) && DateTimeOffset.UtcNow - last < RefreshWindow)
            return;

        try
        {
            using var scope = _scopes.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var now = DateTimeOffset.UtcNow;

            var existing = await db.Users.FirstOrDefaultAsync(u => u.Sid == userId, ct);
            if (existing is null)
            {
                db.Users.Add(new AppUser
                {
                    Sid = userId,
                    DisplayName = displayName,
                    UserPrincipalName = upn ?? string.Empty,
                    Email = email,
                    RolesCsv = rolesCsv,
                    LastSeenUtc = now
                });
            }
            else
            {
                existing.DisplayName = displayName;
                existing.UserPrincipalName = upn ?? existing.UserPrincipalName;
                existing.Email = email ?? existing.Email;
                existing.RolesCsv = rolesCsv;
                existing.LastSeenUtc = now;
            }

            await db.SaveChangesAsync(ct);
            _lastTouched[userId] = now;

            // Refresh just this entry in the snapshot (copy-on-write to stay lock-free for readers).
            _byId = new Dictionary<string, UserSummary>(_byId, StringComparer.OrdinalIgnoreCase)
            {
                [userId] = new UserSummary(userId, displayName, upn, email, rolesCsv)
            };
        }
        catch
        {
            // Directory maintenance must never fail a request; a later touch will retry.
        }
    }

    public IReadOnlyList<UserSummary> All() =>
        _byId.Values.OrderBy(u => u.DisplayName, StringComparer.OrdinalIgnoreCase).ToList();

    public UserSummary? Resolve(string userId) =>
        !string.IsNullOrEmpty(userId) && _byId.TryGetValue(userId, out var u) ? u : null;

    public string DisplayFor(string? userId)
    {
        if (string.IsNullOrEmpty(userId)) return "—";
        if (string.Equals(userId, "system", StringComparison.OrdinalIgnoreCase)) return "System";
        return _byId.TryGetValue(userId, out var u) && !string.IsNullOrWhiteSpace(u.DisplayName)
            ? u.DisplayName
            : userId;
    }

    public string? EmailFor(string userId) =>
        _byId.TryGetValue(userId, out var u) ? u.Email : null;
}
