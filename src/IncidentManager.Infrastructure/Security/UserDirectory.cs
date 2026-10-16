using System.Collections.Concurrent;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Common;
using IncidentManager.Domain.Entities;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

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

    /// <summary>The <c>Users.DisplayName</c>, <c>.UserPrincipalName</c> and <c>.Email</c> columns.</summary>
    public const int MaxDisplayNameLength = 200, MaxUpnLength = 200, MaxEmailLength = 300;

    // BUG-216: after a failed write, how long before that user's is tried again (not on every request).
    private static readonly TimeSpan RetryAfterFailure = TimeSpan.FromMinutes(5);

    private readonly IServiceScopeFactory _scopes;
    private readonly ILogger<UserDirectory> _logger;
    private volatile IReadOnlyDictionary<string, UserSummary> _byId =
        new Dictionary<string, UserSummary>(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DateTimeOffset> _lastTouched = new(StringComparer.OrdinalIgnoreCase);
    // BUG-218: writers swap the snapshot under this lock (readers take it lock-free), so two sign-ins at once can't each
    // copy the same old snapshot and lose the other's entry.
    private readonly object _swap = new();

    public UserDirectory(IServiceScopeFactory scopes, ILogger<UserDirectory>? logger = null)
    {
        _scopes = scopes;
        _logger = logger ?? NullLogger<UserDirectory>.Instance;
        Invalidate();
    }

    public void Invalidate()
    {
        try
        {
            using var scope = _scopes.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var users = db.Users.AsNoTracking().ToList();
            var all = users.ToDictionary(
                u => u.Sid,
                u => new UserSummary(u.Sid, u.DisplayName, u.UserPrincipalName, u.Email, u.RolesCsv),
                StringComparer.OrdinalIgnoreCase);
            lock (_swap) _byId = all;
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

        // C12: directory values over their columns made SQL Server refuse the row, so the user's roles were never mirrored.
        // A long display name is shortened; a UPN or address that long is left out (cut short, it would be someone else's).
        displayName = TextFit.Cap(displayName, MaxDisplayNameLength);
        if (upn?.Length > MaxUpnLength) upn = null;
        if (email?.Length > MaxEmailLength) email = null;

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
            lock (_swap)
                _byId = new Dictionary<string, UserSummary>(_byId, StringComparer.OrdinalIgnoreCase)
                {
                    [userId] = new UserSummary(userId, displayName, upn, email, rolesCsv)
                };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Directory maintenance must never fail a request; a later touch will retry. BUG-216: but not silently, since
            // the mirror's roles feed who a restricted case's notifications reach, and not on every request.
            _logger.LogWarning(ex, "Couldn't update the user directory entry for {UserId}; its roles there may be out of date.", userId);
            _lastTouched[userId] = DateTimeOffset.UtcNow - RefreshWindow + RetryAfterFailure;
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
