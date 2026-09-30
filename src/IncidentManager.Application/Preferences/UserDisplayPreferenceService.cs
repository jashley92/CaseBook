using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Preferences;

/// <summary>A user's display preferences, as the UI reads and writes them.</summary>
public sealed record DisplayPrefs(bool DarkTheme, bool NavCollapsed, bool LocalTime, bool TwelveHourClock, bool CompactRows);

/// <summary>
/// Reads and saves the current user's display preferences (theme, sidebar, time zone, clock, density) so they follow
/// the account rather than the browser. The page renders the saved values before first paint; the browser keeps a
/// copy for pages that load before sign-in resolves.
/// </summary>
public sealed class UserDisplayPreferenceService
{
    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;

    public UserDisplayPreferenceService(IAppDbContextFactory factory, ICurrentUser user, IClock clock)
    {
        _factory = factory;
        _user = user;
        _clock = clock;
    }

    /// <summary>The current user's saved preferences, or null if they've never saved any (or aren't signed in).</summary>
    public async Task<DisplayPrefs?> GetMineAsync(CancellationToken ct = default)
    {
        if (!_user.IsAuthenticated) return null;
        using var db = _factory.CreateDbContext();
        return await db.UserDisplayPreferences.AsNoTracking()
            .Where(p => p.UserId == _user.UserId)
            .Select(p => new DisplayPrefs(p.DarkTheme, p.NavCollapsed, p.LocalTime, p.TwelveHourClock, p.CompactRows))
            .FirstOrDefaultAsync(ct);
    }

    /// <summary>INV-26: whether the user keeps the timeline's attack chain open (folded unless they've opened it).</summary>
    public async Task<bool> GetAttackChainOpenAsync(CancellationToken ct = default)
    {
        if (!_user.IsAuthenticated) return false;
        using var db = _factory.CreateDbContext();
        return await db.UserDisplayPreferences.AsNoTracking()
            .Where(p => p.UserId == _user.UserId).Select(p => p.AttackChainOpen).FirstOrDefaultAsync(ct);
    }

    /// <summary>INV-26: remembers whether the user keeps the timeline's attack chain open. Kept apart from
    /// <see cref="SaveMineAsync"/>, which the browser calls with the settings it holds.</summary>
    public async Task SetAttackChainOpenAsync(bool open, CancellationToken ct = default)
    {
        if (!_user.IsAuthenticated) return;
        using var db = _factory.CreateDbContext();
        var row = await db.UserDisplayPreferences.FirstOrDefaultAsync(p => p.UserId == _user.UserId, ct);
        if (row is null)
        {
            row = new UserDisplayPreference { UserId = _user.UserId };
            db.UserDisplayPreferences.Add(row);
        }
        else if (row.AttackChainOpen == open) return;
        row.AttackChainOpen = open;
        row.UpdatedAtUtc = _clock.UtcNow;
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Saves the current user's preferences, upserting their single row. A no-op when nothing changed.</summary>
    public async Task SaveMineAsync(DisplayPrefs prefs, CancellationToken ct = default)
    {
        if (!_user.IsAuthenticated) return;
        using var db = _factory.CreateDbContext();
        var row = await db.UserDisplayPreferences.FirstOrDefaultAsync(p => p.UserId == _user.UserId, ct);
        if (row is null)
        {
            row = new UserDisplayPreference { UserId = _user.UserId };
            db.UserDisplayPreferences.Add(row);
        }
        else if (row.DarkTheme == prefs.DarkTheme && row.NavCollapsed == prefs.NavCollapsed && row.LocalTime == prefs.LocalTime
                 && row.TwelveHourClock == prefs.TwelveHourClock && row.CompactRows == prefs.CompactRows)
        {
            return;
        }
        row.DarkTheme = prefs.DarkTheme;
        row.NavCollapsed = prefs.NavCollapsed;
        row.LocalTime = prefs.LocalTime;
        row.TwelveHourClock = prefs.TwelveHourClock;
        row.CompactRows = prefs.CompactRows;
        row.UpdatedAtUtc = _clock.UtcNow;
        await db.SaveChangesAsync(ct);
    }
}
