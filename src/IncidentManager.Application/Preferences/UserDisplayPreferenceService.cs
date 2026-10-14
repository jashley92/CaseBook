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
        await UpsertAsync(row =>
        {
            if (row.AttackChainOpen == open) return false;
            row.AttackChainOpen = open;
            return true;
        }, ct);
    }

    /// <summary>RD-24: the current user's keyboard settings (the defaults when they've changed nothing).</summary>
    public async Task<KeymapSettings> GetKeymapAsync(CancellationToken ct = default)
    {
        if (!_user.IsAuthenticated) return KeymapSettings.Default;
        using var db = _factory.CreateDbContext();
        var row = await db.UserDisplayPreferences.AsNoTracking().Where(p => p.UserId == _user.UserId)
            .Select(p => new { p.SingleKeyShortcutsOff, p.KeyBindings }).FirstOrDefaultAsync(ct);
        return row is null ? KeymapSettings.Default : new KeymapSettings(row.SingleKeyShortcutsOff, Keymap.Deserialize(row.KeyBindings));
    }

    /// <summary>RD-24: saves the current user's keyboard settings after <see cref="Keymap.Validate"/>; throws
    /// <see cref="ArgumentException"/> with every problem when they don't validate.</summary>
    public async Task<KeymapSettings> SaveKeymapAsync(bool singleKeysOff, IReadOnlyDictionary<string, string> keys, CancellationToken ct = default)
    {
        if (!_user.IsAuthenticated) throw new InvalidOperationException("Sign in to save keyboard settings.");
        var (settings, problems) = Keymap.Validate(singleKeysOff, keys);
        if (settings is null) throw new ArgumentException(string.Join(" ", problems));
        var stored = Keymap.Serialize(settings.Keys);
        if (stored is { Length: > 2000 }) throw new ArgumentException("That's more key bindings than CaseBook can store.");
        await UpsertAsync(row =>
        {
            row.SingleKeyShortcutsOff = settings.SingleKeysOff;
            row.KeyBindings = stored;
            return true;
        }, ct);
        return settings;
    }

    /// <summary>Saves the current user's preferences, upserting their single row. A no-op when nothing changed.</summary>
    public async Task SaveMineAsync(DisplayPrefs prefs, CancellationToken ct = default)
    {
        if (!_user.IsAuthenticated) return;
        await UpsertAsync(row =>
        {
            if (row.DarkTheme == prefs.DarkTheme && row.NavCollapsed == prefs.NavCollapsed && row.LocalTime == prefs.LocalTime
                && row.TwelveHourClock == prefs.TwelveHourClock && row.CompactRows == prefs.CompactRows)
                return false;
            row.DarkTheme = prefs.DarkTheme;
            row.NavCollapsed = prefs.NavCollapsed;
            row.LocalTime = prefs.LocalTime;
            row.TwelveHourClock = prefs.TwelveHourClock;
            row.CompactRows = prefs.CompactRows;
            return true;
        }, ct);
    }

    /// <summary>
    /// Applies <paramref name="apply"/> (which returns whether it changed anything) to the user's single row, adding the
    /// row when there isn't one. BUG-368: a new user's first two tabs both find no row and both insert; the second hits
    /// the unique UserId index. That one re-reads the row the first inserted and applies its change to it instead.
    /// </summary>
    private async Task UpsertAsync(Func<UserDisplayPreference, bool> apply, CancellationToken ct)
    {
        for (var attempt = 0; ; attempt++)
        {
            using var db = _factory.CreateDbContext();
            var row = await db.UserDisplayPreferences.FirstOrDefaultAsync(p => p.UserId == _user.UserId, ct);
            var adding = row is null;
            if (row is null)
            {
                row = new UserDisplayPreference { UserId = _user.UserId };
                db.UserDisplayPreferences.Add(row);
            }
            if (!apply(row) && !adding) return;
            row.UpdatedAtUtc = _clock.UtcNow;
            try
            {
                await db.SaveChangesAsync(ct);
                return;
            }
            catch (DbUpdateException) when (adding && attempt == 0) { /* lost the insert race: update the row that won */ }
        }
    }
}
