using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Admin;

/// <summary>An editable setting with its current effective value and where that value comes from.</summary>
/// <param name="IsOverridden">True when a DB override exists; false when the catalog default applies.</param>
public sealed record EffectiveSetting(SettingDefinition Definition, string? Value, bool IsOverridden)
{
    public string Source => IsOverridden ? "Database" : "Default";
}

/// <summary>
/// Reads and writes the operational settings administered in the web console (A-02). Every write is a
/// normal tracked mutation, so it flows through the audit/hash-chain interceptor automatically — each
/// change is attributable and tamper-evident. Only whitelisted keys (<see cref="SettingsCatalog"/>)
/// are accepted; anything else is rejected.
/// </summary>
public sealed class AdminSettingsService
{
    private readonly IAppDbContextFactory _factory;
    private readonly ICurrentUser _user;
    private readonly IClock _clock;
    private readonly ISettingsReloader _reloader;
    private readonly ISecurityEventSink? _siem;

    public AdminSettingsService(IAppDbContextFactory factory, ICurrentUser user, IClock clock,
        ISettingsReloader reloader, ISecurityEventSink? siem = null)
    {
        _factory = factory;
        _user = user;
        _clock = clock;
        _reloader = reloader;
        _siem = siem;
    }

    /// <summary>Every editable setting with its current effective value (DB override, else catalog default).</summary>
    public async Task<IReadOnlyList<EffectiveSetting>> GetEffectiveAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var overrides = await db.AppSettings.AsNoTracking()
            .ToDictionaryAsync(s => s.Key, s => s.Value, StringComparer.OrdinalIgnoreCase, ct);

        return SettingsCatalog.Editable
            .Select(d => overrides.TryGetValue(d.Key, out var v)
                ? new EffectiveSetting(d, v, true)
                : new EffectiveSetting(d, d.Default, false))
            .ToList();
    }

    /// <summary>
    /// Upserts an operational setting after validating the key and value. The change is audited and
    /// hash-chained. Throws for unknown keys or values that fail the catalog's type rules.
    /// </summary>
    public async Task SetAsync(string key, string? value, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        if (!SettingsCatalog.ByKey.TryGetValue(key, out var def))
            throw new InvalidOperationException($"'{key}' is not an editable operational setting.");

        var normalized = SettingsCatalog.Normalize(def, value);

        var existing = await db.AppSettings.FirstOrDefaultAsync(s => s.Key == key, ct);
        if (existing is null)
        {
            db.AppSettings.Add(new AppSetting
            {
                Key = key,
                Value = normalized,
                UpdatedAtUtc = _clock.UtcNow,
                UpdatedBy = _user.UserId
            });
        }
        else
        {
            existing.Value = normalized;
            existing.UpdatedAtUtc = _clock.UtcNow;
            existing.UpdatedBy = _user.UserId;
        }

        await db.SaveChangesAsync(ct);
        _reloader.Reload(); // make the override take effect at runtime, no restart
        _siem?.Emit(SecurityEvents.SettingChanged(key, _user.UserId, _user.UserPrincipalName));
    }

    /// <summary>
    /// Removes the DB override for a setting so it reverts to its server-side/catalog default. The
    /// removal is itself audited. No-op if there is no override.
    /// </summary>
    public async Task ResetAsync(string key, CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var existing = await db.AppSettings.FirstOrDefaultAsync(s => s.Key == key, ct);
        if (existing is null) return;

        db.AppSettings.Remove(existing);
        await db.SaveChangesAsync(ct);
        _reloader.Reload(); // revert to the server-side/default value at runtime
        _siem?.Emit(SecurityEvents.SettingChanged(key, _user.UserId, _user.UserPrincipalName));
    }
}
