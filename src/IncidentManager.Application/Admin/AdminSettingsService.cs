using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Admin;

/// <summary>An editable setting with its current effective value and where that value comes from.</summary>
/// <param name="IsOverridden">True when a DB override exists; false when the server's value applies.</param>
/// <param name="ServerValue">BUG-245: what it is without an in-app change (the server's settings file, else the
/// catalog default): what "Reset" returns it to.</param>
/// <param name="ServerValueFromFile">Whether <paramref name="ServerValue"/> comes from the server's settings file.</param>
/// <param name="Discovered">CAP-28 discovery: the domains found on the server's network, when they're in force because the
/// setting isn't set anywhere. <paramref name="Value"/> stays what is saved (blank), so the page's field shows what an
/// administrator saves; "Use these" fills it from here.</param>
/// <param name="ChangedBy">Who last saved it in Administration, and <paramref name="ChangedAtUtc"/> when (overridden only).</param>
public sealed record EffectiveSetting(SettingDefinition Definition, string? Value, bool IsOverridden,
    string? ServerValue = null, bool ServerValueFromFile = false, IReadOnlyList<DiscoveredDomain>? Discovered = null,
    string? ChangedBy = null, DateTimeOffset? ChangedAtUtc = null)
{
    public string Source => IsOverridden ? "Database" : ServerValueFromFile ? "Server settings file"
        : Discovered is not null ? "Discovered" : "Default";

    /// <summary>The value in force: <see cref="Value"/>, or the discovered domains one per line.</summary>
    public string? InForce => Discovered is { Count: > 0 } d ? string.Join("\n", d.Select(x => x.Name)) : Value;
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
    private readonly IServerSettingValues? _server;
    private readonly IRelatedExclusionsProvider? _exclusions;   // CAP-28 discovery: whether the found domains are in force
    private readonly IOrganizationDomains? _domains;

    public AdminSettingsService(IAppDbContextFactory factory, ICurrentUser user, IClock clock,
        ISettingsReloader reloader, ISecurityEventSink? siem = null, IServerSettingValues? server = null,
        IRelatedExclusionsProvider? exclusions = null, IOrganizationDomains? domains = null)
    {
        _factory = factory;
        _user = user;
        _clock = clock;
        _reloader = reloader;
        _siem = siem;
        _server = server;
        _exclusions = exclusions;
        _domains = domains;
    }

    /// <summary>Every editable setting with its current effective value: the in-app change, else the server's settings
    /// file, else the catalog default. BUG-245: not the catalog default alone, which the files may not use (the
    /// production template seals every 24 h, not the default 6), so the page showed values that weren't in force.</summary>
    public async Task<IReadOnlyList<EffectiveSetting>> GetEffectiveAsync(CancellationToken ct = default)
    {
        using var db = _factory.CreateDbContext();
        var overrides = await db.AppSettings.AsNoTracking()
            .ToDictionaryAsync(s => s.Key, s => (s.Value, s.UpdatedBy, s.UpdatedAtUtc), StringComparer.OrdinalIgnoreCase, ct);

        return SettingsCatalog.Editable
            .Select(d =>
            {
                var file = _server?.ValueOf(d.Key) is { } f ? SafeNormalize(d, f) : null;
                var server = file ?? d.Default;
                return overrides.TryGetValue(d.Key, out var v)
                    ? new EffectiveSetting(d, v.Value, true, server, file is not null, null, v.UpdatedBy, v.UpdatedAtUtc)
                    : new EffectiveSetting(d, server, false, server, file is not null,
                        // CAP-28 discovery: never stored, so a bundle or a save of another setting never carries it.
                        d.Key == RelatedExclusionSettings.DomainsKey && file is null ? _exclusions?.DiscoveredInForce : null);
            })
            .ToList();
    }

    // The file's value as the page would save it (a list one item per line, a bool lower-case); as written if it
    // doesn't pass the page's checks, so the page still shows what the server runs on.
    private static string SafeNormalize(SettingDefinition d, string value)
    {
        try { return SettingsCatalog.Normalize(d, value) ?? value; }
        catch (ArgumentException) { return value; }
    }

    /// <summary>
    /// Upserts an operational setting after validating the key and value. The change is audited and
    /// hash-chained. Throws for unknown keys or values that fail the catalog's type rules.
    /// </summary>
    public async Task SetAsync(string key, string? value, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<AdminSettingsService>(_user, _siem);
        await SetCoreAsync(key, value, false, null, ct);
    }

    /// <summary>
    /// BUG-438: as <see cref="SetAsync(string, string?, CancellationToken)"/>, for a value the page saves whole (the report
    /// section layout), so a page opened before another administrator's change can't write over it.
    /// <paramref name="expectedStored"/> is the in-app value the page loaded (null when there was none); a stored value
    /// that differs now is refused.
    /// </summary>
    public async Task SetAsync(string key, string? value, string? expectedStored, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<AdminSettingsService>(_user, _siem);
        await SetCoreAsync(key, value, true, expectedStored, ct);
    }

    private async Task SetCoreAsync(string key, string? value, bool checkExpected, string? expectedStored, CancellationToken ct)
    {
        using var guard = await GuardGate.EnterAsync(ct);   // BUG-567: the stored-value check with the save, and not inside an import
        using var db = _factory.CreateDbContext();
        if (!SettingsCatalog.ByKey.TryGetValue(key, out var def))
            throw new InvalidOperationException($"'{key}' is not an editable operational setting.");

        var normalized = SettingsCatalog.Normalize(def, value);

        var existing = await db.AppSettings.FirstOrDefaultAsync(s => s.Key == key, ct);
        if (checkExpected && !string.Equals(existing?.Value, expectedStored, StringComparison.Ordinal))
            throw new InvalidOperationException(ChangedSinceOpened(def));
        var adding = existing is null;
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

        try { await db.SaveChangesAsync(ct); }
        // BUG-459: the override was reset (removed) between the read above and this update; the context reports that as a
        // ConcurrentEditException, whose message is about cases.
        catch (ConcurrentEditException ex) { throw new InvalidOperationException(ChangedSinceOpened(def), ex); }
        catch (DbUpdateException ex) when (adding)
        {
            // BUG-459 (as BUG-393): another administrator's first override of this setting was saved between the read
            // above and this insert (the unique key refused it).
            using var recheck = _factory.CreateDbContext();
            if (await recheck.AppSettings.AnyAsync(s => s.Key == key, ct))
                throw new InvalidOperationException($"Another administrator saved \"{def.Label}\" at the same moment, so nothing " +
                    "was saved. Reload the page to see their change, then make yours again.", ex);
            throw;
        }
        var reloadError = _reloader.ReloadAndReport(); // make the override take effect at runtime, no restart
        _siem?.Emit(SecurityEvents.SettingChanged(key, _user.UserId, _user.UserPrincipalName));
        ThrowIfNotInEffect(reloadError);
    }

    private static string ChangedSinceOpened(SettingDefinition def) =>
        $"Someone changed \"{def.Label}\" since you opened it, so nothing was saved: " +
        "it would have undone that. Reload the page, then make your change again.";

    /// <summary>
    /// REV-60: the change is saved (and audited), but a reload that couldn't read the settings keeps the earlier values,
    /// so it isn't in effect yet. The page would otherwise show the new value as if it were. BUG-526: as a
    /// <see cref="SettingsNotInEffectException"/>, so the page can tell it from a save that didn't happen.
    /// </summary>
    private static void ThrowIfNotInEffect(string? reloadError) => SettingsReloads.ThrowIfNotInEffect(reloadError);

    /// <summary>
    /// CAP-28 discovery: looks for the organization's domains on the server's network again (Administration's "Look
    /// again"), within the discovery's time limit; joins a look under way. Nothing is saved: the page offers what's found.
    /// </summary>
    public async Task<DomainDiscovery> DiscoverDomainsAsync(CancellationToken ct = default)
    {
        AdminActionPermissions.Require<AdminSettingsService>(_user, _siem);
        return _domains is null ? DomainDiscovery.NotYet : await _domains.DiscoverAsync(ct);
    }

    /// <summary>
    /// Removes the DB override for a setting so it reverts to its server-side/catalog default. The
    /// removal is itself audited. No-op if there is no override.
    /// </summary>
    public async Task ResetAsync(string key, CancellationToken ct = default)
    {
        AdminActionPermissions.Require<AdminSettingsService>(_user, _siem);
        using var guard = await GuardGate.EnterAsync(ct);   // BUG-567: not between an import's load and its save
        using var db = _factory.CreateDbContext();
        var existing = await db.AppSettings.FirstOrDefaultAsync(s => s.Key == key, ct);
        if (existing is null) return;

        db.AppSettings.Remove(existing);
        try { await db.SaveChangesAsync(ct); }
        // BUG-437: another reset (a double click, or another administrator) removed it first; it's reset either way. The
        // context reports the lost delete as a ConcurrentEditException, not EF's own exception.
        catch (ConcurrentEditException) { return; }
        var reloadError = _reloader.ReloadAndReport(); // revert to the server-side/default value at runtime
        _siem?.Emit(SecurityEvents.SettingChanged(key, _user.UserId, _user.UserPrincipalName));
        ThrowIfNotInEffect(reloadError);
    }
}
