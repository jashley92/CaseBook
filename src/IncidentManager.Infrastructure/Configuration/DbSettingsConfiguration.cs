using IncidentManager.Application.Admin;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Configuration;

namespace IncidentManager.Infrastructure.Configuration;

/// <summary>
/// A configuration source backed by the <c>AppSettings</c> table, layered on top of the file/env
/// providers so administered operational overrides take effect at runtime (A-08). Only the
/// whitelisted operational subset is stored there; on <see cref="ConfigurationProvider.Load"/>
/// (triggered by <c>IConfigurationRoot.Reload()</c>) the values re-bind through
/// <c>IOptionsMonitor</c>/<c>IConfiguration</c> without an application restart.
/// </summary>
public sealed class DbSettingsConfigurationSource : IConfigurationSource
{
    private readonly string _provider;
    private readonly string _connectionString;
    private readonly IInterceptor[] _interceptors;

    public DbSettingsConfigurationSource(string provider, string connectionString)
        : this(provider, connectionString, []) { }

    /// <summary>For tests: the settings read goes through <paramref name="interceptors"/>.</summary>
    internal DbSettingsConfigurationSource(string provider, string connectionString, IInterceptor[] interceptors)
    {
        _provider = provider;
        _connectionString = connectionString;
        _interceptors = interceptors;
    }

    public IConfigurationProvider Build(IConfigurationBuilder builder) =>
        new DbSettingsConfigurationProvider(_provider, _connectionString, _interceptors);
}

/// <summary>Reads the operational settings out of the database into the configuration key space.</summary>
public sealed class DbSettingsConfigurationProvider : ConfigurationProvider
{
    private readonly string _provider;
    private readonly string _connectionString;
    private readonly IInterceptor[] _interceptors;

    public DbSettingsConfigurationProvider(string provider, string connectionString)
        : this(provider, connectionString, []) { }

    internal DbSettingsConfigurationProvider(string provider, string connectionString, IInterceptor[] interceptors)
    {
        _provider = provider;
        _connectionString = connectionString;
        _interceptors = interceptors;
    }

    /// <summary>
    /// BUG-623: every load (the read and the store) runs under this one lock, and so does a reload and the reading of its
    /// error (<see cref="ConfigurationReloader"/>). Two reloads at once (two saves, or an email template saved outside
    /// the import gate) could each read, and the one that read first store last, putting back a value just saved.
    /// </summary>
    internal static readonly object LoadGate = new();

    /// <summary>
    /// S-02: keys found in the AppSettings table that are <b>not</b> in the operational whitelist and were
    /// therefore ignored on load. A non-empty snapshot means a row bypassed the audited
    /// <c>AdminSettingsService</c> write path (DB tamper / restored backup) — a tamper indicator the host
    /// surfaces once after startup. Overwritten on each <see cref="Load"/> (initial + every Reload).
    /// </summary>
    public static IReadOnlyCollection<string> RejectedKeys { get; private set; } = Array.Empty<string>();

    public override void Load()
    {
        lock (LoadGate) LoadCore();
    }

    private void LoadCore()
    {
        var data = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        var rejected = new List<string>();
        try
        {
            using var db = BuildContext();
            var rows = db.AppSettings.AsNoTracking()
                .Select(s => new { s.Key, s.Value })
                .ToList();

            foreach (var r in rows)
            {
                if (r.Value is null)
                {
                    // BUG-192: saved blank. Where blank means "off" it hides the file's default; otherwise the default applies.
                    if (SettingsCatalog.ByKey.TryGetValue(r.Key, out var blank) && blank.BlankIsOff) data[r.Key] = "";
                    continue;
                }

                // X-02 taxonomy display labels (Taxonomy:{Kind}:Label:{Member}) share this table but are a
                // known, non-security key space (cosmetic labels only). Load them so ITaxonomyDisplay reads
                // them live; they never map to a server-side config key, so they are NOT a tamper signal.
                if (r.Key.StartsWith(Application.Admin.TaxonomyCatalog.KeyPrefix, StringComparison.OrdinalIgnoreCase))
                {
                    data[r.Key] = r.Value;
                    continue;
                }

                // E-03b email templates (EmailTemplate:{id}:{Subject|Body}) also share this table and are the
                // same kind of admin-editable cosmetic content — branded email copy, never a server-side config
                // key. Load them so the composer reads overrides live; not a tamper signal.
                if (r.Key.StartsWith(Application.Admin.EmailTemplateCatalog.KeyPrefix, StringComparison.OrdinalIgnoreCase))
                {
                    data[r.Key] = r.Value;
                    continue;
                }

                // Enforce the operational whitelist on the READ path too (S-02). AdminSettingsService.SetAsync
                // only ever writes whitelisted keys; a row here whose key is not editable got in out-of-band,
                // so it must NOT override server-side configuration (connection strings, auth mode, signing
                // keys, the SIEM endpoint/token, …). Drop it and record the key as a tamper signal.
                if (!SettingsCatalog.ByKey.TryGetValue(r.Key, out var def))
                {
                    rejected.Add(r.Key);
                    continue;
                }

                if (def.Kind == SettingKind.MultiText)
                {
                    // A list-valued setting binds to a string[]: emit indexed children (Key:0, Key:1, …)
                    // so the configuration binder reconstructs the array, mirroring the JSON-array shape.
                    var lines = r.Value.Split('\n',
                        StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                    for (var i = 0; i < lines.Length; i++)
                        data[$"{r.Key}:{i}"] = lines[i];
                    // BUG-98: the file's own list is indexed the same way, and a longer one would show through past the
                    // end of this one (a shorter list, or a cleared one, kept the file's extra entries). Blank them;
                    // the options drop blank entries.
                    for (var i = lines.Length; i < lines.Length + MaskedListEntries; i++)
                        data[$"{r.Key}:{i}"] = "";
                }
                else
                {
                    data[r.Key] = r.Value;
                }
            }
        }
        catch (Exception ex)
        {
            LoadError = ex.Message;
            // BUG-29: a failed Reload() (the database briefly unreachable) keeps the overrides already loaded, rather
            // than reverting every administered setting to its file default until the next successful reload.
            if (_loaded) return;
            // The AppSettings table may not exist yet (first run, pre-migration). Fall back to the file/env
            // configuration; a later Reload() picks the overrides up once migrated.
            RejectedKeys = rejected;
            Data = data;
            return;
        }

        LoadError = null;
        _loaded = true;
        RejectedKeys = rejected;
        Data = data;
    }

    /// <summary>How many entries past an administered list's end are blanked over the file's list (BUG-98).</summary>
    internal const int MaskedListEntries = 100;

    // Whether a load has read the table successfully (after which a failed reload keeps what it read).
    private bool _loaded;

    /// <summary>BUG-29: why this provider's last load failed, or null when it succeeded. BUG-623: the provider's own (it
    /// was a static shared by every provider), read under <see cref="LoadGate"/> by the reload that ran the load.</summary>
    public string? LoadError { get; private set; }

    private AppDbContext BuildContext()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>();
        if (_provider.Equals("SqlServer", StringComparison.OrdinalIgnoreCase))
            options.UseSqlServer(_connectionString);
        else
            options.UseSqlite(_connectionString);
        if (_interceptors.Length > 0) options.AddInterceptors(_interceptors);

        // No audit interceptor here — this context only reads settings during configuration load.
        return new AppDbContext(options.Options);
    }
}
