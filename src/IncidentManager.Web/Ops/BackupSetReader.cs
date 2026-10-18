using System.Collections.Concurrent;
using System.Data.Common;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Integrity;
using IncidentManager.Infrastructure.Security;
using IncidentManager.Infrastructure.Storage;
using IncidentManager.Web.BackgroundJobs;
using Microsoft.Extensions.Options;

namespace IncidentManager.Web.Ops;

/// <summary>One folder (or file) in the backup set, and what the app found there. <see cref="Facts"/> is null when the
/// setting is blank and nothing is kept on disk for it.</summary>
public sealed record BackupSetPath(string Label, string Key, string? Path, string? Note, BackupPathFacts? Facts);

/// <summary>
/// What a backup-set path holds: whether it's there (null: it didn't answer), whether the app's account can write it (null: not known yet, or not
/// asked, as for a seal folder no seal has been copied to since the restart), and its size, file count and newest write
/// over a bounded walk. <see cref="Complete"/> is false when the walk stopped at its time or entry limit, so the size is a
/// floor, said as such, never a total.
/// </summary>
public sealed record BackupPathFacts(
    bool? Exists, bool? Writable, string? WritableDetail, long SizeBytes, int Files, DateTimeOffset? LastWriteUtc,
    bool Complete, string? Problem);

/// <summary>The backup set as this server is configured: the database and every path OPERATIONS.md §1 lists.</summary>
public sealed record BackupSet(string Provider, string? DatabaseName, IReadOnlyList<BackupSetPath> Paths, DateTimeOffset ReadAtUtc);

/// <summary>
/// CAP-19: every path in the backup set (OPERATIONS.md §1), for the Diagnostics "Backup set" card and the downloadable
/// <c>backup-manifest.json</c>. Paths and file metadata only: no file is opened, so no key material is read. Each path's
/// walk is bounded (C10): a time limit, an entry limit, and one walk per path at a time, so a share that doesn't answer
/// makes the card say so instead of hanging it, and opening Diagnostics again while that walk is stuck joins it rather
/// than starting another. Singleton.
/// </summary>
public sealed class BackupSetReader(
    IConfiguration config,
    IOptions<EvidenceStoreOptions> evidence,
    IOptions<ReportOutputOptions> reports,
    IOptions<ReportBrandingOptions> branding,
    IOptions<ReportTemplateOptions> templates,
    IOptions<SealSigningOptions> integrity,
    EvidenceStoreStatus evidenceProbe,
    SealCopyStatus sealCopies,
    IClock clock)
{
    /// <summary>How long one path's walk may take before the card shows what it found so far.</summary>
    public TimeSpan TimeLimit { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>How many files and folders one walk visits at most (an evidence store can hold millions).</summary>
    public int EntryLimit { get; init; } = 200_000;

    /// <summary>Whether a folder is there (replaceable in tests, to stand in for a share that doesn't answer).</summary>
    public Func<string, bool> Exists { get; init; } = Directory.Exists;

    private readonly ConcurrentDictionary<string, Lazy<Task<BackupPathFacts>>> _walking = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>The configured backup set, without visiting the disk.</summary>
    public (string Provider, string? DatabaseName, IReadOnlyList<(string Label, string Key, string? Path, string? Note, Probe Writable)> Paths) Describe()
    {
        var provider = config["Database:Provider"] ?? "Sqlite";
        var list = new List<(string, string, string?, string?, Probe)>();
        string? database = null;
        var cs = config.GetConnectionString("Default");
        if (provider.Equals("SqlServer", StringComparison.OrdinalIgnoreCase))
            database = ConnectionValue(cs, "Database", "Initial Catalog");
        else if (ConnectionValue(cs, "Data Source", "DataSource", "Filename") is { Length: > 0 } file && file != ":memory:")
        {
            database = System.IO.Path.GetFileName(file);
            list.Add(("Database file", "ConnectionStrings:Default", Full(file), "SQLite: back it up with the app pool stopped", Probe.None));
        }

        list.Add(("Evidence store", "EvidenceStore:RootPath", Full(evidence.Value.RootPath), null, Probe.EvidenceStore));
        list.Add(("Report output", "ReportOutput:RootPath", Full(reports.Value.RootPath), null, Probe.File));
        list.Add(("Seal exports", "Integrity:ExportPath", Full(integrity.Value.ExportPath), "append-only: never prune it", Probe.SealCopy));

        var keys = KeysFolder(integrity.Value);
        list.Add(("Keys folder", "Integrity:SigningKeyPath", keys,
            "the signing key, chain-key.json and evidence-key.json by default; tighter access", Probe.File));
        // Key files set outside the keys folder are backed up where they are.
        AddIfOutside(list, keys, "Chain key file", "Integrity:ChainKey:WrappedKeyPath", integrity.Value.ChainKey.WrappedKeyPath);
        AddIfOutside(list, keys, "Retired chain keys", "Integrity:ChainKey:RetiredWrappedKeysPath", integrity.Value.ChainKey.RetiredWrappedKeysPath);
        AddIfOutside(list, keys, "Retired seal public keys", "Integrity:RetiredPublicKeysPath", integrity.Value.RetiredPublicKeysPath);
        AddIfOutside(list, keys, "Evidence key envelope", "Storage:Encryption:EnvelopePath", config["Storage:Encryption:EnvelopePath"]);
        AddIfOutside(list, keys, "Trusted bundle keys", TrustedBundleKeys.SettingKey, config[TrustedBundleKeys.SettingKey]);   // CAP-16

        var dp = config["DataProtection:KeyPath"];
        list.Add(("Data Protection keys", "DataProtection:KeyPath", string.IsNullOrWhiteSpace(dp) ? null : Full(dp),
            string.IsNullOrWhiteSpace(dp)
                ? "not set: the framework's default, which doesn't survive an app-pool recycle on IIS"
                : "with the database: it decrypts the secrets saved in Administration", Probe.File));

        list.Add(("Report templates", "ReportTemplates:RootPath",
            Full(FileReportTemplateStore.ResolveRoot(templates.Value.RootPath, branding.Value.RootPath)), null, Probe.File));
        list.Add(("Report branding", "ReportBranding:RootPath", Full(branding.Value.RootPath), null, Probe.File));
        return (provider, database, list);
    }

    /// <summary>The backup set with each path's facts, every walk bounded.</summary>
    public async Task<BackupSet> ReadAsync(CancellationToken ct = default)
    {
        var (provider, database, paths) = Describe();
        var read = paths.Select(async p => new BackupSetPath(p.Label, p.Key, p.Path, p.Note,
            p.Path is null ? null : await FactsAsync(p.Path, p.Writable, ct))).ToList();
        return new BackupSet(provider, database, await Task.WhenAll(read), clock.UtcNow);
    }

    private async Task<BackupPathFacts> FactsAsync(string path, Probe writable, CancellationToken ct)
    {
        // One walk per path at a time: a later caller joins it, and it's forgotten when it ends, so the next look is fresh.
        var walk = _walking.GetOrAdd(path, p => new Lazy<Task<BackupPathFacts>>(() =>
        {
            var started = Task.Run(() => Walk(p, writable), CancellationToken.None);   // shared: one caller leaving doesn't stop it
            _ = started.ContinueWith(_ => _walking.TryRemove(p, out var _), CancellationToken.None,
                TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            return started;
        }));
        try
        {
            return await walk.Value.WaitAsync(TimeLimit, ct);
        }
        catch (TimeoutException)
        {
            return new BackupPathFacts(Exists: null, null, null, 0, 0, null, Complete: false,
                $"didn't answer within {TimeLimit.TotalSeconds:0} seconds (a share that's down or slow?)");
        }
    }

    private BackupPathFacts Walk(string path, Probe writable)
    {
        try
        {
            // Half the time limit for the walk itself, so one that's slow but moving says what it found in time; only a
            // call that blocks outright runs into the caller's limit.
            var deadline = DateTime.UtcNow + TimeLimit / 2;
            if (!Exists(path))
            {
                if (!File.Exists(path)) return new BackupPathFacts(false, false, "not there", 0, 0, null, true, null);
                var file = new FileInfo(path);
                return new BackupPathFacts(true, null, null, file.Length, 1, new DateTimeOffset(file.LastWriteTimeUtc, TimeSpan.Zero), true, null);
            }

            var (canWrite, why) = Writable(path, writable);
            long size = 0;
            var files = 0;
            var entries = 0;
            var newest = Directory.GetLastWriteTimeUtc(path);
            var complete = true;
            var options = new EnumerationOptions
            {
                RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint,
            };
            foreach (var entry in new DirectoryInfo(path).EnumerateFileSystemInfos("*", options))
            {
                if (++entries > EntryLimit || DateTime.UtcNow > deadline) { complete = false; break; }
                if (entry.LastWriteTimeUtc > newest) newest = entry.LastWriteTimeUtc;
                if (entry is FileInfo f) { size += f.Length; files++; }
            }
            return new BackupPathFacts(true, canWrite, why, size, files, new DateTimeOffset(newest, TimeSpan.Zero), complete,
                complete ? null : $"stopped after {Math.Min(entries, EntryLimit):N0} entries; at least this much");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            return new BackupPathFacts(null, null, null, 0, 0, null, false, "couldn't be read: " + ex.GetType().Name);
        }
    }

    // Writable by the app's account. The evidence store and the seal folder are judged by their own probes: a seal folder
    // may be WORM, where a probe file could never be deleted again.
    private (bool? Ok, string? Detail) Writable(string path, Probe how)
    {
        switch (how)
        {
            case Probe.EvidenceStore:
                return evidenceProbe.CheckedAtUtc is null ? (null, "not checked yet") : (evidenceProbe.Problem is null, evidenceProbe.Problem);
            case Probe.SealCopy:
                return sealCopies.Snapshot().FirstOrDefault(c => c.Destination == IntegrityService.FolderCopy) is { } last
                    ? (last.Ok, last.LastError)
                    : (null, "no seal copied since the last restart");
            case Probe.File:
                try
                {
                    var probe = System.IO.Path.Combine(path, $".health-{Guid.NewGuid():N}.tmp");
                    File.WriteAllText(probe, "ok");
                    File.Delete(probe);
                    return (true, null);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    return (false, ex.GetType().Name);
                }
            default:
                return (null, null);
        }
    }

    /// <summary>The keys folder: the signing key's folder, whatever the key's source, since the chain key and the evidence
    /// key's envelope live there by default.</summary>
    public static string KeysFolder(SealSigningOptions o) =>
        System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(o.SigningKeyPath)) ?? System.IO.Path.GetFullPath(".");

    private static void AddIfOutside(List<(string, string, string?, string?, Probe)> list, string keys, string label, string key, string? configured)
    {
        if (string.IsNullOrWhiteSpace(configured)) return;
        var full = Full(configured);
        var inside = full.StartsWith(keys.TrimEnd(System.IO.Path.DirectorySeparatorChar) + System.IO.Path.DirectorySeparatorChar,
            OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
        if (!inside) list.Add((label, key, full, "outside the keys folder", Probe.None));
    }

    private static string Full(string path) => System.IO.Path.GetFullPath(path);

    // The database's name only: a connection string can hold a password, so nothing else of it is shown.
    private static string? ConnectionValue(string? connectionString, params string[] keys)
    {
        if (string.IsNullOrWhiteSpace(connectionString)) return null;
        try
        {
            var b = new DbConnectionStringBuilder { ConnectionString = connectionString };
            foreach (var k in keys)
                if (b.TryGetValue(k, out var v) && v?.ToString() is { Length: > 0 } s) return s;
        }
        catch (ArgumentException) { }
        return null;
    }

    /// <summary>How a path's writability is judged.</summary>
    public enum Probe { None, File, EvidenceStore, SealCopy }
}

/// <summary>
/// CAP-19: <c>backup-manifest.json</c>, the backup set as a backup job or a restore drill reads it: the database's name and
/// every path with what was found there. Paths and metadata only, never a key, a secret or a connection string.
/// </summary>
public static class BackupManifest
{
    /// <summary>The manifest's format; a reader checks it.</summary>
    public const int Format = 1;

    private static readonly System.Text.Json.JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    public static byte[] Build(BackupSet set, string server, string appVersion) =>
        System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new
        {
            format = Format,
            generatedAtUtc = set.ReadAtUtc,
            server,
            appVersion,
            database = new { provider = set.Provider, name = set.DatabaseName },
            paths = set.Paths.Select(p => new
            {
                label = p.Label,
                setting = p.Key,
                path = p.Path,
                note = p.Note,
                exists = p.Facts?.Exists,
                writable = p.Facts?.Writable,
                sizeBytes = p.Facts is { Exists: true } f ? f.SizeBytes : (long?)null,
                files = p.Facts is { Exists: true } g ? g.Files : (int?)null,
                lastWriteUtc = p.Facts?.LastWriteUtc,
                complete = p.Facts?.Complete,
                problem = p.Facts?.Problem,
            }),
        }, Json);
}
