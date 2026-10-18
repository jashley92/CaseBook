using System.Collections.Concurrent;
using System.Linq.Expressions;
using IncidentManager.Application.Abstractions;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace IncidentManager.Infrastructure.Persistence;

/// <summary>
/// CAP-22: what the last full-text check found, kept for the whole app (one instance): the status, when it goes stale, and
/// the fallbacks since start. One check runs at a time (<see cref="Gate"/>), so an older read can't land after a newer one.
/// </summary>
public sealed class FullTextStatusCache : IDisposable
{
    public void Dispose() => Gate.Dispose();

    internal readonly SemaphoreSlim Gate = new(1, 1);
    internal volatile FullTextStatus? Current;
    private long _staleAtTicks = DateTimeOffset.MinValue.UtcTicks;
    private int _fallbacks;
    private volatile string? _lastFallback;
    internal readonly ConcurrentDictionary<string, byte> Logged = new(StringComparer.Ordinal);

    internal DateTimeOffset StaleAtUtc
    {
        get => new(Interlocked.Read(ref _staleAtTicks), TimeSpan.Zero);
        set => Interlocked.Exchange(ref _staleAtTicks, value.UtcTicks);
    }

    internal void CountFallback(string what)
    {
        Interlocked.Increment(ref _fallbacks);
        _lastFallback = what;
    }

    internal FullTextStatus WithFallbacks(FullTextStatus s) =>
        s with { Fallbacks = Volatile.Read(ref _fallbacks), LastFallback = _lastFallback };
}

/// <summary>
/// CAP-22: SQL Server full-text search (see <see cref="IFullTextSearch"/>). The check reads <c>SERVERPROPERTY
/// ('IsFullTextInstalled')</c> and which of <see cref="FullTextSchema"/>'s columns are indexed and populated, within
/// <see cref="CheckTimeout"/>; it's cached for <see cref="ReadyFor"/> (<see cref="FillingFor"/> while indexes fill), and a
/// stale status is still used while another request checks it again. SQLite always searches by substring.
/// </summary>
public sealed class SqlFullTextSearch(
    IAppDbContextFactory factory,
    FullTextStatusCache cache,
    IClock clock,
    ILogger<SqlFullTextSearch>? logger = null) : IFullTextSearch
{
    public static readonly TimeSpan CheckTimeout = TimeSpan.FromSeconds(5);
    public static readonly TimeSpan ReadyFor = TimeSpan.FromMinutes(5);
    public static readonly TimeSpan FillingFor = TimeSpan.FromSeconds(30);
    public static readonly TimeSpan UnknownFor = TimeSpan.FromMinutes(1);

    private readonly ILogger _log = logger ?? (ILogger)NullLogger.Instance;

    public Expression<Func<string?, string, bool>> ContainsTemplate { get; } = (column, condition) => EF.Functions.Contains(column!, condition);

    public async Task<FullTextStatus> StatusAsync(CancellationToken ct = default)
    {
        var current = cache.Current;
        if (current is not null && clock.UtcNow < cache.StaleAtUtc) return cache.WithFallbacks(current);
        // Stale: one request checks again, the others go on with what was found last.
        if (current is not null) { if (!await cache.Gate.WaitAsync(0, ct)) return cache.WithFallbacks(current); }
        else await cache.Gate.WaitAsync(ct);
        try
        {
            if (cache.Current is { } fresh && clock.UtcNow < cache.StaleAtUtc) return cache.WithFallbacks(fresh);
            return cache.WithFallbacks(await CheckAndKeepAsync(ct));
        }
        finally { cache.Gate.Release(); }
    }

    public async Task<FullTextStatus> RefreshAsync(CancellationToken ct = default)
    {
        await cache.Gate.WaitAsync(ct);
        try { return cache.WithFallbacks(await CheckAndKeepAsync(ct)); }
        finally { cache.Gate.Release(); }
    }

    private async Task<FullTextStatus> CheckAndKeepAsync(CancellationToken ct)
    {
        var status = await CheckAsync(ct);
        cache.Current = status;
        cache.StaleAtUtc = status.CheckedAtUtc + status.Mode switch
        {
            FullTextMode.NotSqlServer => TimeSpan.FromDays(3650),   // the provider doesn't change while the app runs
            FullTextMode.Populating or FullTextMode.Partial => FillingFor,
            FullTextMode.Unknown => UnknownFor,
            _ => ReadyFor,
        };
        return status;
    }

    private sealed class Row
    {
        public string Table { get; set; } = "";
        public string Column { get; set; } = "";
        public int Enabled { get; set; }
        public int Populate { get; set; }
    }

    /// <summary>TableFullTextPopulateStatus values a table can be searched in: idle, incremental, change tracking.</summary>
    private static readonly int[] Searchable = [0, 6, 9];

    private async Task<FullTextStatus> CheckAsync(CancellationToken ct)
    {
        var now = clock.UtcNow;
        using var ctx = factory.CreateDbContext();
        if (ctx is not DbContext db || !db.Database.IsSqlServer()) return FullTextStatus.Substring(FullTextMode.NotSqlServer, now);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(CheckTimeout);
        try
        {
            var installed = (await db.Database
                .SqlQueryRaw<int>("SELECT CAST(ISNULL(SERVERPROPERTY('IsFullTextInstalled'), 0) AS int) AS [Value]")
                .ToListAsync(timeout.Token)).FirstOrDefault();
            if (installed != 1) return FullTextStatus.Substring(FullTextMode.NotInstalled, now);
            var rows = await db.Database.SqlQueryRaw<Row>(
                    "SELECT t.name AS [Table], c.name AS [Column], CAST(i.is_enabled AS int) AS [Enabled], " +
                    "CAST(ISNULL(OBJECTPROPERTYEX(t.object_id, 'TableFullTextPopulateStatus'), 0) AS int) AS [Populate] " +
                    "FROM sys.fulltext_index_columns ic " +
                    "JOIN sys.fulltext_indexes i ON i.object_id = ic.object_id " +
                    "JOIN sys.tables t ON t.object_id = ic.object_id " +
                    "JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id")
                .ToListAsync(timeout.Token);
            return Classify(rows.Select(r => (r.Table, r.Column, r.Enabled == 1, r.Populate)), now);
        }
        catch (Exception ex) when (ex is SqlException or InvalidOperationException
                                   || (ex is OperationCanceledException && !ct.IsCancellationRequested))
        {
            // The database didn't answer in time, or refused the metadata read: substring until the next check.
            if (cache.Logged.TryAdd("check:" + ex.GetType().Name, 0))
                _log.LogWarning(ex, "Couldn't check SQL Server's full-text indexes; Find and the case list search by substring until it can.");
            return FullTextStatus.Substring(FullTextMode.Unknown, now, ex is OperationCanceledException
                ? $"the check took longer than {CheckTimeout.TotalSeconds:N0} s" : ex.Message);
        }
    }

    /// <summary>The status from what the server reported for each full-text indexed column (Full-Text being installed).</summary>
    public static FullTextStatus Classify(IEnumerable<(string Table, string Column, bool Enabled, int Populate)> rows, DateTimeOffset now)
    {
        var expected = FullTextSchema.Columns.ToList();
        var reported = rows.ToList();
        var indexed = expected.Where(e => reported.Any(r => r.Enabled && Same(r.Table, e.Table.Name) && Same(r.Column, e.Column))).ToList();
        var ready = indexed.Where(e => reported.Any(r => Same(r.Table, e.Table.Name) && Same(r.Column, e.Column)
                                                        && Searchable.Contains(r.Populate))).ToList();
        var columns = ready.Select(e => (e.Table.Entity, e.Column)).ToHashSet();
        if (indexed.Count == 0) return FullTextStatus.Substring(FullTextMode.NotCreated, now);
        if (ready.Count == expected.Count) return new FullTextStatus(FullTextMode.Ready, columns, now);
        if (ready.Count == 0)
            return new FullTextStatus(FullTextMode.Populating, columns, now, $"{indexed.Count} of {expected.Count} columns indexed, still being filled");
        var missing = expected.Except(ready).Select(e => $"{e.Table.Name}.{e.Column}");
        return new FullTextStatus(FullTextMode.Partial, columns, now,
            $"{ready.Count} of {expected.Count} columns searched by word; by substring: {string.Join(", ", missing)}");
    }

    private static bool Same(string a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

    /// <summary>SQL Server's full-text error numbers: the 7600s, the 9900s and the 30000s.</summary>
    public static bool IsFullTextErrorNumber(int number) => number is >= 7600 and <= 7699 or >= 9900 and <= 9999 or >= 30000 and <= 30099;

    public bool IsFullTextFailure(Exception ex) => FullTextErrorNumber(ex) is not null;

    // The first full-text error number in the exception or any inside it.
    private static int? FullTextErrorNumber(Exception? ex)
    {
        for (var e = ex; e is not null; e = e.InnerException)
            if (e is SqlException sql)
                foreach (SqlError err in sql.Errors)
                    if (IsFullTextErrorNumber(err.Number)) return err.Number;
        return null;
    }

    public void FellBack(Exception ex, string search)
    {
        var number = FullTextErrorNumber(ex);
        cache.CountFallback($"{search}: SQL Server error {number}");
        cache.StaleAtUtc = DateTimeOffset.MinValue;   // an index may have gone: check again at the next search
        if (cache.Logged.TryAdd("fallback:" + number, 0))
            _log.LogWarning(ex, "A full-text search ({Search}) failed with SQL Server error {Number} and ran again by substring. "
                                + "Later failures like it are logged at Debug; Diagnostics counts them.", search, number);
        else
            _log.LogDebug(ex, "A full-text search ({Search}) failed with SQL Server error {Number} and ran again by substring.", search, number);
    }

    /// <summary>SQL Server's "permission denied" numbers for DDL.</summary>
    private static readonly int[] Denied = [229, 262, 297, 300, 1088, 15151, 15247];

    public async Task<FullTextStatus> CreateIndexesAsync(CancellationToken ct = default)
    {
        using (var ctx = factory.CreateDbContext())
        {
            if (ctx is not DbContext db || !db.Database.IsSqlServer())
                throw new InvalidOperationException("Full-text search is a SQL Server feature; this database always searches by substring.");
            db.Database.SetCommandTimeout(TimeSpan.FromMinutes(2));
            try
            {
                await db.Database.ExecuteSqlRawAsync(FullTextSchema.Script, ct);
            }
            catch (SqlException ex) when (ex.Errors.Cast<SqlError>().Any(e => Denied.Contains(e.Number)))
            {
                _log.LogWarning(ex, "Couldn't create the full-text indexes: the database account isn't allowed to.");
                throw new InvalidOperationException(
                    "CaseBook's database account isn't allowed to create full-text indexes (it needs db_owner, or db_ddladmin). "
                    + "Ask a DBA to run deploy/sql/03-Enable-FullText.sql on the CaseBook database, then check again.", ex);
            }
            catch (SqlException ex)
            {
                _log.LogError(ex, "Couldn't create the full-text indexes.");
                throw new InvalidOperationException($"SQL Server refused to create the full-text indexes: {ex.Message}", ex);
            }
        }
        _log.LogInformation("Full-text catalog and indexes created where missing; SQL Server fills them in the background.");
        return await RefreshAsync(ct);
    }
}
