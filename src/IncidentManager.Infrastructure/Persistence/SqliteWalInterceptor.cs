using System.Collections.Concurrent;
using System.Data.Common;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace IncidentManager.Infrastructure.Persistence;

/// <summary>
/// SQLite only (development and tests; production is SQL Server): puts the database in write-ahead-log mode the first time
/// this process opens it. In SQLite's default rollback-journal mode a reader holds off a writer's commit for as long as it
/// reads, so a background job walking a table (the row-hash upgrade, the evidence checks) could keep a request's one-row
/// write waiting past the command timeout on a busy machine: "database is locked", a 500 (the flaky API tests). In WAL mode
/// readers never block a writer and a writer never blocks readers; writers still take turns, and wait for it.
/// </summary>
/// <remarks>The mode is stored in the database file, so this runs once per file per process. A file that can't switch
/// (another process holds it, or an in-memory database) keeps its mode: nothing fails because of it.</remarks>
public sealed class SqliteWalInterceptor : DbConnectionInterceptor
{
    private static readonly ConcurrentDictionary<string, bool> Done = new(StringComparer.OrdinalIgnoreCase);

    public override void ConnectionOpened(DbConnection connection, ConnectionEndEventData eventData)
    {
        if (!First(connection)) return;
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA journal_mode=WAL;";
        try { command.ExecuteScalar(); }
        catch (SqliteException) { Done.TryRemove(connection.DataSource, out _); }
    }

    public override async Task ConnectionOpenedAsync(DbConnection connection, ConnectionEndEventData eventData,
        CancellationToken cancellationToken = default)
    {
        if (!First(connection)) return;
        await using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA journal_mode=WAL;";
        try { await command.ExecuteScalarAsync(cancellationToken); }
        catch (SqliteException) { Done.TryRemove(connection.DataSource, out _); }
    }

    private static bool First(DbConnection connection) =>
        connection is SqliteConnection && !string.IsNullOrEmpty(connection.DataSource) && Done.TryAdd(connection.DataSource, true);
}
