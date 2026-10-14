using System.Data.Common;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// Plays a concurrent writer: runs <c>sql</c> once, as another context's committed save landing between this one's read
/// and its write would. It runs as the save's transaction starts (so the save's rollback doesn't undo it), or, for a save
/// without one, just before the first command whose text contains <c>match</c>. Once only, so a retry from a fresh read
/// goes through. Give it to a context that makes one save.
/// </summary>
public sealed class RaceCommandInterceptor(string match, string sql, params (string Name, object Value)[] parameters)
    : DbCommandInterceptor, IDbTransactionInterceptor
{
    private bool _done;

    public bool Ran => _done;

    private void Race(DbCommand command)
    {
        if (_done || !command.CommandText.Contains(match, StringComparison.Ordinal)) return;
        Run(command.Connection!, command.Transaction);
    }

    private void Run(DbConnection connection, DbTransaction? transaction)
    {
        _done = true;
        using var other = connection.CreateCommand();
        other.Transaction = transaction;
        other.CommandText = sql;
        foreach (var (name, value) in parameters)
        {
            var p = other.CreateParameter();
            p.ParameterName = name;
            p.Value = value;
            other.Parameters.Add(p);
        }
        other.ExecuteNonQuery();
    }

    public InterceptionResult<DbTransaction> TransactionStarting(DbConnection connection, TransactionStartingEventData eventData,
        InterceptionResult<DbTransaction> result)
    {
        if (!_done) Run(connection, null);
        return result;
    }

    public ValueTask<InterceptionResult<DbTransaction>> TransactionStartingAsync(DbConnection connection, TransactionStartingEventData eventData,
        InterceptionResult<DbTransaction> result, CancellationToken cancellationToken = default)
    {
        if (!_done) Run(connection, null);
        return ValueTask.FromResult(result);
    }

    public override InterceptionResult<DbDataReader> ReaderExecuting(DbCommand command, CommandEventData eventData,
        InterceptionResult<DbDataReader> result)
    {
        Race(command);
        return base.ReaderExecuting(command, eventData, result);
    }

    public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command, CommandEventData eventData,
        InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default)
    {
        Race(command);
        return base.ReaderExecutingAsync(command, eventData, result, cancellationToken);
    }

    public override InterceptionResult<int> NonQueryExecuting(DbCommand command, CommandEventData eventData, InterceptionResult<int> result)
    {
        Race(command);
        return base.NonQueryExecuting(command, eventData, result);
    }

    public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(DbCommand command, CommandEventData eventData,
        InterceptionResult<int> result, CancellationToken cancellationToken = default)
    {
        Race(command);
        return base.NonQueryExecutingAsync(command, eventData, result, cancellationToken);
    }
}
