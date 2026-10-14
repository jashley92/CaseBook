using System.Data.Common;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// Plays a concurrent writer: just before the first database command whose text contains <c>match</c>, runs
/// <c>sql</c> on the same connection (and transaction), as another context's save landing between this one's read and
/// its write would. Once only, so a retry from a fresh read goes through.
/// </summary>
public sealed class RaceCommandInterceptor(string match, string sql, params (string Name, object Value)[] parameters) : DbCommandInterceptor
{
    private bool _done;

    public bool Ran => _done;

    private void Race(DbCommand command)
    {
        if (_done || !command.CommandText.Contains(match, StringComparison.Ordinal)) return;
        _done = true;
        using var other = command.Connection!.CreateCommand();
        other.Transaction = command.Transaction;
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
