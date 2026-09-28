namespace IncidentManager.Application.Abstractions;

/// <summary>
/// F-08: date arithmetic that runs inside the database. EF can't subtract one DateTimeOffset column from another
/// on SQLite (dev stores them as UTC ticks), so this maps to each provider's own form: a tick difference on SQLite,
/// DATEDIFF_BIG on SQL Server (registered in AppDbContext). Query-only; calling it in memory throws. Pass columns,
/// not captured values: on SQLite a parameter wouldn't pick up the ticks conversion.
/// </summary>
public static class DbTime
{
    /// <summary>The time from <paramref name="from"/> to <paramref name="to"/> in ticks (100 ns); null if either is null.</summary>
    public static long? TicksBetween(DateTimeOffset? from, DateTimeOffset? to)
        => throw new InvalidOperationException($"{nameof(DbTime)}.{nameof(TicksBetween)} only runs inside a database query.");
}
