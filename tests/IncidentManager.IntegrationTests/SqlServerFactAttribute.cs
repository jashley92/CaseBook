using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// A test that needs a real SQL Server (production's database). It runs when <c>CASEBOOK_TEST_SQL</c> holds a
/// connection string to a server (the same variable as the upgrade test; see docs/UPGRADE.md for the local Docker
/// container) and is skipped otherwise, so the default SQLite run needs nothing installed.
/// </summary>
public sealed class SqlServerFactAttribute : FactAttribute
{
    public const string Variable = "CASEBOOK_TEST_SQL";

    /// <summary>The server connection string, or null when none is configured.</summary>
    public static string? Server =>
        Environment.GetEnvironmentVariable(Variable) is { Length: > 0 } s ? s : null;

    public SqlServerFactAttribute()
    {
        if (Server is null) Skip = $"Set {Variable} to a SQL Server connection string to run (docs/UPGRADE.md).";
    }
}
