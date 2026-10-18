using Microsoft.Data.SqlClient;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// CAP-22: a test of SQL Server's full-text path. It runs only on a server that has the Full-Text Search feature
/// (<c>SERVERPROPERTY('IsFullTextInstalled') = 1</c>) and is skipped, saying why, otherwise: the docker image the tests use
/// (mcr.microsoft.com/mssql/server) doesn't have it. The substring fallback is tested on every server.
/// </summary>
public sealed class SqlServerFullTextFactAttribute : FactAttribute
{
    private static readonly Lazy<string?> Reason = new(() =>
    {
        if (SqlServerFactAttribute.Server is not { } server)
            return $"Set {SqlServerFactAttribute.Variable} to a SQL Server connection string to run (docs/UPGRADE.md).";
        try
        {
            using var connection = new SqlConnection(new SqlConnectionStringBuilder(server) { InitialCatalog = "master" }.ConnectionString);
            connection.Open();
            using var cmd = connection.CreateCommand();
            cmd.CommandText = "SELECT CAST(ISNULL(SERVERPROPERTY('IsFullTextInstalled'), 0) AS int)";
            return (int)cmd.ExecuteScalar()! == 1 ? null
                : "The test SQL Server doesn't have Full-Text Search (SERVERPROPERTY('IsFullTextInstalled') = 0), so the full-text "
                  + "path can't run here; the substring fallback is tested on every server.";
        }
        catch (SqlException ex)
        {
            return $"Couldn't ask the test SQL Server whether it has Full-Text Search: {ex.Message}";
        }
    });

    /// <summary>Whether the configured server has Full-Text Search.</summary>
    public static bool Installed => Reason.Value is null;

    public SqlServerFullTextFactAttribute()
    {
        if (Reason.Value is { } why) Skip = why;
    }
}
