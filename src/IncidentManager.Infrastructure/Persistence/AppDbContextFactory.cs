using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace IncidentManager.Infrastructure.Persistence;

/// <summary>
/// Design-time factory so EF tooling (migrations) can build the context without the Web host.
/// Defaults to SQLite — the development provider. Set the <c>IM_MIGRATIONS_PROVIDER=SqlServer</c>
/// environment variable to scaffold/inspect the production SQL Server migrations set (which lives in
/// the <c>IncidentManager.Migrations.SqlServer</c> assembly). No live database is contacted when
/// adding a migration — the connection strings below only need to be well-formed for the provider.
/// </summary>
/// <example>
///   # Regenerate the SQL Server schema migration (PowerShell):
///   $env:IM_MIGRATIONS_PROVIDER = 'SqlServer'
///   dotnet ef migrations add &lt;Name&gt; `
///     --project src/IncidentManager.Migrations.SqlServer `
///     --startup-project src/IncidentManager.Web --context AppDbContext
/// </example>
public sealed class AppDbContextFactory : IDesignTimeDbContextFactory<AppDbContext>
{
    public const string SqlServerMigrationsAssembly = "IncidentManager.Migrations.SqlServer";

    public AppDbContext CreateDbContext(string[] args)
    {
        var provider = Environment.GetEnvironmentVariable("IM_MIGRATIONS_PROVIDER") ?? "Sqlite";
        var builder = new DbContextOptionsBuilder<AppDbContext>();

        if (provider.Equals("SqlServer", StringComparison.OrdinalIgnoreCase))
        {
            // Placeholder connection — design-time migration scaffolding builds from the model, not the DB.
            builder.UseSqlServer(
                "Server=(localdb)\\MSSQLLocalDB;Database=CaseBook;Trusted_Connection=True;TrustServerCertificate=True;",
                sql => sql.MigrationsAssembly(SqlServerMigrationsAssembly));
        }
        else
        {
            builder.UseSqlite("Data Source=App_Data/incidentmanager-design.db");
        }

        return new AppDbContext(builder.Options);
    }
}
