using IncidentManager.Infrastructure.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// The database a provider test runs on: in-memory SQLite (the default run) or, when <c>CASEBOOK_TEST_SQL</c> names a
/// server, a throwaway SQL Server database that's dropped afterwards. A test takes the provider as a theory row from
/// <see cref="Providers"/>, so without a server it runs once, on SQLite, and never passes vacuously as "SQL Server".
/// Run the SQL Server rows alone with <c>--filter "DisplayName~SqlServer"</c>.
/// </summary>
public abstract class TestDatabase : IDisposable
{
    public const string Sqlite = "Sqlite";
    public const string SqlServer = "SqlServer";

    /// <summary>The providers to run on: SQLite always, SQL Server when a server is configured.</summary>
    public static TheoryData<string> Providers
    {
        get
        {
            var rows = new TheoryData<string> { Sqlite };
            if (SqlServerFactAttribute.Server is not null) rows.Add(SqlServer);
            return rows;
        }
    }

    /// <summary>A new, empty database with the schema created.</summary>
    public static TestDatabase Open(string provider, params IInterceptor[] interceptors)
    {
        TestDatabase db = provider switch
        {
            Sqlite => new SqliteDatabase(interceptors),
            SqlServer => new SqlServerDatabase(interceptors),
            _ => throw new ArgumentOutOfRangeException(nameof(provider), provider, null),
        };
        using var ctx = db.NewContext();
        ctx.Database.EnsureCreated();
        return db;
    }

    private readonly IInterceptor[] _interceptors;
    private protected TestDatabase(IInterceptor[] interceptors) => _interceptors = interceptors;

    private protected abstract DbContextOptionsBuilder<AppDbContext> Configure(DbContextOptionsBuilder<AppDbContext> b);

    public DbContextOptions<AppDbContext> Options =>
        Configure(new DbContextOptionsBuilder<AppDbContext>()).AddInterceptors(_interceptors).Options;

    public AppDbContext NewContext() => new(Options);

    public TestDbContextFactory Factory() => new(Options);

    public abstract void Dispose();

    private sealed class SqliteDatabase : TestDatabase
    {
        private readonly SqliteConnection _connection = new("Data Source=:memory:");

        public SqliteDatabase(IInterceptor[] interceptors) : base(interceptors) => _connection.Open();

        private protected override DbContextOptionsBuilder<AppDbContext> Configure(DbContextOptionsBuilder<AppDbContext> b) => b.UseSqlite(_connection);

        public override void Dispose() => _connection.Dispose();
    }

    private sealed class SqlServerDatabase : TestDatabase
    {
        private readonly string _connectionString;

        public SqlServerDatabase(IInterceptor[] interceptors) : base(interceptors) =>
            _connectionString = new Microsoft.Data.SqlClient.SqlConnectionStringBuilder(
                    SqlServerFactAttribute.Server ?? throw new InvalidOperationException($"Set {SqlServerFactAttribute.Variable}."))
                { InitialCatalog = $"casebook_test_{Guid.NewGuid():N}" }.ConnectionString;

        private protected override DbContextOptionsBuilder<AppDbContext> Configure(DbContextOptionsBuilder<AppDbContext> b) => b.UseSqlServer(_connectionString);

        public override void Dispose()
        {
            using var ctx = NewContext();
            ctx.Database.EnsureDeleted();
        }
    }
}
