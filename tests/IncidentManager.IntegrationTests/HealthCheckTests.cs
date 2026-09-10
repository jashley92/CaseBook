using FluentAssertions;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Storage;
using IncidentManager.Web.HealthChecks;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// H-09: the readiness probes report Healthy only when the database is reachable and the evidence-store
/// root is present, and Unhealthy otherwise — without surfacing connection or path detail in the status
/// itself (the endpoint's default writer emits the status word only).
/// </summary>
public sealed class HealthCheckTests : IDisposable
{
    private readonly SqliteConnection _connection;

    public HealthCheckTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
    }

    private sealed class TestEfFactory(DbContextOptions<AppDbContext> options) : IDbContextFactory<AppDbContext>
    {
        public AppDbContext CreateDbContext() => new(options);
    }

    private static HealthCheckContext Context() => new();

    // --- Database check ---------------------------------------------------------

    [Fact]
    public async Task Database_check_is_healthy_when_the_database_is_reachable()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_connection).Options;
        using (var db = new AppDbContext(options)) db.Database.EnsureCreated();

        var result = await new DatabaseHealthCheck(new TestEfFactory(options))
            .CheckHealthAsync(Context());

        result.Status.Should().Be(HealthStatus.Healthy);
    }

    [Fact]
    public async Task Database_check_is_unhealthy_when_the_database_cannot_be_reached()
    {
        // A file provider rooted in a directory that does not exist: opening fails, CanConnect is false.
        var deadPath = Path.Combine(Path.GetTempPath(), "im-health-nodir", Guid.NewGuid().ToString("N"), "x.db");
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite($"Data Source={deadPath}").Options;

        var result = await new DatabaseHealthCheck(new TestEfFactory(options))
            .CheckHealthAsync(Context());

        result.Status.Should().Be(HealthStatus.Unhealthy);
    }

    // --- Evidence-store check ---------------------------------------------------

    [Fact]
    public async Task Evidence_store_check_is_healthy_when_the_root_directory_exists()
    {
        var dir = Path.Combine(Path.GetTempPath(), "im-health-evidence", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var result = await new EvidenceStoreHealthCheck(
                    Options.Create(new EvidenceStoreOptions { RootPath = dir }))
                .CheckHealthAsync(Context());

            result.Status.Should().Be(HealthStatus.Healthy);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public async Task Evidence_store_check_is_unhealthy_when_the_root_is_unreachable()
    {
        var missing = Path.Combine(Path.GetTempPath(), "im-health-evidence", Guid.NewGuid().ToString("N"), "gone");

        var result = await new EvidenceStoreHealthCheck(
                Options.Create(new EvidenceStoreOptions { RootPath = missing }))
            .CheckHealthAsync(Context());

        result.Status.Should().Be(HealthStatus.Unhealthy);
    }

    public void Dispose() => _connection.Dispose();
}
