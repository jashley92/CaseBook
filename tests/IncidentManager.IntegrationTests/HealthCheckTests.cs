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

    [Fact]
    public async Task Evidence_store_check_answers_in_time_when_the_share_doesnt(/* PROD-56, C10 */)
    {
        using var never = new ManualResetEventSlim();
        var check = new EvidenceStoreHealthCheck(Options.Create(new EvidenceStoreOptions { RootPath = @"\\files01\casebook$\evidence" }))
        {
            TimeLimit = TimeSpan.FromMilliseconds(200),
            Exists = _ => { never.Wait(TimeSpan.FromSeconds(30)); return true; },   // a server that's down
        };
        var watch = System.Diagnostics.Stopwatch.StartNew();
        var result = await check.CheckHealthAsync(Context());
        never.Set();

        result.Status.Should().Be(HealthStatus.Unhealthy);
        result.Description.Should().Contain("didn't answer");
        watch.Elapsed.Should().BeLessThan(TimeSpan.FromSeconds(10), "the probe answers rather than hangs");
    }

    [Fact]
    public async Task Evidence_store_probes_at_once_share_one_look_at_a_share_that_doesnt_answer(/* CAP-18 review, C10 */)
    {
        using var gate = new ManualResetEventSlim();
        var looks = 0;
        var shared = new SharedRead<bool>(EvidenceStoreHealthCheck.KeepFor);
        var options = Options.Create(new EvidenceStoreOptions { RootPath = @"\\files01\casebook$\evidence" });
        try
        {
            var results = await Task.WhenAll(Enumerable.Range(0, 10).Select(_ => Task.Run(() =>
                new EvidenceStoreHealthCheck(options, shared)
                {
                    TimeLimit = TimeSpan.FromMilliseconds(300),
                    Exists = _ => { Interlocked.Increment(ref looks); gate.Wait(TimeSpan.FromSeconds(30)); return true; },
                }.CheckHealthAsync(Context()))));

            results.Should().AllSatisfy(r => r.Status.Should().Be(HealthStatus.Unhealthy));
            SpinWait.SpinUntil(() => Volatile.Read(ref looks) > 0, TimeSpan.FromSeconds(10));
            looks.Should().Be(1, "a look still blocked isn't given another thread");
        }
        finally { gate.Set(); }
    }

    public void Dispose() => _connection.Dispose();
}
