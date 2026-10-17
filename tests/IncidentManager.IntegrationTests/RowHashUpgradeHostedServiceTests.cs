using System.Text.RegularExpressions;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Integrity;
using IncidentManager.Domain.Common;
using IncidentManager.Domain.Entities;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using IncidentManager.Web.BackgroundJobs;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// BUG-644/645: the integrity upgrade runs in the background, only once the app has been up and serving for longer than
/// the upgrade script's warm-up, so a large database can't hold the first start past its time limit, and a build that
/// fails its warm-up is rolled back before any row is rewritten. It stops cleanly at a shutdown, and runs once at a time.
/// </summary>
public sealed partial class RowHashUpgradeHostedServiceTests
{
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 11, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { RoleSet = [Domain.Enums.AppRole.SysAdmin] };

    private TestDatabase Seeded()
    {
        var database = TestDatabase.Open(TestDatabase.Sqlite, new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()));
        using var db = database.NewContext();
        DevDataSeeder.SeedAsync(db, _clock).GetAwaiter().GetResult();
        return database;
    }

    private (RowHashUpgradeHostedService Service, CancellationTokenSource Started, ServiceProvider Services) Service(TestDatabase database, double delayMinutes)
    {
        var services = new ServiceCollection()
            .AddScoped(_ => database.NewContext())
            .AddSingleton<IHashChainService>(_hasher)
            .AddSingleton<IClock>(_clock)
            .BuildServiceProvider();
        var started = new CancellationTokenSource();
        var service = new RowHashUpgradeHostedService(services.GetRequiredService<IServiceScopeFactory>(), new Lifetime(started.Token),
            Microsoft.Extensions.Options.Options.Create(new RowHashUpgradeOptions { DelayMinutes = delayMinutes }),
            NullLogger<RowHashUpgradeHostedService>.Instance);
        return (service, started, services);
    }

    private static async Task<bool> UpgradedAsync(TestDatabase database)
    {
        await using var db = database.NewContext();
        return await RowIntegrityVerifier.UpgradedAsync(db);
    }

    [Fact]
    public async Task The_upgrade_starts_only_once_the_app_has_served_for_the_delay()
    {
        using var database = Seeded();
        var (service, started, services) = Service(database, delayMinutes: 0.05);   // 3 s
        using var _ = started;
        await using var __ = services;
        await service.StartAsync(CancellationToken.None);
        await Task.Delay(500);
        (await UpgradedAsync(database)).Should().BeFalse("nothing runs before the app serves");

        await started.CancelAsync();   // the app is up and serving
        await Task.Delay(1000);
        (await UpgradedAsync(database)).Should().BeFalse("nothing runs until the delay has passed");
        // Wait for the job to finish rather than polling: a read here while the upgrade runs would share the test's one
        // SQLite connection with it, and one of them could fail setting up its context (a fault of the test, not the app).
        await service.ExecuteTask!.WaitAsync(TimeSpan.FromSeconds(60));
        (await UpgradedAsync(database)).Should().BeTrue("after the delay the upgrade runs and marks the check strict");
        await service.StopAsync(CancellationToken.None);
    }

    [Fact]
    public async Task A_shutdown_during_the_delay_stops_it_cleanly_and_nothing_is_marked()
    {
        using var database = Seeded();
        var (service, started, services) = Service(database, delayMinutes: 60);
        using var _ = started;
        await using var __ = services;
        await service.StartAsync(CancellationToken.None);
        await started.CancelAsync();
        await Task.Delay(500);   // waiting out the delay
        await service.StopAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(10));
        service.ExecuteTask!.IsCompleted.Should().BeTrue();
        service.ExecuteTask.IsFaulted.Should().BeFalse(service.ExecuteTask.Exception?.ToString() ?? "a shutdown isn't a failure");
        (await UpgradedAsync(database)).Should().BeFalse();
    }

    [Fact]
    public async Task One_upgrade_runs_at_a_time()
    {
        using var database = Seeded();
        using var release = new ManualResetEventSlim(false);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var db1 = database.NewContext();
        await using var db2 = database.NewContext();
        var first = Task.Run(() => RowHashUpgrade.RunAsync(db1, new HoldingHasher(_hasher, entered, release), _clock));
        await entered.Task;
        var second = Task.Run(() => RowHashUpgrade.RunAsync(db2, _hasher, _clock));
        await Task.Delay(500);
        second.IsCompleted.Should().BeFalse("a second run waits for the first");
        release.Set();
        (await first).Marked.Should().BeTrue();
        var then = await second;
        then.Marked.Should().BeFalse("it finds the check already strict");
        then.Recorded.Should().Be(0);
    }

    [Fact]
    public void A_fault_a_restart_wont_clear_is_an_error_and_a_busy_database_a_warning()
    {
        // BUG-657: an EF translation fault (InvalidOperationException) left the check lenient for good with a warning.
        RowHashUpgradeHostedService.IsDefect(new InvalidOperationException("The LINQ expression could not be translated.")).Should().BeTrue();
        RowHashUpgradeHostedService.IsDefect(new ArgumentException("too long")).Should().BeTrue();
        RowHashUpgradeHostedService.IsDefect(new ConcurrentEditException(new InvalidOperationException())).Should().BeFalse();
        RowHashUpgradeHostedService.IsDefect(new DbUpdateException("deadlock")).Should().BeFalse();
        RowHashUpgradeHostedService.IsDefect(new TimeoutException()).Should().BeFalse();
        // EF on SQL Server wraps a transient fault: judged by what it wraps, so a timeout stays a warning and a wrapped
        // defect stays an error.
        RowHashUpgradeHostedService.IsDefect(new InvalidOperationException("transient failure", new TimeoutException())).Should().BeFalse();
        RowHashUpgradeHostedService.IsDefect(new InvalidOperationException("transient failure", new ArgumentException("x"))).Should().BeTrue();
    }

    [Fact]
    public void The_default_delay_is_longer_than_the_upgrade_scripts_warm_up()
    {
        // BUG-645: a build that fails its warm-up is rolled back (Upgrade-CaseBook.ps1) before the upgrade rewrites a row.
        var script = File.ReadAllText(Path.Combine(RepoRoot(), "deploy", "Upgrade-CaseBook.ps1"));
        var warmup = int.Parse(WarmupTimeout().Match(script).Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture);
        warmup.Should().BeGreaterThan(0);
        (new RowHashUpgradeOptions().DelayMinutes * 60).Should().BeGreaterThan(warmup);
    }

    [GeneratedRegex(@"\$WarmupTimeoutSec\s*=\s*(\d+)", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex WarmupTimeout();

    private static string RepoRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "IncidentManager.sln"))) return dir.FullName;
        throw new InvalidOperationException("Couldn't find the repo root (IncidentManager.sln).");
    }

    private sealed class Lifetime(CancellationToken started) : IHostApplicationLifetime
    {
        public CancellationToken ApplicationStarted => started;
        public CancellationToken ApplicationStopping => CancellationToken.None;
        public CancellationToken ApplicationStopped => CancellationToken.None;
        public void StopApplication() { /* not used */ }
    }

    // A hasher whose first check waits until released, holding the run that made it.
    private sealed class HoldingHasher(HashChainService inner, TaskCompletionSource entered, ManualResetEventSlim release) : IHashChainService
    {
        public string Hash(string content) => inner.Hash(content);
        public string ComputeRowHash(IHashableEntity entity) => inner.ComputeRowHash(entity);
        public bool RowHashMatches(IHashableEntity entity, string stored)
        {
            entered.TrySetResult();
            release.Wait();
            return inner.RowHashMatches(entity, stored);
        }
        public void ChainAppend(AuditLogEntry entry, AuditLogEntry? previous) => inner.ChainAppend(entry, previous);
        public ChainVerificationResult VerifyChain(IReadOnlyList<AuditLogEntry> orderedEntries, long? keyedFrom = null) =>
            inner.VerifyChain(orderedEntries, keyedFrom);
        public IChainVerifier BeginVerify(long? keyedFrom = null) => inner.BeginVerify(keyedFrom);
    }
}
