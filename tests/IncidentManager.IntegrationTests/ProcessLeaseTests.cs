using AwesomeAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// One process runs the background jobs. Two CaseBook processes on one database (a web garden, or a second server) share
/// a lease in <c>ProcessLeases</c>: one holds it and runs the jobs, the other stands by, and each sees the other. A lease
/// that's let go, or lapses, is taken over; so is one whose holder on this machine has ended.
/// </summary>
public sealed class ProcessLeaseTests : IDisposable
{
    private readonly SqliteConnection _connection = new("Data Source=:memory:");
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 11, 12, 9, 0, 0, TimeSpan.Zero));
    private readonly ServiceProvider _services;

    public ProcessLeaseTests()
    {
        _connection.Open();
        _services = Services(_connection);
        using var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_connection).Options);
        db.Database.EnsureCreated();
    }

    private static ServiceProvider Services(SqliteConnection connection) =>
        new ServiceCollection().AddDbContextFactory<AppDbContext>(o => o.UseSqlite(connection)).BuildServiceProvider();

    private DbProcessLease Lease(string holder, ServiceProvider? services = null) =>
        new((services ?? _services).GetRequiredService<IServiceScopeFactory>(), _clock, NullLogger<DbProcessLease>.Instance, holder)
        {
            IsRunning = _ => true,
        };

    [Fact]
    public async Task The_first_process_runs_the_jobs_and_a_second_stands_by_and_each_sees_the_other()
    {
        var web01 = Lease("WEB01/100/a");
        var web02 = Lease("WEB02/200/b");
        var changes = 0;
        web01.Changed += () => changes++;

        (await web01.HoldAsync()).Should().BeTrue();
        web01.RunsJobs.Should().BeTrue();
        web01.Status.Others.Should().BeEmpty();

        (await web02.HoldAsync()).Should().BeFalse();
        web02.RunsJobs.Should().BeFalse();
        web02.Status.State.Should().Be(LeaseState.StandingBy);
        web02.Status.HolderName.Should().Be("WEB01, process 100");
        web02.Status.Others.Select(o => o.Name).Should().Equal("WEB01, process 100");

        await web01.HoldAsync();
        web01.RunsJobs.Should().BeTrue("renewed");
        web01.Status.Others.Select(o => o.Name).Should().Equal("WEB02, process 200");
        changes.Should().Be(2, "it took the lease, then saw the other process");
    }

    [Fact]
    public async Task A_lease_let_go_at_shutdown_is_taken_at_the_next_renewal()
    {
        var web01 = Lease("WEB01/100/a");
        var web02 = Lease("WEB02/200/b");
        await web01.HoldAsync();
        await web02.HoldAsync();

        await web01.ReleaseAsync();
        web01.RunsJobs.Should().BeFalse();

        (await web02.HoldAsync()).Should().BeTrue("the lease was let go, so it's taken at once");
        web02.Status.Others.Should().BeEmpty("the stopped process's heartbeat went with it");
    }

    [Fact]
    public async Task A_holder_that_stops_renewing_stops_running_jobs_and_is_taken_over_once_its_lease_lapses()
    {
        var web01 = Lease("WEB01/100/a");
        var web02 = Lease("WEB02/200/b");
        await web01.HoldAsync();
        var since = web01.Status.HeldSinceUtc;

        _clock.UtcNow += TimeSpan.FromMinutes(1);
        await web01.HoldAsync();
        web01.Status.HeldSinceUtc.Should().Be(since, "a renewal keeps when it was taken");
        await web02.HoldAsync();

        // web01 hangs: no renewal from here.
        _clock.UtcNow += DbProcessLease.Expiry - DbProcessLease.Margin;
        web01.RunsJobs.Should().BeFalse("it stops before its lease lapses, so the two never run the jobs at once");
        (await web02.HoldAsync()).Should().BeFalse("the lease hasn't lapsed yet");

        _clock.UtcNow += DbProcessLease.Margin;
        (await web02.HoldAsync()).Should().BeTrue("the lease lapsed");
        web02.Status.Others.Should().BeEmpty($"web01's heartbeat is older than {DbProcessLease.SeenWithin.TotalSeconds:0} s");

        (await web01.HoldAsync()).Should().BeFalse("it wakes up to find web02 holding it");
        web01.Status.State.Should().Be(LeaseState.StandingBy);
    }

    [Fact]
    public async Task A_holder_on_this_machine_whose_process_has_ended_is_taken_over_at_once()
    {
        // A crash or a kill leaves the lease held for minutes. The restarted process on the same machine sees the old
        // process is gone, and takes it straight away rather than standing by behind it and raising the alarm.
        var here = Environment.MachineName;
        var crashed = Lease($"{here}/4242/old");
        await crashed.HoldAsync();

        var restarted = new DbProcessLease(_services.GetRequiredService<IServiceScopeFactory>(), _clock,
            NullLogger<DbProcessLease>.Instance, $"{here}/5151/new") { IsRunning = pid => pid != 4242 };
        (await restarted.HoldAsync()).Should().BeTrue();
        restarted.Status.Others.Should().BeEmpty("an ended process isn't another live one");

        await using var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_connection).Options);
        (await db.ProcessLeases.AnyAsync(l => l.Name == ProcessLease.ProcessPrefix + $"{here}/4242/old"))
            .Should().BeFalse("its heartbeat was removed");
    }

    [Fact]
    public async Task A_holder_that_cant_reach_the_database_runs_the_jobs_only_until_its_lease_nears_its_expiry()
    {
        var own = Services(_connection);
        var web01 = Lease("WEB01/100/a", own);
        await web01.HoldAsync();
        await own.DisposeAsync();   // its database calls fail from here

        _clock.UtcNow += TimeSpan.FromMinutes(1);
        (await web01.HoldAsync()).Should().BeTrue("nobody can take the lease before it lapses");
        web01.RunsJobs.Should().BeTrue();
        web01.Status.Problem.Should().NotBeNull();

        _clock.UtcNow += DbProcessLease.Expiry - DbProcessLease.Margin;
        (await web01.HoldAsync()).Should().BeFalse();
        web01.Status.State.Should().Be(LeaseState.Unreachable);
        web01.RunsJobs.Should().BeFalse();
    }

    [Fact]
    public async Task Of_many_processes_starting_at_once_exactly_one_runs_the_jobs()
    {
        // Each on its own connection to one file, as separate processes would be: the first insert or update wins.
        var path = Path.Combine(Path.GetTempPath(), $"lease-{Guid.NewGuid():N}.db");
        var options = new DbContextOptionsBuilder<AppDbContext>().UseSqlite($"Data Source={path};Pooling=False").Options;
        try
        {
            await using (var db = new AppDbContext(options)) await db.Database.EnsureCreatedAsync();
            await using var services = new ServiceCollection()
                .AddDbContextFactory<AppDbContext>(o => o.UseSqlite($"Data Source={path};Pooling=False")).BuildServiceProvider();
            var leases = Enumerable.Range(1, 8).Select(i => Lease($"WEB{i:D2}/{i}/x", services)).ToList();

            var held = await Task.WhenAll(leases.Select(l => Task.Run(() => l.HoldAsync())));

            held.Count(h => h).Should().Be(1);

        }
        finally
        {
            SqliteConnection.ClearAllPools();
            File.Delete(path);
        }
    }

    [Fact]
    public void A_job_run_by_hand_on_a_standing_by_server_is_refused_with_words()
    {
        var standingBy = new TestProcessLease
        {
            RunsJobs = false,
            Status = ProcessLeaseStatus.NotChecked with { State = LeaseState.StandingBy, Holder = "WEB01/100/a" },
        };
        var act = () => standingBy.RequireRunsJobs();
        act.Should().Throw<StandingByException>()
            .WithMessage("This server is standing by: WEB01, process 100 runs the background jobs. Run it there.");

        var unsure = new TestProcessLease { RunsJobs = false, Status = ProcessLeaseStatus.NotChecked with { State = LeaseState.Unreachable } };
        ((Action)(() => unsure.RequireRunsJobs())).Should().Throw<StandingByException>().WithMessage("*database didn't answer*");

        ((Action)(() => ((IProcessLease?)null).RequireRunsJobs())).Should().NotThrow("no lease (a test's host) runs the jobs");
    }

    public void Dispose()
    {
        _services.Dispose();
        _connection.Dispose();
    }
}
