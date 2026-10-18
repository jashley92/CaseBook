using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Enums;
using IncidentManager.Web.BackgroundJobs;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// CAP-29: Diagnostics' Run now. Only an administrator, only a read-only scan with a pass of its own, never while the job
/// runs (scheduled or another Run now), and a scheduled pass that comes due during a Run now is skipped; each start is in
/// the audit trail. The retention review's own Run now, which reads the database, is in <see cref="RetentionReviewTests"/>.
/// </summary>
public sealed class ScheduledJobsTests
{
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 18, 9, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _admin = new() { UserId = "admin1", RoleSet = [AppRole.SysAdmin] };

    internal sealed class CapturingAudit : IAuditWriter
    {
        public List<(AuditAction Action, string Type, string? Id, string Summary)> Entries { get; } = [];
        public Task RecordAsync(AuditAction action, string entityType, string? entityId, string? caseNumber, string summary,
            CancellationToken ct = default)
        {
            lock (Entries) Entries.Add((action, entityType, entityId, summary));
            return Task.CompletedTask;
        }
    }

    internal sealed class Lifetime : IHostApplicationLifetime
    {
        public CancellationTokenSource Stopping { get; } = new();
        public CancellationToken ApplicationStarted => CancellationToken.None;
        public CancellationToken ApplicationStopping => Stopping.Token;
        public CancellationToken ApplicationStopped => CancellationToken.None;
        public void StopApplication() => Stopping.Cancel();
    }

    private static readonly JobDefinition Scan = new("scan", "The scan", "hourly", RunNow: true);
    private static readonly JobDefinition Prune = new("prune", "The prune", "daily");

    private JobRunNowService Runner(IJobStatus jobs, ICurrentUser? user = null, IAuditWriter? audit = null,
        ISecurityEventSink? siem = null) =>
        new(jobs, user ?? _admin, audit ?? new CapturingAudit(), new Lifetime(), NullLogger<JobRunNowService>.Instance, siem);

    [Fact]
    public async Task Run_now_needs_Administer_on_the_server()
    {
        var jobs = new JobStatus(_clock);
        var ran = false;
        jobs.Register(Scan, (run, _) => { ran = true; run.Succeeded(); return Task.CompletedTask; });
        var siem = new CapturingSecurityEventSink();

        var act = () => Runner(jobs, new TestCurrentUser { UserId = "analyst1" }, siem: siem).RunNowAsync("scan");
        (await act.Should().ThrowAsync<ForbiddenException>()).Which.Required.Should().Be(Permission.Administer);
        siem.Events.Should().ContainSingle(e => e.EventId == SecurityEventIds.ActionRefused);
        ran.Should().BeFalse();
        jobs.Snapshot().Single().Runs.Should().Be(0);
    }

    [Fact]
    public async Task Only_a_read_only_scan_with_a_pass_can_be_run_now()
    {
        var jobs = new JobStatus(_clock);
        jobs.Register(Prune, (_, _) => Task.CompletedTask);   // not a read-only scan: the pass isn't kept
        jobs.Register(Scan);                                   // a scan, but no pass given
        var runner = Runner(jobs);

        runner.CanRunNow(Prune).Should().BeFalse();
        runner.CanRunNow(Scan).Should().BeFalse();
        await FluentActions.Awaiting(() => runner.RunNowAsync("prune")).Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*only the read-only scans*");
        await FluentActions.Awaiting(() => runner.RunNowAsync("nope")).Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task Run_now_never_overlaps_a_run_of_the_same_job()
    {
        var jobs = new JobStatus(_clock);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var passes = 0;
        jobs.Register(Scan, async (run, ct) =>
        {
            Interlocked.Increment(ref passes);
            entered.TrySetResult();
            await release.Task.WaitAsync(ct);
            run.Succeeded(7);
        });
        var audit = new CapturingAudit();
        var runner = Runner(jobs, audit: audit);

        // A scheduled run holds the job: Run now is refused, and its pass never starts.
        var scheduled = jobs.TryStart(Scan)!;
        await FluentActions.Awaiting(() => runner.RunNowAsync("scan")).Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*is running now*");
        passes.Should().Be(0);
        audit.Entries.Should().BeEmpty("a refused Run now isn't recorded as run");
        scheduled.Succeeded(1);

        // A Run now holds it: a second Run now is refused, and a scheduled pass that comes due is skipped.
        var running = await runner.RunNowAsync("scan");
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        jobs.Snapshot().Single().Should().Match<JobStatusRow>(r => r.Running && r.LastRunManual);
        await FluentActions.Awaiting(() => runner.RunNowAsync("scan")).Should().ThrowAsync<InvalidOperationException>();
        jobs.Begin(Scan).Should().BeNull("the scheduled pass skips while the Run now runs");

        release.SetResult();
        await running.WaitAsync(TimeSpan.FromSeconds(10));
        passes.Should().Be(1, "one pass ran, never two at once");
        var row = jobs.Snapshot().Single();
        (row.Running, row.Outcome, row.Items, row.Runs).Should().Be((false, JobOutcome.Succeeded, 7L, 2L));
        audit.Entries.Should().ContainSingle().Which.Should().Be(
            (AuditAction.Access, JobRunNowService.AuditEntity, "scan", "The scan run now from Diagnostics."));
        jobs.TryStart(Scan).Should().NotBeNull("the job is free again");
    }

    [Fact]
    public async Task A_pass_that_throws_is_recorded_as_failed_by_type()
    {
        var jobs = new JobStatus(_clock);
        jobs.Register(Scan, (_, _) => throw new TimeoutException("collector at 10.0.0.5 said no"));
        await (await Runner(jobs).RunNowAsync("scan")).WaitAsync(TimeSpan.FromSeconds(10));

        var row = jobs.Snapshot().Single();
        (row.Outcome, row.LastErrorType, row.Running).Should().Be((JobOutcome.Failed, "TimeoutException", false));
    }
}
