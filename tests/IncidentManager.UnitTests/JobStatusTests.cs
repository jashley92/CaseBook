using FluentAssertions;
using IncidentManager.Application.Abstractions;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// CAP-29: the in-memory registry the Diagnostics jobs table reads. A job is listed once registered; a run records its
/// start, end, outcome and items; a failure keeps the exception's type only; and two runs of one job never overlap, also
/// when many threads start and finish runs at once.
/// </summary>
public sealed class JobStatusTests
{
    private sealed class Clock : IClock
    {
        private long _ticks = new DateTimeOffset(2026, 10, 18, 9, 0, 0, TimeSpan.Zero).UtcTicks;
        public DateTimeOffset UtcNow
        {
            get => new(Interlocked.Read(ref _ticks), TimeSpan.Zero);
            set => Interlocked.Exchange(ref _ticks, value.UtcTicks);
        }
    }

    private static readonly JobDefinition Scan = new("scan", "A scan", "hourly", RunNow: true);
    private static readonly JobDefinition Prune = new("prune", "A prune", "daily");

    [Fact]
    public void A_run_records_its_times_outcome_and_items()
    {
        var clock = new Clock();
        var jobs = new JobStatus(clock);
        jobs.Register(Scan);
        jobs.Register(Prune);
        jobs.Snapshot().Select(r => r.Job.Key).Should().Equal(["scan", "prune"], "rows keep the order they were registered in");
        jobs.Snapshot()[0].Outcome.Should().BeNull("not run yet");

        jobs.Scheduled(Scan, true, clock.UtcNow.AddHours(1));
        var run = jobs.TryStart(Scan)!;
        jobs.Snapshot()[0].Running.Should().BeTrue();
        clock.UtcNow = clock.UtcNow.AddSeconds(3);
        run.Succeeded(42);
        run.Dispose();   // after an outcome, a no-op

        var row = jobs.Snapshot()[0];
        row.Running.Should().BeFalse();
        row.Outcome.Should().Be(JobOutcome.Succeeded);
        row.Items.Should().Be(42);
        (row.FinishedAtUtc - row.StartedAtUtc).Should().Be(TimeSpan.FromSeconds(3));
        row.NextDueUtc.Should().Be(new DateTimeOffset(2026, 10, 18, 10, 0, 0, TimeSpan.Zero));
        (row.Runs, row.Failures).Should().Be((1, 0));
    }

    [Fact]
    public void A_failure_keeps_the_type_never_the_message()
    {
        var jobs = new JobStatus(new Clock());
        var run = jobs.TryStart(Prune)!;
        run.Failed(new InvalidOperationException("case IR-2026-0042 at \\\\share\\evidence", new TimeoutException("relay said no")));

        var row = jobs.Snapshot().Single();
        row.Outcome.Should().Be(JobOutcome.Failed);
        row.LastErrorType.Should().Be("InvalidOperationException (TimeoutException)", "a wrapper is named by what it wraps");
        row.LastErrorType.Should().NotContain("IR-2026").And.NotContain("share").And.NotContain("relay");
        row.Items.Should().BeNull();

        jobs.TryStart(Prune)!.Succeeded(1);
        row = jobs.Snapshot().Single();
        row.LastErrorType.Should().Be("InvalidOperationException (TimeoutException)", "the last error stays shown after a good run");
        (row.Runs, row.Failures).Should().Be((2, 1));
    }

    [Fact]
    public void A_run_cut_off_is_stopped_and_frees_the_job()
    {
        var jobs = new JobStatus(new Clock());
        using (jobs.TryStart(Scan)) { }
        var row = jobs.Snapshot().Single();
        row.Outcome.Should().Be(JobOutcome.Stopped);
        row.Runs.Should().Be(0, "a shutdown isn't a run");
        jobs.TryStart(Scan).Should().NotBeNull();
    }

    [Fact]
    public void A_second_run_of_the_same_job_is_refused_while_the_first_runs()
    {
        var jobs = new JobStatus(new Clock());
        var first = jobs.TryStart(Scan, manual: true);
        first.Should().NotBeNull();
        jobs.TryStart(Scan).Should().BeNull("a scheduled pass skips while a Run now runs");
        jobs.TryStart(Prune).Should().NotBeNull("another job isn't held");
        jobs.Snapshot().First(r => r.Job.Key == "scan").LastRunManual.Should().BeTrue();
        first!.Succeeded();
        jobs.TryStart(Scan).Should().NotBeNull();
    }

    [Fact]
    public void Off_clears_the_next_due_and_a_run_now_pass_needs_a_read_only_scan()
    {
        var jobs = new JobStatus(new Clock());
        jobs.Scheduled(Prune, false, DateTimeOffset.UtcNow);
        jobs.Snapshot().Single().Should().Match<JobStatusRow>(r => !r.Enabled && r.NextDueUtc == null);

        jobs.Register(Prune, (_, _) => Task.CompletedTask);
        jobs.RunNowPass("prune").Should().BeNull("a job that isn't a read-only scan gets no Run now (ADR 0004)");
        jobs.Register(Scan, (_, _) => Task.CompletedTask);
        jobs.RunNowPass("scan").Should().NotBeNull();
        jobs.Register(Scan with { Name = "Renamed" });
        jobs.Snapshot().Single(r => r.Job.Key == "scan").Job.Name.Should().Be("A scan", "the first definition for a key stays");
    }

    [Fact]
    public void Untracked_runs_record_nothing()
    {
        IJobStatus? none = null;
        var run = none.Begin(Scan);
        run.Should().NotBeNull("a job built without the registry still runs");
        run!.Succeeded(3);
        run.Dispose();
    }

    [Fact]
    public async Task Many_threads_starting_and_finishing_runs_never_overlap_one_job_and_lose_no_count()
    {
        var jobs = new JobStatus(new Clock());
        var defs = Enumerable.Range(0, 4).Select(i => new JobDefinition($"job{i}", $"Job {i}", "often")).ToArray();
        var inside = new int[defs.Length];
        var overlaps = 0;
        var ran = new long[defs.Length];
        var failed = new long[defs.Length];

        var workers = Enumerable.Range(0, 16).Select(w => Task.Run(() =>
        {
            for (var i = 0; i < 2_000; i++)
            {
                var j = (w + i) % defs.Length;
                jobs.Scheduled(defs[j], true, DateTimeOffset.UtcNow);
                _ = jobs.Snapshot();
                using var run = jobs.TryStart(defs[j]);
                if (run is null) continue;
                if (Interlocked.Increment(ref inside[j]) != 1) Interlocked.Increment(ref overlaps);
                Thread.SpinWait(20);
                Interlocked.Decrement(ref inside[j]);
                if (i % 7 == 0)
                {
                    Interlocked.Increment(ref failed[j]);
                    run.Failed(new TimeoutException());
                }
                else
                {
                    Interlocked.Increment(ref ran[j]);
                    run.Succeeded(i);
                }
            }
        })).ToArray();
        await Task.WhenAll(workers);

        overlaps.Should().Be(0, "TryStart hands one job's slot to one run at a time");
        var rows = jobs.Snapshot();
        rows.Should().HaveCount(defs.Length, "each job listed once, whichever thread got there first");
        for (var j = 0; j < defs.Length; j++)
        {
            var row = rows.Single(r => r.Job.Key == defs[j].Key);
            row.Running.Should().BeFalse();
            row.Runs.Should().Be(ran[j] + failed[j], "no finish is lost under contention");
            row.Failures.Should().Be(failed[j]);
        }
    }
}
