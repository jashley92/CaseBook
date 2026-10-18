namespace IncidentManager.Application.Abstractions;

/// <summary>
/// CAP-29: one scheduled job, as the Diagnostics table lists it. <paramref name="Key"/> is stable and unique;
/// <paramref name="Cadence"/> is how often it runs, in words; <paramref name="RunNow"/> is true only for a read-only scan
/// (ADR 0004), which an administrator may start from Diagnostics.
/// </summary>
public sealed record JobDefinition(string Key, string Name, string Cadence, bool RunNow = false);

/// <summary>CAP-29: how a job's run ended.</summary>
public enum JobOutcome
{
    Succeeded,
    Failed,
    /// <summary>Ended without an outcome: a shutdown cut it off.</summary>
    Stopped,
}

/// <summary>
/// CAP-29: one job's state since the last restart. <see cref="LastErrorType"/> is an exception's type name only, never its
/// message, which can carry a case number, a path, a recipient or a server's reply (CWE-209). In-memory ops telemetry: not
/// audited, and reset on restart.
/// </summary>
public sealed record JobStatusRow(
    JobDefinition Job,
    bool Enabled,
    bool Running,
    DateTimeOffset? StartedAtUtc,
    DateTimeOffset? FinishedAtUtc,
    JobOutcome? Outcome,
    long? Items,
    DateTimeOffset? NextDueUtc,
    DateTimeOffset? LastErrorAtUtc,
    string? LastErrorType,
    long Runs,
    long Failures,
    bool LastRunManual)
{
    public static JobStatusRow Empty(JobDefinition job) => new(job, true, false, null, null, null, null, null, null, null, 0, 0, false);
}

/// <summary>
/// CAP-29: the scheduled jobs' registry (singleton, in-memory), as <see cref="IDeliveryHealth"/> is for outbound delivery.
/// Each hosted service registers its <see cref="JobDefinition"/> when it's built, reports its schedule on each tick
/// (<see cref="Scheduled"/>) and wraps each run in <see cref="TryStart"/>, which also keeps two runs of one job from
/// overlapping: a scheduled run and a Run now take the same slot, so the second is refused (or skipped) while the first
/// runs. Diagnostics reads <see cref="Snapshot"/>.
/// <para>To join: add a <see cref="JobDefinition"/> to the job's class, call <see cref="Register"/> in its constructor,
/// and run each pass as <c>using var run = jobs.Begin(Job); if (run is null) return; … run.Succeeded(count);</c>
/// (a <see langword="catch"/> calls <see cref="JobRun.Failed"/>). A run disposed without either is recorded as stopped.</para>
/// </summary>
public interface IJobStatus
{
    /// <summary>When the figures began (the process start, near enough).</summary>
    DateTimeOffset SinceUtc { get; }

    /// <summary>Lists the job (idempotent: the first definition for a key stays). A job that can be run now passes its pass.</summary>
    void Register(JobDefinition job, Func<JobRun, CancellationToken, Task>? runNow = null);

    /// <summary>Whether the job is switched on in its settings, and when it's next due (null: not scheduled, or unknown).</summary>
    void Scheduled(JobDefinition job, bool enabled, DateTimeOffset? nextDueUtc);

    /// <summary>
    /// Starts a run: null while a run of the same job is under way (the caller skips its pass, or refuses the Run now).
    /// <paramref name="manual"/> marks a Run now from Diagnostics.
    /// </summary>
    JobRun? TryStart(JobDefinition job, bool manual = false);

    /// <summary>The pass a Run now starts, or null when the job has none (it isn't a read-only scan).</summary>
    Func<JobRun, CancellationToken, Task>? RunNowPass(string key);

    /// <summary>Every registered job, in the order registered.</summary>
    IReadOnlyList<JobStatusRow> Snapshot();
}

/// <summary>CAP-29: one run of a job, from <see cref="IJobStatus.TryStart"/> to its outcome. Dispose it when the run ends.</summary>
public sealed class JobRun : IDisposable
{
    private readonly Action<JobOutcome, long?, string?>? _finish;
    private int _done;

    internal JobRun(Action<JobOutcome, long?, string?>? finish) => _finish = finish;

    /// <summary>A run recorded nowhere: for a job built without the registry (a test).</summary>
    public static JobRun Untracked() => new(null);

    /// <summary>The run did its work; <paramref name="items"/> is what it processed (sent, checked, removed), when it counts.</summary>
    public void Succeeded(long? items = null) => Finish(JobOutcome.Succeeded, items, null);

    /// <summary>The run failed: only <paramref name="error"/>'s type is kept, never its message.</summary>
    public void Failed(Exception error) => Finish(JobOutcome.Failed, null, JobStatus.ErrorType(error));

    /// <summary>The run failed without an exception (a probe that said no): <paramref name="kind"/> is fixed text, never data.</summary>
    public void Failed(string kind) => Finish(JobOutcome.Failed, null, kind);

    public void Dispose() => Finish(JobOutcome.Stopped, null, null);

    private void Finish(JobOutcome outcome, long? items, string? error)
    {
        if (Interlocked.Exchange(ref _done, 1) == 1) return;   // the first outcome stands; Dispose after it is a no-op
        _finish?.Invoke(outcome, items, error);
    }
}

/// <summary>CAP-29: a job reports through these whether or not it was given the registry.</summary>
public static class JobStatusExtensions
{
    /// <summary>
    /// <see cref="IJobStatus.TryStart"/>, or an untracked run when <paramref name="jobs"/> is null. Null means a run is
    /// under way: skip this pass.
    /// </summary>
    public static JobRun? Begin(this IJobStatus? jobs, JobDefinition job) => jobs is null ? JobRun.Untracked() : jobs.TryStart(job);
}

/// <inheritdoc />
public sealed class JobStatus(IClock clock) : IJobStatus
{
    private readonly object _gate = new();
    private readonly List<string> _order = [];
    private readonly Dictionary<string, JobStatusRow> _rows = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Func<JobRun, CancellationToken, Task>> _runNow = new(StringComparer.Ordinal);

    public DateTimeOffset SinceUtc { get; } = clock.UtcNow;

    public void Register(JobDefinition job, Func<JobRun, CancellationToken, Task>? runNow = null)
    {
        ArgumentNullException.ThrowIfNull(job);
        lock (_gate)
        {
            Ensure(job);
            // A Run now only for a job that says it's a read-only scan (ADR 0004).
            if (runNow is not null && job.RunNow) _runNow.TryAdd(job.Key, runNow);
        }
    }

    public void Scheduled(JobDefinition job, bool enabled, DateTimeOffset? nextDueUtc)
    {
        lock (_gate)
        {
            var row = Ensure(job);
            _rows[job.Key] = row with { Enabled = enabled, NextDueUtc = enabled ? nextDueUtc : null };
        }
    }

    public JobRun? TryStart(JobDefinition job, bool manual = false)
    {
        lock (_gate)
        {
            var row = Ensure(job);
            if (row.Running) return null;
            _rows[job.Key] = row with { Running = true, StartedAtUtc = clock.UtcNow, LastRunManual = manual };
        }
        return new JobRun((outcome, items, error) => Finish(job.Key, outcome, items, error));
    }

    public Func<JobRun, CancellationToken, Task>? RunNowPass(string key)
    {
        lock (_gate) return _runNow.GetValueOrDefault(key);
    }

    public IReadOnlyList<JobStatusRow> Snapshot()
    {
        lock (_gate) return _order.Select(k => _rows[k]).ToList();
    }

    private void Finish(string key, JobOutcome outcome, long? items, string? error)
    {
        lock (_gate)
        {
            var row = _rows[key];
            var now = clock.UtcNow;
            _rows[key] = row with
            {
                Running = false,
                FinishedAtUtc = now,
                Outcome = outcome,
                Items = outcome == JobOutcome.Succeeded ? items : null,
                Runs = row.Runs + (outcome == JobOutcome.Stopped ? 0 : 1),
                Failures = row.Failures + (outcome == JobOutcome.Failed ? 1 : 0),
                LastErrorAtUtc = error is null ? row.LastErrorAtUtc : now,
                LastErrorType = error ?? row.LastErrorType,
            };
        }
    }

    /// <summary>The type of what failed, never its message: what EF or SqlClient wraps is named by what it wraps.</summary>
    public static string ErrorType(Exception error)
    {
        var e = error;
        while (e is AggregateException { InnerException: { } inner }) e = inner;
        return e is InvalidOperationException { InnerException: { } wrapped } && e.GetType() == typeof(InvalidOperationException)
            ? $"{e.GetType().Name} ({wrapped.GetType().Name})"
            : e.GetType().Name;
    }

    private JobStatusRow Ensure(JobDefinition job)
    {
        if (_rows.TryGetValue(job.Key, out var row)) return row;
        row = JobStatusRow.Empty(job);
        _rows[job.Key] = row;
        _order.Add(job.Key);
        return row;
    }
}
