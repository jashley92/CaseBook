namespace IncidentManager.Application.Abstractions;

/// <summary>Where this process stands with the background jobs' lease.</summary>
public enum LeaseState
{
    /// <summary>Not asked yet (just started).</summary>
    Unknown,

    /// <summary>This process holds the lease and runs the background jobs.</summary>
    Held,

    /// <summary>Another live process holds it: this one runs no background job until that one stops renewing it.</summary>
    StandingBy,

    /// <summary>The database didn't answer, and this process didn't hold the lease long enough to be sure it still does.</summary>
    Unreachable,
}

/// <summary>Another CaseBook process using this database, as its heartbeat says. <see cref="Holder"/> is its id
/// ("MACHINE/1234/9f0c…"); <see cref="Name"/> says it for a person.</summary>
public sealed record OtherProcess(string Holder, DateTimeOffset StartedAtUtc, DateTimeOffset LastSeenUtc)
{
    public string Name => ProcessLeaseStatus.Describe(Holder) ?? Holder;
}

/// <summary>
/// The lease as this process last saw it. <see cref="Others"/> lists the other live CaseBook processes on this database,
/// which should be none.
/// </summary>
public sealed record ProcessLeaseStatus(
    LeaseState State,
    string? Holder,
    DateTimeOffset? ExpiresAtUtc,
    DateTimeOffset? HeldSinceUtc,
    DateTimeOffset? CheckedAtUtc,
    string? Problem,
    IReadOnlyList<OtherProcess> Others)
{
    public static readonly ProcessLeaseStatus NotChecked = new(LeaseState.Unknown, null, null, null, null, null, []);

    /// <summary>The process holding the lease, for a person ("WEB01, process 4312"), or null.</summary>
    public string? HolderName => Describe(Holder);

    /// <summary>A process id for a person: "WEB01, process 4312" (null for none).</summary>
    public static string? Describe(string? holder)
    {
        if (string.IsNullOrWhiteSpace(holder)) return null;
        var parts = holder.Split('/');
        return parts.Length >= 2 && int.TryParse(parts[1], System.Globalization.CultureInfo.InvariantCulture, out var pid)
            ? $"{parts[0]}, process {pid}"
            : holder;
    }
}

/// <summary>
/// Whether this process runs the background jobs. CaseBook supports one process per database. A second one, such as a web
/// garden or a second server pointed at the same database, stands by: it runs no background job, so nothing is sent or
/// sealed twice. Administrators are shown both processes, because the second one still serves pages, and the audit
/// trail's lock covers one process only.
/// <para>The lease is kept by a hosted service that renews it every <c>RenewEvery</c>. <see cref="RunsJobs"/> reads what
/// the last renewal found, so it's cheap to ask before every pass.</para>
/// </summary>
public interface IProcessLease
{
    /// <summary>This process's id on the lease: "MACHINE/1234/9f0c…".</summary>
    string Holder { get; }

    /// <summary>Whether this process holds the lease, with time left on it. False until the first renewal.</summary>
    bool RunsJobs { get; }

    /// <summary>The lease as this process last saw it.</summary>
    ProcessLeaseStatus Status { get; }

    /// <summary>Raised when <see cref="RunsJobs"/> changes, or another process appears or goes away.</summary>
    event Action? Changed;

    /// <summary>Takes or renews the lease and this process's heartbeat, and reads the others'. Never throws but to cancel.</summary>
    Task<bool> HoldAsync(CancellationToken ct = default);

    /// <summary>Lets the lease go and removes the heartbeat (at shutdown), so another process can take over at once.</summary>
    Task ReleaseAsync(CancellationToken ct = default);
}

/// <summary>A job run by hand (Run now, Convert now) on a process that's standing by: the process holding the lease runs
/// the jobs, so it's run there.</summary>
public sealed class StandingByException(string message) : InvalidOperationException(message)
{
    /// <summary>The words for <paramref name="status"/>: another process runs the jobs, or this one can't yet tell.</summary>
    public static StandingByException For(ProcessLeaseStatus status) => new(status.State == LeaseState.StandingBy
        ? $"This server is standing by: {status.HolderName ?? "another CaseBook process"} runs the background jobs. Run it there."
        : "This server can't confirm it runs the background jobs: the database didn't answer. Try again in a minute.");
}

public static class ProcessLeaseExtensions
{
    /// <summary>Throws <see cref="StandingByException"/> unless this process runs the jobs. No lease (a test's host)
    /// runs them.</summary>
    public static void RequireRunsJobs(this IProcessLease? lease)
    {
        if (lease is null || lease.RunsJobs) return;
        throw StandingByException.For(lease.Status);
    }
}
