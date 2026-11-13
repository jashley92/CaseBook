namespace IncidentManager.Domain.Entities;

/// <summary>
/// One row of the processes' shared lease table. CaseBook supports one process per database. These rows make a second
/// one, such as a web garden or a second server pointed at the same database, harmless to the background jobs and
/// visible to administrators.
/// <list type="bullet">
/// <item>The <see cref="BackgroundJobs"/> row is the lease: the process named in <see cref="Holder"/> runs the background
/// jobs until <see cref="ExpiresAtUtc"/>, renewing it as it goes.</item>
/// <item>A <see cref="ProcessPrefix"/> row is one live process's heartbeat. Each process keeps its own, so each can see
/// the others.</item>
/// </list>
/// Operational state, deliberately NOT audited or hash-chained (see the interceptor's NotAudited set), like the
/// notification marks.
/// </summary>
public class ProcessLease
{
    public const int MaxName = 200;
    public const int MaxHolder = 150;

    /// <summary>The name of the background jobs' lease row.</summary>
    public const string BackgroundJobs = "background-jobs";

    /// <summary>What a heartbeat row's name starts with; the rest is the process's <see cref="Holder"/>.</summary>
    public const string ProcessPrefix = "process:";

    public string Name { get; set; } = "";

    /// <summary>The process: "MACHINE/1234/9f0c…" (machine, process id and a value of its own).</summary>
    public string Holder { get; set; } = "";

    /// <summary>When this holder took the lease, or when the process started (a heartbeat).</summary>
    public DateTimeOffset AcquiredAtUtc { get; set; }

    /// <summary>When the row lapses unless it's renewed.</summary>
    public DateTimeOffset ExpiresAtUtc { get; set; }
}
