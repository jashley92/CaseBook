using IncidentManager.Application.Abstractions;

namespace IncidentManager.Application.Integrity;

/// <summary>
/// BUG-257: what the background integrity check knows between cycles, so a cycle reads only the audit entries written
/// since the last one instead of the whole log. The chain verifier carries on from the last entry it checked (its links
/// and keys), and <see cref="Records"/> keeps each record's latest recorded hash for the record check. Every record is
/// still checked each cycle; what's deferred is re-hashing old entries, done in full every <see cref="FullEvery"/>, on
/// "Verify now", when the chain's key point changes, and after any failure. One per process (singleton).
/// </summary>
public sealed class IntegrityCheckState
{
    /// <summary>How often the whole chain is re-hashed from the start: an edit to an old audit entry is found within this.</summary>
    public static readonly TimeSpan FullEvery = TimeSpan.FromHours(6);

    /// <summary>A check taking longer than this (a tenth of the monitor's 10-minute cycle) is logged as a warning.</summary>
    public static readonly TimeSpan SlowCycle = TimeSpan.FromSeconds(60);

    /// <summary>What the latest check cost (the monitor's or Verify now), or null before the first since start-up.</summary>
    public IntegrityCycleStats? LastCycle { get; internal set; }

    /// <summary>The longest the monitor waits between checks, however slow they get.</summary>
    public static readonly TimeSpan LongestWait = TimeSpan.FromMinutes(30);

    /// <summary>
    /// How long the monitor waits before its next check: <paramref name="poll"/>, or, after an incremental check slower
    /// than <see cref="SlowCycle"/>, ten times that check's time (up to <see cref="LongestWait"/>), so checking never takes
    /// more than a tenth of the database's time. A full check (every <see cref="FullEvery"/>) doesn't stretch the wait.
    /// Detection then takes as long as the wait, which the log and Diagnostics say.
    /// </summary>
    public TimeSpan NextWait(TimeSpan poll) =>
        LastCycle is { Full: false } c && c.Total >= SlowCycle
            ? TimeSpan.FromTicks(Math.Clamp(c.Total.Ticks * 10, poll.Ticks, Math.Max(poll.Ticks, LongestWait.Ticks)))
            : poll;

    internal SemaphoreSlim Gate { get; } = new(1, 1);
    internal IChainVerifier? Verifier { get; private set; }
    internal RowIntegrityVerifier.ChainRecords? Records { get; private set; }
    internal long? KeyedFrom { get; private set; }

    /// <summary>When the last full check (every entry re-hashed) finished, or null before the first.</summary>
    public DateTimeOffset? LastFullUtc { get; private set; }

    internal bool CanContinue(long? keyedFrom, DateTimeOffset now) =>
        Verifier is not null && Records is not null && KeyedFrom == keyedFrom
        && LastFullUtc is { } full && now - full < FullEvery;

    internal void Keep(IChainVerifier verifier, RowIntegrityVerifier.ChainRecords records, long? keyedFrom, DateTimeOffset? fullAt)
    {
        Verifier = verifier;
        Records = records;
        KeyedFrom = keyedFrom;
        if (fullAt is { } at) LastFullUtc = at;
    }

    /// <summary>Starts over at the next cycle (a failure, or a chain that no longer continues from what's kept).</summary>
    internal void Forget()
    {
        Verifier = null;
        Records = null;
        KeyedFrom = null;
        LastFullUtc = null;
    }
}
