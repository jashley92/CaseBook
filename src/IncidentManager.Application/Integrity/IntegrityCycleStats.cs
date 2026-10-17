namespace IncidentManager.Application.Integrity;

/// <summary>
/// What one integrity check cost: how long the chain and the record check took and how much each read. Logged after every
/// check and shown on Administration › Diagnostics, so an install can tell how the check grows with its data (the record
/// check reads every hashed record every cycle).
/// </summary>
public sealed record IntegrityCycleStats(
    DateTimeOffset FinishedAtUtc,
    bool Full,
    bool Intact,
    TimeSpan Chain,
    TimeSpan Records,
    long EntriesHashed,
    long RecordsChecked,
    int RecordsKept,
    IReadOnlyDictionary<string, long> RecordsByTable)
{
    public TimeSpan Total => Chain + Records;
}

/// <summary>The counts a check gathers as it reads, turned into <see cref="IntegrityCycleStats"/> when it ends.</summary>
public sealed class IntegrityCycleCounts
{
    public long EntriesHashed { get; set; }

    public Dictionary<string, long> RecordsByTable { get; } = new(StringComparer.Ordinal);

    public void RecordRead(string table) => RecordsByTable[table] = RecordsByTable.GetValueOrDefault(table) + 1;
}
