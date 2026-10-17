namespace IncidentManager.Application.Integrity;

/// <summary>
/// The most recent evidence-at-rest verification outcome, for the in-app banner/panel (F-17). PROD-53: when runs check
/// one share of the files each, <see cref="Drifts"/> holds what every file was found in at its latest check: a drift
/// stays until that file is checked again (and dropped if its evidence was removed). <see cref="CheckedCount"/> is the
/// latest run's, out of <see cref="TotalCount"/> in the store.
/// </summary>
public sealed record EvidenceIntegrityStatus(
    bool IsClean,
    int CheckedCount,
    int DriftCount,
    IReadOnlyList<EvidenceDrift> Drifts,
    DateTimeOffset CheckedAtUtc,
    int TotalCount = 0);

/// <summary>
/// Holds the latest evidence-at-rest verification result app-wide (singleton, in-memory) and decides
/// when a *new* alert should fire. Each drift (an evidence item and what's wrong with it) alerts once — not on every
/// subsequent cycle while it persists — and a drift that wasn't there on the last pass alerts, even while an older
/// one persists (REV-09); one that clears and comes back alerts again. The banner/panel
/// UI reads <see cref="Current"/>; the background job feeds results in. Mirrors <see cref="IIntegrityMonitor"/>
/// for the audit chain.
/// </summary>
public interface IEvidenceIntegrityMonitor
{
    /// <summary>The last recorded status, or null if evidence has not been verified yet this run.</summary>
    EvidenceIntegrityStatus? Current { get; }

    /// <summary>
    /// Records a verification result and returns true when this transition warrants firing an alert
    /// (i.e. the result holds a drift that the previous result didn't).
    /// </summary>
    bool RecordResult(EvidenceVerificationResult result, DateTimeOffset whenUtc);

    /// <summary>
    /// PROD-57: raises (with <paramref name="detail"/>) or clears (null) a finding about the whole store, such as the
    /// evidence key being unavailable, without touching what's known about each file. True when it's newly raised, so the
    /// caller sends the alarm once per episode.
    /// </summary>
    bool RecordCondition(EvidenceDriftKind kind, string? detail, DateTimeOffset whenUtc) => false;

    /// <summary>BUG-332: raised after each recorded result, so an open banner shows new drift, or hides cleared drift,
    /// without a reload. Raised outside the monitor's lock; a listener that throws is ignored.</summary>
    event Action? Changed;
}

/// <inheritdoc />
public sealed class EvidenceIntegrityMonitor : IEvidenceIntegrityMonitor
{
    private readonly object _gate = new();
    private EvidenceIntegrityStatus? _current;
    private HashSet<(Guid EvidenceId, EvidenceDriftKind Kind)> _alerted = [];
    private readonly Dictionary<EvidenceDriftKind, EvidenceDrift> _conditions = [];   // PROD-57: raised by RecordCondition until cleared

    public EvidenceIntegrityStatus? Current
    {
        get { lock (_gate) return _current; }
    }

    public event Action? Changed;

    public bool RecordCondition(EvidenceDriftKind kind, string? detail, DateTimeOffset whenUtc)
    {
        bool fresh;
        lock (_gate)
        {
            if (detail is null) _conditions.Remove(kind);
            else _conditions[kind] = new EvidenceDrift(Guid.Empty, Guid.Empty, null,
                kind == EvidenceDriftKind.KeyUnavailable ? "(the evidence key)" : "(the evidence store)", "", null, kind, detail);
            var others = (_current?.Drifts ?? []).Where(d => !(d.EvidenceId == Guid.Empty && d.Kind == kind)).ToList();
            var drifts = detail is null ? others : [.. others, _conditions[kind]];
            _current = new EvidenceIntegrityStatus(drifts.Count == 0, _current?.CheckedCount ?? 0, drifts.Count, drifts,
                _current?.CheckedAtUtc ?? whenUtc, _current?.TotalCount ?? 0);
            var key = (Guid.Empty, kind);
            fresh = detail is not null && !_alerted.Contains(key);
            if (detail is null) _alerted.Remove(key); else _alerted.Add(key);
        }
        MonitorEvents.Raise(Changed);
        return fresh;
    }

    public bool RecordResult(EvidenceVerificationResult result, DateTimeOffset whenUtc)
    {
        var alert = Record(result, whenUtc);
        MonitorEvents.Raise(Changed);   // BUG-332
        return alert;
    }

    private bool Record(EvidenceVerificationResult result, DateTimeOffset whenUtc)
    {
        lock (_gate)
        {
            // PROD-53: a run over one share of the files leaves the others as their latest check found them.
            var merged = result.CoversEveryFile || _current is null
                ? result.Drifts
                : _current.Drifts.Where(d => !result.CheckedIds!.Contains(d.EvidenceId) && result.KnownIds!.Contains(d.EvidenceId))
                    .Concat(result.Drifts).ToList();
            // PROD-57: a store-wide condition stays until it's cleared, whatever a run found.
            var drifts = merged.Concat(_conditions.Values.Where(c => !merged.Any(d => d.EvidenceId == Guid.Empty && d.Kind == c.Kind))).ToList();
            _current = new EvidenceIntegrityStatus(
                drifts.Count == 0, result.CheckedCount, drifts.Count, drifts, whenUtc, result.TotalCount);

            // REV-09: latched per drift, not per episode. A file that stays unreadable mustn't hide a second file's bytes
            // being swapped weeks later. What's still drifted stays latched; what cleared can alert again.
            var now = drifts.Select(d => (d.EvidenceId, d.Kind)).ToHashSet();
            var fresh = now.Any(d => !_alerted.Contains(d));
            _alerted = now;
            return fresh;
        }
    }
}
