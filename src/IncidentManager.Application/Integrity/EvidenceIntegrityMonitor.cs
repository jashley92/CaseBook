namespace IncidentManager.Application.Integrity;

/// <summary>The most recent evidence-at-rest verification outcome, for the in-app banner/panel (F-17).</summary>
public sealed record EvidenceIntegrityStatus(
    bool IsClean,
    int CheckedCount,
    int DriftCount,
    IReadOnlyList<EvidenceDrift> Drifts,
    DateTimeOffset CheckedAtUtc);

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
}

/// <inheritdoc />
public sealed class EvidenceIntegrityMonitor : IEvidenceIntegrityMonitor
{
    private readonly object _gate = new();
    private EvidenceIntegrityStatus? _current;
    private HashSet<(Guid EvidenceId, EvidenceDriftKind Kind)> _alerted = [];

    public EvidenceIntegrityStatus? Current
    {
        get { lock (_gate) return _current; }
    }

    public bool RecordResult(EvidenceVerificationResult result, DateTimeOffset whenUtc)
    {
        lock (_gate)
        {
            _current = new EvidenceIntegrityStatus(
                result.IsClean, result.CheckedCount, result.Drifts.Count, result.Drifts, whenUtc);

            // REV-09: latched per drift, not per episode. A file that stays unreadable mustn't hide a second file's bytes
            // being swapped weeks later. What's still drifted stays latched; what cleared can alert again.
            var now = result.Drifts.Select(d => (d.EvidenceId, d.Kind)).ToHashSet();
            var fresh = now.Any(d => !_alerted.Contains(d));
            _alerted = now;
            return fresh;
        }
    }
}
