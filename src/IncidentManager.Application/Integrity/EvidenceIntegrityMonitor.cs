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
/// when a *new* alert should fire. Drift must alert once — not on every subsequent cycle while it
/// persists — and must alert again if the store returns clean and later drifts anew. The banner/panel
/// UI reads <see cref="Current"/>; the background job feeds results in. Mirrors <see cref="IIntegrityMonitor"/>
/// for the audit chain.
/// </summary>
public interface IEvidenceIntegrityMonitor
{
    /// <summary>The last recorded status, or null if evidence has not been verified yet this run.</summary>
    EvidenceIntegrityStatus? Current { get; }

    /// <summary>
    /// Records a verification result and returns true when this transition warrants firing an alert
    /// (i.e. drift was found and we have not already alerted for the current drift episode).
    /// </summary>
    bool RecordResult(EvidenceVerificationResult result, DateTimeOffset whenUtc);
}

/// <inheritdoc />
public sealed class EvidenceIntegrityMonitor : IEvidenceIntegrityMonitor
{
    private readonly object _gate = new();
    private EvidenceIntegrityStatus? _current;
    private bool _alertedForCurrentEpisode;

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

            if (result.IsClean)
            {
                // Store is (again) clean — clear the latch so future drift re-alerts.
                _alertedForCurrentEpisode = false;
                return false;
            }

            // Drift present: alert only on the first detection of this episode.
            if (_alertedForCurrentEpisode) return false;
            _alertedForCurrentEpisode = true;
            return true;
        }
    }
}
