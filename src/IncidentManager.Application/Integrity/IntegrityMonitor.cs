using IncidentManager.Application.Abstractions;

namespace IncidentManager.Application.Integrity;

/// <summary>The most recent audit-chain verification outcome, for the in-app integrity banner (F-16).</summary>
public sealed record IntegrityStatus(bool IsValid, long? FirstBrokenSequence, string? Detail, DateTimeOffset CheckedAtUtc);

/// <summary>
/// Holds the latest chain-verification result app-wide (singleton, in-memory) and decides when a *new*
/// alert should fire. A break must alert once — not on every subsequent cycle while it stays broken —
/// and must alert again if the chain recovers and later breaks anew. The banner UI reads
/// <see cref="Current"/>; the background job and the manual "Verify now" both feed results in.
/// </summary>
public interface IIntegrityMonitor
{
    /// <summary>The last recorded status, or null if the chain has not been verified yet this run.</summary>
    IntegrityStatus? Current { get; }

    /// <summary>
    /// Records a verification result and returns true when this transition warrants firing an alert
    /// (i.e. the chain is broken and we have not already alerted for the current broken episode).
    /// </summary>
    bool RecordResult(ChainVerificationResult result, DateTimeOffset whenUtc);
}

/// <inheritdoc />
public sealed class IntegrityMonitor : IIntegrityMonitor
{
    private readonly object _gate = new();
    private IntegrityStatus? _current;
    private bool _alertedForCurrentBreak;

    public IntegrityStatus? Current
    {
        get { lock (_gate) return _current; }
    }

    public bool RecordResult(ChainVerificationResult result, DateTimeOffset whenUtc)
    {
        lock (_gate)
        {
            _current = new IntegrityStatus(result.IsValid, result.FirstBrokenSequence, result.Detail, whenUtc);

            if (result.IsValid)
            {
                // Chain is (again) intact — clear the latch so a future break re-alerts.
                _alertedForCurrentBreak = false;
                return false;
            }

            // Broken: alert only on the first detection of this episode.
            if (_alertedForCurrentBreak) return false;
            _alertedForCurrentBreak = true;
            return true;
        }
    }
}
