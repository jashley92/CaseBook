namespace IncidentManager.Application.Abstractions;

/// <summary>
/// A point-in-time view of external secret resolution (F-19), for the read-only Admin health panel. Tracks
/// the last successful and last failed CyberArk CCP fetch — timestamps, the reference <em>location</em>
/// (never the secret), a safe failure reason, and running counts. In-memory ops telemetry: it is not part
/// of the audit chain and resets on restart.
/// </summary>
public sealed record SecretResolutionStatus(
    DateTimeOffset? LastSuccessUtc,
    string? LastSuccessReference,
    DateTimeOffset? LastFailureUtc,
    string? LastFailureReference,
    string? LastFailureReason,
    long SuccessCount,
    long FailureCount)
{
    /// <summary>True once at least one fetch (success or failure) has been attempted this run.</summary>
    public bool AnyActivity => SuccessCount > 0 || FailureCount > 0;

    /// <summary>True when the most recent attempt failed (last failure is newer than last success).</summary>
    public bool LastAttemptFailed =>
        LastFailureUtc is { } f && (LastSuccessUtc is not { } s || f >= s);

    public static readonly SecretResolutionStatus Empty = new(null, null, null, null, null, 0, 0);
}

/// <summary>
/// Records external-secret-resolution outcomes app-wide (singleton, in-memory) so the Admin console can show
/// whether the secret store is actually working. The CCP secret provider feeds outcomes in; the health panel
/// reads <see cref="Current"/>. Always registered — even when CyberArk is disabled — so the panel can render
/// "not enabled / no activity" without a missing-service error. Mirrors the F-17 evidence-integrity monitor.
/// </summary>
public interface ISecretResolutionHealth
{
    /// <summary>The latest recorded status (never null; <see cref="SecretResolutionStatus.Empty"/> before any fetch).</summary>
    SecretResolutionStatus Current { get; }

    /// <summary>Record a successful fetch of the secret at <paramref name="referenceLabel"/> (a location, not the secret).</summary>
    void RecordSuccess(string referenceLabel);

    /// <summary>Record a failed fetch, with a non-sensitive <paramref name="reason"/> (status/code/config — never the secret).</summary>
    void RecordFailure(string referenceLabel, string reason);
}

/// <inheritdoc />
public sealed class SecretResolutionHealth(IClock clock) : ISecretResolutionHealth
{
    private readonly object _gate = new();
    private SecretResolutionStatus _current = SecretResolutionStatus.Empty;

    public SecretResolutionStatus Current
    {
        get { lock (_gate) return _current; }
    }

    public void RecordSuccess(string referenceLabel)
    {
        lock (_gate)
        {
            _current = _current with
            {
                LastSuccessUtc = clock.UtcNow,
                LastSuccessReference = referenceLabel,
                SuccessCount = _current.SuccessCount + 1,
            };
        }
    }

    public void RecordFailure(string referenceLabel, string reason)
    {
        lock (_gate)
        {
            _current = _current with
            {
                LastFailureUtc = clock.UtcNow,
                LastFailureReference = referenceLabel,
                LastFailureReason = reason,
                FailureCount = _current.FailureCount + 1,
            };
        }
    }
}
