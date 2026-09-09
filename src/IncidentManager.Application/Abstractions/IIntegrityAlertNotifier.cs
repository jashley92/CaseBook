namespace IncidentManager.Application.Abstractions;

/// <summary>
/// Raises the alarm when the audit hash-chain is found broken (F-16): a high-severity SIEM/log event
/// plus email to a configured distribution. Kept out of the use-case layer so recipients and the
/// delivery channel live in Infrastructure. Implementations must not throw — a failure to notify must
/// never mask the underlying integrity failure.
/// </summary>
public interface IIntegrityAlertNotifier
{
    Task OnChainBrokenAsync(ChainVerificationResult result, CancellationToken ct = default);
}
