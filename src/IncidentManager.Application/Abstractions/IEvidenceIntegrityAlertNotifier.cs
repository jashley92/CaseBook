using IncidentManager.Application.Integrity;

namespace IncidentManager.Application.Abstractions;

/// <summary>
/// Raises the alarm when evidence at rest drifts from its recorded SHA-256 (F-17): a high-severity
/// SIEM/log event plus email to the configured integrity-alert distribution. Kept out of the use-case
/// layer so recipients and the delivery channel live in Infrastructure. Implementations must not throw —
/// a failure to notify must never mask the underlying integrity failure. All channels are out-of-band of
/// the database the audit chain protects.
/// </summary>
public interface IEvidenceIntegrityAlertNotifier
{
    Task OnDriftDetectedAsync(EvidenceVerificationResult result, CancellationToken ct = default);
}
