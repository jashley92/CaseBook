namespace IncidentManager.Application.Abstractions;

/// <summary>
/// BUG-101: sends the emails that must not be lost (the breach escalation to Legal / Privacy, the integrity alarm).
/// A send that fails is kept and tried again with backoff (<see cref="Domain.Entities.AlertDelivery.RetryAfter"/>);
/// one that never goes is shown to administrators and on its case. Never throws, like every notifier.
/// </summary>
public interface ICriticalAlertOutbox
{
    /// <param name="kind">An <see cref="Domain.Entities.AlertDelivery"/> kind constant.</param>
    Task SendAsync(string kind, Guid? caseId, string? caseNumber, EmailMessage message, CancellationToken ct = default);

    /// <summary>Tries again the sends that are due. Returns how many went.</summary>
    Task<int> RetryDueAsync(CancellationToken ct = default);
}
