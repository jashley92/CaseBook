using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Abstractions;

/// <summary>
/// Case-lifecycle notifications (who to tell, and how) — kept out of the use-case layer so recipient
/// configuration and the delivery channel live in Infrastructure. Implementations must not throw.
/// </summary>
public interface ICaseNotifications
{
    /// <summary>Called after a reclassification is persisted (e.g. to alert Legal on a Breach escalation).</summary>
    Task OnReclassifiedAsync(Case c, Classification? from, Classification to, CancellationToken ct = default);
}
