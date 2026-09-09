using IncidentManager.Application.Abstractions;
using Microsoft.AspNetCore.Components.Server.Circuits;

namespace IncidentManager.Web.Realtime;

/// <summary>
/// Per-circuit presence tracker (U-01b). Two jobs:
/// <list type="bullet">
///   <item>Exposes the current <see cref="CircuitId"/> so presence-aware components can tag their
///     registrations with the circuit they belong to.</item>
///   <item>Guarantees cleanup: if a browser tab closes or crashes, the component may not dispose
///     gracefully, but the framework still closes the circuit — at which point every registration
///     made from it is purged.</item>
/// </list>
/// Registered <c>Scoped</c> (one per circuit) and also as the circuit's <see cref="CircuitHandler"/>.
/// </summary>
public sealed class PresenceCircuitTracker : CircuitHandler
{
    private readonly ICasePresenceService _presence;

    public PresenceCircuitTracker(ICasePresenceService presence) => _presence = presence;

    /// <summary>The id of this circuit, available once it has opened (before any component renders).</summary>
    public string? CircuitId { get; private set; }

    public override Task OnCircuitOpenedAsync(Circuit circuit, CancellationToken cancellationToken)
    {
        CircuitId = circuit.Id;
        return Task.CompletedTask;
    }

    public override Task OnCircuitClosedAsync(Circuit circuit, CancellationToken cancellationToken)
    {
        _presence.RemoveCircuit(circuit.Id);
        return Task.CompletedTask;
    }
}
