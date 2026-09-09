namespace IncidentManager.Application.Abstractions;

/// <summary>Allocates the next per-year IRP sequence number (resets each year). Only classified,
/// IRP-ladder cases carry a sequence; Complex Events are numbered by date and never consume one.</summary>
public interface ICaseNumberGenerator
{
    Task<int> NextSequenceAsync(int year, CancellationToken ct = default);
}
