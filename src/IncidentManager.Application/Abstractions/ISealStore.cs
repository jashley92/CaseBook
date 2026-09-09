using IncidentManager.Domain.Entities;

namespace IncidentManager.Application.Abstractions;

/// <summary>
/// Exports a copy of each integrity seal to a location separate from the primary database (ideally
/// restricted/WORM/offsite), so a retroactive edit to history can be caught by comparing against an
/// out-of-band seal even if the database's own seal rows are tampered with.
/// </summary>
public interface ISealStore
{
    Task ExportAsync(IntegritySeal seal, CancellationToken ct = default);
}
