namespace IncidentManager.Domain.Common;

/// <summary>Base type for all persisted entities.</summary>
public abstract class Entity
{
    public Guid Id { get; set; } = Guid.NewGuid();
}
