using IncidentManager.Domain.Common;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// Saved x/y position of an entity node in a case's relationship graph. This is cosmetic
/// view state (a shared, hand-arranged layout) — deliberately NOT audited or hash-chained,
/// so dragging a node never touches the tamper-evident record of the underlying IOC.
/// </summary>
public class EntityLayout : Entity
{
    public Guid CaseId { get; set; }
    public Guid EntityId { get; set; }
    public double X { get; set; }
    public double Y { get; set; }
}
