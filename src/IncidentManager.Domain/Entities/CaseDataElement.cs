using IncidentManager.Domain.Common;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// Links a <see cref="Case"/> to one <see cref="DataElement"/> that its impact assessment involves (X-03),
/// replacing the old <c>[Flags]</c> bit set. The durable value is the element's stable <see cref="ElementKey"/>
/// — that is what the case's tamper-evident canonical hashes and what survives a later relabel or archival of
/// the reference element. The current display label is resolved from the <see cref="DataElement"/> table by
/// <see cref="ElementKey"/> (the X-02 taxonomy philosophy: stored id is stable, label is live).
///
/// Audited as create/delete lines by the chain interceptor like other case children; the set of keys is also
/// folded into the parent case's row hash, so a change is tamper-evident two ways.
/// </summary>
public class CaseDataElement : Entity
{
    public Guid CaseId { get; set; }

    /// <summary>The stable <see cref="DataElement.Key"/> of the involved element.</summary>
    public string ElementKey { get; set; } = string.Empty;
}
