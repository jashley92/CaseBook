using IncidentManager.Domain.Common;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// INV-10: a timeline entry (an event step, an action, a decision) citing a piece of evidence that supports it.
/// Lets a conclusion point at what it rests on, and an evidence item show what relies on it. An audited case
/// record in its own right (adding or removing a citation is in the hash-chained audit trail); it isn't folded
/// into the entry's row hash. When an investigation entry is edited into a new version, its citations move with it.
/// </summary>
public class EvidenceCitation : Entity
{
    /// <summary>The case both sides belong to (scoping and audit attribution).</summary>
    public Guid CaseId { get; set; }
    public Guid TimelineEntryId { get; set; }
    public Guid EvidenceId { get; set; }
}
