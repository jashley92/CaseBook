using IncidentManager.Domain.Common;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// INV-05b: a later correction of when a transition happened — a classification, phase or severity change that
/// was dated wrongly, or entered without its real time. Append-only and hash-chained: it records the old and new
/// effective time and why, while the change record's recorded time (<c>ChangedAtUtc</c>) never moves. The change
/// record's effective time is updated alongside (an audited modification), so every reader sees the corrected time.
/// </summary>
public class TransitionTimeCorrection : AuditableEntity, IHashableEntity
{
    public Guid CaseId { get; set; }
    public TransitionKind Kind { get; set; }

    /// <summary>The id of the <see cref="ClassificationChange"/>, <see cref="StatusChange"/> or <see cref="SeverityChange"/>.</summary>
    public Guid ChangeId { get; set; }

    public DateTimeOffset FromEffectiveUtc { get; set; }
    public DateTimeOffset ToEffectiveUtc { get; set; }
    public string Reason { get; set; } = string.Empty;

    public string? RowHash { get; set; }

    public string BuildCanonicalContent() => string.Join('|',
        CaseId, (int)Kind, ChangeId, FromEffectiveUtc.ToString("o"), ToEffectiveUtc.ToString("o"), Reason,
        CreatedBy, CreatedAtUtc.ToString("o"));
}
