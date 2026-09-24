using IncidentManager.Domain.Common;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// An improvement action identified by a case's post-incident review (PROD-41): what will be done, the area
/// it relates to, who owns it, and the target date — tracked to closure. Unlike an <see cref="ActionItem"/>
/// (case follow-up work that ends with the case), an improvement action is a <em>program</em> change that
/// routinely outlives its originating case, so it stays editable after close and rolls up into the cross-case
/// register (evidence for the CISO's NYDFS 500.04 report and the 500.17 certification). Capture and track
/// only; nothing here acts automatically. Neutral wording by design — see <see cref="PostIncidentReview"/>.
/// </summary>
public class ImprovementAction : AuditableEntity, IHashableEntity
{
    public Guid CaseId { get; set; }

    /// <summary>The action, stated plainly (e.g. "Extend MFA to the vendor VPN portal").</summary>
    public string Title { get; set; } = string.Empty;

    /// <summary>The area, process, or requirement it relates to (e.g. "Remote access", an internal reference).</summary>
    public string? RelatedArea { get; set; }

    /// <summary>Further detail on the planned work.</summary>
    public string? Details { get; set; }

    /// <summary>Accountable owner (directory user id or a free-text name for someone outside the SOC).</summary>
    public string? Owner { get; set; }

    public DateTimeOffset? TargetDateUtc { get; set; }

    public ImprovementActionStatus Status { get; set; } = ImprovementActionStatus.Open;

    /// <summary>When the action reached a closed status (Completed / Not pursued).</summary>
    public DateTimeOffset? ClosedAtUtc { get; set; }

    /// <summary>How it closed — required to close: what was done, or why it was not pursued and who decided.</summary>
    public string? OutcomeNote { get; set; }

    public bool IsClosed => Status.IsClosed();

    public bool IsPastTarget(DateTimeOffset nowUtc) => !IsClosed && TargetDateUtc is { } due && due < nowUtc;

    public string? RowHash { get; set; }

    public string BuildCanonicalContent() => string.Join('|',
        CaseId, Title, RelatedArea, Details, Owner, TargetDateUtc?.ToString("o"), (int)Status,
        ClosedAtUtc?.ToString("o"), OutcomeNote, CreatedBy, CreatedAtUtc.ToString("o"));
}
