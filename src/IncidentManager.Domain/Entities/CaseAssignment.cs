using IncidentManager.Domain.Common;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Domain.Entities;

/// <summary>Assigns a user to a case with a case-specific role (for scoping and workload views). BUG-70: hashed and in
/// the record check: on a restricted case an assignment grants access, so one inserted directly is caught.</summary>
public class CaseAssignment : Entity, IHashableEntity
{
    public Guid CaseId { get; set; }

    /// <summary>Stable AD identifier (SID) of the assigned user.</summary>
    public string UserId { get; set; } = string.Empty;
    public string UserDisplayName { get; set; } = string.Empty;
    public CaseAssignmentRole Role { get; set; }
    public DateTimeOffset AssignedAtUtc { get; set; }
    public string AssignedBy { get; set; } = string.Empty;

    public string? RowHash { get; set; }

    public string BuildCanonicalContent() => string.Join('|', CaseId, UserId, Canonical.Text(UserDisplayName), Canonical.Num(Role),
        Canonical.Time(AssignedAtUtc), AssignedBy);
}
