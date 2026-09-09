using IncidentManager.Domain.Common;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Domain.Entities;

/// <summary>Assigns a user to a case with a case-specific role (for scoping and workload views).</summary>
public class CaseAssignment : Entity
{
    public Guid CaseId { get; set; }

    /// <summary>Stable AD identifier (SID) of the assigned user.</summary>
    public string UserId { get; set; } = string.Empty;
    public string UserDisplayName { get; set; } = string.Empty;
    public CaseAssignmentRole Role { get; set; }
    public DateTimeOffset AssignedAtUtc { get; set; }
    public string AssignedBy { get; set; } = string.Empty;
}
