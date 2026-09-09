using IncidentManager.Domain.Common;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// Grants a <see cref="Role"/> to everyone in an AD security group. Many-to-many: a group may grant
/// several roles and a role may be granted by several groups. Administered in the web console and
/// hash-chained/audited, replacing the file-based <c>RoleMapping</c> section for runtime resolution.
/// </summary>
public class AdGroupRoleMapping : Entity, IHashableEntity
{
    /// <summary>AD security group name (or SID) whose members receive the role.</summary>
    public string AdGroup { get; set; } = string.Empty;

    /// <summary>The <see cref="Role.Name"/> granted to members of <see cref="AdGroup"/>.</summary>
    public string RoleName { get; set; } = string.Empty;

    public DateTimeOffset UpdatedAtUtc { get; set; }
    public string UpdatedBy { get; set; } = string.Empty;
    public string? RowHash { get; set; }

    public string BuildCanonicalContent() =>
        string.Join('|', AdGroup, RoleName, UpdatedAtUtc.ToString("o"), UpdatedBy);
}
