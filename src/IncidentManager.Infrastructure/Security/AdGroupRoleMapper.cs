namespace IncidentManager.Infrastructure.Security;

/// <summary>
/// The file-based AD security-group → role mapping (config section "RoleMapping"). Keys are role names;
/// values are the AD groups (or SIDs) that grant them. Used only to seed the database mapping on first
/// run — runtime resolution is served from the database via <c>IRoleDirectory</c>.
/// </summary>
public sealed class RoleMappingOptions
{
    public Dictionary<string, string[]> Groups { get; set; } = new();
}
