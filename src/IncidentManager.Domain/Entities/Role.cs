using IncidentManager.Domain.Common;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Domain.Entities;

/// <summary>
/// A named bundle of <see cref="Permission"/>s. <b>System</b> roles are seeded from code and locked
/// (their permissions always match <c>RoleDefinitions</c>); <b>custom</b> roles are administered in the
/// web console and may compose any of the existing permission atoms — never invent new ones. Changes are
/// hash-chained and audited like any other mutation.
/// </summary>
public class Role : Entity, IHashableEntity
{
    /// <summary>Stable identity of the role; matches the name carried in role claims and AD mappings.</summary>
    public string Name { get; set; } = string.Empty;

    public string? Description { get; set; }

    /// <summary>True for the seeded, undeletable built-in roles whose permissions are owned by code.</summary>
    public bool IsSystem { get; set; }

    /// <summary>Sorted, comma-joined permission names this role grants.</summary>
    public string PermissionsCsv { get; set; } = string.Empty;

    public DateTimeOffset UpdatedAtUtc { get; set; }
    public string UpdatedBy { get; set; } = string.Empty;
    public string? RowHash { get; set; }

    public IReadOnlySet<Permission> GetPermissions() => ParsePermissions(PermissionsCsv);

    public void SetPermissions(IEnumerable<Permission> permissions, string actor, DateTimeOffset nowUtc)
    {
        PermissionsCsv = string.Join(',', permissions
            .Distinct()
            .OrderBy(p => p.ToString(), StringComparer.Ordinal)
            .Select(p => p.ToString()));
        UpdatedBy = actor;
        UpdatedAtUtc = nowUtc;
    }

    public static IReadOnlySet<Permission> ParsePermissions(string? csv) =>
        (csv ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(s => Enum.TryParse<Permission>(s, out var p) ? (Permission?)p : (Permission?)null)
            .Where(p => p is not null)
            .Select(p => p!.Value)
            .ToHashSet();

    public string BuildCanonicalContent() =>
        string.Join('|', Name, Description ?? "", IsSystem, PermissionsCsv, UpdatedAtUtc.ToString("o"), UpdatedBy);
}
