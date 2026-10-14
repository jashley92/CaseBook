using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Enums;

namespace IncidentManager.IntegrationTests;

/// <summary>BUG-377: "Analyst" grants ViewCases, "Cleared" ViewCases and ViewRestricted, "Reports" neither.</summary>
internal sealed class EntitlementRoles : IRoleDirectory
{
    public IReadOnlySet<Permission> PermissionsForRoles(IEnumerable<string> roleNames)
    {
        var set = new HashSet<Permission>();
        foreach (var r in roleNames)
        {
            if (r == "Analyst") set.Add(Permission.ViewCases);
            if (r == "Cleared") { set.Add(Permission.ViewCases); set.Add(Permission.ViewRestricted); }
            if (r == "Reports") set.Add(Permission.ApproveReports);
        }
        return set;
    }
    public IReadOnlySet<string> RolesForGroups(IEnumerable<string> adGroups) => new HashSet<string>();
    public void Invalidate() { }
}

/// <summary>A user mirror holding each id with the given roles csv (and an address).</summary>
internal sealed class EntitlementUsers(params (string Id, string Roles)[] users) : IUserDirectory
{
    private readonly List<UserSummary> _all = users.Select(u => new UserSummary(u.Id, u.Id, null, $"{u.Id}@x.test", u.Roles)).ToList();
    public UserSummary? Resolve(string userId) => _all.FirstOrDefault(u => string.Equals(u.UserId, userId, StringComparison.OrdinalIgnoreCase));
    public IReadOnlyList<UserSummary> All() => _all;
    public string DisplayFor(string? userId) => userId ?? "";
    public string? EmailFor(string userId) => Resolve(userId)?.Email;
    public Task TouchAsync(string userId, string displayName, string? upn, string? email, string rolesCsv, CancellationToken ct = default) => Task.CompletedTask;
    public void Invalidate() { }
}
