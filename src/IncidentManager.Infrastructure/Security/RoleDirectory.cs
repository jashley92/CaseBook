using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace IncidentManager.Infrastructure.Security;

/// <summary>
/// Singleton cache of roles and AD-group→role mappings. Reads the database once (and again on
/// <see cref="Invalidate"/>) and answers authentication-time lookups from memory, so resolving a
/// user's permissions never costs a query per request. Tolerates a missing schema on first startup.
/// </summary>
public sealed class RoleDirectory : IRoleDirectory
{
    private readonly IServiceScopeFactory _scopes;
    private readonly ILogger<RoleDirectory> _logger;
    private volatile Snapshot _snapshot = Snapshot.Empty;
    private readonly object _reload = new();
    private Timer? _retry;

    /// <summary>BUG-193: how often a failed reload is tried again.</summary>
    internal static TimeSpan RetryEvery { get; set; } = TimeSpan.FromSeconds(30);

    public RoleDirectory(IServiceScopeFactory scopes, ILogger<RoleDirectory>? logger = null)
    {
        _scopes = scopes;
        _logger = logger ?? NullLogger<RoleDirectory>.Instance;
        // Schema not present yet on a first run (pre-migration): resolve nothing until the startup reload after migrating.
        TryLoad(out _);
    }

    /// <inheritdoc />
    public bool IsCurrent => _retry is null;

    public void Invalidate()
    {
        if (TryLoad(out var error)) return;
        // BUG-193: the change is saved, but sessions and tokens still resolve the previous roles and mappings, so a
        // revoked grant would stay in force with nothing said. Say so, and keep trying until it takes.
        _logger.LogCritical(error, "The role directory couldn't reload from the database: role and AD-group mapping " +
            "changes aren't in effect yet, and permissions still follow the previous ones. Retrying every {Seconds} s.",
            RetryEvery.TotalSeconds);
        lock (_reload) _retry ??= new Timer(_ => Retry(), null, RetryEvery, RetryEvery);
    }

    private void Retry()
    {
        if (!TryLoad(out _)) return;
        lock (_reload)
        {
            _retry?.Dispose();
            _retry = null;
        }
        _logger.LogWarning("The role directory reloaded: role and AD-group mapping changes are in effect.");
    }

    private sealed record Snapshot(
        IReadOnlyDictionary<string, IReadOnlySet<Permission>> RolePermissions,
        IReadOnlyDictionary<string, IReadOnlySet<string>> GroupRoles)
    {
        public static readonly Snapshot Empty = new(
            new Dictionary<string, IReadOnlySet<Permission>>(),
            new Dictionary<string, IReadOnlySet<string>>());
    }

    private bool TryLoad(out Exception? error)
    {
        error = null;
        try
        {
            using var scope = _scopes.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

            var roles = db.Roles.AsNoTracking().ToList();
            var maps = db.RoleMappings.AsNoTracking().ToList();

            // BUG-18: names match regardless of case. Should two rows differ only by case (made before that was
            // enforced), the system role wins, so a look-alike custom role can't add permissions to it, and the
            // directory still loads instead of failing on the duplicate and resolving nothing.
            var rolePermissions = roles
                .GroupBy(r => r.Name, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(
                    g => g.Key,
                    g => (IReadOnlySet<Permission>)Role.ParsePermissions(g.OrderByDescending(r => r.IsSystem).First().PermissionsCsv),
                    StringComparer.OrdinalIgnoreCase);

            var groupRoles = maps
                .GroupBy(m => m.AdGroup, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(
                    g => g.Key,
                    g => (IReadOnlySet<string>)g.Select(x => x.RoleName).ToHashSet(StringComparer.OrdinalIgnoreCase),
                    StringComparer.OrdinalIgnoreCase);

            lock (_reload) _snapshot = new Snapshot(rolePermissions, groupRoles);
            return true;
        }
        catch (Exception ex)
        {
            error = ex;
            return false;
        }
    }

    public IReadOnlySet<Permission> PermissionsForRoles(IEnumerable<string> roleNames)
    {
        var snap = _snapshot;
        var set = new HashSet<Permission>();
        foreach (var name in roleNames)
            if (snap.RolePermissions.TryGetValue(name, out var perms))
                set.UnionWith(perms);
        return set;
    }

    public bool IsRole(string name) => _snapshot.RolePermissions.ContainsKey(name);

    public IReadOnlySet<string> RolesForGroups(IEnumerable<string> adGroups)
    {
        var snap = _snapshot;
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var group in adGroups)
            if (snap.GroupRoles.TryGetValue(group, out var roles))
                set.UnionWith(roles);
        return set;
    }
}
