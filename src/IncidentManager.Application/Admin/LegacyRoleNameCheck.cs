using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace IncidentManager.Application.Admin;

/// <summary>
/// BUG-591: at start-up, finds the roles whose names hold a comma (allowed before v1.5.1, BUG-21), so every role list
/// reads them as one name (<see cref="RoleList"/>), and says which they are: renaming each (a new role with its
/// permissions and mappings, then retiring the old one) removes the ambiguity for good. A database that can't be read yet
/// is said and passed over; readers with the role directory still know the names.
/// </summary>
public sealed class LegacyRoleNameCheck(IServiceScopeFactory scopes, ILogger<LegacyRoleNameCheck>? log = null) : IHostedService
{
    /// <summary>The names found at the last start.</summary>
    public IReadOnlyList<string> Found { get; private set; } = [];

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        try
        {
            // A singleton: the context factory is scoped, so it's taken from a scope of its own.
            using var scope = scopes.CreateScope();
            using var db = scope.ServiceProvider.GetRequiredService<IAppDbContextFactory>().CreateDbContext();
            var names = await db.Roles.AsNoTracking().Where(r => r.Name.Contains(',')).Select(r => r.Name)
                .OrderBy(n => n).ToListAsync(cancellationToken);
            RoleList.UseLegacyNames(names);
            Found = names;
            foreach (var name in names)
                log?.LogWarning("The role \"{Role}\" has a comma in its name (allowed before v1.5.1). Role lists are stored " +
                                "comma-separated, so it is read as one name wherever it's known; to remove the ambiguity, give its " +
                                "permissions and AD mappings to a role without a comma and retire this one.", name);
        }
        catch (Exception ex) when (ex is System.Data.Common.DbException or InvalidOperationException)
        {
            log?.LogError(ex, "Couldn't look for role names with a comma at start-up; role lists are read with the role directory's names only.");
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
