using FluentAssertions;
using IncidentManager.Domain.Entities;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Security;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// BUG-609: the roles a mapping by group name grants, which a group whose name didn't come back in time could still be
/// granting; a mapping by SID isn't among them (a user's SIDs are always known).
/// </summary>
public sealed class RoleDirectoryMappedByNameTests : IDisposable
{
    private readonly SqliteConnection _connection = new("Data Source=:memory:");
    private readonly ServiceProvider _services;

    public RoleDirectoryMappedByNameTests()
    {
        _connection.Open();
        _services = new ServiceCollection().AddDbContext<AppDbContext>(o => o.UseSqlite(_connection)).BuildServiceProvider();
        using var scope = _services.CreateScope();
        scope.ServiceProvider.GetRequiredService<AppDbContext>().Database.EnsureCreated();
    }

    [Fact]
    public async Task Only_mappings_by_name_count()
    {
        using (var scope = _services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.RoleMappings.Add(new AdGroupRoleMapping { AdGroup = @"CORP\SOC-Managers", RoleName = "Manager", UpdatedAtUtc = DateTimeOffset.UtcNow, UpdatedBy = "t" });
            db.RoleMappings.Add(new AdGroupRoleMapping { AdGroup = "SOC-Leads", RoleName = "IR Lead", UpdatedAtUtc = DateTimeOffset.UtcNow, UpdatedBy = "t" });
            db.RoleMappings.Add(new AdGroupRoleMapping { AdGroup = "S-1-5-21-7-1105", RoleName = "SysAdmin", UpdatedAtUtc = DateTimeOffset.UtcNow, UpdatedBy = "t" });
            await db.SaveChangesAsync();
        }

        var directory = new RoleDirectory(_services.GetRequiredService<IServiceScopeFactory>());

        directory.RolesMappedByName.Should().BeEquivalentTo(["Manager", "IR Lead"]);
    }

    public void Dispose()
    {
        _services.Dispose();
        _connection.Dispose();
    }
}
