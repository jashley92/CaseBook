using FluentAssertions;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Security;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// BUG-193: a role or mapping change whose reload fails isn't silently left out of effect. The directory says it's
/// not current, and retries until the change takes.
/// </summary>
public sealed class RoleDirectoryReloadTests : IDisposable
{
    private readonly SqliteConnection _connection = new("Data Source=:memory:");
    private readonly ServiceProvider _services;

    public RoleDirectoryReloadTests()
    {
        _connection.Open();
        _services = new ServiceCollection().AddDbContext<AppDbContext>(o => o.UseSqlite(_connection)).BuildServiceProvider();
        using var scope = _services.CreateScope();
        scope.ServiceProvider.GetRequiredService<AppDbContext>().Database.EnsureCreated();
    }

    private void Sql(string sql)
    {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }

    [Fact]
    public async Task A_failed_reload_is_reported_and_retried_until_it_takes()
    {
        var saved = RoleDirectory.RetryEvery;
        RoleDirectory.RetryEvery = TimeSpan.FromMilliseconds(50);
        try
        {
            var directory = new RoleDirectory(_services.GetRequiredService<IServiceScopeFactory>());
            directory.IsCurrent.Should().BeTrue();

            using (var scope = _services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
                var role = new Role { Name = "Reviewers", IsSystem = false };
                role.SetPermissions([Permission.ViewCases], "admin1", DateTimeOffset.UtcNow);
                db.Roles.Add(role);
                await db.SaveChangesAsync();
            }
            Sql("ALTER TABLE Roles RENAME TO RolesOffline");   // the reload fails, as on a timeout or failover

            directory.Invalidate();
            directory.IsCurrent.Should().BeFalse("the saved role isn't in effect");
            directory.IsRole("Reviewers").Should().BeFalse();

            Sql("ALTER TABLE RolesOffline RENAME TO Roles");
            var until = DateTime.UtcNow.AddSeconds(10);
            while (!directory.IsCurrent && DateTime.UtcNow < until) await Task.Delay(25);
            directory.IsCurrent.Should().BeTrue("a retry reloaded it");
            directory.IsRole("Reviewers").Should().BeTrue();
        }
        finally
        {
            RoleDirectory.RetryEvery = saved;
        }
    }

    public void Dispose()
    {
        _services.Dispose();
        _connection.Dispose();
    }
}
