using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// Exercises the roles/mappings store, seeding, the cached directory used at authentication time, and
/// the guardrails — over a real DI graph so the audit interceptor and directory invalidation run.
/// </summary>
public sealed class RoleDirectoryTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly ServiceProvider _sp;
    private readonly TestCurrentUser _user = new() { UserId = "admin1", RoleSet = [AppRole.SysAdmin] };
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 11, 0, 0, 0, TimeSpan.Zero));

    public RoleDirectoryTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();

        var services = new ServiceCollection();
        services.AddSingleton<ICurrentUser>(_user);
        services.AddSingleton<IClock>(_clock);
        services.AddSingleton<IHashChainService, HashChainService>();
        services.AddSingleton<ICaseChangeNotifier, CaseChangeNotifier>();
        services.AddScoped<AuditChainInterceptor>();
        // H-08: a factory, not a shared context — mirrors Infrastructure.DependencyInjection so
        // RoleService (which now takes IAppDbContextFactory) resolves correctly, while the scoped
        // AppDbContext/IAppDbContext bridge keeps this test's direct db reads working unchanged.
        services.AddDbContextFactory<AppDbContext>((sp, o) =>
            o.UseSqlite(_connection).AddInterceptors(sp.GetRequiredService<AuditChainInterceptor>()),
            lifetime: ServiceLifetime.Scoped);
        services.AddScoped<IAppDbContextFactory, AppDbContextFactoryAdapter>();
        services.AddScoped<AppDbContext>(sp => sp.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContext());
        services.AddScoped<IAppDbContext>(sp => sp.GetRequiredService<AppDbContext>());
        services.AddSingleton<IRoleDirectory, RoleDirectory>();
        services.AddScoped<RoleService>();
        _sp = services.BuildServiceProvider();

        using var scope = _sp.CreateScope();
        scope.ServiceProvider.GetRequiredService<AppDbContext>().Database.EnsureCreated();
    }

    private async Task SeedAsync(RoleMappingOptions mapping)
    {
        using var scope = _sp.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        await RoleSeeder.SeedAsync(db, _clock, mapping);
        _sp.GetRequiredService<IRoleDirectory>().Invalidate();
    }

    private IServiceScope Scope() => _sp.CreateScope();

    [Fact]
    public async Task Seeds_system_roles_and_migrates_the_file_mapping()
    {
        await SeedAsync(new RoleMappingOptions
        {
            Groups = new() { ["SysAdmin"] = ["SOC-AppAdmins"], ["Analyst"] = ["SOC-Analysts"] }
        });

        var dir = _sp.GetRequiredService<IRoleDirectory>();
        dir.RolesForGroups(["SOC-AppAdmins"]).Should().Contain("SysAdmin");
        dir.PermissionsForRoles(["SysAdmin"]).Should().BeEquivalentTo(Enum.GetValues<Permission>());
        dir.PermissionsForRoles(["Analyst"]).Should().BeEquivalentTo([Permission.ViewCases, Permission.EditCases]);

        using var scope = Scope();
        var roles = await scope.ServiceProvider.GetRequiredService<RoleService>().ListRolesAsync();
        roles.Where(r => r.IsSystem).Should().HaveCount(5);
    }

    [Fact]
    public async Task Custom_role_grants_its_permissions_through_the_directory()
    {
        await SeedAsync(new RoleMappingOptions { Groups = new() { ["SysAdmin"] = ["SOC-AppAdmins"] } });

        using (var scope = Scope())
        {
            var svc = scope.ServiceProvider.GetRequiredService<RoleService>();
            await svc.CreateRoleAsync("Auditor", "Read-only oversight", [Permission.ViewCases, Permission.ViewRestricted]);
            await svc.AddMappingAsync("Sec-Auditors", "Auditor");
        }

        var dir = _sp.GetRequiredService<IRoleDirectory>();
        dir.RolesForGroups(["Sec-Auditors"]).Should().Contain("Auditor");
        dir.PermissionsForRoles(["Auditor"]).Should().BeEquivalentTo([Permission.ViewCases, Permission.ViewRestricted]);
    }

    [Fact]
    public async Task Role_changes_are_audited_and_hash_chained()
    {
        await SeedAsync(new RoleMappingOptions());

        using (var scope = Scope())
            await scope.ServiceProvider.GetRequiredService<RoleService>()
                .CreateRoleAsync("Auditor", null, [Permission.ViewCases]);

        using var read = Scope();
        var db = read.ServiceProvider.GetRequiredService<AppDbContext>();
        var chain = await db.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).ToListAsync();
        chain.Should().Contain(a => a.EntityType == nameof(IncidentManager.Domain.Entities.Role));
        _sp.GetRequiredService<IHashChainService>().VerifyChain(chain).IsValid.Should().BeTrue();
    }

    [Fact]
    public async Task System_roles_cannot_be_edited_or_deleted()
    {
        await SeedAsync(new RoleMappingOptions());

        using var scope = Scope();
        var svc = scope.ServiceProvider.GetRequiredService<RoleService>();
        var sysAdmin = (await svc.ListRolesAsync()).First(r => r.Name == "SysAdmin");

        var edit = () => svc.UpdateRoleAsync(sysAdmin.Id, "x", [Permission.ViewCases]);
        await edit.Should().ThrowAsync<InvalidOperationException>();

        var delete = () => svc.DeleteRoleAsync(sysAdmin.Id);
        await delete.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task Cannot_remove_the_last_administrator_mapping()
    {
        await SeedAsync(new RoleMappingOptions { Groups = new() { ["SysAdmin"] = ["SOC-AppAdmins"] } });

        using var scope = Scope();
        var svc = scope.ServiceProvider.GetRequiredService<RoleService>();
        var mapping = (await svc.ListMappingsAsync()).First(m => m.RoleName == "SysAdmin");

        var act = () => svc.RemoveMappingAsync(mapping.Id);
        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    public void Dispose()
    {
        _sp.Dispose();
        _connection.Dispose();
    }
}
