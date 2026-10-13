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
        dir.PermissionsForRoles(["Analyst"]).Should().BeEquivalentTo([Permission.ViewCases, Permission.EditCases, Permission.ChangeClassification]);

        using var scope = Scope();
        var roles = await scope.ServiceProvider.GetRequiredService<RoleService>().ListRolesAsync();
        roles.Where(r => r.IsSystem).Should().HaveCount(5);
    }

    [Fact]
    public async Task Role_names_differing_only_by_case_are_the_same_role()
    {
        // BUG-18: SQLite compared case-sensitively, so "sysadmin" was created beside SysAdmin, and the directory then
        // failed on the duplicate and silently resolved nothing.
        await SeedAsync(new RoleMappingOptions { Groups = new() { ["SysAdmin"] = ["SOC-AppAdmins"] } });
        using (var scope = Scope())
        {
            var svc = scope.ServiceProvider.GetRequiredService<RoleService>();
            var dup = () => svc.CreateRoleAsync("sysadmin", null, [Permission.ViewCases]);
            await dup.Should().ThrowAsync<InvalidOperationException>().WithMessage("*already exists*");

            // BUG-21: a comma would split one name into two wherever roles are stored as a list.
            var comma = () => svc.CreateRoleAsync("Readers,SysAdmin", null, [Permission.ViewCases]);
            await comma.Should().ThrowAsync<ArgumentException>().WithMessage("*comma*");

            await svc.AddMappingAsync("SOC-Leads", "analyst");
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            (await db.RoleMappings.SingleAsync(m => m.AdGroup == "SOC-Leads")).RoleName.Should().Be("Analyst", "the role's own spelling is stored");
        }

        // A look-alike row already in the database (made before this was enforced) can't add to the system role.
        using (var scope = Scope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.Roles.Add(new IncidentManager.Domain.Entities.Role { Name = "analyst", IsSystem = false, PermissionsCsv = "Administer", UpdatedAtUtc = _clock.UtcNow, UpdatedBy = "t" });
            await db.SaveChangesAsync();
        }
        var dir = _sp.GetRequiredService<IRoleDirectory>();
        dir.Invalidate();
        dir.RolesForGroups(["SOC-AppAdmins"]).Should().Contain("SysAdmin", "the directory still loads");
        dir.PermissionsForRoles(["Analyst"]).Should().NotContain(Permission.Administer);
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
    public async Task Deleting_a_role_removes_its_mappings_whatever_their_casing(/* WF-46 */)
    {
        await SeedAsync(new RoleMappingOptions());
        using (var seed = Scope())
        {
            var svc = seed.ServiceProvider.GetRequiredService<RoleService>();
            await svc.CreateRoleAsync("Responders", null, [Permission.ViewCases]);
            var db = seed.ServiceProvider.GetRequiredService<AppDbContext>();
            // As a config bundle stored it before WF-45: the bundle's spelling of the role.
            db.RoleMappings.Add(new IncidentManager.Domain.Entities.AdGroupRoleMapping { AdGroup = "SOC-Responders", RoleName = "responders", UpdatedAtUtc = _clock.UtcNow, UpdatedBy = "admin1" });
            await db.SaveChangesAsync();
        }

        using var scope = Scope();
        var roles = scope.ServiceProvider.GetRequiredService<RoleService>();
        await roles.DeleteRoleAsync((await roles.ListRolesAsync()).Single(r => r.Name == "Responders").Id);

        (await roles.ListMappingsAsync()).Should().NotContain(m => m.AdGroup == "SOC-Responders");
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

    [Fact]
    public async Task Cannot_edit_Administer_off_the_last_admin_role()
    {
        // S-17: admin access comes only through a custom role (no AD group maps to SysAdmin).
        await SeedAsync(new RoleMappingOptions());
        using var scope = Scope();
        var svc = scope.ServiceProvider.GetRequiredService<RoleService>();
        await svc.CreateRoleAsync("Platform Admins", null, [Permission.ViewCases, Permission.Administer]);
        await svc.AddMappingAsync("SOC-Platform", "Platform Admins");
        var role = (await svc.ListRolesAsync()).First(r => r.Name == "Platform Admins");

        var strip = () => svc.UpdateRoleAsync(role.Id, null, [Permission.ViewCases]);
        await strip.Should().ThrowAsync<InvalidOperationException>().WithMessage("*last administrator*");

        // Editing it while keeping Administer is fine.
        await svc.UpdateRoleAsync(role.Id, "Platform team", [Permission.ViewCases, Permission.EditCases, Permission.Administer]);
    }

    [Fact]
    public async Task A_role_someone_changed_since_the_editor_opened_is_not_written_back(/* REV-27 */)
    {
        await SeedAsync(new RoleMappingOptions());
        using var scope = Scope();
        var svc = scope.ServiceProvider.GetRequiredService<RoleService>();
        await svc.CreateRoleAsync("IR Lead", null, [Permission.ViewCases, Permission.ViewRestricted]);
        var opened = (await svc.ListRolesAsync()).First(r => r.Name == "IR Lead");
        var stamp = opened.RowHash;

        await svc.UpdateRoleAsync(opened.Id, null, [Permission.ViewCases], stamp);   // another admin takes ViewRestricted off
        var stale = () => svc.UpdateRoleAsync(opened.Id, "Leads", [Permission.ViewCases, Permission.ViewRestricted], stamp);

        await stale.Should().ThrowAsync<InvalidOperationException>().WithMessage("*since you opened it*");
        (await svc.ListRolesAsync()).First(r => r.Name == "IR Lead").GetPermissions().Should().NotContain(Permission.ViewRestricted);
    }

    public void Dispose()
    {
        _sp.Dispose();
        _connection.Dispose();
    }
}
