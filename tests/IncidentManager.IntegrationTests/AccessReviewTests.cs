using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

public sealed class AccessReviewTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 11, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { UserId = "admin1", RoleSet = [AppRole.SysAdmin] };

    public AccessReviewTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
    }

    private AppDbContext NewContext()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options;
        var db = new AppDbContext(options);
        db.Database.EnsureCreated();
        return db;
    }

    private IAppDbContextFactory NewFactory() =>
        new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options);

    [Fact]
    public async Task Reports_broad_access_roles_and_restricted_cases()
    {
        await using (var db = NewContext())
        {
            await RoleSeeder.SeedAsync(db, _clock, new RoleMappingOptions
            {
                Groups = new()
                {
                    ["Manager"] = ["SOC-Leadership"],
                    ["SysAdmin"] = ["SOC-AppAdmins"],
                    ["Analyst"] = ["SOC-Analysts"]
                }
            });

            var restricted = Case.Open(2026, 1, "Restricted Matter", "Sensitive",
                Classification.Incident, Severity.High, CaseOrigin.InternalDetection, "system", _clock.UtcNow);
            restricted.IsRestricted = true;
            restricted.Assign("ic-uid", "Alice IC", CaseAssignmentRole.IncidentCommander, "system", _clock.UtcNow);
            restricted.Assign("an-uid", "Bob Analyst", CaseAssignmentRole.Analyst, "system", _clock.UtcNow);
            db.Cases.Add(restricted);

            var open = Case.Open(2026, 2, "Open Matter", "Public",
                Classification.AdverseEvent, Severity.Low, CaseOrigin.InternalDetection, "system", _clock.UtcNow);
            db.Cases.Add(open);

            await db.SaveChangesAsync();
        }

        await using (var db = NewContext())
        {
            var review = await new AccessReviewService(NewFactory()).BuildAsync();

            // Broad access: roles with ViewAllCases / ViewRestricted, with their AD groups.
            review.Broad.Should().Contain(b => b.RoleName == "Manager" && b.ViewAllCases);
            review.Broad.Single(b => b.RoleName == "Manager").Groups.Should().Contain("SOC-Leadership");
            review.Broad.Should().Contain(b => b.RoleName == "IncidentCommander" && b.ViewRestricted && !b.ViewAllCases);
            review.Broad.Should().NotContain(b => b.RoleName == "Analyst"); // neither capability

            // Only the restricted, non-archived case appears, with its need-to-know grantees.
            review.RestrictedCases.Should().ContainSingle();
            var rc = review.RestrictedCases[0];
            rc.CaseNumber.Should().Contain("Restricted");
            rc.IncidentCommander.Should().Be("ic-uid");
            rc.Assignees.Should().Contain("Bob Analyst");
        }
    }

    public void Dispose() => _connection.Dispose();
}
