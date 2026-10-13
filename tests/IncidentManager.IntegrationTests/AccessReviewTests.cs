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
    public async Task Only_an_administrator_can_build_the_review(/* BUG-22 */)
    {
        var analyst = new TestCurrentUser { UserId = "an1", RoleSet = [AppRole.Analyst] };
        await new AccessReviewService(NewFactory(), _clock, analyst).Invoking(s => s.BuildAsync())
            .Should().ThrowAsync<IncidentManager.Application.Security.ForbiddenException>();
    }

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

            // REV-58: archived, but its commander can still open it.
            var archived = Case.Open(2026, 3, "Archived Matter", "Old and sensitive",
                Classification.Incident, Severity.Low, CaseOrigin.InternalDetection, "system", _clock.UtcNow);
            archived.IsRestricted = true;
            archived.Assign("ic-uid", "Alice IC", CaseAssignmentRole.IncidentCommander, "system", _clock.UtcNow);
            archived.Archive("system", _clock.UtcNow);
            db.Cases.Add(archived);

            // PROD-14: the sign-in mirror — one active user, one idle past the dormancy threshold.
            db.Users.Add(new AppUser { Sid = "an-uid", DisplayName = "Bob Analyst", UserPrincipalName = "bob@corp",
                RolesCsv = "Analyst", LastSeenUtc = _clock.UtcNow.AddDays(-2) });
            db.Users.Add(new AppUser { Sid = "old-uid", DisplayName = "Old Manager", RolesCsv = "Manager, IncidentCommander",
                LastSeenUtc = _clock.UtcNow - AccessReviewService.DormantAfter - TimeSpan.FromDays(1) });

            await db.SaveChangesAsync();
        }

        await using (var db = NewContext())
        {
            var review = await new AccessReviewService(NewFactory(), _clock, _user).BuildAsync();

            // Broad access: roles with ViewAllCases / ViewRestricted, with their AD groups.
            review.Broad.Should().Contain(b => b.RoleName == "Manager" && b.ViewAllCases);
            review.Broad.Single(b => b.RoleName == "Manager").Groups.Should().Contain("SOC-Leadership");
            review.Broad.Should().Contain(b => b.RoleName == "IncidentCommander" && b.ViewRestricted && !b.ViewAllCases);
            review.Broad.Should().NotContain(b => b.RoleName == "Analyst"); // neither capability

            // The restricted cases appear with their need-to-know grantees, archived ones too (REV-58), after the rest.
            review.RestrictedCases.Should().HaveCount(2);
            review.RestrictedCases[1].IsArchived.Should().BeTrue();
            review.RestrictedCases[1].IncidentCommander.Should().Be("ic-uid");
            var rc = review.RestrictedCases[0];
            rc.CaseNumber.Should().Contain("Restricted");
            rc.IncidentCommander.Should().Be("ic-uid");
            rc.Assignees.Should().Contain("Bob Analyst");

            // Known users: dormant first, roles split from the sign-in snapshot.
            review.KnownUsers.Select(u => (u.DisplayName, u.IsDormant)).Should().Equal(
                ("Old Manager", true), ("Bob Analyst", false));
            review.KnownUsers[0].Roles.Should().Equal("Manager", "IncidentCommander");
            review.KnownUsers[1].UserPrincipalName.Should().Be("bob@corp");
        }
    }

    public void Dispose() => _connection.Dispose();
}
