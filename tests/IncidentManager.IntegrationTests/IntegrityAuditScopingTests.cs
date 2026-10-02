using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Integrity;
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

/// <summary>
/// The audit-trail reads behind <c>/integrity</c> and the case Audit tab are need-to-know scoped: a user without
/// <c>ViewAllCases</c>/<c>Administer</c> never sees a restricted case's number, actors or entity labels, and
/// never sees the case-less (configuration) entries.
/// </summary>
public sealed class IntegrityAuditScopingTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 8, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { UserId = "seeder", RoleSet = [AppRole.SysAdmin] };

    public IntegrityAuditScopingTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
    }

    private AppDbContext NewContext()
    {
        var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options);
        db.Database.EnsureCreated();
        return db;
    }

    // Read-only: the scoping tests never sign or export a seal, so no signer or store is needed.
    private IntegrityService NewService(ICurrentUser user) =>
        new(new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_connection).Options),
            _hasher, null!, null!, user, _clock, new IntegrityMonitor(), new NoOpIntegrityAlerts());

    private async Task<(string Open, string Restricted)> SeedAsync()
    {
        await using var db = NewContext();
        var open = Case.Open(2026, 1, "Open", "Ordinary matter",
            Classification.Incident, Severity.Medium, CaseOrigin.InternalDetection, "someone-else", _clock.UtcNow);
        var restricted = Case.Open(2026, 2, "Secret", "Restricted matter",
            Classification.Breach, Severity.High, CaseOrigin.InternalDetection, "someone-else", _clock.UtcNow);
        restricted.IsRestricted = true;
        restricted.IncidentCommander = "commander1";
        db.Cases.AddRange(open, restricted);
        await db.SaveChangesAsync();
        db.AuditLog.Should().Contain(a => a.CaseNumber == restricted.CaseNumber, "the seed must put the restricted case on the chain");
        return (open.CaseNumber, restricted.CaseNumber);
    }

    private static TestCurrentUser Analyst() => new() { UserId = "analyst-unrelated", RoleSet = [AppRole.Analyst] };

    [Fact]
    public async Task An_unassigned_analyst_sees_no_restricted_case_entries_on_the_cross_case_trail()
    {
        var (open, restricted) = await SeedAsync();
        var svc = NewService(Analyst());

        var recent = await svc.RecentAsync(null, 100);
        recent.Should().Contain(a => a.CaseNumber == open);
        recent.Should().NotContain(a => a.CaseNumber == restricted);
        recent.Should().OnlyContain(a => a.CaseNumber == open);
        (await svc.RecentAsync(restricted, 100)).Should().BeEmpty();
    }

    [Fact]
    public async Task The_filtered_query_and_facets_are_scoped_too()
    {
        var (open, restricted) = await SeedAsync();
        var svc = NewService(Analyst());

        (await svc.QueryAsync(new AuditQueryFilter())).Should().OnlyContain(a => a.CaseNumber == open);
        (await svc.QueryAsync(new AuditQueryFilter { CaseNumber = restricted })).Should().BeEmpty();
        var (actors, types) = await svc.AuditFacetsAsync(restricted);
        actors.Should().BeEmpty();
        types.Should().BeEmpty();
    }

    [Fact]
    public async Task An_assignee_sees_the_restricted_case_and_oversight_sees_everything()
    {
        var (_, restricted) = await SeedAsync();

        var commander = new TestCurrentUser { UserId = "commander1", RoleSet = [AppRole.Analyst] };
        (await NewService(commander).RecentAsync(null, 100)).Should().Contain(a => a.CaseNumber == restricted);

        var admin = new TestCurrentUser { UserId = "admin1", RoleSet = [AppRole.SysAdmin] };
        (await NewService(admin).RecentAsync(null, 100)).Should().Contain(a => a.CaseNumber == restricted);
    }

    private sealed class NoOpIntegrityAlerts : IIntegrityAlertNotifier
    {
        public Task OnChainBrokenAsync(ChainVerificationResult result, CancellationToken ct = default) => Task.CompletedTask;
    }

    public void Dispose() => _connection.Dispose();
}
