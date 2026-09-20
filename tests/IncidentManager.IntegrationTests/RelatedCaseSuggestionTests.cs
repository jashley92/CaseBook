using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
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
/// PROD-40: mid-investigation correlation — <see cref="CaseService.FindRelatedOpenCasesAsync"/> surfaces the
/// visible OPEN cases that share an indicator with the case in view and are not already linked. Refang-aware,
/// need-to-know scoped, and a suggestion only (it never creates a link).
/// </summary>
public sealed class RelatedCaseSuggestionTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 9, 20, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();

    public RelatedCaseSuggestionTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _user.RoleSet = [AppRole.SysAdmin]; // sees all + may edit; a scoping test drops to a lesser role
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

    private IAppDbContextFactory NewFactory() =>
        new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options);

    private CaseService NewService(AppDbContext db) =>
        new(NewFactory(), _user, _clock, new CaseNumberGenerator(db), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());

    private sealed class NoOpCaseNotifications : ICaseNotifications
    {
        public Task OnReclassifiedAsync(IncidentManager.Domain.Entities.Case c, Classification? from, Classification to, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnAssignedAsync(IncidentManager.Domain.Entities.Case c, string a, string b, CaseAssignmentRole role, string by, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnActionItemsOverdueAsync(IReadOnlyList<OverdueActionItem> items, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnActionItemsDueSoonAsync(IReadOnlyList<DueSoonActionItem> items, int leadHours, CancellationToken ct = default) => Task.CompletedTask;
    }

    private static CreateCaseRequest Req(string name) => new()
    {
        DescriptiveName = name,
        Title = $"{name} case",
        Classification = Classification.Incident,
        Severity = Severity.Medium,
        Origin = CaseOrigin.InternalDetection
    };

    [Fact]
    public async Task Suggests_an_open_case_that_shares_an_indicator()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var alpha = (await svc.CreateAsync(Req("Alpha"))).Id;
        var beta = (await svc.CreateAsync(Req("Beta"))).Id;
        var gamma = (await svc.CreateAsync(Req("Gamma"))).Id;

        await svc.AddEntityAsync(alpha, EntityType.IpAddress, "203.0.113.9", null, EntityDisposition.Malicious, null, null);
        await svc.AddEntityAsync(beta, EntityType.IpAddress, "203.0.113.9", null, EntityDisposition.Suspicious, null, null);
        await svc.AddEntityAsync(gamma, EntityType.IpAddress, "198.51.100.7", null, EntityDisposition.Suspicious, null, null);

        var related = await svc.FindRelatedOpenCasesAsync(alpha);

        related.Should().ContainSingle();
        related[0].CaseId.Should().Be(beta);
        related[0].SharedIndicators.Should().ContainSingle().Which.Should().Be("203.0.113.9");
    }

    [Fact]
    public async Task A_defanged_indicator_matches_a_live_one_on_another_case()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var alpha = (await svc.CreateAsync(Req("Alpha"))).Id;
        var beta = (await svc.CreateAsync(Req("Beta"))).Id;

        await svc.AddEntityAsync(alpha, EntityType.IpAddress, "1.1.1.1", null, EntityDisposition.Suspicious, null, null);
        await svc.AddEntityAsync(beta, EntityType.IpAddress, "1.1.1[.]1", null, EntityDisposition.Suspicious, null, null); // refanged on store

        (await svc.FindRelatedOpenCasesAsync(alpha)).Should().ContainSingle().Which.CaseId.Should().Be(beta);
    }

    [Fact]
    public async Task An_already_linked_case_is_not_re_suggested()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var alpha = (await svc.CreateAsync(Req("Alpha"))).Id;
        var beta = (await svc.CreateAsync(Req("Beta"))).Id;
        await svc.AddEntityAsync(alpha, EntityType.Domain, "evil.example.com", null, EntityDisposition.Malicious, null, null);
        await svc.AddEntityAsync(beta, EntityType.Domain, "evil.example.com", null, EntityDisposition.Malicious, null, null);

        (await svc.FindRelatedOpenCasesAsync(alpha)).Should().ContainSingle();   // before linking
        await svc.LinkCaseAsync(alpha, beta, CaseLinkType.RelatedTo, null);
        (await svc.FindRelatedOpenCasesAsync(alpha)).Should().BeEmpty();         // after linking
    }

    [Fact]
    public async Task Closed_and_archived_cases_are_not_suggested()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var alpha = (await svc.CreateAsync(Req("Alpha"))).Id;
        var closed = (await svc.CreateAsync(Req("Closed"))).Id;
        var archived = (await svc.CreateAsync(Req("Archived"))).Id;
        foreach (var id in new[] { alpha, closed, archived })
            await svc.AddEntityAsync(id, EntityType.FileHash, "44d88612fea8a8f36de82e1278abb02f", null, EntityDisposition.Malicious, null, null);

        await svc.ChangePhaseAsync(closed, CasePhase.Closed, "resolved");
        await svc.SetArchivedAsync(archived, true);

        (await svc.FindRelatedOpenCasesAsync(alpha)).Should().BeEmpty();
    }

    [Fact]
    public async Task A_restricted_case_the_caller_cannot_see_is_not_suggested()
    {
        Guid mine;
        await using (var db = NewContext())
        {
            var svc = NewService(db);
            mine = (await svc.CreateAsync(Req("Mine"))).Id;
            await svc.AddEntityAsync(mine, EntityType.IpAddress, "203.0.113.50", null, EntityDisposition.Malicious, null, null);

            var r = IncidentManager.Domain.Entities.Case.Open(2026, 99, "Restricted", "Restricted",
                Classification.Breach, Severity.High, CaseOrigin.InternalDetection, "someone-else", _clock.UtcNow);
            r.IsRestricted = true;
            r.AddEntity(EntityType.IpAddress, "203.0.113.50", null, EntityDisposition.Malicious, null, null, "someone-else", _clock.UtcNow);
            db.Cases.Add(r);
            await db.SaveChangesAsync();
        }

        _user.UserId = "analyst-not-assigned";
        _user.RoleSet = [AppRole.Analyst];

        await using (var db = NewContext())
        {
            var svc = NewService(db);
            (await svc.FindRelatedOpenCasesAsync(mine)).Should().BeEmpty();   // restricted case is invisible → not suggested
        }
    }

    public void Dispose() => _connection.Dispose();
}
