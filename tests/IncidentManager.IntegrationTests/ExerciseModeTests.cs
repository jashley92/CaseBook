using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Export;
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
/// PROD-43: a tabletop / exercise case is fully usable in its own right, but is deliberately kept out of the
/// working case list (unless asked for), the pushed IOC feed, and cross-case IOC correlation — so a drill
/// never pollutes real metrics or gets linked to a live case. The flag is fixed at creation.
/// </summary>
public sealed class ExerciseModeTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 9, 21, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();

    public ExerciseModeTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _user.RoleSet = [AppRole.SysAdmin]; // sees all cases + may edit (F-21: intake/entities assert EditCases)
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

    private CaseService NewService(AppDbContext db) =>
        new(NewFactory(), _user, _clock, new CaseNumberGenerator(db), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());

    private sealed class NoOpCaseNotifications : ICaseNotifications
    {
        public Task OnAssignedAsync(IncidentManager.Domain.Entities.Case c, string assigneeUserId, string assigneeDisplayName, CaseAssignmentRole role, string assignedByUserId, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnActionItemsOverdueAsync(IReadOnlyList<OverdueActionItem> items, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnActionItemsDueSoonAsync(IReadOnlyList<DueSoonActionItem> items, int leadHours, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnReclassifiedAsync(IncidentManager.Domain.Entities.Case c, Classification? from, Classification to, CancellationToken ct = default) => Task.CompletedTask;
    }

    private static CreateCaseRequest Req(string name, bool isExercise = false) => new()
    {
        DescriptiveName = name,
        Title = $"{name} case",
        Classification = Classification.Incident,
        Severity = Severity.Medium,
        Origin = CaseOrigin.InternalDetection,
        IsExercise = isExercise
    };

    [Fact]
    public async Task Exercise_flag_is_set_at_creation_and_persists()
    {
        Guid drillId, realId;
        await using (var db = NewContext())
        {
            var svc = NewService(db);
            drillId = (await svc.CreateAsync(Req("Tabletop", isExercise: true))).Id;
            realId = (await svc.CreateAsync(Req("RealMatter"))).Id;
        }

        await using (var db = NewContext())
        {
            (await db.Cases.AsNoTracking().FirstAsync(c => c.Id == drillId)).IsExercise.Should().BeTrue();
            (await db.Cases.AsNoTracking().FirstAsync(c => c.Id == realId)).IsExercise.Should().BeFalse();
        }
    }

    [Fact]
    public async Task Exercise_case_is_hidden_from_the_default_list_but_shown_when_included()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var real = await svc.CreateAsync(Req("RealMatter"));
        var drill = await svc.CreateAsync(Req("Tabletop", isExercise: true));

        var defaultList = await svc.ListAsync(new CaseFilter());
        defaultList.Items.Should().ContainSingle().Which.Id.Should().Be(real.Id);

        var withExercises = await svc.ListAsync(new CaseFilter { IncludeExercises = true });
        withExercises.Items.Select(i => i.Id).Should().BeEquivalentTo(new[] { real.Id, drill.Id });
        withExercises.Items.Single(i => i.Id == drill.Id).IsExercise.Should().BeTrue();
    }

    [Fact]
    public async Task Exercise_case_is_not_suggested_as_a_related_case()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var real = await svc.CreateAsync(Req("RealMatter"));
        var otherReal = await svc.CreateAsync(Req("OtherReal"));
        var drill = await svc.CreateAsync(Req("Tabletop", isExercise: true));

        // The same indicator lands on a real case, another real case, and a drill.
        const string ip = "203.0.113.77";
        await svc.AddEntityAsync(real.Id, EntityType.IpAddress, ip, null, EntityDisposition.Malicious, null, null);
        await svc.AddEntityAsync(otherReal.Id, EntityType.IpAddress, ip, null, EntityDisposition.Suspicious, null, null);
        await svc.AddEntityAsync(drill.Id, EntityType.IpAddress, ip, null, EntityDisposition.Malicious, null, null);

        // PROD-40 mid-investigation suggestion from the real case: the other real case, never the drill.
        var suggestions = await svc.FindRelatedOpenCasesAsync(real.Id);
        suggestions.Select(s => s.CaseId).Should().BeEquivalentTo(new[] { otherReal.Id });

        // E-23 intake dedup on that indicator: only the real cases, never the drill.
        var matches = await svc.FindOpenCaseMatchesForIocsAsync(new[] { ip });
        matches.Select(m => m.CaseId).Should().BeEquivalentTo(new[] { real.Id, otherReal.Id });
    }

    [Fact]
    public async Task Exercise_case_malicious_iocs_are_excluded_from_the_pushed_feed()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var real = await svc.CreateAsync(Req("RealMatter"));
        var drill = await svc.CreateAsync(Req("Tabletop", isExercise: true));

        await svc.AddEntityAsync(real.Id, EntityType.IpAddress, "198.51.100.5", null, EntityDisposition.Malicious, null, "SIEM");
        await svc.AddEntityAsync(drill.Id, EntityType.IpAddress, "198.51.100.250", null, EntityDisposition.Malicious, null, "drill");

        var feed = await new IocFeedService(NewFactory(), _user).GetMaliciousIocsAsync();

        feed.Select(f => f.Value).Should().BeEquivalentTo("198.51.100.5"); // the drill IOC never leaves the tool
    }

    public void Dispose() => _connection.Dispose();
}
