using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Sla;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

public sealed class CaseSearchTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 8, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();

    public CaseSearchTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _user.RoleSet = [AppRole.Manager]; // sees all cases (no need-to-know scoping)
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
        new(NewFactory(), _user, _clock, new CaseNumberGenerator(db), new CreateCaseValidator(), new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());

    private sealed class NoOpCaseNotifications : IncidentManager.Application.Abstractions.ICaseNotifications
    {
        public System.Threading.Tasks.Task OnAssignedAsync(IncidentManager.Domain.Entities.Case c, string assigneeUserId, string assigneeDisplayName, IncidentManager.Domain.Enums.CaseAssignmentRole role, string assignedByUserId, System.Threading.CancellationToken ct = default) => System.Threading.Tasks.Task.CompletedTask;
        public System.Threading.Tasks.Task OnActionItemsOverdueAsync(System.Collections.Generic.IReadOnlyList<IncidentManager.Application.Abstractions.OverdueActionItem> items, System.Threading.CancellationToken ct = default) => System.Threading.Tasks.Task.CompletedTask;
        public Task OnReclassifiedAsync(IncidentManager.Domain.Entities.Case c, Classification? from, Classification to, CancellationToken ct = default)
            => Task.CompletedTask;
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
    public async Task Origin_filter_returns_only_matching_cases()
    {
        await using (var db = NewContext())
        {
            db.Cases.Add(IncidentManager.Domain.Entities.Case.Open(2026, 1, "Internal One", "Internal",
                Classification.Incident, Severity.Medium, CaseOrigin.InternalDetection, "system", _clock.UtcNow));
            db.Cases.Add(IncidentManager.Domain.Entities.Case.Open(2026, 2, "Vendor One", "Vendor",
                Classification.Breach, Severity.High, CaseOrigin.ThirdParty, "system", _clock.UtcNow));
            await db.SaveChangesAsync();
        }

        await using (var db = NewContext())
        {
            var thirdParty = await NewService(db).ListAsync(new CaseFilter { Origin = CaseOrigin.ThirdParty });
            thirdParty.Items.Should().ContainSingle().Which.Origin.Should().Be(CaseOrigin.ThirdParty);

            var all = await NewService(db).ListAsync(new CaseFilter());
            all.Total.Should().Be(2);
        }
    }

    [Fact]
    public async Task Overdue_filter_returns_only_cases_with_a_past_due_open_task()
    {
        Guid overdueCaseId;
        await using (var db = NewContext())
        {
            var overdue = IncidentManager.Domain.Entities.Case.Open(2026, 1, "Overdue", "Overdue",
                Classification.Incident, Severity.Medium, CaseOrigin.InternalDetection, "system", _clock.UtcNow);
            var onTrack = IncidentManager.Domain.Entities.Case.Open(2026, 2, "On track", "On track",
                Classification.Incident, Severity.Medium, CaseOrigin.InternalDetection, "system", _clock.UtcNow);
            db.Cases.AddRange(overdue, onTrack);
            overdueCaseId = overdue.Id;

            db.ActionItems.Add(new IncidentManager.Domain.Entities.ActionItem
            {
                CaseId = overdue.Id, Title = "Past due", Status = ActionItemStatus.Open,
                DueAtUtc = _clock.UtcNow.AddDays(-2)
            });
            db.ActionItems.Add(new IncidentManager.Domain.Entities.ActionItem
            {
                CaseId = onTrack.Id, Title = "Future", Status = ActionItemStatus.Open,
                DueAtUtc = _clock.UtcNow.AddDays(5)
            });
            await db.SaveChangesAsync();
        }

        await using (var db = NewContext())
        {
            var page = await NewService(db).ListAsync(new CaseFilter { OverdueOnly = true });
            page.Items.Should().ContainSingle().Which.Id.Should().Be(overdueCaseId);
        }
    }

    [Fact]
    public async Task Sla_at_risk_filter_returns_only_flagged_open_cases()
    {
        Guid breachedId;
        await using (var db = NewContext())
        {
            // Critical containment target is 4h; open one 10h ago (breached) and one right now (on track).
            var breached = IncidentManager.Domain.Entities.Case.Open(2026, 1, "Breached", "Breached",
                Classification.Incident, Severity.Critical, CaseOrigin.InternalDetection, "system", _clock.UtcNow.AddHours(-10));
            var onTrack = IncidentManager.Domain.Entities.Case.Open(2026, 2, "Fresh", "Fresh",
                Classification.Incident, Severity.Critical, CaseOrigin.InternalDetection, "system", _clock.UtcNow);
            db.Cases.AddRange(breached, onTrack);
            breachedId = breached.Id;
            await db.SaveChangesAsync();
        }

        var targets = new SlaTargets(
            new Dictionary<(SlaClock, Severity), int> { [(SlaClock.Containment, Severity.Critical)] = 4 }, 80);

        await using (var db = NewContext())
        {
            var svc = new CaseService(NewFactory(), _user, _clock, new CaseNumberGenerator(db),
                new CreateCaseValidator(), new NoOpCaseNotifications(),
                new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets(targets));

            var flagged = await svc.ListAsync(new CaseFilter { SlaAtRiskOnly = true });
            flagged.Items.Should().ContainSingle().Which.Id.Should().Be(breachedId);
            // The projection carries the lifecycle stamps the flag is computed from.
            flagged.Items[0].DetectedAtUtc.Should().NotBeNull();

            var all = await svc.ListAsync(new CaseFilter());
            all.Total.Should().Be(2);
        }
    }

    [Fact]
    public async Task Opened_month_filter_returns_only_that_months_cases()
    {
        await using (var db = NewContext())
        {
            db.Cases.Add(IncidentManager.Domain.Entities.Case.Open(2026, 1, "March", "March",
                Classification.Incident, Severity.Medium, CaseOrigin.InternalDetection, "system",
                new DateTimeOffset(2026, 3, 10, 0, 0, 0, TimeSpan.Zero)));
            db.Cases.Add(IncidentManager.Domain.Entities.Case.Open(2026, 2, "April", "April",
                Classification.Incident, Severity.Medium, CaseOrigin.InternalDetection, "system",
                new DateTimeOffset(2026, 4, 3, 0, 0, 0, TimeSpan.Zero)));
            await db.SaveChangesAsync();
        }

        await using (var db = NewContext())
        {
            var march = await NewService(db).ListAsync(new CaseFilter { OpenedYear = 2026, OpenedMonth = 3, IncludeClosed = true });
            march.Items.Should().ContainSingle().Which.Title.Should().Be("March");
        }
    }

    [Fact]
    public async Task Search_matches_an_ioc_value_not_just_the_case_number()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var alpha = await svc.CreateAsync(Req("Alpha"));
        await svc.CreateAsync(Req("Beta"));
        await svc.AddEntityAsync(alpha.Id, EntityType.IpAddress, "203.0.113.42", null, EntityDisposition.Malicious, null, null);

        var result = await svc.ListAsync(new CaseFilter { Search = "203.0.113.42" });

        result.Total.Should().Be(1);
        result.Items.Single().Id.Should().Be(alpha.Id);
    }

    [Fact]
    public async Task Overlap_finds_a_shared_ioc_on_another_visible_case()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var alpha = await svc.CreateAsync(Req("Alpha"));
        var beta = await svc.CreateAsync(Req("Beta"));
        var gamma = await svc.CreateAsync(Req("Gamma"));
        await svc.AddEntityAsync(alpha.Id, EntityType.IpAddress, "198.51.100.9", null, EntityDisposition.Malicious, null, null);
        await svc.AddEntityAsync(beta.Id, EntityType.IpAddress, "198.51.100.9", null, EntityDisposition.Suspicious, null, null);
        await svc.AddEntityAsync(gamma.Id, EntityType.IpAddress, "10.0.0.1", null, EntityDisposition.Unknown, null, null);

        var overlaps = await svc.FindEntityOverlapsAsync(alpha.Id);

        overlaps.Should().ContainSingle();
        overlaps[0].OtherCaseId.Should().Be(beta.Id);
    }

    [Fact]
    public async Task Listing_pages_results_and_reports_the_total()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        await svc.CreateAsync(Req("Alpha"));
        await svc.CreateAsync(Req("Beta"));
        await svc.CreateAsync(Req("Gamma"));

        var page1 = await svc.ListAsync(new CaseFilter { PageSize = 2, Page = 1 });
        page1.Total.Should().Be(3);
        page1.TotalPages.Should().Be(2);
        page1.Items.Should().HaveCount(2);

        var page2 = await svc.ListAsync(new CaseFilter { PageSize = 2, Page = 2 });
        page2.Items.Should().ContainSingle();
    }

    public void Dispose() => _connection.Dispose();
}
