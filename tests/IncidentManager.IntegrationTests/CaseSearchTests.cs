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
        _user.RoleSet = [AppRole.SysAdmin]; // sees all cases + may edit (F-21: intake asserts EditCases)
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


    private static CreateCaseRequest Req(string name) => new()
    {
        DescriptiveName = name,
        Title = $"{name} case",
        Classification = Classification.Incident,
        Severity = Severity.Medium,
        Origin = CaseOrigin.InternalDetection
    };

    // The dashboard trend's month drill-in lists the same cases the bar counted: months in the reporting time zone.
    [Fact]
    public async Task Opened_month_drill_in_uses_the_reporting_time_zone()
    {
        await using (var db = NewContext())
        {
            // 03:00 UTC on 1 February is 22:00 on 31 January in New York.
            db.Cases.Add(IncidentManager.Domain.Entities.Case.Open(2026, 1, "Late January", "Late January",
                Classification.Incident, Severity.Medium, CaseOrigin.InternalDetection, "system", new DateTimeOffset(2026, 2, 1, 3, 0, 0, TimeSpan.Zero)));
            db.Cases.Add(IncidentManager.Domain.Entities.Case.Open(2026, 2, "Early February", "Early February",
                Classification.Incident, Severity.Medium, CaseOrigin.InternalDetection, "system", new DateTimeOffset(2026, 2, 1, 5, 0, 0, TimeSpan.Zero)));
            await db.SaveChangesAsync();
        }

        await using (var db = NewContext())
        {
            var eastern = new CaseService(NewFactory(), _user, _clock, new CaseNumberGenerator(db), new CreateCaseValidator(),
                new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets(),
                zone: new EasternZone());
            var january = await eastern.ListAsync(new CaseFilter { OpenedYear = 2026, OpenedMonth = 1 });
            var february = await eastern.ListAsync(new CaseFilter { OpenedYear = 2026, OpenedMonth = 2 });
            january.Items.Select(c => c.Title).Should().Equal("Late January");
            february.Items.Select(c => c.Title).Should().Equal("Early February");
        }
    }

    private sealed class EasternZone : IncidentManager.Application.Abstractions.IOrganizationTimeZone
    {
        public TimeZoneInfo Current { get; } = TimeZoneInfo.FindSystemTimeZoneById("America/New_York");
    }

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

    [Fact]
    public async Task Listing_carries_the_owner_and_a_count_of_other_assignees()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var alpha = await svc.CreateAsync(Req("Alpha"));
        var beta = await svc.CreateAsync(Req("Beta"));
        await svc.AssignAsync(alpha.Id, "S-1-analyst", "Alex Analyst", CaseAssignmentRole.Analyst);
        await svc.AssignAsync(alpha.Id, "S-1-ic", "Ivy Commander", CaseAssignmentRole.IncidentCommander);
        await svc.AssignAsync(alpha.Id, "S-1-obs", "Olive Observer", CaseAssignmentRole.Observer);
        await svc.AssignAsync(beta.Id, "S-1-obs", "Olive Observer", CaseAssignmentRole.Observer);

        var items = (await svc.ListAsync(new CaseFilter())).Items;

        var a = items.Single(i => i.Id == alpha.Id);
        a.OwnerName.Should().Be("Ivy Commander", "the incident commander leads the case");
        a.OtherAssignees.Should().Be(1, "observers don't count as assignees");
        a.OwnerUserId.Should().Be("S-1-ic");
        var b = items.Single(i => i.Id == beta.Id);
        b.OwnerName.Should().BeNull("an observer alone leaves the case unassigned");
        b.OtherAssignees.Should().Be(0);
    }

    [Fact]
    public async Task A_case_number_or_its_year_sequence_prefix_resolves_to_the_case()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var alpha = await svc.CreateAsync(Req("Alpha"));
        await svc.CreateAsync(Req("Beta"));

        (await svc.FindIdByNumberAsync(alpha.CaseNumber)).Should().Be(alpha.Id);
        (await svc.FindIdByNumberAsync(alpha.CaseNumber.Split('_')[0])).Should().Be(alpha.Id);
        (await svc.FindIdByNumberAsync("1999-01")).Should().BeNull();
        (await svc.FindIdByNumberAsync("  ")).Should().BeNull();
    }

    [Fact]
    public async Task The_list_sorts_by_severity_or_by_how_late_the_sla_clock_is()
    {
        var now = _clock.UtcNow;
        IncidentManager.Domain.Entities.Case Open(int seq, string name, Severity sev, double hoursSinceDetection)
        {
            var c = IncidentManager.Domain.Entities.Case.Open(2026, seq, name, name, Classification.Incident, sev,
                CaseOrigin.InternalDetection, "system", now.AddHours(-hoursSinceDetection));
            c.DetectedAtUtc = now.AddHours(-hoursSinceDetection);
            return c;
        }
        await using (var db = NewContext())
        {
            db.Cases.AddRange(
                Open(1, "Medium late", Severity.Medium, 100),   // 72h target: 28h over
                Open(2, "Critical fresh", Severity.Critical, 1), // 4h target: 3h left
                Open(3, "High late", Severity.High, 30),        // 24h target: 6h over
                Open(4, "Low untimed", Severity.Low, 2));       // no target
            await db.SaveChangesAsync();
        }

        var targets = new SlaTargets(new Dictionary<(SlaClock, Severity), int>
        {
            [(SlaClock.Containment, Severity.Critical)] = 4,
            [(SlaClock.Containment, Severity.High)] = 24,
            [(SlaClock.Containment, Severity.Medium)] = 72,
        }, SlaPolicy.DefaultAtRiskThresholdPercent);
        await using (var db = NewContext())
        {
            var svc = new CaseService(NewFactory(), _user, _clock, new CaseNumberGenerator(db), new CreateCaseValidator(),
                new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets(targets));

            (await svc.ListAsync(new CaseFilter { Sort = CaseSort.Sla, SortDescending = false })).Items.Select(i => i.Title)
                .Should().Equal("Medium late", "High late", "Critical fresh", "Low untimed");
            (await svc.ListAsync(new CaseFilter { Sort = CaseSort.Severity })).Items.Select(i => i.Title)
                .Should().Equal("Critical fresh", "High late", "Medium late", "Low untimed");
            var page2 = await svc.ListAsync(new CaseFilter { Sort = CaseSort.Sla, SortDescending = false, Page = 2, PageSize = 2 });
            page2.Items.Select(i => i.Title).Should().Equal("Critical fresh", "Low untimed");
            page2.Total.Should().Be(4);
        }
    }

    [Fact]
    public async Task The_preview_shows_the_next_task_and_shared_indicators_within_need_to_know()
    {
        Guid alpha, gamma;
        await using (var db = NewContext())
        {
            var svc = NewService(db);
            alpha = (await svc.CreateAsync(Req("Alpha"))).Id;
            var beta = (await svc.CreateAsync(Req("Beta"))).Id;
            gamma = (await svc.CreateAsync(Req("Gamma"))).Id;
            await svc.AddEntityAsync(alpha, EntityType.IpAddress, "203.0.113.66", null, EntityDisposition.Malicious, null, null);
            await svc.AddEntityAsync(alpha, EntityType.Host, "FIN-WKS-07", null, EntityDisposition.Benign, null, null);
            await svc.AddEntityAsync(beta, EntityType.IpAddress, "203.0.113.66", null, EntityDisposition.Unknown, null, null);
            await svc.AddEntityAsync(gamma, EntityType.IpAddress, "203.0.113.66", null, EntityDisposition.Malicious, null, null);
            await svc.AddActionItemAsync(alpha, "Later", null, _clock.UtcNow.AddDays(3));
            await svc.AddActionItemAsync(alpha, "Undated", null, null);
            await svc.AddActionItemAsync(alpha, "Sooner", null, _clock.UtcNow.AddDays(1));
            var g = await db.Cases.FirstAsync(c => c.Id == gamma);
            g.IsRestricted = true;
            await db.SaveChangesAsync();
        }

        await using (var db = NewContext())
        {
            var p = await NewService(db).GetPreviewAsync(alpha);
            p!.OpenTasks.Should().Be(3);
            p.NextTask!.Title.Should().Be("Sooner");
            p.IndicatorCount.Should().Be(2);
            p.Indicators[0].Value.Should().Be("203.0.113.66", "malicious indicators lead");
            p.Indicators[0].OtherCases.Should().Be(2);
        }

        // An analyst who isn't on the restricted case can't preview it, and it doesn't count toward "other cases".
        var analyst = new TestCurrentUser { UserId = "analyst-not-assigned" };
        analyst.RoleSet = [AppRole.Analyst];
        await using (var db = NewContext())
        {
            var svc = new CaseService(new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_connection).Options),
                analyst, _clock, new CaseNumberGenerator(db), new CreateCaseValidator(), new NoOpCaseNotifications(),
                new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());
            (await svc.GetPreviewAsync(gamma)).Should().BeNull();
            (await svc.GetPreviewAsync(alpha))!.Indicators[0].OtherCases.Should().Be(1);
        }
    }

    public void Dispose() => _connection.Dispose();
}
