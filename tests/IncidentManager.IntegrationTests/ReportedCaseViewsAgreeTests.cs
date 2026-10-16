using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Compliance;
using IncidentManager.Application.StageGates;
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
/// C19 (BUG-618, BUG-625): after any change to a reported case's elements, notices or element jurisdictions, every view of
/// its regulatory clock agrees: the case page, the Legal register, the dashboard and Desk, the reminder scan and the close
/// gate each see a running clock exactly when the case isn't reported. Each view is read the way it reads it in the app.
/// </summary>
public sealed class ReportedCaseViewsAgreeTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 9, 20, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { RoleSet = [AppRole.SysAdmin] };
    private readonly StubSettings _settings = new()
    {
        Current = new NotificationDeadlineSettings(true, NotificationStartBasis.Determination, 72, 80),
    };

    public ReportedCaseViewsAgreeTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        using var db = NewContext();
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

    private NotificationDeadlineService NewDeadlines() =>
        new(NewFactory(), _settings, new NotificationRuleService(NewFactory(), _user, _clock), _clock);

    private CaseService Cases() =>
        new(NewFactory(), _user, _clock, new CaseNumberGenerator(NewContext()), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new StageGateEvaluator(_settings), new TestSlaTargets(),
            notifySettings: _settings, notifyRules: new NotificationRuleService(NewFactory(), _user, _clock));

    // A material breach 10 h into its clock, with SSN (NY); EMAIL (no regulator), DL (NJ) and PASS (NY) to add.
    private async Task<Guid> SeedAsync()
    {
        await using var db = NewContext();
        foreach (var (key, label, juris) in new[]
                 {
                     ("SSN", "Social Security number", "NY"), ("EMAIL", "Email address", ""),
                     ("DL", "Driver's licence", "NJ"), ("PASS", "Passport number", "NY"),
                 })
            db.DataElements.Add(new DataElement
            {
                Key = key, Label = label, NotificationJurisdictions = juris, IsActive = true,
                CreatedBy = "system", CreatedAtUtc = _clock.UtcNow,
            });
        var c = Case.Open(2026, 1, "Breach", "Breach case", Classification.Breach, Severity.High,
            CaseOrigin.InternalDetection, "alice", _clock.UtcNow.AddHours(-11));
        c.SetImpactAssessment(500, ["SSN"], "NY", "alice", _clock.UtcNow);
        c.RecordMateriality(MaterialityStatus.Material, "Disclosure Committee", _clock.UtcNow.AddHours(-10),
            "Reasonable likelihood of harm.", "alice", _clock.UtcNow);
        db.Cases.Add(c);
        db.StageGates.Add(new StageGate
        {
            Trigger = StageGateTrigger.CloseCase, Name = "Closure", IsActive = true,
            CreatedBy = "system", CreatedAtUtc = _clock.UtcNow,
            Requirements =
            {
                new StageGateRequirement
                {
                    Kind = GateRequirementKind.MachineCheck, CheckKey = GateCheckKeys.NotificationsRecorded,
                    Label = "Required regulatory notifications recorded", IsBlocking = true, Order = 1,
                },
            },
        });
        await db.SaveChangesAsync();
        return c.Id;
    }

    private async Task MapAsync(string key, string jurisdictions)
    {
        DataElement e;
        await using (var db = NewContext()) e = await db.DataElements.AsNoTracking().SingleAsync(x => x.Key == key);
        await new DataElementService(NewFactory(), _user, _clock).SaveAsync([new DataElementRow(e.Id, e.Label, jurisdictions)]);
    }

    private Task ElementsAsync(Guid id, params string[] keys) => Cases().UpdateImpactAssessmentAsync(id, 500, keys, null);

    // The changes a reported case can go through, and the jurisdictions in play after each.
    public static TheoryData<string, string[]> Changes => new()
    {
        { "a: an element with no regulator is added, and an admin maps it later (BUG-618)", ["NY"] },
        { "b: as (a), on a case reported as a whole (BUG-618)", ["NY"] },
        { "c: an element added brings a new regulator in", ["NJ", "NY"] },
        { "d: the element added is taken out again", ["NY"] },
        { "e: one of two notices is removed", ["NJ", "NY"] },
        { "f: an admin gives an element it had another regulator", ["NY"] },
        { "g: an element added names a notified regulator, and an admin adds another to it (BUG-618)", ["NY"] },
        { "h: a notice is removed after the admin unmapped every element (BUG-625)", ["NJ", "NY"] },
    };

    [Theory]
    [MemberData(nameof(Changes))]
    public async Task Every_view_sees_a_running_clock_exactly_when_the_case_is_not_reported(string change, string[] inPlay)
    {
        var id = await SeedAsync();
        switch (change[0])
        {
            case 'a':
                await Cases().MarkReportedAsync(id, _clock.UtcNow);
                await ElementsAsync(id, "SSN", "EMAIL");
                await MapAsync("EMAIL", "CA");
                break;
            case 'b':
                await using (var db = NewContext())
                {
                    var c = await db.Cases.Include(x => x.DataElements).SingleAsync(x => x.Id == id);
                    c.MarkReported(_clock.UtcNow, "alice", _clock.UtcNow, ["NY"]);   // no notice per jurisdiction
                    await db.SaveChangesAsync();
                }
                await ElementsAsync(id, "SSN", "EMAIL");
                await MapAsync("EMAIL", "CA");
                break;
            case 'c':
                await Cases().MarkReportedAsync(id, _clock.UtcNow);
                await ElementsAsync(id, "SSN", "DL");
                break;
            case 'd':
                await Cases().MarkReportedAsync(id, _clock.UtcNow);
                await ElementsAsync(id, "SSN", "DL");
                await ElementsAsync(id, "SSN");
                break;
            case 'e':
                await ElementsAsync(id, "SSN", "DL");
                await Cases().MarkReportedAsync(id, _clock.UtcNow);
                await Cases().RemoveNoticeAsync(id, "NJ");
                break;
            case 'f':
                await Cases().MarkReportedAsync(id, _clock.UtcNow);
                await MapAsync("SSN", "NY,CA");
                break;
            case 'g':
                await Cases().MarkReportedAsync(id, _clock.UtcNow);
                await ElementsAsync(id, "SSN", "PASS");
                await MapAsync("PASS", "NY,TX");
                break;
            case 'h':
                await ElementsAsync(id, "SSN", "DL");
                await Cases().MarkReportedAsync(id, _clock.UtcNow);
                await MapAsync("SSN", "");
                await MapAsync("DL", "");
                await Cases().RemoveNoticeAsync(id, "NJ");
                break;
        }

        await using var q = NewContext();
        var reported = (await q.Cases.AsNoTracking().SingleAsync(c => c.Id == id)).ReportedAtUtc is not null;
        var views = await ViewsAsync(q, id);
        views.Should().AllSatisfy(v => v.Value.Should().Be(!reported,
            $"after \"{change}\" the case is {(reported ? "" : "not ")}reported, so the {v.Key} must agree"));
        (await NewDeadlines().EvaluateAsync(id)).Statuses.Select(s => s.JurisdictionCode).Should().Equal(inPlay);
    }

    [Fact]
    public async Task The_close_gate_doesnt_wait_on_a_regulator_no_view_has_in_play(/* BUG-625 */)
    {
        // Reported with nothing in play; an element added brings NJ in, so it's unreported but keeps ";EMAIL"; an admin
        // maps EMAIL (which it had) to CA; the element added is taken out. No regulator is in play on any view, and the
        // gate used to read today's mapping of EMAIL and block the close.
        var id = await SeedAsync();
        await ElementsAsync(id, "EMAIL");
        await Cases().MarkReportedAsync(id, _clock.UtcNow);
        await ElementsAsync(id, "EMAIL", "DL");
        await MapAsync("EMAIL", "CA");
        await ElementsAsync(id, "EMAIL");

        await using var q = NewContext();
        (await NewDeadlines().EvaluateAsync(id)).Statuses.Should().BeEmpty();
        (await ViewsAsync(q, id)).Should().AllSatisfy(v => v.Value.Should().BeFalse($"the {v.Key} has no clock to run"));
    }

    // Whether each view shows the case's regulatory clock as running.
    private async Task<Dictionary<string, bool>> ViewsAsync(AppDbContext q, Guid id)
    {
        var deadlines = NewDeadlines();
        var one = q.Cases.AsNoTracking().Where(c => c.Id == id);
        var ruleSet = await new NotificationRuleService(NewFactory(), _user, _clock).LoadRuleSetAsync(_settings.Current.DefaultWindowHours);
        var gate = await new StageGateEvaluator(_settings).EvaluateAsync(q, id, StageGateTrigger.CloseCase);
        return new Dictionary<string, bool>
        {
            ["case page"] = (await deadlines.EvaluateAsync(id)).Statuses.Any(s => s.IsActive),
            ["Legal register"] = (await deadlines.HeadlinesNowAsync(q, one, includeReported: true)).TryGetValue(id, out var r) && r.IsActive,
            ["Desk"] = (await deadlines.HeadlinesNowAsync(q, one)).TryGetValue(id, out var d) && d.IsActive,
            ["dashboard"] = (await NotificationDeadlineService.OpenHeadlinesAsync(q, one, _settings.Current, ruleSet, _clock.UtcNow))
                .TryGetValue(id, out var h) && h.IsActive,
            ["reminder scan"] = (await deadlines.AllNowAsync(q, one.Where(c => !c.IsArchived && c.ReportedAtUtc == null && c.Classification != null)))
                .TryGetValue(id, out var all) && all.Any(s => s.IsActive),
            ["close gate"] = !gate.Requirements.Single().MachineSatisfied,
        };
    }

    private sealed class StubSettings : INotificationDeadlineSettingsProvider
    {
        public NotificationDeadlineSettings Current { get; set; } = NotificationDeadlineSettings.Off;
    }

    public void Dispose() => _connection.Dispose();
}
