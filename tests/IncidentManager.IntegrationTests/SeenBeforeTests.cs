using FluentAssertions;
using IncidentManager.Application.Admin;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Intel;
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
/// HR-03: history is found when it matters. In the six-month review, an account compromised in a closed case was
/// invisible from the next case: intake checked open cases only, and the account was typed Account there and Email
/// address here.
/// </summary>
public sealed class SeenBeforeTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 1, 9, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();

    public SeenBeforeTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _user.RoleSet = [AppRole.IncidentCommander];
    }

    private DbContextOptions<AppDbContext> Options() => new DbContextOptionsBuilder<AppDbContext>()
        .UseSqlite(_connection)
        .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
        .Options;

    private AppDbContext NewContext()
    {
        var db = new AppDbContext(Options());
        db.Database.EnsureCreated();
        return db;
    }

    private CaseService Cases(AppDbContext db) => new(new TestDbContextFactory(Options()), _user, _clock,
        new CaseNumberGenerator(db), new CreateCaseValidator(), new NoOpCaseNotifications(),
        new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());

    private static CreateCaseRequest Req(string name, bool exercise = false) => new()
    {
        DescriptiveName = name, Title = name + " case", Classification = Classification.Incident,
        Severity = Severity.High, Origin = CaseOrigin.InternalDetection, IsExercise = exercise
    };

    /// <summary>A closed case where the UPN was an Account and Compromised, closed as Confirmed with a conclusion.</summary>
    private async Task<(AppDbContext Db, CaseService Svc, Guid OldId)> ClosedTakeoverAsync()
    {
        var db = NewContext();
        await DevDataSeeder.SeedCaseOutcomesAsync(db, _clock);
        var svc = Cases(db);
        var old = (await svc.CreateAsync(Req("Takeover"))).Id;
        await svc.AddEntityAsync(old, EntityType.Account, "J.Morales@contoso-insurance.example", "Jordan Morales",
            EntityDisposition.Compromised, null, null);
        _clock.UtcNow = _clock.UtcNow.AddHours(4);
        await svc.ChangePhaseAsync(old, CasePhase.Closed, null, closing: new(CaseOutcomeCatalog.Confirmed,
            "Phishing and MFA fatigue gave an attacker the session.", "Account takeover; no payment was made."));
        _clock.UtcNow = _clock.UtcNow.AddDays(3);
        return (db, svc, old);
    }

    [Fact]
    public async Task Intake_shows_closed_cases_that_recorded_the_indicator_with_how_they_ended()
    {
        var (db, svc, old) = await ClosedTakeoverAsync();
        await using var _ = db;

        var history = await svc.FindCaseHistoryForIocsAsync(["j.morales@contoso-insurance.example"]);

        var h = history.Should().ContainSingle().Subject;
        h.CaseId.Should().Be(old);
        h.OutcomeKey.Should().Be(CaseOutcomeCatalog.Confirmed);
        h.ClosingLine.Should().Be("Account takeover; no payment was made.");
        h.ClosedAtUtc.Should().NotBeNull();
        h.Indicators.Should().ContainSingle().Which.Disposition.Should().Be(EntityDisposition.Compromised);
        (await svc.FindOpenCaseMatchesForIocsAsync(["j.morales@contoso-insurance.example"])).Should().BeEmpty(
            "open-case duplicate detection is unchanged");
    }

    [Fact]
    public async Task An_account_and_an_email_address_with_one_value_are_the_same_identity_across_cases()
    {
        var (db, svc, old) = await ClosedTakeoverAsync();
        await using var _ = db;
        var fresh = (await svc.CreateAsync(Req("Mfa"))).Id;
        var entityId = await svc.AddEntityAsync(fresh, EntityType.EmailAddress, "j.morales@contoso-insurance.example", null,
            EntityDisposition.Unknown, null, null);

        var overlap = (await svc.FindEntityOverlapsAsync(fresh)).Should().ContainSingle().Subject;

        overlap.EntityId.Should().Be(entityId);
        overlap.OtherCaseId.Should().Be(old);
        overlap.IsClosed.Should().BeTrue();
        overlap.DispositionThere.Should().Be(EntityDisposition.Compromised);
        overlap.OutcomeKey.Should().Be(CaseOutcomeCatalog.Confirmed);
        overlap.ClosingLine.Should().Be("Account takeover; no payment was made.");
        overlap.OtherTitle.Should().Be("Takeover case");

        // A host with the same text is a different family: no match.
        var other = (await svc.CreateAsync(Req("Host"))).Id;
        await svc.AddEntityAsync(other, EntityType.Host, "j.morales@contoso-insurance.example", null, EntityDisposition.Unknown, null, null);
        (await svc.FindEntityOverlapsAsync(other)).Should().BeEmpty();
    }

    [Fact]
    public async Task The_indicator_library_lists_an_account_and_email_address_as_one_identity()
    {
        var (db, svc, _) = await ClosedTakeoverAsync();
        await using var __ = db;
        var fresh = (await svc.CreateAsync(Req("Mfa"))).Id;
        await svc.AddEntityAsync(fresh, EntityType.EmailAddress, "j.morales@contoso-insurance.example", null,
            EntityDisposition.Suspicious, null, null);

        var library = await new IndicatorService(new TestDbContextFactory(Options()), _user)
            .SearchAsync(new IndicatorFilter(Scope: IndicatorTypeScope.AllTypes, Type: EntityType.Account));

        var row = library.Rows.Should().ContainSingle().Subject;
        row.CaseCount.Should().Be(2);
        row.WorstDisposition.Should().Be(EntityDisposition.Compromised);
    }

    [Fact]
    public async Task Exercises_and_cases_the_viewer_cannot_see_are_not_history()
    {
        var db = NewContext();
        await using var _ = db;
        await DevDataSeeder.SeedCaseOutcomesAsync(db, _clock);
        var svc = Cases(db);
        var drill = (await svc.CreateAsync(Req("Drill", exercise: true))).Id;
        await svc.AddEntityAsync(drill, EntityType.IpAddress, "185.220.101.47", null, EntityDisposition.Malicious, null, null);
        await svc.ChangePhaseAsync(drill, CasePhase.Closed, null, closing: TestOutcomes.Closing());

        (await svc.FindCaseHistoryForIocsAsync(["185.220.101[.]47"])).Should().BeEmpty();
    }

    public void Dispose() => _connection.Dispose();
}
