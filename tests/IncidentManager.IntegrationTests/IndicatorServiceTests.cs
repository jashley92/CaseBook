using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Intel;
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

/// <summary>PROD-10: the cross-case indicator pivot — dedupe, verdict roll-up, filters and need-to-know.</summary>
public sealed class IndicatorServiceTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 9, 1, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { UserId = "ic1", RoleSet = [AppRole.IncidentCommander] };

    public IndicatorServiceTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
    }

    private DbContextOptions<AppDbContext> Options() =>
        new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options;

    private IndicatorService Service() => new(new TestDbContextFactory(Options()), _user);

    /// <summary>Three visible cases share an IP (with different casing/verdicts); one restricted case the
    /// viewer can't see also carries it; an exercise case carries a domain.</summary>
    private async Task<(Guid A, Guid Restricted)> SeedAsync()
    {
        await using var db = new AppDbContext(Options());
        await db.Database.EnsureCreatedAsync();

        Case NewCase(int seq, string name, bool exercise = false) =>
            Case.Open(2026, seq, name, name, Classification.Incident, Severity.High, CaseOrigin.InternalDetection,
                "ic1", _clock.UtcNow.AddDays(seq), isExercise: exercise);

        var a = NewCase(1, "Alpha");
        a.AddEntity(EntityType.IpAddress, "203.0.113.66", null, EntityDisposition.Suspicious, null, null, "ic1", _clock.UtcNow.AddDays(1));
        a.AddEntity(EntityType.Account, "jdoe", null, EntityDisposition.Compromised, null, null, "ic1", _clock.UtcNow.AddDays(1));
        var b = NewCase(2, "Bravo");
        b.AddEntity(EntityType.IpAddress, "203.0.113.66", null, EntityDisposition.Malicious, null, null, "ic1", _clock.UtcNow.AddDays(2));
        b.AddEntity(EntityType.Domain, "Evil.Example", null, EntityDisposition.Malicious, null, null, "ic1", _clock.UtcNow.AddDays(2));
        var restricted = NewCase(3, "Restricted");
        restricted.IsRestricted = true;
        restricted.AddEntity(EntityType.IpAddress, "203.0.113.66", null, EntityDisposition.Malicious, null, null, "other", _clock.UtcNow.AddDays(3));
        restricted.AddEntity(EntityType.Domain, "secret.example", null, EntityDisposition.Malicious, null, null, "other", _clock.UtcNow.AddDays(3));
        var drill = NewCase(4, "Drill", exercise: true);
        drill.AddEntity(EntityType.Domain, "evil.example", null, EntityDisposition.Unknown, null, null, "ic1", _clock.UtcNow.AddDays(4));

        db.Cases.AddRange(a, b, restricted, drill);
        await db.SaveChangesAsync();
        return (a.Id, restricted.Id);
    }

    [Fact]
    public async Task Indicators_dedupe_across_visible_cases_with_the_worst_verdict()
    {
        await SeedAsync();
        _user.UserId = "outsider";      // not IC/assignee on the restricted case
        _user.RoleSet = [AppRole.Analyst];

        var lib = await Service().SearchAsync(new IndicatorFilter());

        // IOC types only by default (the Account is left out); restricted-case occurrences never count.
        lib.Rows.Select(r => (r.Type, r.Value, r.CaseCount)).Should().Equal(
            (EntityType.IpAddress, "203.0.113.66", 2),
            (EntityType.Domain, "Evil.Example", 1));
        var ip = lib.Rows[0];
        ip.WorstDisposition.Should().Be(EntityDisposition.Malicious);
        ip.Cases.Select(c => c.CaseNumber).Should().OnlyContain(n => !n.Contains("Restricted"));
        lib.Summary.Should().Be(new IndicatorSummary(Indicators: 2, Shared: 1, Malicious: 2, InOpenCases: 2));
        lib.Rows.Should().NotContain(r => r.Value == "secret.example");
    }

    [Fact]
    public async Task Exercises_join_only_when_asked_and_match_case_insensitively()
    {
        await SeedAsync();
        _user.RoleSet = [AppRole.Manager];   // sees everything, including the restricted case

        var lib = await Service().SearchAsync(new IndicatorFilter(IncludeExercises: true));

        lib.Rows.Single(r => r.Type == EntityType.Domain && r.Value.Equals("evil.example", StringComparison.OrdinalIgnoreCase))
            .Cases.Should().HaveCount(2).And.Contain(c => c.IsExercise);
        lib.Rows.Single(r => r.Type == EntityType.IpAddress).CaseCount.Should().Be(3);
    }

    [Fact]
    public async Task Filters_narrow_by_defanged_search_type_verdict_and_sharing()
    {
        await SeedAsync();
        var svc = Service();

        (await svc.SearchAsync(new IndicatorFilter(Search: "203.0.113[.]66"))).Rows.Should().ContainSingle();
        (await svc.SearchAsync(new IndicatorFilter(SharedOnly: true))).Rows.Should().OnlyContain(r => r.CaseCount > 1);
        (await svc.SearchAsync(new IndicatorFilter(Type: EntityType.Account))).Rows
            .Should().ContainSingle(r => r.Value == "jdoe" && r.WorstDisposition == EntityDisposition.Compromised);
        (await svc.SearchAsync(new IndicatorFilter(Scope: IndicatorTypeScope.AllTypes))).Rows.Should().Contain(r => r.Type == EntityType.Account);
        (await svc.SearchAsync(new IndicatorFilter(Disposition: EntityDisposition.Suspicious))).Rows.Should().BeEmpty(
            "the shared IP's worst verdict is Malicious, not Suspicious");
    }

    [Fact]
    public async Task A_pivot_resolves_an_entity_id_only_within_need_to_know()
    {
        var (a, restricted) = await SeedAsync();
        Guid visibleId, hiddenId;
        await using (var db = new AppDbContext(Options()))
        {
            visibleId = (await db.CaseEntities.FirstAsync(e => e.CaseId == a && e.Type == EntityType.IpAddress)).Id;
            hiddenId = (await db.CaseEntities.FirstAsync(e => e.CaseId == restricted && e.Type == EntityType.Domain)).Id;
        }
        _user.UserId = "outsider";
        _user.RoleSet = [AppRole.Analyst];

        (await Service().ResolveEntityAsync(visibleId)).Should().Be((EntityType.IpAddress, "203.0.113.66"));
        (await Service().ResolveEntityAsync(hiddenId)).Should().BeNull();
    }

    public void Dispose() => _connection.Dispose();
}
