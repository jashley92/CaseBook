using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Campaigns;
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
/// Campaign rollup (E-29): given any member case, the service walks the PartOfCampaign link component and
/// rolls the members up into one cross-case picture — members, shared IOCs, ATT&amp;CK coverage, a merged
/// event timeline and aggregate posture — all need-to-know scoped so a restricted case never appears and
/// never bridges two components.
/// </summary>
public sealed class CampaignServiceTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 9, 11, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();   // analyst1, Analyst role (no ViewAllCases)

    public CampaignServiceTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        using var db = NewContext();
        db.Database.EnsureCreated();
    }

    private AppDbContext NewContext() =>
        new(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options);

    private IAppDbContextFactory NewFactory() =>
        new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options);

    private CampaignService NewService() => new(NewFactory(), _user);

    private Guid SeedCase(string name, int seq, Classification? cls = Classification.Incident,
        Severity sev = Severity.Medium, bool restricted = false, DateTimeOffset? detected = null,
        Action<Case>? extra = null)
    {
        using var db = NewContext();
        var c = Case.Open(2026, seq, name, $"{name} case", cls, sev, CaseOrigin.InternalDetection, "creator", _clock.UtcNow);
        if (detected is { } d) c.DetectedAtUtc = d;
        c.IsRestricted = restricted;
        extra?.Invoke(c);
        db.Cases.Add(c);
        db.SaveChanges();
        return c.Id;
    }

    private void LinkCampaign(Guid a, Guid b)
    {
        using var db = NewContext();
        db.CaseLinks.Add(new CaseLink { CaseId = a, RelatedCaseId = b, Type = CaseLinkType.PartOfCampaign });
        db.SaveChanges();
    }

    private static void AddEntity(Case c, EntityType type, string value,
        EntityDisposition disp = EntityDisposition.Suspicious, string? label = null) =>
        c.Entities.Add(new CaseEntity { Id = Guid.NewGuid(), CaseId = c.Id, Type = type, Value = value, Disposition = disp, Label = label });

    [Fact]
    public async Task Rolls_up_every_case_in_the_link_component_from_any_member()
    {
        _user.RoleSet = [AppRole.Manager]; // sees all
        var a = SeedCase("Alpha", 1);
        var b = SeedCase("Bravo", 2);
        var d = SeedCase("Delta", 3);
        LinkCampaign(a, b);
        LinkCampaign(b, d); // chain a—b—d; reachable transitively

        var rollup = await NewService().GetRollupAsync(d); // start from the far end
        rollup.Should().NotBeNull();
        rollup!.MemberCount.Should().Be(3);
        rollup.Members.Select(m => m.CaseId).Should().BeEquivalentTo(new[] { a, b, d });
        rollup.AnchorCaseId.Should().Be(d);
    }

    [Fact]
    public async Task Surfaces_only_indicators_that_appear_on_more_than_one_member()
    {
        _user.RoleSet = [AppRole.Manager];
        var a = SeedCase("Alpha", 1, extra: c =>
        {
            AddEntity(c, EntityType.IpAddress, "185.220.101.47", EntityDisposition.Malicious);
            AddEntity(c, EntityType.Domain, "only-on-alpha.example");
        });
        var b = SeedCase("Bravo", 2, extra: c =>
            AddEntity(c, EntityType.IpAddress, "185.220.101.47", EntityDisposition.Compromised));
        LinkCampaign(a, b);

        var rollup = (await NewService().GetRollupAsync(a))!;

        rollup.SharedIocs.Should().ContainSingle();
        var ioc = rollup.SharedIocs[0];
        ioc.Value.Should().Be("185.220.101.47");
        ioc.CaseCount.Should().Be(2);
        ioc.Disposition.Should().Be(EntityDisposition.Compromised); // strongest verdict wins
        ioc.CaseNumbers.Should().HaveCount(2);
    }

    [Fact]
    public async Task Aggregates_posture_techniques_and_a_merged_timeline()
    {
        _user.RoleSet = [AppRole.Manager];
        var early = new DateTimeOffset(2026, 9, 1, 8, 0, 0, TimeSpan.Zero);
        var later = new DateTimeOffset(2026, 9, 5, 8, 0, 0, TimeSpan.Zero);

        var a = SeedCase("Alpha", 1, Classification.Incident, Severity.Medium, detected: later, extra: c =>
        {
            c.Techniques.Add(new CaseTechnique { Id = Guid.NewGuid(), CaseId = c.Id, TechniqueId = "T1566", Name = "Phishing" });
            c.TimelineEntries.Add(new TimelineEntry { Id = Guid.NewGuid(), CaseId = c.Id, Kind = TimelineKind.Event, OccurredAtUtc = later, Type = TimelineEntryType.Detection, Description = "Alpha detected" });
        });
        var b = SeedCase("Bravo", 2, Classification.Breach, Severity.Critical, detected: early, extra: c =>
        {
            c.Techniques.Add(new CaseTechnique { Id = Guid.NewGuid(), CaseId = c.Id, TechniqueId = "T1566", Name = "Phishing" });
            c.TimelineEntries.Add(new TimelineEntry { Id = Guid.NewGuid(), CaseId = c.Id, Kind = TimelineKind.Event, OccurredAtUtc = early, Type = TimelineEntryType.Detection, Description = "Bravo detected" });
        });
        LinkCampaign(a, b);

        var rollup = (await NewService().GetRollupAsync(a))!;

        rollup.HighestSeverity.Should().Be(Severity.Critical);
        rollup.HighestClassification.Should().Be(Classification.Breach);
        rollup.EarliestDetectedAtUtc.Should().Be(early);

        // T1566 appears on both cases → one rolled-up technique with a case count of 2.
        rollup.Techniques.Should().ContainSingle();
        rollup.Techniques[0].TechniqueId.Should().Be("T1566");
        rollup.Techniques[0].CaseCount.Should().Be(2);

        // Merged event timeline, chronological across both cases.
        rollup.Timeline.Select(t => t.Description).Should().ContainInOrder("Bravo detected", "Alpha detected");
    }

    [Fact]
    public async Task A_case_with_no_campaign_links_yields_a_single_member_rollup()
    {
        _user.RoleSet = [AppRole.Manager];
        var a = SeedCase("Lonely", 1);

        var rollup = (await NewService().GetRollupAsync(a))!;
        rollup.MemberCount.Should().Be(1);
        rollup.SharedIocs.Should().BeEmpty();
    }

    [Fact]
    public async Task A_restricted_member_the_caller_cannot_see_is_excluded_and_does_not_bridge_the_component()
    {
        // Component a—b—d where b is restricted and the analyst is neither IC nor assigned on it.
        // b must be hidden, and because the only path to d runs through b, d must not appear either.
        _user.RoleSet = [AppRole.Manager];
        var a = SeedCase("Alpha", 1);
        var b = SeedCase("Bravo", 2, restricted: true);
        var d = SeedCase("Delta", 3);
        LinkCampaign(a, b);
        LinkCampaign(b, d);

        _user.UserId = "analyst-not-on-bravo";
        _user.RoleSet = [AppRole.Analyst]; // no ViewAllCases

        var rollup = (await NewService().GetRollupAsync(a))!;
        rollup.Members.Select(m => m.CaseId).Should().BeEquivalentTo(new[] { a }); // only the visible anchor
        rollup.MemberCount.Should().Be(1);
    }

    [Fact]
    public async Task An_anchor_the_caller_cannot_see_returns_null()
    {
        _user.RoleSet = [AppRole.Manager];
        var restricted = SeedCase("Restricted", 1, restricted: true);

        _user.UserId = "outsider";
        _user.RoleSet = [AppRole.Analyst];

        (await NewService().GetRollupAsync(restricted)).Should().BeNull();
    }

    public void Dispose() => _connection.Dispose();
}
