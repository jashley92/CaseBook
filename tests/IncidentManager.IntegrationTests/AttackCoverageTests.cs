using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Mitre;
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

/// <summary>PROD-42: the program-wide ATT&amp;CK heatmap aggregation.</summary>
public sealed class AttackCoverageTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 9, 1, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { UserId = "ic1", RoleSet = [AppRole.IncidentCommander] };

    public AttackCoverageTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
    }

    private DbContextOptions<AppDbContext> Options() =>
        new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options;

    private AttackCoverageService Service() => new(new TestDbContextFactory(Options()), _user, _clock);

    private async Task SeedAsync()
    {
        await using var db = new AppDbContext(Options());
        await db.Database.EnsureCreatedAsync();
        var now = _clock.UtcNow;
        Case NewCase(int seq, DateTimeOffset opened, bool exercise = false) =>
            Case.Open(2026, seq, $"C{seq}", $"Case {seq}", Classification.Incident, Severity.High,
                CaseOrigin.InternalDetection, "ic1", opened, isExercise: exercise);

        // Two recent cases share phishing (one via the parent tag, one via a sub-technique step).
        var a = NewCase(1, now.AddDays(-10));
        a.AddTechnique("T1566", "Phishing", MitreTactic.InitialAccess, "ic1", now);
        a.AddTechnique("T1566", "Phishing", MitreTactic.InitialAccess, "ic1", now);   // re-tag: still one case
        var b = NewCase(2, now.AddDays(-20));
        b.AddEventStep(now.AddDays(-20), [MitreTactic.InitialAccess], "T1566.001", null, null, "Spearphish", null, "ic1", now);
        b.AddEventStep(now.AddDays(-19), [MitreTactic.Discovery], null, null, null, "Looked around", null, "ic1", now);
        // An old case, outside a 12-month window.
        var old = NewCase(3, now.AddMonths(-18));
        old.AddTechnique("T1486", "Data Encrypted for Impact", MitreTactic.Impact, "ic1", now);
        // A drill, excluded by default.
        var drill = NewCase(4, now.AddDays(-5), exercise: true);
        drill.AddTechnique("T1078", "Valid Accounts", MitreTactic.InitialAccess, "ic1", now);
        // A restricted case the outsider can't see.
        var hidden = NewCase(5, now.AddDays(-3));
        hidden.IsRestricted = true;
        hidden.AddTechnique("T1566", "Phishing", MitreTactic.InitialAccess, "other", now);

        db.Cases.AddRange(a, b, old, drill, hidden);
        await db.SaveChangesAsync();
    }

    [Fact]
    public async Task Rolls_sub_techniques_up_and_counts_each_case_once()
    {
        await SeedAsync();
        _user.UserId = "outsider";
        _user.RoleSet = [AppRole.Analyst];

        var cov = await Service().GetAsync(months: 12);

        cov.CasesInPeriod.Should().Be(2, "old, drill and restricted cases are all out");
        var initial = cov.Tactics.Single(t => t.Tactic == MitreTactic.InitialAccess);
        var phishing = initial.Techniques.Should().ContainSingle().Subject;
        phishing.TechniqueId.Should().Be("T1566");
        phishing.CaseCount.Should().Be(2);
        phishing.SubTechniques.Should().Equal("T1566.001");
        cov.MaxTechniqueCases.Should().Be(2);

        // A tactic-only step still lights its column, with no technique cell.
        var discovery = cov.Tactics.Single(t => t.Tactic == MitreTactic.Discovery);
        discovery.CaseCount.Should().Be(1);
        discovery.Techniques.Should().BeEmpty();
        cov.Tactics.Should().NotContain(t => t.Tactic == MitreTactic.Impact);
    }

    [Fact]
    public async Task A_vendor_attack_counts_and_is_marked_and_its_disclosure_milestones_add_nothing()
    {
        await SeedAsync();
        await using (var db = new AppDbContext(Options()))
        {
            var now = _clock.UtcNow;
            var v = Case.Open(2026, 6, "Vendor", "Vendor breach", Classification.Breach, Severity.High,
                CaseOrigin.ThirdParty, "ic1", now.AddDays(-2));
            v.AddEventStep(now.AddDays(-2), [MitreTactic.InitialAccess], "T1566.002", null, null, "Phished the vendor's admin", "Acme", "ic1", now);
            v.AddEventStep(now.AddDays(-1), [], null, null, null, "Vendor notified us", "Acme", "ic1", now, type: TimelineEntryType.Notified);
            db.Cases.Add(v);
            await db.SaveChangesAsync();
        }

        var cov = await Service().GetAsync(months: 12);

        var phishing = cov.Tactics.Single(t => t.Tactic == MitreTactic.InitialAccess).Techniques.Single(t => t.TechniqueId == "T1566");
        phishing.CaseCount.Should().Be(4, "two recent cases, the restricted one the commander can see, and the vendor's");
        phishing.ThirdPartyCount.Should().Be(1);
        phishing.Cases.Single(c => c.CaseNumber.StartsWith("2026-06")).ThirdParty.Should().BeTrue();
        cov.Tactics.SelectMany(t => t.Cases).Where(c => c.ThirdParty).Should().OnlyContain(c => c.CaseNumber.StartsWith("2026-06"));
    }

    [Fact]
    public async Task All_time_and_exercises_widen_the_view()
    {
        await SeedAsync();

        var cov = await Service().GetAsync(months: null, includeExercises: true);

        cov.Tactics.Should().Contain(t => t.Tactic == MitreTactic.Impact);
        cov.Tactics.Single(t => t.Tactic == MitreTactic.InitialAccess).Techniques
            .Select(t => t.TechniqueId).Should().BeEquivalentTo("T1566", "T1078");
    }

    [Fact]
    public void Parent_id_strips_the_sub_technique()
    {
        AttackCoverageService.ParentId(" t1566.001 ").Should().Be("T1566");
        AttackCoverageService.ParentId("T1078").Should().Be("T1078");
    }

    public void Dispose() => _connection.Dispose();
}
