using FluentAssertions;
using IncidentManager.Application.Cases;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// CAP-02: one verdict recorded on several of a case's entities at once. Each that changes keeps its own verdict history
/// row and milestone (HR-05), the reason rule is the single verdict's, need-to-know holds, an entity from elsewhere is
/// refused, and one bad row records none. Runs on SQLite always and on SQL Server when <c>CASEBOOK_TEST_SQL</c> is set.
/// </summary>
public sealed class AssessEntitiesTests
{
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 16, 15, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { UserId = "ic1", RoleSet = [AppRole.SysAdmin] };

    public static TheoryData<string> Providers => TestDatabase.Providers;

    private TestDatabase Open(string provider) =>
        TestDatabase.Open(provider, new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()));

    private CaseService NewService(TestDatabase database, TestCurrentUser? user = null) =>
        new(database.Factory(), user ?? _user, _clock, new CaseNumberGenerator(database.NewContext()), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());

    private async Task<(Guid Case, Guid[] Entities)> SeedAsync(CaseService svc, int entities = 3)
    {
        var id = (await svc.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "Assess", Title = "Phishing wave", Classification = Classification.Incident, Severity = Severity.High,
            Origin = CaseOrigin.InternalDetection, DetectedAtUtc = _clock.UtcNow.AddDays(-2)
        })).Id;
        var added = await svc.AddOrMatchEntitiesAsync(id, Enumerable.Range(1, entities)
            .Select(i => new CaseService.EntityToAdd(EntityType.Domain, $"bad{i}.example", null, EntityDisposition.Unknown, null, null)).ToList());
        return (id, added.Select(a => a.Id).ToArray());
    }

    private static async Task<Case> LoadAsync(TestDatabase database, Guid id)
    {
        await using var db = database.NewContext();
        return await db.Cases.AsNoTracking().AsSplitQuery().Include(c => c.Entities).Include(c => c.VerdictChanges).SingleAsync(c => c.Id == id);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Each_entity_that_changes_gets_its_own_history_row_and_milestone(string provider)
    {
        using var database = Open(provider);
        var svc = NewService(database);
        var (id, entities) = await SeedAsync(svc);
        // One already at the verdict is left as it is: no second row, no milestone.
        await svc.SetEntityVerdictAsync(id, entities[2], EntityDisposition.Benign, null, EntityDisposition.Unknown);
        var reached = _clock.UtcNow.AddHours(-3);
        _clock.UtcNow = _clock.UtcNow.AddMinutes(5);

        var changed = await svc.AssessEntitiesAsync(id, entities, EntityDisposition.Benign, "Sinkholed by the registrar",
            determinedAtUtc: reached);

        changed.Should().Be(2);
        var c = await LoadAsync(database, id);
        c.Entities.Should().OnlyContain(e => e.Disposition == EntityDisposition.Benign);
        var rows = c.VerdictChanges.Where(v => v.EntityId != entities[2]).ToList();
        rows.Select(v => v.EntityId).Should().BeEquivalentTo(entities[..2]);
        rows.Should().OnlyContain(v => v.From == EntityDisposition.Unknown && v.To == EntityDisposition.Benign
            && v.Reason == "Sinkholed by the registrar" && v.EffectiveAtUtc == reached && v.ChangedBy == "ic1");
        c.VerdictChanges.Count(v => v.EntityId == entities[2]).Should().Be(1, "the one already Benign keeps its single row");
        var milestones = CaseMilestones.Project(c, new MilestoneLabels(x => "", s => "", p => "", m => ""))
            .Where(m => m.Kind == MilestoneKind.Verdict).ToList();
        milestones.Should().HaveCount(3);
        milestones.Count(m => m.AtUtc == reached).Should().Be(2);

        await using var db = database.NewContext();
        var chain = await db.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).ToListAsync();
        _hasher.VerifyChain(chain).IsValid.Should().BeTrue();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Malicious_or_compromised_needs_a_reason_as_the_single_verdict_does(string provider)
    {
        using var database = Open(provider);
        var svc = NewService(database);
        var (id, entities) = await SeedAsync(svc);

        foreach (var verdict in new[] { EntityDisposition.Malicious, EntityDisposition.Compromised })
            await svc.Invoking(s => s.AssessEntitiesAsync(id, entities, verdict, "  "))
                .Should().ThrowAsync<ArgumentException>().WithMessage("Say why*");
        // A backdated one needs a reason too (BUG-414); Suspicious now doesn't.
        await svc.Invoking(s => s.AssessEntitiesAsync(id, entities, EntityDisposition.Suspicious, null, determinedAtUtc: _clock.UtcNow.AddHours(-2)))
            .Should().ThrowAsync<ArgumentException>();
        (await LoadAsync(database, id)).VerdictChanges.Should().BeEmpty();

        (await svc.AssessEntitiesAsync(id, entities, EntityDisposition.Suspicious, null)).Should().Be(3);
        (await svc.AssessEntitiesAsync(id, entities, EntityDisposition.Malicious, "C2 beaconing in the proxy logs")).Should().Be(3);
        (await LoadAsync(database, id)).VerdictChanges.Should().HaveCount(6);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_restricted_case_is_refused_to_someone_without_need_to_know(string provider)
    {
        using var database = Open(provider);
        var svc = NewService(database);
        var (id, entities) = await SeedAsync(svc);
        await svc.SetRestrictedAsync(id, true, "Insider matter");

        var outsider = NewService(database, new TestCurrentUser { UserId = "analyst-unrelated", RoleSet = [AppRole.Analyst] });
        await outsider.Invoking(s => s.AssessEntitiesAsync(id, entities, EntityDisposition.Benign, null))
            .Should().ThrowAsync<InvalidOperationException>().WithMessage("Case not found or not accessible.");
        (await LoadAsync(database, id)).VerdictChanges.Should().BeEmpty();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task An_entity_from_another_case_is_refused_and_nothing_is_recorded(string provider)
    {
        using var database = Open(provider);
        var svc = NewService(database);
        var (id, entities) = await SeedAsync(svc);
        var (other, foreign) = await SeedAsync(svc, 1);

        await svc.Invoking(s => s.AssessEntitiesAsync(id, [.. entities, foreign[0]], EntityDisposition.Benign, null))
            .Should().ThrowAsync<InvalidOperationException>().WithMessage("Some of those entities are no longer on this case*");
        await svc.Invoking(s => s.AssessEntitiesAsync(id, [Guid.NewGuid()], EntityDisposition.Benign, null))
            .Should().ThrowAsync<InvalidOperationException>();
        (await LoadAsync(database, id)).VerdictChanges.Should().BeEmpty();
        (await LoadAsync(database, other)).Entities.Single().Disposition.Should().Be(EntityDisposition.Unknown);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task One_row_that_refuses_the_time_means_none_are_saved(string provider)
    {
        using var database = Open(provider);
        var svc = NewService(database);
        var (id, entities) = await SeedAsync(svc);
        // The last entity already has a verdict reached an hour ago; a new one can't be dated before it (BUG-414).
        await svc.SetEntityVerdictAsync(id, entities[2], EntityDisposition.Suspicious, "First look", EntityDisposition.Unknown,
            determinedAtUtc: _clock.UtcNow.AddMinutes(-30));
        var before = await LoadAsync(database, id);

        await svc.Invoking(s => s.AssessEntitiesAsync(id, entities, EntityDisposition.Benign, "Cleared on review",
                determinedAtUtc: _clock.UtcNow.AddHours(-2)))
            .Should().ThrowAsync<ArgumentException>();

        var after = await LoadAsync(database, id);
        after.VerdictChanges.Should().HaveCount(before.VerdictChanges.Count);
        after.Entities.Where(e => e.Id != entities[2]).Should().OnlyContain(e => e.Disposition == EntityDisposition.Unknown);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_verdict_someone_changed_since_they_were_picked_refuses_them_all(string provider)
    {
        using var database = Open(provider);
        var svc = NewService(database);
        var (id, entities) = await SeedAsync(svc);
        var seen = entities.ToDictionary(e => e, _ => EntityDisposition.Unknown);
        await svc.SetEntityVerdictAsync(id, entities[1], EntityDisposition.Malicious, "Colleague's finding", EntityDisposition.Unknown);

        await svc.Invoking(s => s.AssessEntitiesAsync(id, entities, EntityDisposition.Benign, null, seen))
            .Should().ThrowAsync<StaleEditException>();
        var c = await LoadAsync(database, id);
        c.Entities.Single(e => e.Id == entities[1]).Disposition.Should().Be(EntityDisposition.Malicious);
        c.VerdictChanges.Should().ContainSingle();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task The_cap_takes_exactly_the_limit_and_refuses_one_more(string provider)
    {
        using var database = Open(provider);
        var svc = NewService(database);
        var max = CaseService.MaxEntitiesPerAssessment;
        var (id, entities) = await SeedAsync(svc, max + 1);

        await svc.Invoking(s => s.AssessEntitiesAsync(id, entities, EntityDisposition.Benign, null))
            .Should().ThrowAsync<ArgumentException>().WithMessage($"Assess up to {max:N0} entities at a time.");
        await svc.Invoking(s => s.AssessEntitiesAsync(id, [], EntityDisposition.Benign, null)).Should().ThrowAsync<ArgumentException>();
        // A repeated id counts once.
        (await svc.AssessEntitiesAsync(id, [.. entities[..max], entities[0]], EntityDisposition.Benign, null)).Should().Be(max);
        (await LoadAsync(database, id)).VerdictChanges.Should().HaveCount(max);
    }
}
