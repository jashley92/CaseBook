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
/// BUG-113: two saves made from the same starting point don't both land. Runs on SQLite always and on SQL Server when
/// <c>CASEBOOK_TEST_SQL</c> is set.
/// </summary>
public sealed class CaseEditRaceTests
{
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 12, 9, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { RoleSet = [AppRole.SysAdmin] };

    public static TheoryData<string> Providers => TestDatabase.Providers;

    private async Task<(TestDatabase Db, Guid CaseId)> SeedAsync(string provider)
    {
        var database = TestDatabase.Open(provider, new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()));
        await using var db = database.NewContext();
        var c = Case.Open(2026, 1, "Race", "Two closes", Classification.Incident, Severity.Medium, CaseOrigin.InternalDetection, "ic1", _clock.UtcNow);
        c.ChangePhase(CasePhase.Containment, "contained", "ic1", _clock.UtcNow.AddMinutes(30));
        c.MarkContained("ic1", _clock.UtcNow.AddMinutes(30));
        c.ChangePhase(CasePhase.Recovery, "recovered", "ic1", _clock.UtcNow.AddHours(1));
        // BUG-581: a step and a file to cite on it.
        c.Evidence.Add(new Evidence { CaseId = c.Id, OriginalFileName = "shot.png", Sha256 = new string('a', 64), StoragePath = "x", CreatedBy = "ic1", CreatedAtUtc = _clock.UtcNow });
        c.AddEventStep(_clock.UtcNow, [MitreTactic.InitialAccess], null, null, null, "Phish opened", null, "ic1", _clock.UtcNow);
        db.Cases.Add(c);
        await db.SaveChangesAsync();
        return (database, c.Id);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Of_two_simultaneous_closes_only_the_first_lands(string provider)
    {
        var (database, id) = await SeedAsync(provider);
        using var _ = database;
        await using var first = database.NewContext();
        await using var second = database.NewContext();
        var a = await first.Cases.Include(x => x.StatusChanges).SingleAsync(x => x.Id == id);
        var b = await second.Cases.Include(x => x.StatusChanges).SingleAsync(x => x.Id == id);

        a.ChangePhase(CasePhase.Closed, "done", "ic1", _clock.UtcNow.AddHours(2));
        await first.SaveChangesAsync();
        b.ChangePhase(CasePhase.Closed, "done too", "ic2", _clock.UtcNow.AddHours(2));
        var late = async () => await second.SaveChangesAsync();
        await late.Should().ThrowAsync<ConcurrentEditException>().WithMessage("Someone else just changed this case*");

        await using var check = database.NewContext();
        (await check.StatusChanges.CountAsync(s => s.CaseId == id && s.To == CasePhase.Closed)).Should().Be(1);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Adding_to_a_case_someone_else_just_saved_is_refused_too(string provider)
    {
        // Two brief revisions from the same version: without the guard both became current.
        var (database, id) = await SeedAsync(provider);
        using var _ = database;
        await using var first = database.NewContext();
        await using var second = database.NewContext();
        var a = await first.Cases.Include(x => x.Briefs).SingleAsync(x => x.Id == id);
        var b = await second.Cases.Include(x => x.Briefs).SingleAsync(x => x.Id == id);

        a.ReviseBrief("Summary A", "Assessment A", null, null, null, "ic1", _clock.UtcNow);
        await first.SaveChangesAsync();
        b.ReviseBrief("Summary B", "Assessment B", null, null, null, "ic2", _clock.UtcNow);
        var late = async () => await second.SaveChangesAsync();
        await late.Should().ThrowAsync<ConcurrentEditException>();

        await using var check = database.NewContext();
        (await check.CaseBriefs.CountAsync(x => x.CaseId == id && x.IsCurrent)).Should().Be(1);
    }

    /// <summary>
    /// BUG-581: the unique children of a case, and how a save made with the case loaded adds one. The database may insert
    /// the child before it checks the case's version, so the loser of the race hits the child's unique index first.
    /// </summary>
    private static readonly Dictionary<string, (Func<IQueryable<Case>, IQueryable<Case>> Load, Action<AppDbContext, Case, DateTimeOffset> Add)> UniqueChildren = new()
    {
        [nameof(CaseAssignment)] = (q => q.Include(x => x.Assignments).Include(x => x.AssignmentChanges),
            (_, c, now) => c.Assign("u1", "User One", CaseAssignmentRole.Analyst, "u1", now)),
        [nameof(CaseTechnique)] = (q => q.Include(x => x.Techniques),
            (_, c, now) => c.AddTechnique("T1566", "Phishing", MitreTactic.InitialAccess, "ic1", now)),
        [nameof(CaseDataElement)] = (q => q.Include(x => x.DataElements),
            (_, c, now) => c.SetImpactAssessment(3, ["ssn"], null, "ic1", now)),
        [nameof(JurisdictionNotice)] = (q => q.Include(x => x.JurisdictionNotices),
            (_, c, now) => c.RecordNotice("NY", now, "ic1", now)),
        [nameof(EvidenceCitation)] = (q => q.Include(x => x.TimelineEntries).Include(x => x.Evidence).Include(x => x.Citations),
            (_, c, now) => c.SetCitations(c.TimelineEntries.Single().Id, [c.Evidence.Single().Id], "ic1", now)),
        // LessonsService.SaveReviewAsync: the case is loaded tracked, the first review is added beside it.
        [nameof(PostIncidentReview)] = (q => q,
            (db, c, now) => db.PostIncidentReviews.Add(new PostIncidentReview { CaseId = c.Id, CreatedBy = "ic1", CreatedAtUtc = now })),
    };

    /// <summary>
    /// BUG-581: entities with a CaseId and a unique index that aren't raced above, and why a lost race on them doesn't
    /// reach the user as a raw database error.
    /// </summary>
    private static readonly Dictionary<string, string> UniqueChildrenElsewhere = new()
    {
        [nameof(CaseBrief)] = "Raced above (Adding_to_a_case_someone_else_just_saved_is_refused_too); BUG-113's index match.",
        [nameof(CaseLink)] = "Added under the link gate (BUG-525); LinkCaseAsync also rechecks on the unique index.",
        [nameof(EntityLayout)] = "SaveEntityLayoutAsync writes it without loading the case and retries on the unique index (BUG-512).",
        [nameof(PinnedCase)] = "Per-user, written without the case; CaseShortcutService rechecks on the unique index (BUG-431).",
        [nameof(OpenCaseTab)] = "Per-user, written without the case; CaseTabsService swallows the unique index (it's open either way).",
    };

    public static TheoryData<string, string> ProvidersAndChildren
    {
        get
        {
            var rows = new TheoryData<string, string>();
            foreach (var provider in TestDatabase.Providers)
                foreach (var child in UniqueChildren.Keys) rows.Add(provider, child);
            return rows;
        }
    }

    [Theory]
    [MemberData(nameof(ProvidersAndChildren))]
    public async Task Adding_the_same_unique_child_from_two_loads_refuses_the_second(string provider, string child)
    {
        // BUG-581: a double "Assign to me", two tabs tagging one technique: the second save threw the raw unique-index error
        // (the circuit died; a bulk assign stopped mid-loop) instead of "Someone else just changed this case".
        var (load, add) = UniqueChildren[child];
        var (database, id) = await SeedAsync(provider);
        using var _ = database;
        await using var first = database.NewContext();
        await using var second = database.NewContext();
        var a = await load(first.Cases).SingleAsync(x => x.Id == id);
        var b = await load(second.Cases).SingleAsync(x => x.Id == id);

        add(first, a, _clock.UtcNow);
        await first.SaveChangesAsync();
        add(second, b, _clock.UtcNow);
        var late = async () => await second.SaveChangesAsync();
        await late.Should().ThrowAsync<ConcurrentEditException>().WithMessage("Someone else just changed this case*");
    }

    [Theory]
    [MemberData(nameof(ProvidersAndChildren))]
    public async Task The_sync_save_refuses_the_second_too(string provider, string child)
    {
        var (load, add) = UniqueChildren[child];
        var (database, id) = await SeedAsync(provider);
        using var _ = database;
        await using var first = database.NewContext();
        await using var second = database.NewContext();
        var a = await load(first.Cases).SingleAsync(x => x.Id == id);
        var b = await load(second.Cases).SingleAsync(x => x.Id == id);

        add(first, a, _clock.UtcNow);
        first.SaveChanges();
        add(second, b, _clock.UtcNow);
        var late = () => second.SaveChanges();
        late.Should().Throw<ConcurrentEditException>();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_unique_clash_on_a_case_nobody_changed_stays_a_database_error(string provider)
    {
        // BUG-581: the recheck only rewords a clash when the case moved on; a clash with an unchanged case (here a row
        // written past the audit chain, so the case's version stood still) is still the database's error.
        var (database, id) = await SeedAsync(provider);
        using var _ = database;
        await using (var raw = new AppDbContext(database.OptionsWithoutInterceptors))
        {
            raw.CaseTechniques.Add(new CaseTechnique { CaseId = id, TechniqueId = "T1566", Name = "x", CreatedBy = "x", CreatedAtUtc = _clock.UtcNow });
            await raw.SaveChangesAsync();
        }
        await using var db = database.NewContext();
        var c = await db.Cases.SingleAsync(x => x.Id == id);   // techniques not loaded, so AddTechnique adds a second
        c.AddTechnique("T1566", "Phishing", MitreTactic.InitialAccess, "ic1", _clock.UtcNow);
        var save = async () => await db.SaveChangesAsync();
        (await save.Should().ThrowAsync<DbUpdateException>()).Which.Should().NotBeOfType<DbUpdateConcurrencyException>();
    }

    [Fact]
    public void Every_unique_child_of_a_case_is_raced_or_explained()
    {
        // BUG-581: a new entity with a CaseId and a unique index joins the theory above, or says here why it needn't.
        using var database = TestDatabase.Open(TestDatabase.Sqlite);
        using var db = database.NewContext();
        var found = db.Model.GetEntityTypes()
            .Where(t => t.ClrType != typeof(Case) && t.FindProperty("CaseId") is not null && t.GetIndexes().Any(i => i.IsUnique))
            .Select(t => t.ClrType.Name).ToHashSet();
        found.Except(UniqueChildren.Keys).Except(UniqueChildrenElsewhere.Keys)
            .Should().BeEmpty("each entity with a CaseId and a unique index is raced in the theory or explained in the allow-list");
        UniqueChildren.Keys.Concat(UniqueChildrenElsewhere.Keys).Except(found)
            .Should().BeEmpty("the lists name only entities that still have a CaseId and a unique index");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task The_database_holds_one_current_brief_per_case(string provider)
    {
        var (database, id) = await SeedAsync(provider);
        using var _ = database;
        await using var raw = new AppDbContext(database.OptionsWithoutInterceptors);
        raw.CaseBriefs.Add(new CaseBrief { CaseId = id, Version = 7, Summary = "x", CreatedBy = "x", CreatedAtUtc = _clock.UtcNow });
        raw.CaseBriefs.Add(new CaseBrief { CaseId = id, Version = 8, Summary = "y", CreatedBy = "x", CreatedAtUtc = _clock.UtcNow });
        var save = async () => await raw.SaveChangesAsync();
        await save.Should().ThrowAsync<ConcurrentEditException>("the unique index refuses a second current brief");
    }
}
