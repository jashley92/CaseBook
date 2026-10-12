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
        c.ChangePhase(CasePhase.Recovery, "recovered", "ic1", _clock.UtcNow.AddHours(1));
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
