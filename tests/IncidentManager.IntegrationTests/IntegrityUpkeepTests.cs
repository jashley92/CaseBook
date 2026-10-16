using FluentAssertions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Integrity;
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
/// C18: what CaseBook writes to keep its own records (a derived value filled in at start-up, a row hash recorded at the
/// upgrade) is an audited change, so the row hash and the trail agree, but it isn't a change anybody made: changes after
/// closure, the activity feed and the Desk leave it out, and nobody can pass their own change off as it.
/// </summary>
public sealed class IntegrityUpkeepTests
{
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 11, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { RoleSet = [AppRole.SysAdmin] };

    public static TheoryData<string> Providers => TestDatabase.Providers;

    private TestDatabase Seeded(string provider)
    {
        var database = TestDatabase.Open(provider, new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()));
        using var db = database.NewContext();
        DevDataSeeder.SeedAsync(db, _clock).GetAwaiter().GetResult();
        DevDataSeeder.SeedHistoricalDemoAsync(db, _clock).GetAwaiter().GetResult();   // closed and reported cases
        return database;
    }

    private async Task<RowIntegrityVerifier.RowMismatch?> VerifyAsync(TestDatabase database)
    {
        await using var db = database.NewContext();
        var chain = await db.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).ToListAsync();
        return await RowIntegrityVerifier.VerifyAsync(db, _hasher, chain);
    }

    // A closed case, closed before now (the seeded clock), with the change-after-closure count as it stands.
    private static async Task<(Guid Id, int Count)> ClosedCaseAsync(TestDatabase database)
    {
        await using var db = database.NewContext();
        foreach (var id in await db.Cases.Where(c => c.Phase == CasePhase.Closed).Select(c => c.Id).ToListAsync())
            if (await AfterClosure.QueryAsync(db, id) is { } after) return (id, after.Count);
        throw new InvalidOperationException("the sample data has no closed case");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Upkeep_on_a_closed_case_is_audited_but_not_counted_as_a_change_after_closure(string provider)
    {
        using var database = Seeded(provider);
        var (id, before) = await ClosedCaseAsync(database);
        _clock.UtcNow = _clock.UtcNow.AddHours(1);

        await using (var db = database.NewContext())
        {
            var c = await db.Cases.Include(x => x.DataElements).SingleAsync(x => x.Id == id);
            c.ReportedJurisdictions = "NY;SSN";
            db.PendingUpkeep = true;
            await db.SaveChangesAsync();
        }
        await using (var db = database.NewContext())
        {
            var entry = await db.AuditLog.AsNoTracking().OrderByDescending(a => a.Sequence).FirstAsync();
            entry.Reason.Should().Be(IntegrityUpkeep.Reason);
            entry.AfterJson.Should().Contain("RowHash", "the hash it now covers is recorded");
            (await AfterClosure.QueryAsync(db, id))!.Count.Should().Be(before, "CaseBook's upkeep isn't a change to the record");
        }
        (await VerifyAsync(database))?.Detail.Should().BeNull();

        // The same change made by someone is counted.
        _clock.UtcNow = _clock.UtcNow.AddHours(1);
        await using (var db = database.NewContext())
        {
            var c = await db.Cases.Include(x => x.DataElements).SingleAsync(x => x.Id == id);
            c.ReportedJurisdictions = "NY,NJ;SSN";
            await db.SaveChangesAsync();
            (await AfterClosure.QueryAsync(db, id))!.Count.Should().Be(before + 1);
        }
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_reason_typed_to_read_as_upkeep_is_refused(string provider)
    {
        using var database = Seeded(provider);
        await using var db = database.NewContext();
        var note = await db.Notes.FirstAsync(n => n.IsCurrent);
        var c = await db.Cases.Include(x => x.Notes).Include(x => x.DataElements).SingleAsync(x => x.Id == note.CaseId);
        c.EditNote(note.Id, "Rewritten quietly", _user.UserId, _clock.UtcNow);
        db.PendingChangeReason = "  casebook upkeep: not a change to the record";
        var act = () => db.SaveChangesAsync();
        (await act.Should().ThrowAsync<ArgumentException>()).Which.Message.Should().Contain("reserved");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task The_kept_jurisdictions_back_fill_is_audited_upkeep_and_a_value_changed_later_is_caught(string provider /* BUG-631 */)
    {
        using var database = Seeded(provider);
        Guid id;
        await using (var db = database.NewContext())
        {
            // As a case reported before WF-11 left it: reported, nothing kept.
            var c = await db.Cases.Include(x => x.DataElements).FirstAsync(x => x.ReportedAtUtc == null && x.Phase != CasePhase.Closed);
            c.MarkReported(_clock.UtcNow, "alice", _clock.UtcNow);
            await db.SaveChangesAsync();
            id = c.Id;
            (await db.Cases.AsNoTracking().SingleAsync(x => x.Id == id)).ReportedJurisdictions.Should().BeNull();
        }
        (await VerifyAsync(database))?.Detail.Should().BeNull();

        await using (var db = database.NewContext())
            (await ReportedJurisdictionsBackfill.RunAsync(db)).Should().BeGreaterThan(0);
        await using (var db = database.NewContext())
        {
            var written = await db.AuditLog.AsNoTracking().Where(a => a.EntityType == nameof(Case) && a.EntityId == id.ToString())
                .OrderByDescending(a => a.Sequence).FirstAsync();
            written.Reason.Should().Be(IntegrityUpkeep.Reason);
            written.AfterJson.Should().Contain(nameof(Case.ReportedJurisdictions));
        }
        (await VerifyAsync(database))?.Detail.Should().BeNull("the back-fill is recorded with the hash it leaves");

        // The kept set rewritten in the database (a regulator added or dropped).
        await using (var raw = new AppDbContext(database.OptionsWithoutInterceptors))
        {
            var kept = await raw.Cases.Where(c => c.Id == id).Select(c => c.ReportedJurisdictions).SingleAsync();
            await raw.Cases.Where(c => c.Id == id).ExecuteUpdateAsync(s => s.SetProperty(c => c.ReportedJurisdictions, "ZZ" + kept));
        }
        var bad = await VerifyAsync(database);
        bad!.EntityType.Should().Be(nameof(Case));
        bad.Detail.Should().Contain("no longer matches its hash");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_legal_hold_release_request_planted_in_the_database_is_caught(string provider /* BUG-632 */)
    {
        using var database = Seeded(provider);
        Guid id;
        await using (var db = database.NewContext()) id = await db.Cases.Where(c => c.LegalHold).Select(c => c.Id).FirstOrDefaultAsync();
        if (id == Guid.Empty)
            await using (var db = database.NewContext())
            {
                var c = await db.Cases.Include(x => x.DataElements).FirstAsync();
                c.LegalHold = true;
                await db.SaveChangesAsync();
                id = c.Id;
            }
        (await VerifyAsync(database))?.Detail.Should().BeNull();

        // A request "by" someone else, so the planter can approve the release alone.
        await using (var raw = new AppDbContext(database.OptionsWithoutInterceptors))
            await raw.Database.ExecuteSqlInterpolatedAsync(
                $"UPDATE Cases SET LegalHoldReleaseRequestedBy = {"carol"}, LegalHoldReleaseReason = {"retention"} WHERE Id = {id}");
        var bad = await VerifyAsync(database);
        bad!.EntityType.Should().Be(nameof(Case));
        bad.Id.Should().Be(id);
    }
}
