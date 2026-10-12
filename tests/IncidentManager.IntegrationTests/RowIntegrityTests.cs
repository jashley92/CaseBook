using FluentAssertions;
using IncidentManager.Application.Integrity;
using IncidentManager.Domain.Common;
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
/// BUG-06: the integrity check covers the records, not only the audit chain. An edit made outside CaseBook is caught
/// whether or not its author also recomputed the row hash, and ordinary use (including the sample data) passes.
/// Runs on SQLite always and on SQL Server when <c>CASEBOOK_TEST_SQL</c> is set.
/// </summary>
public sealed class RowIntegrityTests
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
        return database;
    }

    private async Task<RowIntegrityVerifier.RowMismatch?> VerifyAsync(TestDatabase database)
    {
        await using var db = database.NewContext();
        var chain = await db.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).ToListAsync();
        _hasher.VerifyChain(chain).IsValid.Should().BeTrue("these tests leave the audit log itself alone");
        return await RowIntegrityVerifier.VerifyAsync(db, _hasher, chain);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task The_sample_data_and_ordinary_edits_pass(string provider)
    {
        using var database = Seeded(provider);
        (await VerifyAsync(database))?.Detail.Should().BeNull();

        // A change that only touches the case row but changes its hash (its data elements) is still recorded.
        await using (var db = database.NewContext())
        {
            var c = await db.Cases.Include(x => x.DataElements).FirstAsync(x => x.Classification == Classification.Breach);
            db.DataElements.Add(new DataElement { Key = "PASSPORT", Label = "Passport number", IsActive = true, CreatedBy = "t", CreatedAtUtc = _clock.UtcNow });
            await db.SaveChangesAsync();
            c.SetImpactAssessment(c.AffectedIndividualsCount, c.DataElements.Select(d => d.ElementKey).Append("PASSPORT").ToArray(),
                c.AffectedStates, _user.UserId, _clock.UtcNow);
            await db.SaveChangesAsync();
        }
        (await VerifyAsync(database))?.Detail.Should().BeNull();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task An_edit_made_directly_in_the_database_is_caught(string provider)
    {
        using var database = Seeded(provider);
        await using (var db = database.NewContext())
        {
            var id = await db.TimelineEntries.Select(t => t.Id).FirstAsync();
            await db.TimelineEntries.Where(t => t.Id == id).ExecuteUpdateAsync(s => s.SetProperty(t => t.Description, "Nothing happened."));
        }

        var bad = await VerifyAsync(database);
        bad.Should().NotBeNull();
        bad!.EntityType.Should().Be(nameof(TimelineEntry));
        bad.Detail.Should().Contain("no longer matches its hash");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task An_edit_whose_author_also_recomputed_the_row_hash_is_caught(string provider)
    {
        using var database = Seeded(provider);
        await using (var db = database.NewContext())
        {
            var c = await db.Cases.AsNoTracking().Include(x => x.DataElements).FirstAsync();
            c.Title = "Nothing to see here";
            var forged = _hasher.ComputeRowHash(c);
            await db.Cases.Where(x => x.Id == c.Id).ExecuteUpdateAsync(s => s
                .SetProperty(x => x.Title, c.Title)
                .SetProperty(x => x.RowHash, forged));
        }

        var bad = await VerifyAsync(database);
        bad.Should().NotBeNull();
        bad!.EntityType.Should().Be(nameof(Case));
        bad.Detail.Should().Contain("last recorded change");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task An_edit_that_clears_the_row_hash_is_caught(string provider /* BUG-64 */)
    {
        using var database = Seeded(provider);
        await using (var db = database.NewContext())
        {
            var id = await db.Cases.Select(c => c.Id).FirstAsync();
            await db.Cases.Where(c => c.Id == id).ExecuteUpdateAsync(s => s
                .SetProperty(c => c.Title, "Nothing to see here").SetProperty(c => c.RowHash, (string?)null));
        }

        var bad = await VerifyAsync(database);
        bad!.Detail.Should().Contain("hash removed");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_record_deleted_directly_in_the_database_is_caught(string provider /* BUG-65 */)
    {
        using var database = Seeded(provider);
        await using (var db = database.NewContext())
        {
            var id = await db.Notes.Select(n => n.Id).FirstAsync();
            await db.Notes.Where(n => n.Id == id).ExecuteDeleteAsync();
        }

        var bad = await VerifyAsync(database);
        bad!.EntityType.Should().Be(nameof(AnalystNote));
        bad.Detail.Should().Contain("is missing");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_record_added_directly_in_the_database_is_caught(string provider /* BUG-65 */)
    {
        using var database = Seeded(provider);
        await using (var db = database.NewContext())
        {
            var caseId = await db.Cases.Select(c => c.Id).FirstAsync();
            var note = new AnalystNote { CaseId = caseId, Body = "Planted", CreatedBy = "x", CreatedAtUtc = _clock.UtcNow };
            note.RowHash = _hasher.ComputeRowHash(note);
            await using var raw = new AppDbContext(database.OptionsWithoutInterceptors);
            raw.Notes.Add(note);
            await raw.SaveChangesAsync();
        }

        var bad = await VerifyAsync(database);
        bad!.Detail.Should().Contain("isn't in the audit trail");
    }

    [Fact]
    public async Task An_existing_database_passes_when_one_is_named()
    {
        // Upgrade test hook: tools/upgrade-test/upgrade-path.sh sets CASEBOOK_VERIFY_SQL to the upgraded database, so an
        // upgrade from a real release is checked for false alarms. Does nothing otherwise.
        if (Environment.GetEnvironmentVariable("CASEBOOK_VERIFY_SQL") is not { Length: > 0 } conn) return;
        await using var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlServer(conn).Options);
        var chain = await db.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).ToListAsync();
        (await RowIntegrityVerifier.VerifyAsync(db, _hasher, chain))?.Detail.Should().BeNull();
    }

    [Fact]
    public void Every_hashable_table_is_checked()
    {
        using var database = TestDatabase.Open(TestDatabase.Sqlite);
        using var db = database.NewContext();
        var hashable = db.Model.GetEntityTypes()
            .Where(t => !t.IsOwned() && typeof(IHashableEntity).IsAssignableFrom(t.ClrType))
            .Select(t => t.ClrType).ToHashSet();
        var checkedTypes = RowIntegrityVerifier.Tables(db).Select(q => q.ElementType).ToHashSet();

        hashable.Except(checkedTypes).Should().BeEmpty("a new hashable entity needs adding to RowIntegrityVerifier.Tables");
    }
}
