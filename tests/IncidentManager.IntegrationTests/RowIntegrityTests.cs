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

    // BUG-194: the records as the chain stood when it was read, and the record check against them, optionally with the
    // re-check that reads the entries written since.
    private async Task<(RowIntegrityVerifier.ChainRecords Records, IncidentManager.Application.Abstractions.IChainVerifier Chain)> ReadChainAsync(
        TestDatabase database)
    {
        await using var db = database.NewContext();
        var records = new RowIntegrityVerifier.ChainRecords();
        var chain = _hasher.BeginVerify();
        await foreach (var e in db.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).AsAsyncEnumerable())
        {
            chain.Add(e).Should().BeTrue();
            records.Add(e);
        }
        return (records, chain);
    }

    private async Task<RowIntegrityVerifier.RowMismatch?> CheckRecordsAsync(TestDatabase database,
        (RowIntegrityVerifier.ChainRecords Records, IncidentManager.Application.Abstractions.IChainVerifier Chain) read, bool recheck)
    {
        await using var db = database.NewContext();
        var again = recheck
            ? new RowIntegrityVerifier.Recheck(async ct =>
            {
                var from = read.Records.Head ?? 0;
                await foreach (var e in db.AuditLog.AsNoTracking().Where(a => a.Sequence > from).OrderBy(a => a.Sequence).AsAsyncEnumerable())
                {
                    read.Chain.Add(e).Should().BeTrue();
                    read.Records.Add(e);
                }
            })
            : null;
        return await RowIntegrityVerifier.VerifyAsync(db, _hasher, read.Records, again);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Saves_landing_during_the_check_are_not_reported_as_tampering(string provider /* BUG-194 */)
    {
        using var database = Seeded(provider);
        var read = await ReadChainAsync(database);

        // After the chain was read: a record added, one changed and one removed, each by CaseBook.
        await using (var db = database.NewContext())
        {
            var c = await db.Cases.FirstAsync();
            db.Notes.Add(new AnalystNote { CaseId = c.Id, Body = "Added during the check", CreatedBy = "t", CreatedAtUtc = _clock.UtcNow });
            (await db.TimelineEntries.Include(t => t.Tactics).FirstAsync()).Description = "Changed during the check";
            db.Notes.Remove(await db.Notes.OrderBy(n => n.CreatedAtUtc).FirstAsync());
            await db.SaveChangesAsync();
        }

        (await CheckRecordsAsync(database, read, recheck: false)).Should().NotBeNull("against the stale records, they look tampered");
        (await CheckRecordsAsync(database, read, recheck: true))?.Detail.Should().BeNull("each is in the entries written since");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_real_edit_is_still_caught_when_saves_land_during_the_check(string provider /* BUG-194 */)
    {
        using var database = Seeded(provider);
        var read = await ReadChainAsync(database);
        await using (var db = database.NewContext())
        {
            (await db.TimelineEntries.Include(t => t.Tactics).OrderBy(t => t.Id).FirstAsync()).Description = "A save in progress";
            await db.SaveChangesAsync();
            var other = await db.TimelineEntries.OrderBy(t => t.Id).Skip(1).Select(t => t.Id).FirstAsync();
            await db.TimelineEntries.Where(t => t.Id == other).ExecuteUpdateAsync(s => s.SetProperty(t => t.Description, "Nothing happened."));
        }

        var bad = await CheckRecordsAsync(database, read, recheck: true);
        bad.Should().NotBeNull();
        bad!.Detail.Should().Contain("no longer matches its hash");
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

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Moving_when_a_transition_happened_directly_in_the_database_is_caught(string provider /* BUG-70 */)
    {
        using var database = Seeded(provider);
        await using (var db = database.NewContext())
        {
            var id = await db.StatusChanges.Where(s => s.From != null).Select(s => s.Id).FirstAsync();
            await db.StatusChanges.Where(s => s.Id == id)
                .ExecuteUpdateAsync(s => s.SetProperty(x => x.EffectiveAtUtc, _clock.UtcNow.AddDays(-30)));
        }

        var bad = await VerifyAsync(database);
        bad!.EntityType.Should().Be(nameof(StatusChange));
        bad.Detail.Should().Contain("no longer matches its hash");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task An_assignment_inserted_directly_in_the_database_is_caught_with_or_without_a_hash(string provider /* BUG-70 */)
    {
        using var database = Seeded(provider);
        var caseId = Guid.Empty;
        await using (var db = database.NewContext()) caseId = await db.Cases.Select(c => c.Id).FirstAsync();

        var planted = new CaseAssignment { CaseId = caseId, UserId = "intruder", UserDisplayName = "Intruder",
            Role = CaseAssignmentRole.Analyst, AssignedAtUtc = _clock.UtcNow, AssignedBy = "intruder" };
        await using (var raw = new AppDbContext(database.OptionsWithoutInterceptors))
        {
            raw.Assignments.Add(planted);
            await raw.SaveChangesAsync();
        }
        (await VerifyAsync(database))!.Detail.Should().Contain("isn't in the audit trail");

        await using (var raw = new AppDbContext(database.OptionsWithoutInterceptors))
        {
            var hash = _hasher.ComputeRowHash(planted);
            await raw.Assignments.Where(a => a.Id == planted.Id).ExecuteUpdateAsync(s => s.SetProperty(a => a.RowHash, hash));
        }
        (await VerifyAsync(database))!.Detail.Should().Contain("isn't in the audit trail");
    }

    // As a database upgraded from before v1.5.2 has its status changes: no row hash, and entries that never recorded one.
    // (Rewriting the entries breaks their own hashes, so these tests check the records, not the chain's links.)
    private async Task AsBeforeTheUpgradeAsync(TestDatabase database, bool hashedByV152 = false)
    {
        await using var raw = new AppDbContext(database.OptionsWithoutInterceptors);
        foreach (var entry in await raw.AuditLog.Where(a => a.EntityType == nameof(StatusChange) && a.AfterJson != null).ToListAsync())
        {
            var after = System.Text.Json.Nodes.JsonNode.Parse(entry.AfterJson!)!.AsObject();
            after.Remove("RowHash");
            entry.AfterJson = after.ToJsonString();
        }
        await raw.SaveChangesAsync();
        if (!hashedByV152)
            await raw.StatusChanges.ExecuteUpdateAsync(s => s.SetProperty(x => x.RowHash, (string?)null));
    }

    private async Task<RowIntegrityVerifier.RowMismatch?> VerifyRecordsAsync(TestDatabase database)
    {
        await using var db = database.NewContext();
        var chain = await db.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).ToListAsync();
        return await RowIntegrityVerifier.VerifyAsync(db, _hasher, chain);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task The_upgrade_back_fill_hashes_recorded_rows_in_the_chain_and_the_check_then_passes(string provider /* BUG-70, BUG-153 */)
    {
        using var database = Seeded(provider);
        await AsBeforeTheUpgradeAsync(database);

        await using (var db = database.NewContext())
        {
            (await RowHashBackfill.RunAsync(db, _hasher)).Should().BeGreaterThan(0);
            (await db.StatusChanges.AnyAsync(s => s.RowHash == null)).Should().BeFalse();
            (await RowHashBackfill.RunAsync(db, _hasher)).Should().Be(0, "once every row is recorded it does nothing");
        }
        (await VerifyRecordsAsync(database))?.Detail.Should().BeNull();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task After_the_back_fill_a_deleted_or_rehashed_history_row_is_caught(string provider /* BUG-153 */)
    {
        using var database = Seeded(provider);
        await AsBeforeTheUpgradeAsync(database);
        await using (var db = database.NewContext()) await RowHashBackfill.RunAsync(db, _hasher);

        Guid edited, deleted;
        await using (var raw = new AppDbContext(database.OptionsWithoutInterceptors))
        {
            var rows = await raw.StatusChanges.OrderBy(x => x.Id).Take(2).ToListAsync();
            (edited, deleted) = (rows[0].Id, rows[1].Id);
            rows[0].EffectiveAtUtc = rows[0].EffectiveAt.AddHours(-6);   // moved, and its hash recomputed to match
            rows[0].RowHash = _hasher.ComputeRowHash(rows[0]);
            await raw.SaveChangesAsync();
        }
        var bad = await VerifyRecordsAsync(database);
        bad!.Id.Should().Be(edited);
        bad.Detail.Should().Contain("doesn't match its last recorded change");

        await using (var raw = new AppDbContext(database.OptionsWithoutInterceptors))
        {
            await raw.StatusChanges.Where(x => x.Id == edited).ExecuteDeleteAsync();
            await raw.StatusChanges.Where(x => x.Id == deleted).ExecuteDeleteAsync();
        }
        (await VerifyRecordsAsync(database))!.Detail.Should().Contain("is missing");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Rows_v152_hashed_without_recording_are_recorded_unless_they_no_longer_match(string provider /* BUG-153 */)
    {
        using var database = Seeded(provider);
        await AsBeforeTheUpgradeAsync(database, hashedByV152: true);
        Guid changed;
        await using (var raw = new AppDbContext(database.OptionsWithoutInterceptors))
        {
            changed = await raw.StatusChanges.OrderBy(x => x.Id).Select(x => x.Id).FirstAsync();
            await raw.StatusChanges.Where(x => x.Id == changed).ExecuteUpdateAsync(s => s.SetProperty(x => x.Reason, "edited"));
        }

        await using (var db = database.NewContext())
            (await RowHashBackfill.RunAsync(db, _hasher)).Should().Be(await db.StatusChanges.CountAsync() - 1);

        var bad = await VerifyRecordsAsync(database);
        bad!.Id.Should().Be(changed, "the edited row isn't recorded with its new content");
        bad.Detail.Should().Contain("no longer matches its hash");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task Text_moved_between_two_fields_directly_in_the_database_is_caught(string provider /* BUG-24 */)
    {
        using var database = Seeded(provider);
        Guid id;
        await using (var db = database.NewContext())
        {
            var e = await db.CaseEntities.FirstAsync();
            e.Description = "seen beaconing|EDR";
            e.Source = "triage";
            await db.SaveChangesAsync();   // through CaseBook: hashed and audited
            id = e.Id;
        }
        (await VerifyAsync(database))?.Detail.Should().BeNull();

        await using (var db = database.NewContext())
            await db.CaseEntities.Where(x => x.Id == id).ExecuteUpdateAsync(s => s
                .SetProperty(x => x.Description, "seen beaconing").SetProperty(x => x.Source, "EDR|triage"));

        var bad = await VerifyAsync(database);
        bad!.EntityType.Should().Be(nameof(CaseEntity));
        bad.Detail.Should().Contain("no longer matches its hash");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_row_hashed_in_the_first_format_still_verifies(string provider /* BUG-24 */)
    {
        // As a row written before format 2 has it: the hash without the prefix, recorded as such in the chain.
        using var database = Seeded(provider);
        await using (var db = database.NewContext())
        {
            var note = await db.Notes.FirstAsync();
            var v1 = _hasher.Hash(note.BuildCanonicalContent());
            await db.Notes.Where(n => n.Id == note.Id).ExecuteUpdateAsync(s => s.SetProperty(n => n.RowHash, v1));
            var v2 = note.RowHash!;
            await db.AuditLog.Where(a => a.EntityId == note.Id.ToString() && a.AfterJson != null)
                .ExecuteUpdateAsync(s => s.SetProperty(a => a.AfterJson, a => a.AfterJson!.Replace(v2, v1)));
        }
        await using (var db = database.NewContext())
        {
            var chain = await db.AuditLog.AsNoTracking().OrderBy(a => a.Sequence).ToListAsync();
            (await RowIntegrityVerifier.VerifyAsync(db, _hasher, chain))?.Detail.Should().BeNull();
        }
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
