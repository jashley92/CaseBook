using System.Text.Json.Nodes;
using FluentAssertions;
using IncidentManager.Application.Cases;
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

    // As an older release left a record's trail: the RowHash taken out of its update entries (v1.0-v1.5.0).
    private static async Task UnrecordHashAsync(TestDatabase database, string type, Guid id)
    {
        await using var raw = new AppDbContext(database.OptionsWithoutInterceptors);
        var key = id.ToString();
        foreach (var entry in await raw.AuditLog.Where(a => a.EntityType == type && a.EntityId == key && a.AfterJson != null
                                                             && a.Action != AuditAction.Create).ToListAsync())
        {
            var after = JsonNode.Parse(entry.AfterJson!)!.AsObject();
            after.Remove(nameof(IHashableEntity.RowHash));
            entry.AfterJson = after.ToJsonString();
        }
        await raw.SaveChangesAsync();
    }

    // As v1.6.3-v1.6.12 left a case: its hash, and its trail's, in format 3.
    private async Task AsFormat3Async(TestDatabase database, Guid id)
    {
        await using var raw = new AppDbContext(database.OptionsWithoutInterceptors);
        var row = await raw.Cases.Include(c => c.DataElements).SingleAsync(c => c.Id == id);
        var v4 = row.RowHash!;
        var v3 = Canonical.V3Prefix + _hasher.Hash(Canonical.InFormat(3, row.BuildCanonicalContent));
        row.RowHash = v3;
        var key = id.ToString();
        foreach (var e in await raw.AuditLog.Where(a => a.EntityType == nameof(Case) && a.EntityId == key && a.AfterJson != null).ToListAsync())
            e.AfterJson = e.AfterJson!.Replace(v4, v3, StringComparison.Ordinal);
        await raw.SaveChangesAsync();
    }

    private async Task<Guid> ReportedWithoutKeptJurisdictionsAsync(TestDatabase database, int skip)
    {
        await using var db = database.NewContext();
        var c = await db.Cases.Include(x => x.DataElements).Where(x => x.ReportedAtUtc == null && x.Phase != CasePhase.Closed)
            .OrderBy(x => x.CaseNumber).Skip(skip).FirstAsync();
        c.MarkReported(_clock.UtcNow, "alice", _clock.UtcNow);   // as before WF-11: reported, nothing kept
        await db.SaveChangesAsync();
        return c.Id;
    }

    private static async Task<string?> KeptAsync(TestDatabase database, Guid id)
    {
        await using var db = database.NewContext();
        return await db.Cases.AsNoTracking().Where(c => c.Id == id).Select(c => c.ReportedJurisdictions).SingleAsync();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task The_back_fill_doesnt_sign_off_a_case_changed_in_the_database(string provider /* BUG-639 */)
    {
        using var database = Seeded(provider);
        var id = await ReportedWithoutKeptJurisdictionsAsync(database, 0);
        // Its title rewritten in the database, and the kept jurisdictions cleared so the back-fill re-hashes it.
        await using (var raw = new AppDbContext(database.OptionsWithoutInterceptors))
            await raw.Cases.Where(c => c.Id == id).ExecuteUpdateAsync(s => s
                .SetProperty(c => c.Title, "Nothing to see").SetProperty(c => c.ReportedJurisdictions, (string?)null));
        (await VerifyAsync(database))!.Id.Should().Be(id);

        await using (var db = database.NewContext()) await ReportedJurisdictionsBackfill.RunAsync(db);
        (await KeptAsync(database, id)).Should().BeNull("a case that no longer matches its hash isn't filled in");
        var bad = await VerifyAsync(database);
        bad!.Id.Should().Be(id, "the change is still reported");
        bad.Detail.Should().Contain("no longer matches its hash");
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task The_back_fill_doesnt_sign_off_a_case_from_before_v151_rewritten_with_its_hash(string provider /* BUG-639 */)
    {
        using var database = Seeded(provider);
        var id = await ReportedWithoutKeptJurisdictionsAsync(database, 0);
        await UnrecordHashAsync(database, nameof(Case), id);   // its latest entry as v1.0-v1.5.0 wrote it
        await using (var raw = new AppDbContext(database.OptionsWithoutInterceptors))
        {
            var row = await raw.Cases.Include(c => c.DataElements).SingleAsync(c => c.Id == id);
            row.Title = "Nothing to see";
            row.ReportedJurisdictions = null;
            row.RowHash = _hasher.ComputeRowHash(row);   // recomputed: before the upgrade nothing can tell (BUG-629)
            await raw.SaveChangesAsync();
        }

        await using (var db = database.NewContext()) await ReportedJurisdictionsBackfill.RunAsync(db);
        (await KeptAsync(database, id)).Should().BeNull("it doesn't agree with its trail");
        RowHashUpgrade.Result result;
        await using (var db = database.NewContext()) result = await RowHashUpgrade.RunAsync(db, _hasher, _clock);
        result.Left.Should().ContainSingle().Which.Should().StartWith($"{nameof(Case)} {id}");
        (await VerifyAsync(database))!.Id.Should().Be(id);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task The_back_fill_fills_honest_cases_from_older_releases(string provider /* BUG-639 */)
    {
        using var database = Seeded(provider);
        var format3 = await ReportedWithoutKeptJurisdictionsAsync(database, 0);
        var beforeV151 = await ReportedWithoutKeptJurisdictionsAsync(database, 1);
        await AsFormat3Async(database, format3);
        await UnrecordHashAsync(database, nameof(Case), beforeV151);
        (await VerifyAsync(database))?.Detail.Should().BeNull();

        await using (var db = database.NewContext()) await ReportedJurisdictionsBackfill.RunAsync(db);
        (await KeptAsync(database, format3)).Should().NotBeNull("a format-3 case that matches its hash and trail is filled");
        (await KeptAsync(database, beforeV151)).Should().NotBeNull("a case whose trail predates hashes, and agrees with it, is filled");
        (await VerifyAsync(database))?.Detail.Should().BeNull();
        await using (var db = database.NewContext()) (await RowHashUpgrade.RunAsync(db, _hasher, _clock)).Left.Should().BeEmpty();
        (await VerifyAsync(database))?.Detail.Should().BeNull();
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_kept_jurisdiction_dropped_before_the_upgrade_isnt_signed_off_by_the_back_fill(string provider /* BUG-646 */)
    {
        using var database = Seeded(provider);
        Guid id;
        await using (var db = database.NewContext())
        {
            // As a case reported before BUG-284 kept its elements: the codes only, recorded in its trail.
            var c = await db.Cases.Include(x => x.DataElements)
                .Where(x => x.ReportedAtUtc == null && x.Phase != CasePhase.Closed).OrderBy(x => x.CaseNumber).FirstAsync();
            if (c.DataElements.Count == 0) c.DataElements.Add(new CaseDataElement { CaseId = c.Id, ElementKey = "SSN" });
            c.MarkReported(_clock.UtcNow, "alice", _clock.UtcNow);
            c.ReportedJurisdictions = "NY,TX";
            await db.SaveChangesAsync();
            id = c.Id;
        }
        await AsFormat3Async(database, id);   // as v1.6.12 left it: its hash doesn't cover the kept value
        // TX dropped in the database: the format-3 hash can't show it.
        await using (var raw = new AppDbContext(database.OptionsWithoutInterceptors))
            await raw.Cases.Where(c => c.Id == id).ExecuteUpdateAsync(s => s.SetProperty(c => c.ReportedJurisdictions, "NY"));
        (await VerifyAsync(database))?.Detail.Should().BeNull("before the upgrade nothing can tell");

        await using (var db = database.NewContext()) await ReportedJurisdictionsBackfill.RunAsync(db);
        (await KeptAsync(database, id)).Should().Be("NY", "a case that disagrees with its trail isn't filled in and re-hashed");
        RowHashUpgrade.Result result;
        await using (var db = database.NewContext()) result = await RowHashUpgrade.RunAsync(db, _hasher, _clock);
        result.Left.Should().ContainSingle().Which.Should().StartWith($"{nameof(Case)} {id}");
        var bad = await VerifyAsync(database);
        bad!.Id.Should().Be(id, "the dropped code is still reported after the upgrade");
        bad.Detail.Should().Contain("doesn't cover");
    }

    public static TheoryData<string, bool> ProvidersAndUpkeep()
    {
        var rows = new TheoryData<string, bool>();
        foreach (var provider in ((IEnumerable<object[]>)TestDatabase.Providers).Select(r => (string)r[0]))
            foreach (var hashOnly in new[] { false, true }) rows.Add(provider, hashOnly);
        return rows;
    }

    [Theory]
    [MemberData(nameof(ProvidersAndUpkeep))]
    public async Task Upkeep_doesnt_overwrite_a_change_saved_while_it_waited_for_the_chain(string provider, bool hashOnly /* BUG-657 */)
    {
        using var database = Seeded(provider);
        Guid id;
        await using (var db = database.NewContext())
        {
            var caseId = await db.Cases.Select(c => c.Id).FirstAsync();
            var n = new JurisdictionNotice
            {
                CaseId = caseId, Jurisdiction = "NY", NotifiedAtUtc = _clock.UtcNow.AddHours(-2), CreatedBy = "alice", CreatedAtUtc = _clock.UtcNow,
            };
            db.JurisdictionNotices.Add(n);
            await db.SaveChangesAsync();
            id = n.Id;
        }
        (await VerifyAsync(database))?.Detail.Should().BeNull();

        var userHolds = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var upkeepRead = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        // The upkeep reads the notice, then someone's change to it is under way (holding the chain) as the upkeep saves.
        await using var upkeep = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>(database.Options)
            .AddInterceptors(new SignalOnTrailRead(upkeepRead)).Options);
        var stale = await upkeep.JurisdictionNotices.SingleAsync(n => n.Id == id);
        // A start-up fill, or (hashOnly) the upgrade recording a hash, as RowHashUpgrade and RowHashBackfill do.
        if (hashOnly) upkeep.Entry(stale).Property(x => x.RowHash).IsModified = true;
        else stale.DueAtUtc = _clock.UtcNow.AddDays(1);
        upkeep.PendingUpkeep = true;
        await using var user = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>(database.Options)
            .AddInterceptors(new HoldSave(userHolds, release.Task)).Options);
        var edited = await user.JurisdictionNotices.SingleAsync(n => n.Id == id);
        edited.NotifiedAtUtc = _clock.UtcNow.AddHours(-3);
        var userSave = user.SaveChangesAsync();
        await userHolds.Task;
        var upkeepSave = upkeep.SaveChangesAsync();
        // Before the fix the upkeep vouched for the notice here, before the chain was free; after it, it waits first.
        await Task.WhenAny(upkeepRead.Task, Task.Delay(TimeSpan.FromSeconds(1)));
        release.SetResult();
        await userSave;
        await upkeepSave;

        (await VerifyAsync(database))?.Detail.Should().BeNull("the upkeep doesn't save a hash of the notice as it read it over the change");
        await using (var db = database.NewContext())
        {
            var now = await db.JurisdictionNotices.AsNoTracking().SingleAsync(n => n.Id == id);
            now.NotifiedAtUtc.Should().Be(_clock.UtcNow.AddHours(-3));
            now.DueAtUtc.Should().BeNull("the upkeep skips a row changed since it read it; the next start fills it");
        }
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public async Task A_database_timeout_in_the_upkeep_recheck_surfaces_as_itself(string provider /* BUG-660 */)
    {
        using var database = Seeded(provider);
        var fail = new FailNextRead();
        await using (var upkeep = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>(database.Options).AddInterceptors(fail).Options))
        {
            var note = await upkeep.Notes.FirstAsync();
            upkeep.Entry(note).Property(x => x.RowHash).IsModified = true;
            upkeep.PendingUpkeep = true;
            fail.Armed = true;   // the save's first read is the re-check of the rows' stored hashes
            var ex = (await FluentActions.Awaiting(() => upkeep.SaveChangesAsync()).Should().ThrowExactlyAsync<TimeoutException>()).Which;
            Web.BackgroundJobs.RowHashUpgradeHostedService.IsDefect(ex).Should().BeFalse("a timeout is tried again at the next start");
        }
        // The chain is free again: an ordinary save goes through.
        await using (var db = database.NewContext())
        {
            var c = await db.Cases.Include(x => x.DataElements).FirstAsync();
            c.Title += " (renamed)";
            await db.SaveChangesAsync();
        }
    }

    // Once armed, the next query times out (as a busy database's would).
    private sealed class FailNextRead : Microsoft.EntityFrameworkCore.Diagnostics.DbCommandInterceptor
    {
        public volatile bool Armed;

        private void Check()
        {
            if (!Armed) return;
            Armed = false;
            throw new TimeoutException("The database didn't answer in time.");
        }

        public override Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<System.Data.Common.DbDataReader> ReaderExecuting(
            System.Data.Common.DbCommand command, Microsoft.EntityFrameworkCore.Diagnostics.CommandEventData eventData,
            Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<System.Data.Common.DbDataReader> result)
        {
            Check();
            return result;
        }

        public override ValueTask<Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<System.Data.Common.DbDataReader>> ReaderExecutingAsync(
            System.Data.Common.DbCommand command, Microsoft.EntityFrameworkCore.Diagnostics.CommandEventData eventData,
            Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<System.Data.Common.DbDataReader> result, CancellationToken cancellationToken = default)
        {
            Check();
            return ValueTask.FromResult(result);
        }
    }

    // Holds a save once the audit chain is held (it runs after AuditChainInterceptor), until released.
    private sealed class HoldSave(TaskCompletionSource holding, Task release) : Microsoft.EntityFrameworkCore.Diagnostics.SaveChangesInterceptor
    {
        public override async ValueTask<Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<int>> SavingChangesAsync(
            Microsoft.EntityFrameworkCore.Diagnostics.DbContextEventData eventData,
            Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            holding.TrySetResult();
            await release;
            return result;
        }
    }

    // Signals when the context reads the audit trail (the upkeep guard's vouch).
    private sealed class SignalOnTrailRead(TaskCompletionSource read) : Microsoft.EntityFrameworkCore.Diagnostics.DbCommandInterceptor
    {
        public override Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<System.Data.Common.DbDataReader> ReaderExecuting(
            System.Data.Common.DbCommand command, Microsoft.EntityFrameworkCore.Diagnostics.CommandEventData eventData,
            Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<System.Data.Common.DbDataReader> result)
        {
            if (command.CommandText.Contains("AuditLog", StringComparison.Ordinal)) read.TrySetResult();
            return result;
        }

        public override ValueTask<Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<System.Data.Common.DbDataReader>> ReaderExecutingAsync(
            System.Data.Common.DbCommand command, Microsoft.EntityFrameworkCore.Diagnostics.CommandEventData eventData,
            Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<System.Data.Common.DbDataReader> result, CancellationToken cancellationToken = default)
        {
            if (command.CommandText.Contains("AuditLog", StringComparison.Ordinal)) read.TrySetResult();
            return ValueTask.FromResult(result);
        }
    }
}
