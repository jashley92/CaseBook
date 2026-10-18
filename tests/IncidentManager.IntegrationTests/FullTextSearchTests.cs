using System.Linq.Expressions;
using System.Text.Json;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Search;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// CAP-22: full-text search on SQL Server, optional with a substring fallback. On both providers the check reports how
/// search works and Find and the case list find exactly what they did; on SQL Server a full-text query the server refuses
/// runs again by substring with the same results, and the migrations apply whether or not the server has Full-Text Search.
/// The full-text path itself runs only on a server with the feature (<see cref="SqlServerFullTextFactAttribute"/>).
/// </summary>
public sealed class FullTextSearchTests : IDisposable
{
    private TestDatabase? _db;
    private static readonly DateTimeOffset Now = new(2026, 10, 18, 12, 0, 0, TimeSpan.Zero);
    private readonly FixedClock _clock = new(Now);
    private readonly TestCurrentUser _user = new() { RoleSet = [AppRole.SysAdmin] };
    private Guid _alpha;

    public void Dispose() => _db?.Dispose();

    private void Use(string provider)
    {
        _db = TestDatabase.Open(provider);
        Seed();
    }

    private void Seed()
    {
        using var db = _db!.NewContext();
        var a = Case.Open(2026, 1, "Credential_Theft", "Credential theft on the finance share", Classification.Incident, Severity.High,
            CaseOrigin.InternalDetection, "robin", Now.AddDays(-3));
        a.SetInitialSummary("Lateral movement after LSASS was dumped on WS-001234.", "robin", Now.AddDays(-3));
        a.TimelineEntries.Add(new TimelineEntry { Kind = TimelineKind.Event, Type = TimelineEntryType.Detection, OccurredAtUtc = Now.AddDays(-3),
            Description = "Dumped LSASS memory with an unsigned binary from a user temp folder.", CreatedBy = "robin", CreatedAtUtc = Now.AddDays(-3) });
        a.TimelineEntries.Add(new TimelineEntry { Kind = TimelineKind.Investigation, Type = TimelineEntryType.Decision, OccurredAtUtc = Now.AddDays(-2),
            Description = "Reset every password on the share", Rationale = "Credentials were captured (salsa night)", CreatedBy = "robin", CreatedAtUtc = Now.AddDays(-2) });
        a.ActionItems.Add(new ActionItem { Title = "Rotate the krbtgt password twice", Description = "AND then check replication", CreatedBy = "robin", CreatedAtUtc = Now.AddDays(-2) });
        a.Notes.Add(new AnalystNote { Body = "Hunch: the lateral movement used PsExec", CreatedBy = "robin", CreatedAtUtc = Now.AddDays(-2) });
        a.Evidence.Add(new Evidence { OriginalFileName = "lsass_dump.dmp", Description = "memory image", Sha256 = new string('b', 64), StoragePath = "x",
            CreatedBy = "robin", CreatedAtUtc = Now.AddDays(-2) });
        a.Entities.Add(new CaseEntity { Type = EntityType.IpAddress, Value = "198.51.100.7", CreatedBy = "robin", CreatedAtUtc = Now.AddDays(-2) });
        _alpha = a.Id;
        var b = Case.Open(2026, 2, "Phish", "Phishing wave", Classification.AdverseEvent, Severity.Low, CaseOrigin.InternalDetection, "lee", Now.AddDays(-1));
        b.TimelineEntries.Add(new TimelineEntry { Kind = TimelineKind.Investigation, Type = TimelineEntryType.Note, OccurredAtUtc = Now.AddDays(-1),
            Description = "User reported a lure from 198.51.100.7; no credentials entered.", CreatedBy = "lee", CreatedAtUtc = Now.AddDays(-1) });
        db.Cases.AddRange(a, b);
        db.SaveChanges();
    }

    private SqlFullTextSearch Real(FullTextStatusCache? cache = null) => new(_db!.Factory(), cache ?? new FullTextStatusCache(), _clock);

    private FindService Find(IFullTextSearch? fullText) => new(_db!.Factory(), _user, new ListedUserDirectory(), fullText: fullText);

    private CaseService Cases(IFullTextSearch? fullText)
    {
        var factory = _db!.Factory();
        return new CaseService(factory, _user, _clock, new CaseNumberGenerator(factory.CreateAppDbContext()), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets(), fullText: fullText);
    }

    // What a search shows, every field of it (results, counts, snippets, how it read the words), for comparing two runs.
    private static string Shown(object result) => JsonSerializer.Serialize(result);

    /// <summary>What Find and the case list are asked in these tests: words, a phrase, odd input, an indicator, filters.</summary>
    private static readonly string[] Queries =
    [
        "lsass", "lsa", "credential", "lateral movement", "\"lateral movement\"", "salsa", "AND", "OR NEAR ~", "pass*", "\"quoted",
        "198.51.100.7", "2026-1", "type:decision password", "in:notes psexec", "nothing-at-all", "ws-001234", "*", "lsass_dump",
    ];

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task The_check_says_how_search_works_on_this_database(string provider)
    {
        Use(provider);
        var status = await Real().RefreshAsync();

        if (provider == TestDatabase.Sqlite)
        {
            status.Mode.Should().Be(FullTextMode.NotSqlServer);
            status.Label.Should().Be("Search: substring (SQLite)");
        }
        else if (!SqlServerFullTextFactAttribute.Installed)
        {
            status.Mode.Should().Be(FullTextMode.NotInstalled);
            status.Label.Should().Be("Search: substring (full-text not installed)");
        }
        else status.Mode.Should().Be(FullTextMode.NotCreated, "a database made without the migration has no full-text indexes");
        status.Any.Should().BeFalse();
        status.CheckedAtUtc.Should().Be(Now);
    }

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task The_status_is_kept_and_checked_again_when_stale_or_after_a_fallback(string provider)
    {
        Use(provider);
        var cache = new FullTextStatusCache();
        var search = Real(cache);
        var first = await search.StatusAsync();
        _clock.UtcNow = Now.AddMinutes(1);
        (await search.StatusAsync()).CheckedAtUtc.Should().Be(first.CheckedAtUtc, "it's kept between checks");
        _clock.UtcNow = Now.AddMinutes(1) + SqlFullTextSearch.ReadyFor;
        var later = await search.StatusAsync();
        if (provider == TestDatabase.Sqlite) later.CheckedAtUtc.Should().Be(Now, "SQLite never becomes SQL Server");
        else later.CheckedAtUtc.Should().Be(_clock.UtcNow, "stale, so checked again");

        search.FellBack(new InvalidOperationException("x"), "a test");
        var after = await search.StatusAsync();
        after.Fallbacks.Should().Be(1);
        after.LastFallback.Should().StartWith("a test");
    }

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task Without_full_text_Find_and_the_case_list_find_exactly_what_they_did(string provider)
    {
        Use(provider);
        var withCheck = Real();
        foreach (var q in Queries)
        {
            Shown(await Find(withCheck).FindAsync(q)).Should().Be(Shown(await Find(null).FindAsync(q)), q);
            Shown(await Cases(withCheck).ListAsync(new CaseFilter { Search = q, IncludeClosed = true }))
                .Should().Be(Shown(await Cases(null).ListAsync(new CaseFilter { Search = q, IncludeClosed = true })), q);
        }
        (await withCheck.StatusAsync()).Fallbacks.Should().Be(0);

        // Substring, as ever: part of a word finds it.
        (await Find(withCheck).FindAsync("sass")).Entries.Should().Contain(e => e.Text.Contains("LSASS"));
        (await Cases(withCheck).ListAsync(new CaseFilter { Search = "sass", IncludeClosed = true })).Items.Should().ContainSingle(c => c.Id == _alpha);
    }

    /// <summary>The check's real behaviour, but claiming every column is indexed: on a database with no full-text indexes,
    /// every full-text query the server is sent fails, as one would after an index was dropped since the check.</summary>
    private sealed class ClaimsEveryIndex(SqlFullTextSearch real) : IFullTextSearch
    {
        public FullTextStatus Claimed { get; } = new(FullTextMode.Ready,
            FullTextSchema.Columns.Select(c => (c.Table.Entity, c.Column)).ToHashSet(), Now);
        public Task<FullTextStatus> StatusAsync(CancellationToken ct = default) => Task.FromResult(Claimed);
        public Task<FullTextStatus> RefreshAsync(CancellationToken ct = default) => Task.FromResult(Claimed);
        public Expression<Func<string?, string, bool>> ContainsTemplate => real.ContainsTemplate;
        public bool IsFullTextFailure(Exception ex) => real.IsFullTextFailure(ex);
        public void FellBack(Exception ex, string search) => real.FellBack(ex, search);
        public Task<FullTextStatus> CreateIndexesAsync(CancellationToken ct = default) => real.CreateIndexesAsync(ct);
    }

    [SqlServerFact]
    public async Task A_full_text_query_the_server_refuses_runs_again_by_substring_with_the_same_results()
    {
        Use(TestDatabase.SqlServer);
        var real = Real();
        var claims = new ClaimsEveryIndex(real);
        foreach (var q in Queries)
        {
            Shown(await Find(claims).FindAsync(q)).Should().Be(Shown(await Find(null).FindAsync(q)), q);
            Shown(await Cases(claims).ListAsync(new CaseFilter { Search = q, IncludeClosed = true }))
                .Should().Be(Shown(await Cases(null).ListAsync(new CaseFilter { Search = q, IncludeClosed = true })), q);
        }
        var status = await real.StatusAsync();
        status.Fallbacks.Should().BeGreaterThan(Queries.Length / 2, "most of these words reached the full-text path, and each refusal is counted");
        status.LastFallback.Should().Contain("SQL Server error 76", "a full-text error: not indexed, or not installed");
    }

    [Fact]
    public async Task On_SQLite_full_text_is_never_sent()
    {
        Use(TestDatabase.Sqlite);
        var real = Real();
        (await real.StatusAsync()).Any.Should().BeFalse();
        // Even a status claiming every index can't reach SQLite: Find asks the check, which says SQLite.
        var r = await Find(real).FindAsync("lsass");
        r.Entries.Should().NotBeEmpty();
        (await real.StatusAsync()).Fallbacks.Should().Be(0);
    }

    [Fact]
    public void The_full_text_schema_names_the_model_s_tables_columns_and_keys()
    {
        using var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlServer("Server=unused;Database=unused;TrustServerCertificate=True").Options);
        foreach (var t in FullTextSchema.Tables)
        {
            var entity = db.Model.FindEntityType(t.Entity);
            entity.Should().NotBeNull(t.Name);
            entity!.GetTableName().Should().Be(t.Name);
            entity.FindPrimaryKey()!.GetName().Should().Be(t.KeyIndex, "full-text's key is the table's primary key");
            entity.FindPrimaryKey()!.Properties.Should().ContainSingle("a full-text key is one column");
            foreach (var c in t.Columns)
            {
                var p = entity.FindProperty(c);
                p.Should().NotBeNull($"{t.Name}.{c}");
                p!.ClrType.Should().Be<string>();
                p.GetColumnName().Should().Be(c, "the queries name the property, the index the column");
            }
        }
    }

    [Fact]
    public void The_dba_script_and_the_migration_are_the_app_s_full_text_script()
    {
        static string Lf(string s) => s.Replace("\r\n", "\n").Trim('\n');
        var dba = File.ReadAllText(Path.Combine(RepoRoot(), "deploy", "sql", "03-Enable-FullText.sql"));
        Lf(dba).Should().EndWith(Lf(FullTextSchema.Script), "deploy/sql/03-Enable-FullText.sql is a copy of FullTextSchema.Script");

        // As it shipped: until a later migration changes the indexes, the migration ran exactly what the app runs.
        var migration = (Migration)Activator.CreateInstance(
            Type.GetType("IncidentManager.Migrations.SqlServer.Migrations.FullTextSearch, IncidentManager.Migrations.SqlServer", throwOnError: true)!)!;
        var up = migration.UpOperations.OfType<Microsoft.EntityFrameworkCore.Migrations.Operations.SqlOperation>().Should().ContainSingle().Subject;
        up.SuppressTransaction.Should().BeTrue("full-text DDL can't run in a transaction");
        Lf(up.Sql).Should().Be(Lf(FullTextSchema.Script));
        var down = migration.DownOperations.OfType<Microsoft.EntityFrameworkCore.Migrations.Operations.SqlOperation>().Should().ContainSingle().Subject;
        down.SuppressTransaction.Should().BeTrue();
        Lf(down.Sql).Should().Be(Lf(FullTextSchema.DropScript));
    }

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "IncidentManager.sln")) && !Directory.Exists(Path.Combine(dir.FullName, "deploy", "sql")))
            dir = dir.Parent;
        return dir?.FullName ?? throw new InvalidOperationException("The repository root wasn't found.");
    }

    [SqlServerFact]
    public async Task The_migrations_apply_on_this_server_and_make_full_text_only_where_it_is_installed()
    {
        var cs = new SqlConnectionStringBuilder(SqlServerFactAttribute.Server) { InitialCatalog = $"casebook_fts_{Guid.NewGuid():N}" }.ConnectionString;
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlServer(cs, sql => sql.MigrationsAssembly(AppDbContextFactory.SqlServerMigrationsAssembly)).Options;
        try
        {
            await using (var db = new AppDbContext(options)) await db.Database.MigrateAsync();
            await using (var db = new AppDbContext(options))
            {
                (await db.Database.GetAppliedMigrationsAsync()).Should().Contain(m => m.EndsWith("_FullTextSearch", StringComparison.Ordinal));
                (await db.Database.GetPendingMigrationsAsync()).Should().BeEmpty();
                var catalogs = (await db.Database.SqlQueryRaw<int>(
                    $"SELECT COUNT(*) AS [Value] FROM sys.fulltext_catalogs WHERE name = N'{FullTextSchema.Catalog}'").ToListAsync()).Single();
                catalogs.Should().Be(SqlServerFullTextFactAttribute.Installed ? 1 : 0);
            }
            var status = await new SqlFullTextSearch(new TestDbContextFactory(options), new FullTextStatusCache(), _clock).RefreshAsync();
            if (SqlServerFullTextFactAttribute.Installed) status.Mode.Should().NotBe(FullTextMode.NotCreated);
            else status.Mode.Should().Be(FullTextMode.NotInstalled);

            // Down and up again: the drop and the create run cleanly a second time (neither inside a transaction).
            await using (var db = new AppDbContext(options))
            {
                var applied = (await db.Database.GetAppliedMigrationsAsync()).ToList();
                var before = applied[applied.FindIndex(m => m.EndsWith("_FullTextSearch", StringComparison.Ordinal)) - 1];
                await db.GetService<IMigrator>().MigrateAsync(before);
            }
            await using (var db = new AppDbContext(options)) await db.Database.MigrateAsync();
        }
        finally
        {
            await using var db = new AppDbContext(options);
            await db.Database.EnsureDeletedAsync();
        }
    }

    // --- The full-text path: only on a server with Full-Text Search ---

    // The indexes made and filled: the app's own script, then the check until it says Ready.
    private async Task<SqlFullTextSearch> IndexedAsync()
    {
        await using (var db = _db!.NewContext()) await db.Database.ExecuteSqlRawAsync(FullTextSchema.Script);
        var search = Real();
        var deadline = DateTime.UtcNow.AddMinutes(2);
        FullTextStatus status;
        while ((status = await search.RefreshAsync()).Mode != FullTextMode.Ready)
        {
            if (DateTime.UtcNow > deadline) throw new TimeoutException($"The full-text indexes weren't filled in 2 minutes: {status.Mode} {status.Detail}");
            await Task.Delay(500);
        }
        return search;
    }

    [SqlServerFullTextFact]
    public async Task With_full_text_a_word_finds_the_words_that_start_with_it()
    {
        Use(TestDatabase.SqlServer);
        var search = await IndexedAsync();
        (await search.StatusAsync()).Label.Should().Be("Search: full-text (SQL Server)");

        (await Find(search).FindAsync("lsa")).Entries.Should().Contain(e => e.Text.Contains("LSASS"), "a prefix of LSASS");
        (await Find(search).FindAsync("sass")).Entries.Should().NotContain(e => e.Text.Contains("LSASS"), "not the middle of a word");
        (await Find(search).FindAsync("salsa")).Entries.Should().ContainSingle(e => e.Why != null && e.Why.Contains("salsa"), "a whole word in the rationale");
        (await Find(search).FindAsync("lateral movement")).Cases.Should().ContainSingle(c => c.Id == _alpha, "two words, each a prefix");
        (await Find(search).FindAsync("in:notes psex")).Notes.Should().ContainSingle();
        (await Find(search).FindAsync("lsass")).Evidence.Should().ContainSingle(x => x.FileName == "lsass_dump.dmp");
        (await Find(search).FindAsync("krbtgt")).Tasks.Should().ContainSingle();
        // An indicator doesn't use it: matched as it's written, inside the text.
        var ip = await Find(search).FindAsync("198.51.100.7");
        ip.ReadAs.Should().Be(FindReadAs.Indicator);
        ip.Entries.Should().ContainSingle(e => e.Text.Contains("198.51.100.7"));
        (await Cases(search).ListAsync(new CaseFilter { Search = "lsa", IncludeClosed = true })).Items.Should().ContainSingle(c => c.Id == _alpha);

        // Operators typed as words, quotes and stars: no error, and nothing fell back.
        foreach (var q in Queries) await Find(search).FindAsync(q);
        (await search.StatusAsync()).Fallbacks.Should().Be(0);

        // Written after the index: searchable within seconds (change tracking), not at the next rebuild.
        await using (var db = _db!.NewContext())
        {
            db.Notes.Add(new AnalystNote { CaseId = _alpha, Body = "Zerologon attempt blocked", CreatedBy = "robin", CreatedAtUtc = Now });
            await db.SaveChangesAsync();
        }
        var until = DateTime.UtcNow.AddSeconds(30);
        while ((await Find(search).FindAsync("in:notes zerolog")).Notes.Count == 0 && DateTime.UtcNow < until) await Task.Delay(500);
        (await Find(search).FindAsync("in:notes zerolog")).Notes.Should().ContainSingle();
    }

    // CAP-22 review (F2): SQL Server's English word breaker keeps words joined by _ or - as one token (lsass_dump.dmp,
    // svc_backup, e-mail). Evidence file names are no longer indexed, so part of one still finds it; in the free text it's
    // the documented limit of searching by word, and Search:Mode Substring is the way round it.
    [SqlServerFullTextFact]
    public async Task Joined_words_by_word_and_with_search_mode_substring()
    {
        Use(TestDatabase.SqlServer);
        await using (var db = _db!.NewContext())
        {
            db.Notes.Add(new AnalystNote { CaseId = _alpha, Body = "The svc_backup account was added to Domain Admins", CreatedBy = "robin", CreatedAtUtc = Now });
            db.Notes.Add(new AnalystNote { CaseId = _alpha, Body = "A phishing e-mail from the CFO's lookalike domain", CreatedBy = "robin", CreatedAtUtc = Now });
            await db.SaveChangesAsync();
        }
        var search = await IndexedAsync();

        (await Find(search).FindAsync("dump")).Evidence.Should().ContainSingle(x => x.FileName == "lsass_dump.dmp", "a file name is a substring match");
        (await Find(search).FindAsync("dmp")).Evidence.Should().ContainSingle();
        (await Find(search).FindAsync("in:notes svc_backup")).Notes.Should().ContainSingle("the whole token, by word");
        (await Find(search).FindAsync("in:notes e-mail")).Notes.Should().ContainSingle();
        (await Find(search).FindAsync("in:notes svc")).Notes.Should().ContainSingle("the token's start is a prefix of it");
        // The documented limit (find.md, OPERATIONS §9): by word, the part after the _ or - isn't a word of its own.
        (await Find(search).FindAsync("in:notes backup")).Notes.Should().BeEmpty();
        (await Find(search).FindAsync("in:notes mail")).Notes.Should().BeEmpty();

        // Search:Mode Substring: the same indexes, every column matched anywhere in the text.
        var config = new Microsoft.Extensions.Configuration.ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { [SqlFullTextSearch.ModeKey] = "Substring" }).Build();
        var off = new SqlFullTextSearch(_db!.Factory(), new FullTextStatusCache(), _clock, config: config);
        var status = await off.StatusAsync();
        status.TurnedOff.Should().BeTrue();
        status.Mode.Should().Be(FullTextMode.Ready);
        status.Any.Should().BeFalse();
        (await Find(off).FindAsync("in:notes backup")).Notes.Should().ContainSingle();
        (await Find(off).FindAsync("in:notes mail")).Notes.Should().ContainSingle();
        (await Find(off).FindAsync("sass")).Entries.Should().Contain(e => e.Text.Contains("LSASS"), "part of a word, as without full-text");
        foreach (var q in Queries)
            Shown(await Find(off).FindAsync(q)).Should().Be(Shown(await Find(null).FindAsync(q)), q);
    }

    // CAP-22 review (C21): a fallback while a check is in flight leaves the status stale, whatever the check finds after.
    [Fact]
    public void A_check_that_began_before_a_fallback_does_not_mark_the_status_fresh()
    {
        var cache = new FullTextStatusCache();
        var ready = SqlFullTextSearch.Classify(FullTextSchema.Columns.Select(c => (c.Table.Name, c.Column, true, 0)), Now);
        var began = cache.Generation;
        cache.MarkStale();   // the fallback, during the check
        cache.Keep(ready, Now + SqlFullTextSearch.ReadyFor, began);
        cache.Current.Should().BeSameAs(ready);
        cache.StaleAtUtc.Should().Be(DateTimeOffset.MinValue, "the next search checks again");

        cache.Keep(ready, Now + SqlFullTextSearch.ReadyFor, cache.Generation);
        cache.StaleAtUtc.Should().Be(Now + SqlFullTextSearch.ReadyFor, "a check that began after it is kept as fresh");
    }

    /// <summary>Cancels the caller's token as the check's query starts, as a person leaving the page would.</summary>
    private sealed class CancelOnQuery(CancellationTokenSource cts) : Microsoft.EntityFrameworkCore.Diagnostics.DbCommandInterceptor
    {
        public override ValueTask<Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<System.Data.Common.DbDataReader>> ReaderExecutingAsync(
            System.Data.Common.DbCommand command, Microsoft.EntityFrameworkCore.Diagnostics.CommandEventData eventData,
            Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<System.Data.Common.DbDataReader> result, CancellationToken cancellationToken = default)
        {
            if (command.CommandText.Contains("IsFullTextInstalled", StringComparison.Ordinal)) cts.Cancel();
            return base.ReaderExecutingAsync(command, eventData, result, cancellationToken);
        }
    }

    // CAP-22 review: the caller cancelling during the check isn't the database failing, so nothing is kept as Unknown.
    [SqlServerFact]
    public async Task A_caller_cancelling_during_the_check_is_not_kept_as_unknown()
    {
        Use(TestDatabase.SqlServer);
        using var cts = new CancellationTokenSource();
        var options = new DbContextOptionsBuilder<AppDbContext>().UseSqlServer(_db!.Connection.ConnectionString)
            .AddInterceptors(new CancelOnQuery(cts)).Options;
        var cache = new FullTextStatusCache();
        var search = new SqlFullTextSearch(new TestDbContextFactory(options), cache, _clock);

        var check = () => search.StatusAsync(cts.Token);
        await check.Should().ThrowAsync<Exception>();
        cts.IsCancellationRequested.Should().BeTrue();
        cache.Current.Should().BeNull("nothing was found, so nothing is kept");
        (await Real(cache).StatusAsync()).Mode.Should().NotBe(FullTextMode.Unknown, "the next search checks");
    }

    [SqlServerFullTextFact]
    public async Task The_Diagnostics_action_creates_what_is_missing_and_is_recorded()
    {
        Use(TestDatabase.SqlServer);
        var audit = new RecordingAudit();
        var admin = new FullTextAdminService(Real(), _user, audit);
        (await admin.StatusAsync()).Mode.Should().Be(FullTextMode.NotCreated);
        var after = await admin.CreateIndexesAsync();
        after.Mode.Should().BeOneOf(FullTextMode.Ready, FullTextMode.Populating, FullTextMode.Partial);
        audit.Entries.Should().ContainSingle(e => e.Contains(FullTextAdminService.AuditEntity));
        await admin.CreateIndexesAsync();   // again: nothing missing, no error
    }

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task The_Diagnostics_action_is_Administer_s_and_refused_where_full_text_can_t_be(string provider)
    {
        Use(provider);
        var analyst = new TestCurrentUser { RoleSet = [AppRole.Analyst] };
        var refused = () => new FullTextAdminService(Real(), analyst, new RecordingAudit()).CreateIndexesAsync();
        await refused.Should().ThrowAsync<IncidentManager.Application.Security.ForbiddenException>();

        if (provider == TestDatabase.SqlServer && SqlServerFullTextFactAttribute.Installed) return;
        var audit = new RecordingAudit();
        var create = () => new FullTextAdminService(Real(), _user, audit).CreateIndexesAsync();
        (await create.Should().ThrowAsync<InvalidOperationException>()).Which.Message
            .Should().Contain(provider == TestDatabase.Sqlite ? "SQL Server feature" : "doesn't have Full-Text Search");
        audit.Entries.Should().BeEmpty("nothing was done");
    }

    private sealed class RecordingAudit : IAuditWriter
    {
        public List<string> Entries { get; } = [];
        public Task RecordAsync(AuditAction action, string entityType, string? entityId, string? caseNumber, string summary,
            CancellationToken ct = default)
        {
            Entries.Add($"{action} {entityType}: {summary}");
            return Task.CompletedTask;
        }
    }
}
