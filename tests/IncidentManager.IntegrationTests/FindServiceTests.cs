using System.Globalization;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Search;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// RD-20: Find. Typed results across entities, cases, record entries (closing briefs included), tasks, evidence names and,
/// on request, working notes; it says how it read the query; the grammar is literal; need-to-know scoped throughout.
/// Each runs on SQLite and, when a server is configured, on SQL Server (<see cref="TestDatabase"/>).
/// </summary>
public sealed class FindServiceTests : IDisposable
{
    private TestDatabase? _db;
    private static readonly DateTimeOffset Now = new(2026, 10, 4, 12, 0, 0, TimeSpan.Zero);
    private readonly TestCurrentUser _me = new() { UserId = "analyst1", DisplayName = "Analyst One", RoleSet = [AppRole.Analyst] };
    private Guid _alpha, _beta, _decisionId;

    private void Use(string provider, params Microsoft.EntityFrameworkCore.Diagnostics.IInterceptor[] interceptors)
    {
        _db = TestDatabase.Open(provider, interceptors);
        Seed();
    }

    private AppDbContext NewContext() => _db!.NewContext();

    private FindService NewFind() => new(_db!.Factory(), _me, new Directory());

    private static DateTimeOffset H(int hoursFromNow) => Now.AddHours(hoursFromNow);

    private void Seed()
    {
        using var db = NewContext();
        // Alpha (open): the IP is malicious here, an adversary step names it, a decision, a task and a working note.
        var a = Case.Open(2026, 1, "Phishing_Wave", "Phishing wave", Classification.Breach, Severity.High, CaseOrigin.InternalDetection, "robin", H(-200));
        a.AffectedStates = "NY, NJ";
        a.Entities.Add(new CaseEntity { Type = EntityType.IpAddress, Value = "203.0.113.66", Disposition = EntityDisposition.Malicious, CreatedBy = "robin", CreatedAtUtc = H(-190) });
        a.TimelineEntries.Add(new TimelineEntry { Kind = TimelineKind.Event, Type = TimelineEntryType.Detection, OccurredAtUtc = H(-180),
            Description = "Sign-in to the mailbox from 203.0.113.66 using the captured credentials.", CreatedBy = "robin", CreatedAtUtc = H(-180) });
        var decision = new TimelineEntry { Kind = TimelineKind.Investigation, Type = TimelineEntryType.Decision, OccurredAtUtc = H(-170),
            Description = "Force a password reset for every clicked account", Rationale = "Credentials were captured", CreatedBy = "robin", CreatedAtUtc = H(-170) };
        a.TimelineEntries.Add(decision);
        a.ActionItems.Add(new ActionItem { Title = "Block 203.0.113.66 at the proxy", Owner = "analyst1", DueAtUtc = H(5), CreatedBy = "robin", CreatedAtUtc = H(-170) });
        a.Notes.Add(new AnalystNote { Body = "Hunch: 203.0.113.66 is a VPN exit", CreatedBy = "analyst1", CreatedAtUtc = H(-160) });
        a.Evidence.Add(new Evidence { OriginalFileName = "proxy-203.0.113.66.csv", Sha256 = new string('a', 64), StoragePath = "x", CreatedBy = "robin", CreatedAtUtc = H(-150) });
        _alpha = a.Id;
        _decisionId = decision.Id;

        // Beta (closed with a conclusion): the same IP judged benign, the conclusion names it.
        var b = Case.Open(2025, 31, "Anomalous_VPN", "Anomalous VPN", Classification.AdverseEvent, Severity.Low, CaseOrigin.InternalDetection, "lee", H(-900));
        b.Entities.Add(new CaseEntity { Type = EntityType.IpAddress, Value = "203.0.113.66", Disposition = EntityDisposition.Benign, CreatedBy = "lee", CreatedAtUtc = H(-890) });
        b.ReviseBrief("VPN alert", "VPN egress change at the provider; 203.0.113.66 confirmed as a provider address.", null, null, null, "lee", H(-800));
        b.ChangePhase(CasePhase.Closed, "done", "lee", H(-800), outcomeKey: "benign");
        _beta = b.Id;

        // Gamma: restricted and not mine. Nothing from it may surface.
        var g = Case.Open(2026, 2, "Secret", "Secret matter", Classification.Incident, Severity.Critical, CaseOrigin.InternalDetection, "ivy", H(-100));
        g.IsRestricted = true;
        g.Entities.Add(new CaseEntity { Type = EntityType.IpAddress, Value = "203.0.113.66", Disposition = EntityDisposition.Malicious, CreatedBy = "ivy", CreatedAtUtc = H(-90) });
        g.TimelineEntries.Add(new TimelineEntry { Kind = TimelineKind.Investigation, Type = TimelineEntryType.Decision, OccurredAtUtc = H(-80),
            Description = "password reset for the board", CreatedBy = "ivy", CreatedAtUtc = H(-80) });

        // An exercise: left out unless asked.
        var x = Case.Open(2026, 3, "Tabletop", "Tabletop", Classification.Incident, Severity.Low, CaseOrigin.InternalDetection, "robin", H(-50), isExercise: true);
        x.Entities.Add(new CaseEntity { Type = EntityType.IpAddress, Value = "203.0.113.66", CreatedBy = "robin", CreatedAtUtc = H(-50) });

        db.Cases.AddRange(a, b, g, x);
        db.SaveChanges();
    }

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task An_indicator_is_read_as_one_and_found_across_every_kind_on_cases_you_can_see(string provider)
    {
        Use(provider);
        var r = await NewFind().FindAsync("203.0.113[.]66");

        r.ReadAs.Should().Be(FindReadAs.Indicator);
        r.Reading.Should().Be("an IP address");

        // The entity first, with its verdict on each visible case (not the restricted one, not the exercise).
        r.Entities.Should().ContainSingle();
        r.Entities[0].Cases.Select(c => (c.CaseId, c.Verdict)).Should().BeEquivalentTo(
            [(_alpha, EntityDisposition.Malicious), (_beta, EntityDisposition.Benign)]);

        r.Cases.Select(c => c.Id).Should().BeEquivalentTo([_alpha, _beta]);
        r.Cases.Single(c => c.Id == _beta).ClosingLine.Should().Contain("provider address");

        // Record entries quote the record, including the closed case's conclusion.
        r.Entries.Should().HaveCount(2);
        r.Entries.Should().ContainSingle(e => e.IsClosingBrief && e.CaseId == _beta);
        r.Entries.Should().ContainSingle(e => !e.IsClosingBrief && e.Kind == TimelineKind.Event && e.Text.Contains("captured credentials"));

        r.Tasks.Should().ContainSingle(t => t.Title.StartsWith("Block"));
        r.Evidence.Should().ContainSingle(e => e.FileName == "proxy-203.0.113.66.csv");

        // Working notes are opt-in.
        r.Notes.Should().BeEmpty();
        r.Counts.Should().NotContainKey(FindKind.Notes);
        var withNotes = await NewFind().FindAsync("203.0.113.66 in:notes");
        withNotes.Notes.Should().ContainSingle(n => n.Text.Contains("VPN exit"));

        // Exercises only when asked.
        (await NewFind().FindAsync("203.0.113.66 exercises:yes")).Entities[0].Cases.Should().HaveCount(3);
    }

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task Plain_question_filters_narrow_the_record_and_are_said_back(string provider)
    {
        Use(provider);
        var r = await NewFind().FindAsync("type:decision \"password reset\" after:2026-01-01");

        r.ReadAs.Should().Be(FindReadAs.Words);
        r.Filters.Should().Contain(["decisions", "from 1 Jan 2026"]);
        r.Entries.Should().ContainSingle().Which.Id.Should().Be(_decisionId);   // the restricted case's decision never appears
        r.Cases.Should().BeEmpty();   // an entry-type filter is about entries, not cases or entities
        r.Counts.Should().NotContainKey(FindKind.Entities);

        var closed = await NewFind().FindAsync("entity:203.0.113.66 status:closed");
        closed.Cases.Should().ContainSingle().Which.Id.Should().Be(_beta);

        var ny = await NewFind().FindAsync("class:breach state:NY");
        ny.ReadAs.Should().Be(FindReadAs.Nothing);
        ny.Cases.Should().ContainSingle().Which.Id.Should().Be(_alpha);
        ny.Filters.Should().Contain(["Breaches", "residents of NY affected"]);

        var odd = await NewFind().FindAsync("status:pending reset");
        odd.Filters.Should().ContainSingle(f => f.StartsWith("not understood: status:pending"));
    }

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task A_person_or_a_case_number_reads_as_one(string provider)
    {
        Use(provider);
        var robin = await NewFind().FindAsync("robin");
        robin.ReadAs.Should().Be(FindReadAs.Person);
        robin.Reading.Should().Be("a person: Robin Reyes");
        robin.Entries.Should().HaveCount(2).And.OnlyContain(e => e.CaseId == _alpha);

        var mine = await NewFind().FindAsync("owner:me");
        mine.Tasks.Should().ContainSingle(t => t.Owner == "analyst1");

        var number = await NewFind().FindAsync("2025-31");
        number.ReadAs.Should().Be(FindReadAs.CaseNumber);
        number.Cases.Should().ContainSingle().Which.Id.Should().Be(_beta);
    }

    [Fact]
    public void The_grammar_keeps_phrases_and_unknown_keys_as_words_and_edits_one_filter()
    {
        var q = FindQuery.Parse("\"password reset\" https://x.example/a type:handoff by:me");
        q.Terms.Should().Equal("password reset", "https://x.example/a");
        q.EntryType.Should().Be(TimelineEntryType.Handoff);
        q.By.Should().Be("me");

        FindQuery.WithFilter("reset status:open", "status", "closed").Should().Be("reset status:closed");
        FindQuery.WithFilter("reset status:open", "status", null).Should().Be("reset");
        FindQuery.WithFilter("reset jurisdiction:NY", "state", "NJ").Should().Be("reset state:NJ");
    }

    // What a person types goes to the database only as a parameter value, never as SQL text, and the LIKE wildcards
    // (% _ [) match themselves. Every command Find sends is recorded to prove it on the provider it runs on.
    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task What_is_typed_is_sent_as_a_value_never_as_SQL_and_wildcards_match_literally(string provider)
    {
        var sent = new CommandRecorder();
        Use(provider, sent);
        using (var db = NewContext())
        {
            var c = db.Cases.Single(x => x.Id == _alpha);
            db.ActionItems.Add(new ActionItem { CaseId = c.Id, Title = "Rotate 100% of the tokens", CreatedBy = "robin", CreatedAtUtc = H(-10) });
            db.ActionItems.Add(new ActionItem { CaseId = c.Id, Title = "Check the [ops] mailbox", CreatedBy = "robin", CreatedAtUtc = H(-10) });
            db.SaveChanges();
        }
        sent.Clear();

        string[] hostile =
        [
            "x'; DROP TABLE Cases; --",
            "\" OR 1=1 --",
            "') OR ('1'='1",
            "reset' UNION SELECT Body FROM Notes --",
            "type:decision by:robin' OR '1'='1",
        ];
        foreach (var q in hostile)
        {
            var r = await NewFind().FindAsync(q + " in:notes exercises:yes");
            (r.Entities.Count + r.Cases.Count + r.Entries.Count + r.Tasks.Count + r.Evidence.Count + r.Notes.Count)
                .Should().Be(0, $"nothing in the record contains {q}");
        }

        sent.Commands.Should().NotBeEmpty();
        foreach (var sql in sent.Commands)
        {
            sql.Should().NotContain("DROP TABLE").And.NotContain("UNION SELECT").And.NotContain("1=1").And.NotContain("'1'='1");
        }
        sent.Values.Should().Contain(v => v.Contains("x';"), "the words travel as parameter values");

        // The schema is untouched and the restricted case still never surfaces.
        using (var db = NewContext()) db.Cases.Count().Should().Be(4);

        // LIKE wildcards are matched as the characters they are.
        (await NewFind().FindAsync("%")).Tasks.Should().ContainSingle(t => t.Title.StartsWith("Rotate"), "not every task");
        (await NewFind().FindAsync("_")).Tasks.Should().BeEmpty();
        (await NewFind().FindAsync("100%")).Tasks.Should().ContainSingle(t => t.Title.StartsWith("Rotate"));
        (await NewFind().FindAsync("0%_")).Tasks.Should().BeEmpty();
        (await NewFind().FindAsync("[ops]")).Tasks.Should().ContainSingle(t => t.Title.Contains("[ops]"));
        (await NewFind().FindAsync("[o]ps")).Tasks.Should().BeEmpty();
    }

    // Each word is a condition in every query; a few hundred once overflowed the query translator's stack and ended the
    // server process. Past the limit the rest are left out, and Find says so.
    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task A_very_long_query_uses_the_first_words_and_says_so(string provider)
    {
        Use(provider);
        var words = string.Join(' ', Enumerable.Range(0, 2500).Select(i => "w" + i));

        var r = await NewFind().FindAsync("203.0.113.66 " + words);

        r.Query.Terms.Should().HaveCount(FindQuery.MaxTerms);
        r.Filters.Should().Contain($"only the first {FindQuery.MaxTerms} words used");
        r.Cases.Should().BeEmpty();   // every word must appear, and w0..w10 don't

        var shortOne = await NewFind().FindAsync("password reset");
        shortOne.Filters.Should().NotContain(f => f.StartsWith("only the first"));
    }

    public void Dispose() => _db?.Dispose();

    /// <summary>Records the SQL text and parameter values of every command sent.</summary>
    private sealed class CommandRecorder : Microsoft.EntityFrameworkCore.Diagnostics.DbCommandInterceptor
    {
        private readonly List<string> _commands = [], _values = [];
        private readonly Lock _gate = new();

        public IReadOnlyList<string> Commands { get { lock (_gate) return [.. _commands]; } }
        public IReadOnlyList<string> Values { get { lock (_gate) return [.. _values]; } }
        public void Clear() { lock (_gate) { _commands.Clear(); _values.Clear(); } }

        private void Record(System.Data.Common.DbCommand c)
        {
            lock (_gate)
            {
                _commands.Add(c.CommandText);
                foreach (System.Data.Common.DbParameter p in c.Parameters) _values.Add(Convert.ToString(p.Value, CultureInfo.InvariantCulture) ?? "");
            }
        }

        public override ValueTask<Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<System.Data.Common.DbDataReader>> ReaderExecutingAsync(
            System.Data.Common.DbCommand command, Microsoft.EntityFrameworkCore.Diagnostics.CommandEventData eventData,
            Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<System.Data.Common.DbDataReader> result, CancellationToken cancellationToken = default)
        {
            Record(command);
            return base.ReaderExecutingAsync(command, eventData, result, cancellationToken);
        }
    }

    private sealed class Directory : IUserDirectory
    {
        private readonly Dictionary<string, UserSummary> _u = new(StringComparer.OrdinalIgnoreCase)
        {
            ["analyst1"] = new("analyst1", "Analyst One", "analyst1@contoso.example", null, ""),
            ["robin"] = new("robin", "Robin Reyes", "rreyes@contoso.example", null, ""),
            ["lee"] = new("lee", "Lee Park", "lpark@contoso.example", null, ""),
        };
        public Task TouchAsync(string id, string n, string? u, string? e, string r, CancellationToken ct = default) => Task.CompletedTask;
        public IReadOnlyList<UserSummary> All() => _u.Values.ToList();
        public UserSummary? Resolve(string id) => _u.GetValueOrDefault(id);
        public string DisplayFor(string? id) => id is not null && _u.TryGetValue(id, out var s) ? s.DisplayName : (id ?? "—");
        public string? EmailFor(string id) => null;
        public void Invalidate() { }
    }
}
