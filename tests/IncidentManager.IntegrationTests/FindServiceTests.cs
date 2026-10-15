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
    public async Task A_closing_brief_is_found_and_quoted_as_it_stood_at_closure_in_plain_text(string provider /* BUG-527 */)
    {
        Use(provider);
        Guid deltaId;
        using (var db = NewContext())
        {
            var d = Case.Open(2025, 40, "Proxy_Drift", "Proxy drift", Classification.AdverseEvent, Severity.Low, CaseOrigin.InternalDetection, "lee", H(-760));
            d.ReviseBrief("Proxy drift", "The **egress** change was _benign_.", null, null, null, "lee", H(-700));
            d.ChangePhase(CasePhase.Closed, "done", "lee", H(-700), outcomeKey: "benign");
            d.ReviseBrief("Proxy drift", "Later wording: rotated keys.", null, null, null, "lee", H(-600));   // after closure
            db.Cases.Add(d);
            db.SaveChanges();
            deltaId = d.Id;
        }

        var r = await NewFind().FindAsync("egress benign");
        r.Entries.Should().ContainSingle(e => e.IsClosingBrief && e.CaseId == deltaId)
            .Which.Text.Should().Be("The egress change was benign.");
        (await NewFind().FindAsync("status:closed")).Cases.Should().ContainSingle(c => c.Id == deltaId)
            .Which.ClosingLine.Should().Be("The egress change was benign.");

        // The revision made since isn't the conclusion, so it isn't found as one.
        (await NewFind().FindAsync("rotated keys")).Entries.Should().NotContain(e => e.IsClosingBrief && e.CaseId == deltaId);
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

    [Theory]
    [InlineData("2026-01-31", FindReadAs.Words)]
    [InlineData("CE-2026-01-31", FindReadAs.CaseNumber)]
    [InlineData("2026-01", FindReadAs.CaseNumber)]
    [InlineData("2026-01_Phishing_Wave", FindReadAs.CaseNumber)]
    public void A_bare_date_is_not_read_as_a_case_number(string text, FindReadAs expected /* BUG-56 */) =>
        FindQuery.ReadShape(text).As.Should().Be(expected);

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

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task A_task_owned_by_any_of_a_persons_identifiers_is_theirs(string provider /* WF-01 */)
    {
        Use(provider);
        using (var db = NewContext())
        {
            db.ActionItems.Add(new ActionItem { CaseId = _alpha, Title = "Rotate the VPN secret", Owner = " RREYES@contoso.example ", CreatedBy = "robin", CreatedAtUtc = H(-10) });
            db.ActionItems.Add(new ActionItem { CaseId = _alpha, Title = "Brief the board", Owner = "Analyst One", CreatedBy = "robin", CreatedAtUtc = H(-10) });
            db.SaveChanges();
        }

        (await NewFind().FindAsync("owner:robin")).Tasks.Select(t => t.Title).Should().Equal("Rotate the VPN secret");
        (await NewFind().FindAsync("owner:me")).Tasks.Select(t => t.Title).Should().BeEquivalentTo(["Block 203.0.113.66 at the proxy", "Brief the board"]);
    }

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task A_cve_id_shaped_like_a_case_number_is_searched_for_in_the_record(string provider /* WF-02 */)
    {
        Use(provider);
        using (var db = NewContext())
        {
            db.TimelineEntries.Add(new TimelineEntry { CaseId = _alpha, Kind = TimelineKind.Investigation, Type = TimelineEntryType.Note, OccurredAtUtc = H(-5),
                Description = "The appliance is exposed to CVE-2024-3094.", CreatedBy = "robin", CreatedAtUtc = H(-5) });
            db.SaveChanges();
        }

        var r = await NewFind().FindAsync("CVE-2024-3094");

        r.ReadAs.Should().Be(FindReadAs.Words);
        r.Entries.Should().ContainSingle(e => e.Text.Contains("CVE-2024-3094"));
        (await NewFind().FindAsync("2026-01")).ReadAs.Should().Be(FindReadAs.CaseNumber, "a visible case number holds it");
    }

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task An_indicator_is_matched_in_the_form_entities_are_stored_in(string provider /* WF-03 */)
    {
        Use(provider);
        using (var db = NewContext())
        {
            db.CaseEntities.Add(new CaseEntity { CaseId = _alpha, Type = EntityType.IpAddress, Value = "2001:db8::1", CreatedBy = "robin", CreatedAtUtc = H(-5) });
            db.CaseEntities.Add(new CaseEntity { CaseId = _alpha, Type = EntityType.Domain, Value = "evil.example", CreatedBy = "robin", CreatedAtUtc = H(-5) });
            db.SaveChanges();
        }

        (await NewFind().FindAsync("2001:0db8:0000:0000:0000:0000:0000:0001")).Entities.Should().ContainSingle(e => e.Value == "2001:db8::1");
        (await NewFind().FindAsync("evil.example.")).Entities.Should().ContainSingle(e => e.Value == "evil.example");
        (await NewFind().FindAsync("entity:evil[.]example.")).Cases.Select(c => c.Id).Should().Equal(_alpha);
    }

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task Owner_with_an_entry_filter_is_said_back_not_shown_as_applied(string provider /* WF-04 */)
    {
        Use(provider);
        var r = await NewFind().FindAsync("owner:me type:decision");

        r.Filters.Should().Contain(f => f.StartsWith("not understood: owner:me")).And.NotContain(f => f.StartsWith("tasks of"));
        r.Entries.Should().ContainSingle(e => e.Id == _decisionId);
    }

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task Archived_cases_arent_open_dates_apply_to_entities_and_recorded_by_is_the_first_author(string provider /* WF-07..10 */)
    {
        Use(provider);
        using (var db = NewContext())
        {
            // Robin's decision, then corrected by me: a new current version superseding Robin's.
            var original = db.TimelineEntries.Single(e => e.Id == _decisionId);
            original.IsCurrent = false;
            db.TimelineEntries.Add(new TimelineEntry { CaseId = _alpha, Kind = TimelineKind.Investigation, Type = TimelineEntryType.Decision,
                OccurredAtUtc = original.OccurredAtUtc, Description = "Force a password reset for every clicked account (all regions)",
                Rationale = original.Rationale, Version = 2, SupersedesEntryId = original.Id, CreatedBy = "analyst1", CreatedAtUtc = H(-1) });
            db.SaveChanges();
        }

        // WF-09: who recorded it is who first did.
        (await NewFind().FindAsync("by:robin type:decision")).Entries.Should().ContainSingle(e => e.Text.Contains("all regions"));
        (await NewFind().FindAsync("by:me type:decision")).Entries.Should().BeEmpty("I only corrected it");

        // WF-08: dates are when the entity was added (alpha's on 26 Sep, beta's in August).
        var recent = await NewFind().FindAsync("203.0.113.66 after:2026-09-20");
        recent.Entities.Should().ContainSingle().Which.Cases.Select(c => c.CaseId).Should().Equal(_alpha);

        // WF-10: quoted, a sign-in name is searched as a word.
        (await NewFind().FindAsync("\"robin\"")).ReadAs.Should().Be(FindReadAs.Words);

        // WF-07: an archived case isn't open, and is labelled.
        using (var db = NewContext())
        {
            db.Cases.Single(c => c.Id == _alpha).IsArchived = true;
            db.SaveChanges();
        }
        (await NewFind().FindAsync("phishing status:open")).Cases.Should().BeEmpty();
        (await NewFind().FindAsync("phishing")).Cases.Should().ContainSingle(c => c.Id == _alpha).Which.IsArchived.Should().BeTrue();
    }

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task Entities_are_counted_in_full_and_the_most_widespread_listed(string provider /* WF-06 */)
    {
        Use(provider);
        using (var db = NewContext())
        {
            foreach (var (caseId, value) in new[] { (_alpha, "zzz1.example"), (_beta, "ZZZ1.example"), (_alpha, "zzz2.example"), (_alpha, "zzz3.example") })
                db.CaseEntities.Add(new CaseEntity { CaseId = caseId, Type = EntityType.Domain, Value = value, CreatedBy = "robin", CreatedAtUtc = H(-5) });
            db.ActionItems.Add(new ActionItem { CaseId = _alpha, Title = "zzz later", DueAtUtc = H(48), CreatedBy = "robin", CreatedAtUtc = H(-5) });
            db.ActionItems.Add(new ActionItem { CaseId = _alpha, Title = "zzz sooner", DueAtUtc = H(2), CreatedBy = "robin", CreatedAtUtc = H(-5) });
            db.ActionItems.Add(new ActionItem { CaseId = _alpha, Title = "zzz undated", CreatedBy = "robin", CreatedAtUtc = H(-5) });
            db.SaveChanges();
        }

        var r = await NewFind().FindAsync("zzz", limit: 2);

        r.Counts[FindKind.Entities].Should().Be(3);
        r.Entities.Should().HaveCount(2);
        r.Entities[0].Value.Should().BeEquivalentTo("zzz1.example");
        r.Entities[0].Cases.Should().HaveCount(2);
        r.Counts[FindKind.Tasks].Should().Be(3);
        r.Tasks.Select(t => t.Title).Should().Equal("zzz sooner", "zzz later");
    }

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task An_entity_is_found_where_it_is_tagged_by_its_label(string provider /* WF-83, WF-85, WF-86, WF-90 */)
    {
        Use(provider);
        Guid noteId;
        using (var db = NewContext())
        {
            var ip = db.CaseEntities.Single(e => e.CaseId == _alpha && e.Value == "203.0.113.66");
            ip.Label = "Foreign ASN egress";
            var tag = $"[Foreign ASN egress](entity:{ip.Id})";
            db.TimelineEntries.Add(new TimelineEntry { CaseId = _alpha, Kind = TimelineKind.Investigation, Type = TimelineEntryType.Note,
                OccurredAtUtc = H(-20), Description = $"Egress seen from {tag} at 02:10", CreatedBy = "robin", CreatedAtUtc = H(-20) });
            db.ActionItems.Add(new ActionItem { CaseId = _alpha, Title = "Ask the ISP about it", AboutRef = $"entity:{ip.Id}",
                CreatedBy = "robin", CreatedAtUtc = H(-20) });
            // A note written by robin and edited by me: listed under robin.
            var first = new AnalystNote { CaseId = _alpha, Body = $"Probably {tag}", CreatedBy = "robin", CreatedAtUtc = H(-19), IsCurrent = false };
            db.Notes.Add(first);
            var edit = new AnalystNote { CaseId = _alpha, Body = $"Probably {tag}, confirmed", CreatedBy = "analyst1", CreatedAtUtc = H(-18),
                Version = 2, SupersedesNoteId = first.Id };
            db.Notes.Add(edit);
            noteId = edit.Id;
            db.Evidence.Add(new Evidence { CaseId = _alpha, OriginalFileName = "hashes.txt", Description = "MD5 9e107d9d372bb6826bd81d3542a419d6",
                Sha256 = new string('b', 64), StoragePath = "y", CreatedBy = "robin", CreatedAtUtc = H(-10) });
            db.SaveChanges();
        }

        var r = await NewFind().FindAsync("entity:203.0.113.66 in:notes");
        r.Entries.Should().Contain(e => e.Text.Contains("Egress seen"), "the entry tags it by its label");
        r.Tasks.Should().Contain(t => t.Title == "Ask the ISP about it", "the task is about it");
        r.Notes.Should().ContainSingle(n => n.Id == noteId).Which.By.Should().Be("Robin Reyes");
        (await NewFind().FindAsync("203.0.113.66")).Entries.Should().Contain(e => e.Text.Contains("Egress seen"));

        // WF-90: an MD5 is looked for in evidence descriptions.
        (await NewFind().FindAsync("9e107d9d372bb6826bd81d3542a419d6")).Evidence.Should().ContainSingle(e => e.FileName == "hashes.txt");

        // WF-85: the entity's case list marks an archived case.
        using (var db = NewContext())
        {
            db.Cases.Single(c => c.Id == _alpha).IsArchived = true;
            db.SaveChanges();
        }
        (await NewFind().FindAsync("203.0.113.66")).Entities.Single().Cases.Should().Contain(c => c.CaseId == _alpha && c.IsArchived);
    }

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task The_entity_filter_narrows_and_words_must_still_appear(string provider /* BUG-564 */)
    {
        Use(provider);
        Guid deltaId;
        using (var db = NewContext())
        {
            var ip = db.CaseEntities.Single(e => e.CaseId == _alpha && e.Value == "203.0.113.66");
            ip.Label = "Foreign ASN egress";
            var tag = $"[Foreign ASN egress](entity:{ip.Id})";
            db.TimelineEntries.Add(new TimelineEntry { CaseId = _alpha, Kind = TimelineKind.Investigation, Type = TimelineEntryType.Note,
                OccurredAtUtc = H(-20), Description = $"Seen from {tag} at 02:10", CreatedBy = "robin", CreatedAtUtc = H(-20) });
            db.ActionItems.Add(new ActionItem { CaseId = _alpha, Title = "Ask the ISP about it", AboutRef = $"entity:{ip.Id}",
                CreatedBy = "robin", CreatedAtUtc = H(-20) });
            db.Notes.Add(new AnalystNote { CaseId = _alpha, Body = $"Probably {tag}", CreatedBy = "analyst1", CreatedAtUtc = H(-19) });
            // Another indicator on the same case, tagged only by its label.
            var dom = new CaseEntity { CaseId = _alpha, Type = EntityType.Domain, Value = "evil.example.com", Label = "C2 host",
                CreatedBy = "robin", CreatedAtUtc = H(-18) };
            db.CaseEntities.Add(dom);
            db.TimelineEntries.Add(new TimelineEntry { CaseId = _alpha, Kind = TimelineKind.Investigation, Type = TimelineEntryType.Note,
                OccurredAtUtc = H(-17), Description = $"Beacon from 203.0.113.66 to [C2 host](entity:{dom.Id})", CreatedBy = "robin", CreatedAtUtc = H(-17) });
            db.ActionItems.Add(new ActionItem { CaseId = _alpha, Title = "Sinkhole it for 203.0.113.66", AboutRef = $"entity:{dom.Id}",
                CreatedBy = "robin", CreatedAtUtc = H(-17) });
            // A closed case whose closing brief tags the IP by its label.
            var d = Case.Open(2025, 41, "Egress_Review", "Egress review", Classification.AdverseEvent, Severity.Low, CaseOrigin.InternalDetection, "lee", H(-760));
            var dip = new CaseEntity { Type = EntityType.IpAddress, Value = "203.0.113.66", Label = "Provider", CreatedBy = "lee", CreatedAtUtc = H(-750) };
            d.Entities.Add(dip);
            d.ReviseBrief("Egress review", $"[Provider](entity:{dip.Id}) traffic confirmed.", null, null, null, "lee", H(-700));
            d.ChangePhase(CasePhase.Closed, "done", "lee", H(-700), outcomeKey: "benign");
            db.Cases.Add(d);
            db.SaveChanges();
            deltaId = d.Id;
        }

        // The filter alone still lists what tags the entity (WF-83).
        var only = await NewFind().FindAsync("entity:203.0.113.66 in:notes");
        only.Entries.Should().Contain(e => e.Text.Contains("Seen from"));
        only.Tasks.Should().Contain(t => t.Title == "Ask the ISP about it");
        only.Notes.Should().Contain(n => n.Text.Contains("Probably"));

        // A word that appears nowhere: tagging the entity doesn't make the word appear.
        var absent = await NewFind().FindAsync("entity:203.0.113.66 ransomware in:notes");
        absent.Entries.Should().BeEmpty();
        absent.Tasks.Should().BeEmpty();
        absent.Notes.Should().BeEmpty();

        // A word that does appear (here in the tag's visible label) is found.
        var present = await NewFind().FindAsync("entity:203.0.113.66 isp in:notes");
        present.Tasks.Should().ContainSingle(t => t.Title == "Ask the ISP about it");
        present.Entries.Should().BeEmpty();
        // A closing brief: the word in its tag's label (the tag counts for the filter, the label for the word).
        var provider2 = await NewFind().FindAsync("entity:203.0.113.66 provider");
        provider2.Entries.Should().Contain(e => e.IsClosingBrief && e.CaseId == deltaId);
        provider2.Entries.Should().NotContain(e => e.Text.Contains("Seen from"));

        // Another indicator under the filter is found by its own tags, not the filter's.
        var ioc = await NewFind().FindAsync("entity:203.0.113.66 evil.example.com");
        ioc.ReadAs.Should().Be(FindReadAs.Indicator);
        ioc.Entries.Should().ContainSingle().Which.Text.Should().StartWith("Beacon from");
        ioc.Tasks.Should().ContainSingle().Which.Title.Should().Be("Sinkhole it for 203.0.113.66");

        // The bare indicator still finds what tags it.
        (await NewFind().FindAsync("evil.example.com")).Entries.Should().ContainSingle(e => e.Text.StartsWith("Beacon from"));
    }

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task Sign_in_names_owner_and_hidden_link_text(string provider /* WF-84, WF-87, WF-89 */)
    {
        Use(provider);
        using (var db = NewContext())
        {
            db.TimelineEntries.Add(new TimelineEntry { CaseId = _alpha, Kind = TimelineKind.Investigation, Type = TimelineEntryType.Analysis,
                OccurredAtUtc = H(-30), Description = $"See the [proxy log](evidence:{Guid.NewGuid()}) for the times", CreatedBy = "robin", CreatedAtUtc = H(-30) });
            db.SaveChanges();
        }

        // WF-89: a colleague's address is the indicator and the person: the tasks they own are listed too.
        var mail = await NewFind().FindAsync("analyst1@contoso.example");
        mail.ReadAs.Should().Be(FindReadAs.Indicator);
        mail.Reading.Should().Contain("and a person: Analyst One");
        mail.Tasks.Should().Contain(t => t.Title == "Block 203.0.113.66 at the proxy");

        // WF-87: owner: lists tasks alone.
        var mine = await NewFind().FindAsync("owner:me proxy");
        mine.Tasks.Should().NotBeEmpty();
        mine.Entries.Should().BeEmpty();

        // WF-84: a word only in a link's hidden target doesn't match; the link's shown name does.
        (await NewFind().FindAsync("evidence")).Entries.Should().NotContain(e => e.Text.Contains("proxy log"));
        (await NewFind().FindAsync("proxy log")).Entries.Should().Contain(e => e.Text.Contains("proxy log"));

        // BUG-273: the case summary is Markdown too.
        using (var db = NewContext())
        {
            db.Cases.Single(c => c.Id == _alpha).Summary = "Started from the [mailbox audit](evidence:deadbeef-0000-4000-8000-000000000002).";
            db.SaveChanges();
        }
        (await NewFind().FindAsync("deadbeef")).Cases.Should().NotContain(c => c.Id == _alpha);
        (await NewFind().FindAsync("mailbox audit")).Cases.Should().Contain(c => c.Id == _alpha);
    }

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task Without_ViewCases_nothing_is_found(string provider /* BUG-465 */)
    {
        Use(provider);
        _me.RoleSet = [];   // signed in by Windows, no CaseBook role
        foreach (var query in new[] { "203.0.113.66", "password reset", "Phishing_Wave", "2026-01_Phishing_Wave" })
        {
            var r = await NewFind().FindAsync(query);
            r.Entities.Should().BeEmpty(query);
            r.Cases.Should().BeEmpty(query);
            r.Entries.Should().BeEmpty(query);
            r.Tasks.Should().BeEmpty(query);
            r.Evidence.Should().BeEmpty(query);
            r.Notes.Should().BeEmpty(query);
            r.Counts.Values.Should().AllSatisfy(n => n.Should().Be(0), query);
        }
    }

    [Fact]
    public void A_filter_it_cant_use_is_said_back(/* WF-88 */)
    {
        FindQuery.Parse("exercises:maybe").Unread.Should().ContainSingle(u => u.StartsWith("exercises:maybe"));
        FindQuery.Parse("exercises:no").Exercises.Should().BeFalse();
        var unknown = FindQuery.Parse("subject:\"invoice overdue\"");
        unknown.Terms.Should().Equal("invoice overdue");
        unknown.Unread.Should().ContainSingle(u => u.StartsWith("subject:"));
    }

    [Fact]
    public void The_parser_refuses_what_it_would_misread(/* WF-04, WF-05 */)
    {
        FindQuery.Parse("after:0001-01-01").After.Should().BeNull();
        FindQuery.Parse("after:0001-01-01").Unread.Should().ContainSingle(u => u.StartsWith("after:0001-01-01"));
        FindQuery.Parse("before:9999-12-31").Before.Should().BeNull();
        FindQuery.Parse("type:containment,eradication").EntryType.Should().BeNull();
        FindQuery.Parse("type:2").EntryType.Should().BeNull();
        FindQuery.Parse("type:decision").EntryType.Should().Be(TimelineEntryType.Decision);
        var twice = FindQuery.Parse("status:open status:closed");
        twice.Open.Should().BeFalse();
        twice.Unread.Should().ContainSingle(u => u.Contains("more than once"));
        FindQuery.Parse("state:NY jurisdiction:NJ").Unread.Should().ContainSingle(u => u.Contains("more than once"));
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
