using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Search;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// RD-20: Find. Typed results across entities, cases, record entries (closing briefs included), tasks, evidence names and,
/// on request, working notes; it says how it read the query; the grammar is literal; need-to-know scoped throughout.
/// </summary>
public sealed class FindServiceTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private static readonly DateTimeOffset Now = new(2026, 10, 4, 12, 0, 0, TimeSpan.Zero);
    private readonly TestCurrentUser _me = new() { UserId = "analyst1", DisplayName = "Analyst One", RoleSet = [AppRole.Analyst] };
    private Guid _alpha, _beta, _decisionId;

    public FindServiceTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        Seed();
    }

    private AppDbContext NewContext()
    {
        var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_connection).Options);
        db.Database.EnsureCreated();
        return db;
    }

    private FindService NewFind() =>
        new(new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_connection).Options), _me, new Directory());

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

    [Fact]
    public async Task An_indicator_is_read_as_one_and_found_across_every_kind_on_cases_you_can_see()
    {
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

    [Fact]
    public async Task Plain_question_filters_narrow_the_record_and_are_said_back()
    {
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

    [Fact]
    public async Task A_person_or_a_case_number_reads_as_one()
    {
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

    public void Dispose() => _connection.Dispose();

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
