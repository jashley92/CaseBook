using System.Text.Json;
using FluentAssertions;
using IncidentManager.Application.Export;
using IncidentManager.Application.Reporting;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using Xunit;
using Xunit.Abstractions;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// CAP-09: the IOC feed as machines pull it: a delta since a time, bounded (C10) with the cut said, need-to-know scoped
/// for the token's owner, exercises left out, and the cross-case STIX bundle with each indicator's TLP. The HTTP side
/// (token sign-in, 304, the rate limit) is in <see cref="ApiEndpointTests"/>.
/// Runs on SQLite and, when a server is configured, on SQL Server (<see cref="TestDatabase"/>).
/// </summary>
public sealed class IocFeedPullTests(ITestOutputHelper output) : IDisposable
{
    private TestDatabase? _db;
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 1, 9, 0, 0, TimeSpan.Zero));

    // A feed token's owner: ViewCases only, so a restricted case's indicators are out unless it's on the case.
    private readonly TestCurrentUser _feed = new() { UserId = "apitoken:firewall", PermissionSet = [Permission.ViewCases] };

    private static readonly DateTimeOffset T0 = new(2026, 9, 1, 0, 0, 0, TimeSpan.Zero);

    private AppDbContext NewContext() => _db!.NewContext();

    private IocFeedService Feed(TestCurrentUser user, TlpLevel defaultTlp = TlpLevel.Amber) =>
        new(_db!.Factory(), user, new TestOptionsMonitor<ReportingOptions>(new ReportingOptions { DefaultTlp = defaultTlp.ToString() }));

    private StixExportService Stix(TestCurrentUser user) =>
        new(_db!.Factory(), user, _clock, new TestOptionsMonitor<ReportingOptions>(new ReportingOptions { OrganizationName = "Northwind Mutual" }));

    private Case Add(int seq, bool restricted = false, bool exercise = false, params CaseEntity[] entities)
    {
        using var db = NewContext();
        var c = Case.Open(2026, seq, $"case{seq}", $"Case {seq}", Classification.Incident, Severity.High, CaseOrigin.InternalDetection,
            "ic1", T0, isExercise: exercise);
        c.IsRestricted = restricted;
        foreach (var e in entities)
        {
            e.CaseId = c.Id;
            c.Entities.Add(e);
        }
        db.Cases.Add(c);
        db.SaveChanges();
        return c;
    }

    private static CaseEntity Ioc(string value, EntityType type = EntityType.IpAddress, DateTimeOffset? created = null,
        DateTimeOffset? modified = null, TlpLevel? tlp = null, EntityDisposition disposition = EntityDisposition.Malicious) => new()
    {
        Id = Guid.NewGuid(), Type = type, Value = value, Disposition = disposition, Source = "SIEM",
        CreatedAtUtc = created ?? T0, CreatedBy = "ic1", ModifiedAtUtc = modified, Tlp = tlp,
    };

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task A_restricted_case_feeds_only_a_token_that_could_open_it_and_an_exercise_never(string provider)
    {
        _db = TestDatabase.Open(provider);
        Add(1, entities: Ioc("198.51.100.1"));
        var secret = Add(2, restricted: true, entities: Ioc("198.51.100.2"));
        Add(3, exercise: true, entities: Ioc("198.51.100.3"));

        (await Feed(_feed).GetFeedAsync(null)).Rows.Select(r => r.Value).Should().Equal("198.51.100.1");

        var cleared = new TestCurrentUser { UserId = "apitoken:tip", PermissionSet = [Permission.ViewCases, Permission.ViewRestricted] };
        (await Feed(cleared).GetFeedAsync(null)).Rows.Select(r => r.Value).Should().Equal("198.51.100.1", "198.51.100.2");

        // Assigned to the restricted case, the owner sees its indicators as they'd see the case.
        await using (var db = NewContext())
        {
            db.Set<CaseAssignment>().Add(new CaseAssignment { CaseId = secret.Id, UserId = _feed.UserId, UserDisplayName = "Firewall",
                Role = CaseAssignmentRole.Analyst, AssignedAtUtc = T0, AssignedBy = "ic1" });
            await db.SaveChangesAsync();
        }
        (await Feed(_feed).GetFeedAsync(null)).Rows.Select(r => r.Value).Should().Contain("198.51.100.2").And.NotContain("198.51.100.3");

        var none = new TestCurrentUser { UserId = "apitoken:nothing", PermissionSet = [Permission.ManageLegal] };
        (await Feed(none).GetFeedAsync(null)).Rows.Should().BeEmpty("no case at all without ViewCases");
    }

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task Since_gives_indicators_added_or_changed_from_then_on(string provider)
    {
        _db = TestDatabase.Open(provider);
        Add(1, entities:
        [
            Ioc("old.example", EntityType.Domain, created: T0),
            Ioc("newly-marked.example", EntityType.Domain, created: T0, modified: T0.AddDays(10)),   // a verdict set later
            Ioc("new.example", EntityType.Domain, created: T0.AddDays(12)),
        ]);

        var delta = await Feed(_feed).GetFeedAsync(T0.AddDays(5));
        delta.Rows.Select(r => r.Value).Should().BeEquivalentTo("newly-marked.example", "new.example");
        delta.Since.Should().Be(T0.AddDays(5));
        (await Feed(_feed).GetFeedAsync(T0.AddDays(20))).Rows.Should().BeEmpty();
        (await Feed(_feed).GetFeedAsync(null)).Rows.Should().HaveCount(3);
    }

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task Past_its_bound_the_feed_keeps_the_most_recently_changed_and_says_it_was_cut(string provider)
    {
        _db = TestDatabase.Open(provider);
        Add(1, entities: [Ioc("198.51.100.10", created: T0), Ioc("198.51.100.11", created: T0.AddDays(1)), Ioc("198.51.100.12", created: T0.AddDays(2))]);

        var cut = await Feed(_feed).GetFeedAsync(null, limit: 2);
        cut.Cut.Should().BeTrue();
        cut.Rows.Select(r => r.Value).Should().BeEquivalentTo("198.51.100.11", "198.51.100.12");
        (await Feed(_feed).GetFeedAsync(null, limit: 3)).Cut.Should().BeFalse("exactly at the bound nothing is left out");

        var csv = IocFeedCsv.Build(cut, _clock.UtcNow);
        var lines = csv.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
        lines[1].Should().StartWith("# Cut: more than 2 indicator occurrences");
        lines[^1].Should().StartWith("# Cut:", "said at the end too, where a reader stops");
    }

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task The_csv_and_the_stix_bundle_carry_each_indicators_marking_with_the_default_where_none_is_set(string provider)
    {
        _db = TestDatabase.Open(provider);
        Add(1, entities: [Ioc("203.0.113.5", tlp: TlpLevel.Red), Ioc("bad.example", EntityType.Domain)]);
        Add(2, entities: [Ioc("203.0.113.5", tlp: TlpLevel.Green)]);   // the same IP, looser elsewhere: the stricter wins

        var feed = await Feed(_feed).GetFeedAsync(T0.AddDays(-1));
        var csv = IocFeedCsv.Build(feed, _clock.UtcNow);
        csv.Should().Contain("# Only indicators added or changed since 2026-08-31 00:00:00 UTC.");
        csv.Should().Contain("ip,203.0.113.5,malicious,").And.Contain(",TLP:RED\r\n");
        csv.Should().Contain("domain,bad.example,malicious,").And.Contain(",TLP:AMBER\r\n");

        var stix = Stix(_feed);
        var json = JsonSerializer.Serialize(stix.BuildFeed(feed));
        using var doc = JsonDocument.Parse(json);
        var objects = doc.RootElement.GetProperty("objects").EnumerateArray().ToList();
        objects[0].GetProperty("type").GetString().Should().Be("identity");
        var report = objects[1];
        report.GetProperty("type").GetString().Should().Be("report");
        report.GetProperty("x_casebook_since").GetString().Should().Be("2026-08-31T00:00:00.000Z");
        report.TryGetProperty("x_casebook_truncated", out _).Should().BeFalse();

        var markings = objects.Where(o => o.GetProperty("type").GetString() == "marking-definition")
            .ToDictionary(o => o.GetProperty("name").GetString()!, o => o.GetProperty("id").GetString()!);
        markings.Keys.Should().BeEquivalentTo("TLP:AMBER", "TLP:RED");
        report.GetProperty("object_marking_refs")[0].GetString().Should().Be(markings["TLP:RED"], "the report is as restricted as its strictest indicator");

        var ip = objects.Single(o => o.GetProperty("type").GetString() == "ipv4-addr");
        ip.GetProperty("value").GetString().Should().Be("203.0.113.5");
        ip.GetProperty("object_marking_refs")[0].GetString().Should().Be(markings["TLP:RED"]);
        ip.GetProperty("x_casebook_cases").EnumerateArray().Select(c => c.GetString()).Should().HaveCount(2);
        ip.GetProperty("x_casebook_disposition").GetString().Should().Be("Malicious");
        var domain = objects.Single(o => o.GetProperty("type").GetString() == "domain-name");
        domain.GetProperty("object_marking_refs")[0].GetString().Should().Be(markings["TLP:AMBER"], "unmarked means the default, never unmarked");

        // The same indicator is the same object in every pull, so a TIP updates it.
        var again = JsonSerializer.Serialize(stix.BuildFeed(await Feed(_feed).GetFeedAsync(null)));
        using var second = JsonDocument.Parse(again);
        second.RootElement.GetProperty("objects").EnumerateArray()
            .Single(o => o.GetProperty("type").GetString() == "ipv4-addr").GetProperty("id").GetString()
            .Should().Be(ip.GetProperty("id").GetString());
        stix.Fingerprint(feed).Should().Be(stix.Fingerprint(await Feed(_feed).GetFeedAsync(T0.AddDays(-1))), "nothing changed");
        feed.Fingerprint("csv").Should().NotBe(stix.Fingerprint(feed), "each format has its own tag");
    }

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task A_delta_row_is_the_whole_indicator_not_just_the_occurrence_that_changed(string provider)
    {
        // CAP-09 review: since picks the indicators; their marking, cases and first seen are over every occurrence.
        _db = TestDatabase.Open(provider);
        var a = Add(1, entities: Ioc("203.0.113.77", created: T0, tlp: TlpLevel.Red));
        var b = Add(2, entities: Ioc("203.0.113.77", created: T0.AddDays(10), tlp: TlpLevel.Green));
        Add(3, entities: Ioc("203.0.113.78", created: T0));   // nothing changed since: not in the delta

        var feed = await Feed(_feed).GetFeedAsync(T0.AddDays(5));
        var row = feed.Rows.Should().ContainSingle().Which;
        row.Value.Should().Be("203.0.113.77");
        row.Tlp.Should().Be(TlpLevel.Red, "the delta never downgrades a marking to the changed occurrence's");
        row.Cases.Should().BeEquivalentTo(a.CaseNumber, b.CaseNumber);
        row.FirstSeenUtc.Should().Be(T0);
        row.LastSeenUtc.Should().Be(T0.AddDays(10));

        var csv = IocFeedCsv.Build(feed, _clock.UtcNow);
        csv.Should().Contain($"ip,203.0.113.77,malicious,2026-09-01 00:00:00,2026-09-11 00:00:00,2,{a.CaseNumber}; {b.CaseNumber},SIEM,TLP:RED\r\n");

        using var doc = JsonDocument.Parse(JsonSerializer.Serialize(Stix(_feed).BuildFeed(feed)));
        var objects = doc.RootElement.GetProperty("objects").EnumerateArray().ToList();
        var red = objects.Single(o => o.GetProperty("type").GetString() == "marking-definition" && o.GetProperty("name").GetString() == "TLP:RED");
        var ip = objects.Single(o => o.GetProperty("type").GetString() == "ipv4-addr");
        ip.GetProperty("object_marking_refs")[0].GetString().Should().Be(red.GetProperty("id").GetString());
        ip.GetProperty("x_casebook_cases").EnumerateArray().Select(c => c.GetString()).Should().BeEquivalentTo(a.CaseNumber, b.CaseNumber);
        ip.GetProperty("x_casebook_first_seen").GetString().Should().Be("2026-09-01T00:00:00.000Z");
    }

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task A_cut_keeps_whole_indicators_never_part_of_ones_occurrences(string provider)
    {
        _db = TestDatabase.Open(provider);
        Add(1, entities: [Ioc("198.51.100.30", created: T0, tlp: TlpLevel.Red), Ioc("bad.example", EntityType.Domain, created: T0.AddDays(12))]);
        Add(2, entities: Ioc("198.51.100.30", created: T0.AddDays(10), tlp: TlpLevel.Green));

        // Three occurrences, a bound of two: the newest indicator (one occurrence) fits; the IP's two don't fit beside it,
        // and its newer GREEN occurrence alone would have gone out as a GREEN indicator on one case.
        var cut = await Feed(_feed).GetFeedAsync(null, limit: 2);
        cut.Cut.Should().BeTrue();
        cut.Rows.Select(r => r.Value).Should().Equal("bad.example");

        var whole = await Feed(_feed).GetFeedAsync(null, limit: 3);
        whole.Cut.Should().BeFalse();
        whole.Rows.Single(r => r.Value == "198.51.100.30").Tlp.Should().Be(TlpLevel.Red);

        // A delta that's cut is cut the same way.
        var delta = await Feed(_feed).GetFeedAsync(T0.AddDays(5), limit: 2);
        delta.Cut.Should().BeTrue();
        delta.Rows.Select(r => r.Value).Should().Equal("bad.example");
        (await Feed(_feed).GetFeedAsync(T0.AddDays(5), limit: 1)).Rows.Select(r => r.Value).Should().Equal("bad.example");
    }

    [Fact]
    public async Task The_stix_etag_changes_with_the_default_marking()
    {
        _db = TestDatabase.Open(TestDatabase.Sqlite);
        Add(1, entities: Ioc("198.51.100.40", tlp: TlpLevel.Green));   // marked: its row doesn't move with the default
        var feed = await Feed(_feed).GetFeedAsync(null);
        StixWith(TlpLevel.Amber).Fingerprint(feed).Should().NotBe(StixWith(TlpLevel.Red).Fingerprint(feed),
            "the bundle lists the default and the report takes it when it's the strictest, so a 304 would be stale");
        StixWith(TlpLevel.Amber).Fingerprint(feed).Should().Be(StixWith(TlpLevel.Amber).Fingerprint(feed));
    }

    private StixExportService StixWith(TlpLevel defaultTlp) =>
        new(_db!.Factory(), _feed, _clock, new TestOptionsMonitor<ReportingOptions>(
            new ReportingOptions { OrganizationName = "Northwind Mutual", DefaultTlp = defaultTlp.ToString() }));

    [Fact]
    public async Task A_cut_bundle_says_so_in_its_report()
    {
        _db = TestDatabase.Open(TestDatabase.Sqlite);
        Add(1, entities: [Ioc("198.51.100.20", created: T0), Ioc("198.51.100.21", created: T0.AddDays(1))]);
        var feed = await Feed(_feed).GetFeedAsync(null, limit: 1);
        using var doc = JsonDocument.Parse(JsonSerializer.Serialize(Stix(_feed).BuildFeed(feed)));
        var report = doc.RootElement.GetProperty("objects")[1];
        report.GetProperty("x_casebook_truncated").GetBoolean().Should().BeTrue();
        report.GetProperty("description").GetString().Should().Contain("Cut: more than 1 indicator occurrences");
    }

    [Fact]
    public async Task A_delta_over_twenty_thousand_occurrences_is_read_in_a_few_seconds_on_sqlite()
    {
        // R2: the delta picks its indicators with one grouped query, not a correlated EXISTS per occurrence, which SQLite ran
        // in O(n²). 20,000 occurrences of 10,000 indicators over 1,000 cases, a quarter changed since the delta's start.
        _db = TestDatabase.Open(TestDatabase.Sqlite);
        const int occurrences = 20_000, cases = 1_000, indicators = 10_000;
        var rnd = new Random(7);
        await using (var db = NewContext())
        {
            db.ChangeTracker.AutoDetectChangesEnabled = false;
            var ids = new Guid[cases];
            for (var i = 0; i < cases; i++)
            {
                var c = Case.Open(2026, i + 1, $"case{i + 1}", $"Case {i + 1}", Classification.Incident, Severity.High,
                    CaseOrigin.InternalDetection, "ic1", T0);
                ids[i] = c.Id;
                db.Cases.Add(c);
            }
            for (var i = 0; i < occurrences; i++)
            {
                var e = Ioc($"host{rnd.Next(indicators)}.example", EntityType.Domain, created: T0,
                    modified: i % 4 == 0 ? T0.AddDays(10) : null);
                e.CaseId = ids[rnd.Next(cases)];
                db.CaseEntities.Add(e);
            }
            await db.SaveChangesAsync();
        }

        var run = System.Diagnostics.Stopwatch.StartNew();
        var delta = await Feed(_feed).GetFeedAsync(T0.AddDays(5));
        var whole = run.Elapsed;
        delta.Cut.Should().BeFalse();
        delta.Rows.Should().NotBeEmpty().And.HaveCountLessThan(indicators);

        run.Restart();
        var cut = await Feed(_feed).GetFeedAsync(T0.AddDays(5), limit: 1_000);
        var bounded = run.Elapsed;
        cut.Cut.Should().BeTrue();
        cut.Rows.Should().NotBeEmpty();
        output.WriteLine($"Delta over {occurrences:N0} occurrences: {whole.TotalMilliseconds:N0} ms; cut at 1,000: {bounded.TotalMilliseconds:N0} ms.");

        whole.Should().BeLessThan(TimeSpan.FromSeconds(5));
        bounded.Should().BeLessThan(TimeSpan.FromSeconds(5));
    }

    public void Dispose() => _db?.Dispose();
}
