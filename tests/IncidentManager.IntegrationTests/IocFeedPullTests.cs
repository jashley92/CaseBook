using System.Text.Json;
using FluentAssertions;
using IncidentManager.Application.Export;
using IncidentManager.Application.Reporting;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// CAP-09: the IOC feed as machines pull it: a delta since a time, bounded (C10) with the cut said, need-to-know scoped
/// for the token's owner, exercises left out, and the cross-case STIX bundle with each indicator's TLP. The HTTP side
/// (token sign-in, 304, the rate limit) is in <see cref="ApiEndpointTests"/>.
/// Runs on SQLite and, when a server is configured, on SQL Server (<see cref="TestDatabase"/>).
/// </summary>
public sealed class IocFeedPullTests : IDisposable
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

    public void Dispose() => _db?.Dispose();
}
