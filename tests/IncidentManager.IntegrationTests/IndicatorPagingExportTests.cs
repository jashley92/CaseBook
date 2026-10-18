using FluentAssertions;
using IncidentManager.Application.Intel;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Web.Components.Shared;
using Microsoft.AspNetCore.WebUtilities;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// CAP-27: the Indicators page pages from the server by keyset (the row a page ends or starts at), so indicators recorded
/// while someone pages neither repeat nor push others out of sight; and its CSV holds every indicator the page's filter
/// matches, whatever the verdict, with case counts and each case's number and verdict, need-to-know scoped as the page is.
/// Runs on SQLite and, when a server is configured, on SQL Server.
/// </summary>
public sealed class IndicatorPagingExportTests : IDisposable
{
    private TestDatabase? _db;
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 1, 9, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _me = new() { UserId = "analyst1", RoleSet = [AppRole.Analyst] };

    private IndicatorService Service() => new(_db!.Factory(), _me);

    private Case NewCase(int seq, string title, bool restricted = false, bool exercise = false)
    {
        var c = Case.Open(2026, seq, $"c{seq}", title, Classification.Incident, Severity.High, CaseOrigin.InternalDetection,
            "ivy", _clock.UtcNow.AddDays(-30), isExercise: exercise);
        c.IsRestricted = restricted;
        return c;
    }

    /// <summary>Alpha and Bravo (visible) share three IPs; Alpha has 20 more of its own; a restricted case shares one IP and
    /// carries a domain no one else has; an exercise case carries a domain.</summary>
    private (Guid Alpha, Guid Bravo) Seed()
    {
        using var db = _db!.NewContext();
        var alpha = NewCase(1, "Alpha");
        var bravo = NewCase(2, "Bravo");
        var secret = NewCase(3, "Secret", restricted: true);
        var drill = NewCase(4, "Drill", exercise: true);
        for (var i = 1; i <= 23; i++)
            alpha.AddEntity(EntityType.IpAddress, $"198.51.100.{i}", null, i % 4 == 0 ? EntityDisposition.Malicious : EntityDisposition.Unknown,
                null, null, "ivy", _clock.UtcNow.AddHours(-i));
        for (var i = 1; i <= 3; i++)
            bravo.AddEntity(EntityType.IpAddress, $"198.51.100.{i}", null, EntityDisposition.Suspicious, null, null, "ivy",
                _clock.UtcNow.AddHours(-i).AddMinutes(-30));
        secret.AddEntity(EntityType.IpAddress, "198.51.100.1", null, EntityDisposition.Malicious, null, null, "other", _clock.UtcNow);
        secret.AddEntity(EntityType.Domain, "hidden.example", null, EntityDisposition.Malicious, null, null, "other", _clock.UtcNow);
        drill.AddEntity(EntityType.Domain, "drill.example", null, EntityDisposition.Benign, null, null, "ivy", _clock.UtcNow);
        db.Cases.AddRange(alpha, bravo, secret, drill);
        db.SaveChanges();
        _numbers = [alpha.CaseNumber, bravo.CaseNumber, secret.CaseNumber, drill.CaseNumber];
        return (alpha.Id, bravo.Id);
    }

    private string[] _numbers = [];

    private void AddIndicators(Guid caseId, string prefix, int count, DateTimeOffset at)
    {
        using var db = _db!.NewContext();
        for (var i = 1; i <= count; i++)
            db.CaseEntities.Add(new CaseEntity
            {
                CaseId = caseId, Type = EntityType.Domain, Value = $"{prefix}{i}.example", Disposition = EntityDisposition.Unknown,
                CreatedBy = "ivy", CreatedAtUtc = at.AddSeconds(i),
            });
        db.SaveChanges();
    }

    private static string Key(IndicatorRow r) => $"{r.Type}|{r.Value.ToLowerInvariant()}";

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task Paging_forward_shows_each_indicator_once_while_new_ones_are_recorded(string provider)
    {
        _db = TestDatabase.Open(provider);
        var (alpha, bravo) = Seed();
        var svc = Service();
        var everyone = (await svc.SearchAsync(new IndicatorFilter(), IndicatorPageAt.First, pageSize: 1000)).Rows.Select(Key).ToList();
        everyone.Should().HaveCount(23);

        var seen = new List<string>();
        var page = await svc.SearchAsync(new IndicatorFilter(), IndicatorPageAt.First, pageSize: 5);
        page.FirstIndex.Should().Be(0);
        page.HasPrevious.Should().BeFalse();
        page.Matched.Should().Be(23);
        var n = 0;
        while (true)
        {
            seen.AddRange(page.Rows.Select(Key));
            if (!page.HasNext) break;
            // Between pages, analysts record more: newest first, shared, so they sort ahead of the page just read. An offset
            // page would now start that many rows earlier and repeat them.
            n++;
            AddIndicators(alpha, $"new{n}-", 2, _clock.UtcNow.AddMinutes(n));
            AddIndicators(bravo, $"new{n}-", 2, _clock.UtcNow.AddMinutes(n));
            page = await svc.SearchAsync(new IndicatorFilter(), IndicatorPageAt.Next(page.Rows[^1]), pageSize: 5);
        }

        n.Should().BeGreaterThan(2, "the walk went over several pages");
        seen.Should().OnlyHaveUniqueItems("no indicator is shown twice");
        seen.Should().Contain(everyone, "every indicator there when paging began is reached");
        seen.Should().NotContain(k => k.Contains("hidden.example") || k.Contains("drill.example"));
    }

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task Paging_back_returns_to_the_first_page_full(string provider)
    {
        _db = TestDatabase.Open(provider);
        Seed();
        var svc = Service();
        var all = (await svc.SearchAsync(new IndicatorFilter(), IndicatorPageAt.First, pageSize: 1000)).Rows.Select(Key).ToList();

        var page = await svc.SearchAsync(new IndicatorFilter(), IndicatorPageAt.First, pageSize: 10);
        page = await svc.SearchAsync(new IndicatorFilter(), IndicatorPageAt.Next(page.Rows[^1]), pageSize: 10);
        page = await svc.SearchAsync(new IndicatorFilter(), IndicatorPageAt.Next(page.Rows[^1]), pageSize: 10);
        page.Rows.Select(Key).Should().Equal(all.Skip(20));
        page.HasNext.Should().BeFalse();
        page.FirstIndex.Should().Be(20);
        IndicatorQuery.PageRange(page).Should().Contain("21").And.Contain("23");

        page = await svc.SearchAsync(new IndicatorFilter(), IndicatorPageAt.Previous(page.Rows[0]), pageSize: 10);
        page.Rows.Select(Key).Should().Equal(all.Skip(10).Take(10));
        page = await svc.SearchAsync(new IndicatorFilter(), IndicatorPageAt.Previous(page.Rows[0]), pageSize: 10);
        page.Rows.Select(Key).Should().Equal(all.Take(10));
        page.HasPrevious.Should().BeFalse();

        // From a row only a few from the start (the rows before it changed), Previous is the first page, full.
        page = await svc.SearchAsync(new IndicatorFilter(), IndicatorPageAt.Previous(page.Rows[4]), pageSize: 10);
        page.Rows.Select(Key).Should().Equal(all.Take(10), "a Previous that reaches the start is the first page, full");
        page.FirstIndex.Should().Be(0);
    }

    // B4 review: Previous from an empty page past the end went back from Next's place exclusively, so it showed the page
    // ending one row before the page left (its last row gone, the row before it in).
    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task Previous_from_an_empty_page_past_the_end_is_the_page_left(string provider)
    {
        _db = TestDatabase.Open(provider);
        Seed();
        var svc = Service();
        var filter = new IndicatorFilter();
        var at = IndicatorPageAt.First;
        var page = await svc.SearchAsync(filter, at, pageSize: 10);
        at = IndicatorPageAt.Next(page.Rows[^1], page.Rows[0]);
        var pageN = await svc.SearchAsync(filter, at, pageSize: 10);
        pageN.Rows.Should().HaveCount(10);
        pageN.HasNext.Should().BeTrue();

        // The rows after page N's last go (their cases were closed off, or the indicators removed).
        var all = (await svc.SearchAsync(filter, IndicatorPageAt.First, pageSize: 1000)).Rows;
        var after = all.SkipWhile(r => Key(r) != Key(pageN.Rows[^1])).Skip(1).Select(r => r.Value).ToList();
        after.Should().NotBeEmpty();
        using (var db = _db.NewContext())
        {
            db.CaseEntities.RemoveRange(db.CaseEntities.Where(e => after.Contains(e.Value)));
            db.SaveChanges();
        }

        at = IndicatorPageAt.Next(pageN.Rows[^1], pageN.Rows[0]);
        var past = await svc.SearchAsync(filter, at, pageSize: 10);
        past.Rows.Should().BeEmpty();
        past.HasPrevious.Should().BeTrue();

        at = at.PreviousFrom(past.Rows);
        var back = await svc.SearchAsync(filter, at, pageSize: 10);
        back.Rows.Select(Key).Should().Equal(pageN.Rows.Select(Key), "Previous returns to the page Next left");
        back.FirstIndex.Should().Be(pageN.FirstIndex);
    }

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task The_export_holds_every_verdict_with_case_counts_and_numbers_within_need_to_know(string provider)
    {
        _db = TestDatabase.Open(provider);
        Seed();
        var svc = Service();

        var page = await svc.SearchAsync(new IndicatorFilter(), IndicatorPageAt.First, pageSize: 1000);
        var export = await svc.ExportAsync(new IndicatorFilter());
        export.Truncated.Should().BeFalse();
        export.Matched.Should().Be(23);
        export.Rows.Select(Key).Should().Equal(page.Rows.Select(Key), "the CSV is the page's list, in the page's order");

        var csv = IndicatorCsv.Build(export.Rows, _clock.UtcNow, export.Truncated);
        var lines = csv.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
        lines[0].Should().StartWith("# CaseBook indicators");
        lines[1].Should().Be("type,indicator,worst_verdict,case_count,open_case_count,first_seen_utc,last_seen_utc,cases");
        lines.Should().HaveCount(2 + 23);
        var shared = lines.Single(l => l.StartsWith("ip,198.51.100.1,", StringComparison.Ordinal));
        shared.Should().Be($"ip,198.51.100.1,suspicious,2,2,2026-10-01 07:30:00,2026-10-01 08:00:00,{_numbers[0]} (unknown); {_numbers[1]} (suspicious)",
            "the restricted case's malicious verdict and number stay out, as on the page");
        lines.Should().Contain(l => l.StartsWith("ip,198.51.100.4,malicious,1,", StringComparison.Ordinal));
        lines.Should().Contain(l => l.Contains(",unknown,", StringComparison.Ordinal), "every verdict, not only malicious");
        csv.Should().NotContain("hidden.example").And.NotContain(_numbers[2]).And.NotContain("drill.example");

        var withDrill = await svc.ExportAsync(new IndicatorFilter(Scope: IndicatorTypeScope.AllTypes, IncludeExercises: true));
        IndicatorCsv.Build(withDrill.Rows, _clock.UtcNow, false).Should().Contain("domain,drill.example,benign,1,1,")
            .And.Contain($"{_numbers[3]} (benign, exercise)").And.NotContain("hidden.example");
    }

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task An_export_past_its_bound_is_cut_and_says_so_at_the_top_and_the_end(string provider)
    {
        _db = TestDatabase.Open(provider);
        Seed();
        var export = await Service().ExportAsync(new IndicatorFilter(), limit: 4);
        export.Rows.Should().HaveCount(4);
        export.Truncated.Should().BeTrue();
        export.Matched.Should().Be(23);

        var lines = IndicatorCsv.Build(export.Rows, _clock.UtcNow, export.Truncated).Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
        lines[1].Should().StartWith("# Truncated: only the first 50000 indicators");
        lines[^1].Should().Be(lines[1]);
        lines[1].Should().NotContain(",").And.NotContain(";");
    }

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task The_export_link_names_the_pages_filter_and_reads_back_to_it(string provider /* C2 */)
    {
        _db = TestDatabase.Open(provider);
        Seed();
        foreach (var (search, type, verdict, shared, exercises) in new (string?, string, EntityDisposition?, bool, bool)[]
                 {
                     (null, "ioc", null, false, false), ("198.51.100[.]2", "ioc", null, false, false), (null, "all", null, false, true),
                     (null, "IpAddress", EntityDisposition.Suspicious, true, false), (null, "Domain", null, false, true),
                 })
        {
            var onPage = IndicatorQuery.Filter(search, type, verdict, shared, exercises);
            var href = IndicatorQuery.ExportHref(onPage, search is null ? null : "ref123");
            href.Should().NotContain("198.51", "an indicator value never rides in the link");
            var q = QueryHelpers.ParseQuery(href.Contains('?') ? href[href.IndexOf('?')..] : "");
            if (search is not null) q["qref"].ToString().Should().Be("ref123");
            var read = IndicatorQuery.Parse(k => q.TryGetValue(k, out var v) ? v.ToString() : null, search);
            read.Should().Be(onPage);

            var page = await Service().SearchAsync(onPage, IndicatorPageAt.First, pageSize: 1000);
            (await Service().ExportAsync(read)).Rows.Select(Key).Should().Equal(page.Rows.Select(Key));
        }
    }

    public void Dispose() => _db?.Dispose();
}
