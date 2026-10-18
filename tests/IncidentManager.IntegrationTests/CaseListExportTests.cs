using FluentAssertions;
using IncidentManager.Application.Cases;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Web.Components.Shared;
using Microsoft.AspNetCore.WebUtilities;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// CAP-17: /export/cases.csv lists exactly what the Cases page lists for the same URL filter (C2): the same parser reads
/// the query, and the same CaseService.ListAsync reads the cases, a page at a time, so need-to-know, the exercise rule and
/// every filter are the list's own. Runs on SQLite and, when a server is configured, on SQL Server.
/// </summary>
public sealed class CaseListExportTests : IDisposable
{
    private TestDatabase? _db;
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 5, 9, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _me = new() { UserId = "analyst1", RoleSet = [AppRole.Analyst] };

    private CaseService NewCases() => new(_db!.Factory(), _me, _clock, new CaseNumberGenerator(_db!.NewContext()), new CreateCaseValidator(),
        new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());

    private void Seed()
    {
        using var db = _db!.NewContext();
        var severities = new[] { Severity.Low, Severity.Medium, Severity.High, Severity.Critical };
        for (var i = 1; i <= 12; i++)
        {
            var c = Case.Open(2026, i, $"c{i}", i % 3 == 0 ? $"Alpha phishing {i}" : $"Case {i}",
                i % 2 == 0 ? Classification.Incident : Classification.AdverseEvent, severities[i % 4],
                i % 5 == 0 ? CaseOrigin.ThirdParty : CaseOrigin.InternalDetection, "ivy", _clock.UtcNow.AddHours(-i));
            c.DetectedAtUtc = _clock.UtcNow.AddHours(-i - 1);
            if (i == 4) c.LegalHold = true;
            if (i == 6) c.ReportedAtUtc = _clock.UtcNow.AddHours(-2);
            if (i == 7) c.IncidentCommander = "analyst1";
            db.Cases.Add(c);
        }
        var secret = Case.Open(2026, 50, "secret", "Alpha secret", Classification.Incident, Severity.Critical, CaseOrigin.InternalDetection, "ivy", _clock.UtcNow);
        secret.IsRestricted = true;
        db.Cases.Add(secret);
        db.Cases.Add(Case.Open(2026, 51, "drill", "Alpha drill", Classification.Incident, Severity.High, CaseOrigin.InternalDetection, "ivy",
            _clock.UtcNow, isExercise: true));
        db.SaveChanges();
    }

    private static CaseFilter Parse(string query)
    {
        var q = QueryHelpers.ParseQuery(query);
        return CaseListQuery.Parse(k => q.TryGetValue(k, out var v) ? v.ToString() : null);
    }

    public static TheoryData<string, string> Queries()
    {
        var rows = new TheoryData<string, string>();
        foreach (var provider in SqlServerFactAttribute.Server is null ? [TestDatabase.Sqlite] : new[] { TestDatabase.Sqlite, TestDatabase.SqlServer })
            foreach (var q in new[]
                     {
                         "scope=all", "sev=High", "classification=Incident", "origin=ThirdParty", "q=alpha", "hold=true",
                         "sort=severity&dir=asc", "sort=case", "sort=sla", "scope=mine", "exercises=true&q=alpha", "sev=9&phase=1",
                         "classification=Incident&sev=Medium&sort=updated&dir=desc",
                     })
                rows.Add(provider, q);
        return rows;
    }

    [Theory, MemberData(nameof(Queries))]
    public async Task The_export_lists_exactly_what_the_page_lists_for_the_same_query_in_the_same_order(string provider, string query)
    {
        _db = TestDatabase.Open(provider);
        Seed();
        var cases = NewCases();

        // The page: one big page of the same filter, as Cases.razor reads it (CaseListQuery.Parse of its own query).
        var pageFilter = Parse(query);
        pageFilter.PageSize = 1000;
        var page = await cases.ListAsync(pageFilter);

        // The export: a few cases a read, so the paging is exercised.
        var (items, truncated) = await CaseListCsv.CollectAsync(cases, Parse(query), pageSize: 5);

        truncated.Should().BeFalse();
        items.Select(i => i.Id).Should().Equal(page.Items.Select(i => i.Id), $"the export of ?{query} is the page's list");
        items.Should().NotContain(i => i.Title == "Alpha secret", "need-to-know (ForUser) holds in the export");
        if (!query.Contains("exercises")) items.Should().NotContain(i => i.IsExercise);
    }

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task An_export_past_its_bound_is_cut_and_says_so_at_the_top_and_the_end(string provider)
    {
        _db = TestDatabase.Open(provider);
        Seed();
        var (items, truncated) = await CaseListCsv.CollectAsync(NewCases(), Parse("scope=all"), limit: 4, pageSize: 3);
        items.Should().HaveCount(4);
        truncated.Should().BeTrue();

        var csv = CaseListCsv.Build(items, _clock.UtcNow, truncated, c => c?.ToString() ?? "Complex Event", p => p.ToString(), s => s.ToString(), _ => "");
        var lines = csv.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
        lines[1].Should().StartWith("# Truncated");
        lines[^1].Should().StartWith("# Truncated");
    }

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task The_file_has_the_lists_columns_and_the_lifecycle_times(string provider)
    {
        _db = TestDatabase.Open(provider);
        Seed();
        var (items, _) = await CaseListCsv.CollectAsync(NewCases(), Parse("q=Alpha phishing 6"));
        var csv = CaseListCsv.Build(items, _clock.UtcNow, false, c => c?.ToString() ?? "", p => p.ToString(), s => s.ToString(), _ => "On track");
        var lines = csv.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);

        lines[1].Should().Be("case_number,title,classification,phase,severity,sla,owner,other_assignees,origin,restricted,legal_referral," +
                             "legal_hold,exercise,opened_utc,detected_utc,contained_utc,resolved_utc,closed_utc,reported_utc");
        var row = lines[2].Split(',');
        row[1].Should().Be("Alpha phishing 6");
        row[5].Should().Be("On track");
        row[13].Should().Be("2026-10-05 03:00:00");
        row[14].Should().Be("2026-10-05 02:00:00");
        row[18].Should().Be("2026-10-05 07:00:00", "the reported time");
    }

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task A_case_worked_on_while_the_export_reads_is_still_in_it(string provider /* CAP-17 review */)
    {
        // Audited, so "updated" is the latest work on the case (REV-15): every seeded case ties, and the id breaks it.
        _db = TestDatabase.Open(provider, new IncidentManager.Infrastructure.Persistence.Interceptors.AuditChainInterceptor(
            new IncidentManager.Infrastructure.Security.HashChainService(), _me, _clock, new IncidentManager.Infrastructure.Realtime.CaseChangeNotifier()));
        Seed();
        var cases = NewCases();
        const string query = "scope=all&sort=updated&dir=desc";
        var everyone = Parse(query);
        everyone.PageSize = 1000;
        var expected = (await cases.ListAsync(everyone)).Items.Select(i => i.Id).ToList();
        expected.Should().HaveCountGreaterThan(6);
        var last = expected[^1];

        // After the first read, someone works on the case the list shows last: it's now the most recently updated, and
        // would sit on the page already read.
        var touched = false;
        var (items, truncated) = await CaseListCsv.CollectAsync(cases, Parse(query), CaseListCsv.Limit, pageSize: 3, afterPage: async n =>
        {
            if (n != 1) return;
            _clock.UtcNow = _clock.UtcNow.AddMinutes(5);
            using var db = _db!.NewContext();
            var c = db.Cases.Single(x => x.Id == last);
            c.Title += " (worked on)";
            await db.SaveChangesAsync();
            touched = true;
        }, ct: default);

        touched.Should().BeTrue();
        truncated.Should().BeFalse();
        items.Select(i => i.Id).Should().BeEquivalentTo(expected, "every case the filter matched is in the file, once");
        items.Select(i => i.Id).Should().OnlyHaveUniqueItems();
        var now = Parse(query);
        now.PageSize = 1000;
        (await cases.ListAsync(now)).Items[0].Id.Should().Be(last, "the touch did move it to the top of the list");
    }

    [Theory, MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task An_sla_ordered_export_ranks_once_and_matches_the_page(string provider /* CAP-17 review */)
    {
        _db = TestDatabase.Open(provider);
        Seed();
        var cases = NewCases();
        var page = Parse("sort=sla&dir=desc");
        page.PageSize = 1000;
        var expected = (await cases.ListAsync(page)).Items.Select(i => i.Id).ToList();

        var reads = 0;
        var (items, _) = await CaseListCsv.CollectAsync(cases, Parse("sort=sla&dir=desc"), CaseListCsv.Limit, pageSize: 2,
            afterPage: _ => { reads++; return Task.CompletedTask; }, ct: default);

        items.Select(i => i.Id).Should().Equal(expected);
        reads.Should().Be((expected.Count + 1) / 2, "the rows are read a chunk at a time");
    }

    public void Dispose() => _db?.Dispose();
}
