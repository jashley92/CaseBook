using FluentAssertions;
using IncidentManager.Application.Cases;
using IncidentManager.Domain.Enums;
using IncidentManager.Web.Components.Shared;
using IncidentManager.Web.Services;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// CAP-17: the Cases page's URL filter, read by one parser for the page and its CSV export (C2), and the search reference
/// that keeps a search's text out of the export's URL.
/// </summary>
public sealed class CaseListQueryTests
{
    private static CaseFilter Parse(params (string Key, string Value)[] query) =>
        CaseListQuery.Parse(k => query.FirstOrDefault(p => p.Key == k).Value);

    [Fact]
    public void Every_filter_the_page_writes_is_read()
    {
        var f = Parse(("scope", "mine"), ("classification", "Breach"), ("phase", "Containment"), ("sev", "High"),
            ("origin", "ThirdParty"), ("outcome", "false-positive"), ("vendor", "Northwind"), ("team", " SocTier1 "), ("q", "10.0.0.5"), ("closed", "true"), ("exercises", "true"),
            ("overdue", "true"), ("sla", "true"), ("notify", "true"), ("referred", "true"), ("hold", "true"),
            ("assignee", "ivy"), ("opened", "2026-03"), ("sort", "severity"), ("dir", "asc"));

        f.OnlyMine.Should().BeTrue();
        f.Classification.Should().Be(Classification.Breach);
        f.Phase.Should().Be(CasePhase.Containment);
        f.MinSeverity.Should().Be(Severity.High);
        f.Origin.Should().Be(CaseOrigin.ThirdParty);
        f.OutcomeKey.Should().Be("false-positive");
        f.Vendor.Should().Be("Northwind");
        f.TeamKey.Should().Be("SocTier1", "CAP-36: the team filter, trimmed");
        f.Search.Should().Be("10.0.0.5");
        new[] { f.IncludeClosed, f.IncludeExercises, f.OverdueOnly, f.SlaAtRiskOnly, f.NotifyDeadlineOnly, f.ReferredOnly, f.OnHoldOnly }
            .Should().AllBeEquivalentTo(true);
        f.AssigneeUserId.Should().Be("ivy");
        f.UnassignedOnly.Should().BeFalse();
        (f.OpenedYear, f.OpenedMonth).Should().Be((2026, 3));
        f.Sort.Should().Be(CaseSort.Severity);
        f.SortDescending.Should().BeFalse();
    }

    [Fact]
    public void Bad_values_are_ignored_as_the_page_ignores_them(/* C16, BUG-31, BUG-475 */)
    {
        var f = Parse(("sev", "9"), ("phase", "1,2"), ("closed", "maybe"), ("opened", "9999-12"), ("sort", "nonsense"), ("assignee", "none"));
        f.MinSeverity.Should().BeNull();
        f.Phase.Should().BeNull();
        f.IncludeClosed.Should().BeFalse();
        f.OpenedYear.Should().BeNull();
        f.Sort.Should().Be(CaseSort.Opened);
        f.SortDescending.Should().BeTrue();
        f.UnassignedOnly.Should().BeTrue();
        f.AssigneeUserId.Should().BeNull();
    }

    [Fact]
    public void Copying_a_filter_copies_every_filter_but_the_page_position_and_size(/* C2: a new filter can't be left out */)
    {
        var props = typeof(CaseFilter).GetProperties().Where(p => p.Name is not (nameof(CaseFilter.Page) or nameof(CaseFilter.PageSize))).ToList();
        var from = new CaseFilter();
        foreach (var p in props)
            p.SetValue(from, p.PropertyType switch
            {
                var t when t == typeof(bool) => true,
                var t when t == typeof(string) => "x",
                var t when t == typeof(int?) => 7,
                var t when t == typeof(CaseSort) => CaseSort.Phase,
                var t when Nullable.GetUnderlyingType(t) is { IsEnum: true } e => Enum.GetValues(e).GetValue(1),
                _ => throw new InvalidOperationException($"CaseFilter.{p.Name} ({p.PropertyType.Name}): add it to CaseListQuery and this test"),
            });
        var to = new CaseFilter { Page = 3, PageSize = 50, SortDescending = false };
        from.SortDescending = true;

        CaseListQuery.CopyFilters(from, to);

        foreach (var p in props) p.GetValue(to).Should().Be(p.GetValue(from), $"CaseListQuery.CopyFilters copies {p.Name}");
        (to.Page, to.PageSize).Should().Be((3, 50));
    }

    [Fact]
    public void A_held_search_is_read_back_only_by_its_user_and_only_while_held()
    {
        var time = new ManualTime();
        var refs = new ExportSearchRefs(time);
        var id = refs.Hold("ivy", "jdoe@example.com");

        id.Should().NotContain("jdoe").And.HaveLength(32);
        refs.Hold("ivy", "jdoe@example.com").Should().Be(id, "the same search keeps its reference");
        refs.Read("ivy", id).Should().Be("jdoe@example.com");
        refs.Read("mallory", id).Should().BeNull("another user can't read it");
        refs.Read("ivy", "not-a-ref").Should().BeNull();

        time.Now += ExportSearchRefs.Lifetime + TimeSpan.FromMinutes(1);
        refs.Read("ivy", id).Should().BeNull("it lapses");
    }

    [Fact]
    public void A_user_holds_only_a_few_searches_at_once()
    {
        var refs = new ExportSearchRefs(new ManualTime());
        var first = refs.Hold("ivy", "search 0");
        for (var i = 1; i <= ExportSearchRefs.PerUser; i++) refs.Hold("ivy", $"search {i}");
        refs.Read("ivy", first).Should().BeNull("the oldest goes once the user holds the most");
    }

    [Fact]
    public void The_csv_neutralizes_formulas_and_quotes_commas(/* C13 */)
    {
        var item = new CaseListItem(Guid.NewGuid(), "IRP-2026-001", "=HYPERLINK(\"http://x\"),ok", Classification.Incident, CasePhase.Triage,
            Severity.High, CaseOrigin.InternalDetection, false, false, false, DateTimeOffset.UnixEpoch, null, null, null, null,
            OwnerName: "@ivy");
        var csv = CaseListCsv.Build([item], DateTimeOffset.UnixEpoch, false, _ => "Incident", _ => "Triage", _ => "High", _ => "");
        var row = csv.Split("\r\n")[2];
        row.Should().Contain("\"'=HYPERLINK(\"\"http://x\"\"),ok\"").And.Contain(",'@ivy,");
    }

    private sealed class ManualTime : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = new(2026, 10, 18, 12, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => Now;
    }
}
