using FluentAssertions;
using IncidentManager.Application.Import;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// BUG-636: a case-import document's times written without an offset are read in a stated zone: the document's own
/// "timeZone", else the one the import page offers (the organization's), else UTC as the API's contract says. A time with
/// an offset or a Z keeps it. BUG-635: "exercise" makes the new case a tabletop case.
/// </summary>
public sealed class CaseImportTimeZoneTests
{
    private static readonly TimeZoneInfo Eastern = TimeZoneInfo.FindSystemTimeZoneById("America/New_York");

    private static string Doc(string occurred, string? timeZone = null) => $$"""
        {
          "format": "casebook-case-import", "schemaVersion": 1,
          {{(timeZone is null ? "" : $"\"timeZone\": \"{timeZone}\",")}}
          "target": { "newCase": { "title": "Zone test", "severity": "Medium", "exercise": true } },
          "timeline": [ { "occurredAtUtc": "{{occurred}}", "kind": "Investigation", "type": "Analysis", "description": "x" } ]
        }
        """;

    private static DateTimeOffset Occurred(CaseImportParse p) => p.Document!.Timeline![0].OccurredAtUtc!.Value;

    [Fact]
    public void A_time_without_an_offset_is_utc_when_nothing_says_otherwise()
    {
        var p = CaseImportService.Parse(Doc("2026-07-14T09:05:00"));

        p.Ok.Should().BeTrue();
        Occurred(p).UtcDateTime.Should().Be(new DateTime(2026, 7, 14, 9, 5, 0));
        p.UnzonedTimes.Should().Be(1);
    }

    [Fact]
    public void The_page_zone_applies_to_times_without_an_offset_including_daylight_saving()
    {
        Occurred(CaseImportService.Parse(Doc("2026-07-14T09:05:00"), Eastern)).UtcDateTime
            .Should().Be(new DateTime(2026, 7, 14, 13, 5, 0), "EDT is UTC-4");
        Occurred(CaseImportService.Parse(Doc("2026-01-14T09:05:00"), Eastern)).UtcDateTime
            .Should().Be(new DateTime(2026, 1, 14, 14, 5, 0), "EST is UTC-5");
    }

    [Fact]
    public void The_documents_own_zone_wins_and_a_stated_offset_is_never_moved()
    {
        Occurred(CaseImportService.Parse(Doc("2026-07-14T09:05:00", "Europe/London"), Eastern)).UtcDateTime
            .Should().Be(new DateTime(2026, 7, 14, 8, 5, 0), "BST is UTC+1");

        var stated = CaseImportService.Parse(Doc("2026-07-14T09:05:00-04:00"), TimeZoneInfo.Utc);
        Occurred(stated).UtcDateTime.Should().Be(new DateTime(2026, 7, 14, 13, 5, 0));
        stated.UnzonedTimes.Should().Be(0);

        Occurred(CaseImportService.Parse(Doc("2026-07-14T09:05:00Z"), Eastern)).UtcDateTime
            .Should().Be(new DateTime(2026, 7, 14, 9, 5, 0), "Z is UTC whatever the page offers");
    }

    [Fact]
    public void An_unknown_zone_is_refused_with_a_clear_message()
    {
        var p = CaseImportService.Parse(Doc("2026-07-14T09:05:00", "Eastern Daylight Moon Time"));

        p.Ok.Should().BeFalse();
        p.Error.Should().Contain("Unknown \"timeZone\"").And.Contain("America/New_York");
    }

    [Fact]
    public void Times_in_the_daylight_saving_changes_are_read_without_throwing()
    {
        // 2026-03-08 02:30 doesn't exist in New York (clocks jump 02:00 to 03:00); it lands just after the jump.
        Occurred(CaseImportService.Parse(Doc("2026-03-08T02:30:00"), Eastern)).UtcDateTime
            .Should().Be(new DateTime(2026, 3, 8, 7, 30, 0));
        // 2026-11-01 01:30 happens twice; the later (standard-time) one.
        Occurred(CaseImportService.Parse(Doc("2026-11-01T01:30:00"), Eastern)).UtcDateTime
            .Should().Be(new DateTime(2026, 11, 1, 6, 30, 0));
    }

    [Fact]
    public void The_converter_says_which_zone_times_were_read_in()
    {
        var c = IocImportConverter.Convert(Doc("2026-07-14T09:05:00"), unzonedIn: Eastern);

        c.Ok.Should().BeTrue();
        c.Notes.Should().ContainSingle().Which.Should().Contain("1 time has no time zone").And.Contain("America/New_York");
    }

    [Theory]   // BUG-662: the schema allows what the importer reads (RFC 3339 "date-time" refused a time without an offset)
    [InlineData("2026-07-14T09:05:00Z", true)]
    [InlineData("2026-07-14T09:05:00-04:00", true)]
    [InlineData("2026-07-14T09:05:00", true)]
    [InlineData("2026-07-14T09:05", true)]
    [InlineData("2026-07-14T09:05:00.1234567+01:00", true)]
    [InlineData("2026-07-14", true)]
    [InlineData("14/07/2026 09:05", false)]
    [InlineData("2026-07-14 09:05", false)]
    public void The_schema_date_pattern_matches_what_the_importer_reads(string value, bool allowed)
    {
        var pattern = CaseImportSchema.Root()["$defs"]!["timelineEntry"]!["properties"]!["occurredAtUtc"]!["pattern"]!.GetValue<string>();

        System.Text.RegularExpressions.Regex.IsMatch(value, pattern).Should().Be(allowed);
        if (allowed)
            CaseImportService.Parse(Doc(value)).Ok.Should().BeTrue($"the importer reads {value}");
    }

    // BUG-663: the preferred names, the old "...Utc" ones still read, and a document can't give both.
    [Fact]
    public void Times_can_use_the_preferred_names_or_the_old_ones_but_not_both()
    {
        const string preferred = """
            { "format": "casebook-case-import", "schemaVersion": 1, "timeZone": "America/New_York",
              "target": { "newCase": { "title": "t", "detectedAt": "2026-07-14T09:00:00", "occurredAt": "2026-07-14T08:00:00" } },
              "timeline": [ { "occurredAt": "2026-07-14T09:05:00", "timePrecision": "Window", "occurredUntil": "2026-07-16T00:00:00", "kind": "Event", "description": "x" } ],
              "actionItems": [ { "title": "y", "dueAt": "2026-07-20T17:00:00" } ] }
            """;
        var d = CaseImportService.Parse(preferred).Document!;
        d.Target!.NewCase!.DetectedAtUtc!.Value.UtcDateTime.Should().Be(new DateTime(2026, 7, 14, 13, 0, 0));
        d.Target.NewCase.OccurredAtUtc!.Value.UtcDateTime.Should().Be(new DateTime(2026, 7, 14, 12, 0, 0));
        d.Timeline![0].OccurredAtUtc!.Value.UtcDateTime.Should().Be(new DateTime(2026, 7, 14, 13, 5, 0));
        d.Timeline[0].OccurredUntilUtc!.Value.UtcDateTime.Should().Be(new DateTime(2026, 7, 16, 4, 0, 0));
        d.ActionItems![0].DueAtUtc!.Value.UtcDateTime.Should().Be(new DateTime(2026, 7, 20, 21, 0, 0));

        Occurred(CaseImportService.Parse(Doc("2026-07-14T09:05:00Z"))).UtcDateTime
            .Should().Be(new DateTime(2026, 7, 14, 9, 5, 0), "the old name is still read");

        var both = CaseImportService.Parse("""
            { "format": "casebook-case-import", "schemaVersion": 1,
              "timeline": [ { "occurredAt": "2026-07-14T09:05:00Z", "occurredAtUtc": "2026-07-14T13:05:00Z", "description": "x" } ] }
            """);
        both.Ok.Should().BeFalse();
        both.Error.Should().Contain("Timeline entry 1").And.Contain("\"occurredAt\"").And.Contain("\"occurredAtUtc\"");
    }

    [Fact]
    public void The_ai_prompt_uses_only_the_preferred_names()
    {
        var prompt = CaseImportPrompt.Build(new CaseImportPromptOptions(TimeZone: "America/New_York"));

        prompt.Should().NotContain("AtUtc").And.NotContain("UntilUtc");
        prompt.Should().Contain("\"occurredAt\"").And.Contain("\"dueAt\"").And.Contain("America/New_York");
    }

    [Fact]
    public void Exercise_in_the_document_is_read()
    {
        CaseImportService.Parse(Doc("2026-07-14T09:05:00Z")).Document!.Target!.NewCase!.Exercise.Should().BeTrue();
    }
}
