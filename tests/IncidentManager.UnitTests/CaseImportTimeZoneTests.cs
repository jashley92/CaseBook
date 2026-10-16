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

    [Fact]
    public void Exercise_in_the_document_is_read()
    {
        CaseImportService.Parse(Doc("2026-07-14T09:05:00Z")).Document!.Target!.NewCase!.Exercise.Should().BeTrue();
    }
}
