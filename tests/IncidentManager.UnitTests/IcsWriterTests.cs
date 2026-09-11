using FluentAssertions;
using IncidentManager.Application.Work;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>E-39: the ICS writer emits a well-formed VCALENDAR with UTC stamps and RFC-5545 escaping.</summary>
public class IcsWriterTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 10, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Writes_a_vcalendar_envelope_with_one_event_per_item()
    {
        var ics = IcsWriter.Write("My items",
        [
            new IcsEvent("i1@casebook", Now.AddDays(1), "[2026-01] Patch box", "Case A", "https://cb.example/cases/1", Overdue: false),
        ], Now);

        ics.Should().StartWith("BEGIN:VCALENDAR\r\n").And.EndWith("END:VCALENDAR\r\n");
        ics.Should().Contain("VERSION:2.0").And.Contain("PRODID:-//CaseBook//Agenda//EN");
        ics.Should().Contain("BEGIN:VEVENT").And.Contain("END:VEVENT");
        ics.Should().Contain("UID:i1@casebook");
        ics.Should().Contain("DTSTART:20260911T120000Z");
        ics.Should().Contain("DTEND:20260911T123000Z");   // 30-minute nominal block
        ics.Should().Contain("SUMMARY:[2026-01] Patch box");
        ics.Should().Contain("URL:https://cb.example/cases/1");
    }

    [Fact]
    public void Marks_overdue_items_with_a_category()
    {
        var ics = IcsWriter.Write("x", [new IcsEvent("i1", Now.AddDays(-1), "late", null, null, Overdue: true)], Now);
        ics.Should().Contain("CATEGORIES:OVERDUE");
    }

    [Fact]
    public void Escapes_special_characters_in_text()
    {
        var ics = IcsWriter.Write("x",
            [new IcsEvent("i1", Now, "Alpha; Beta, Gamma\\Delta\nNext", "d", null, false)], Now);

        ics.Should().Contain("SUMMARY:Alpha\\; Beta\\, Gamma\\\\Delta\\nNext");
    }

    [Fact]
    public void Omits_optional_lines_when_absent()
    {
        var ics = IcsWriter.Write("x", [new IcsEvent("i1", Now, "s", null, null, false)], Now);

        ics.Should().NotContain("DESCRIPTION:");
        ics.Should().NotContain("URL:");
        ics.Should().NotContain("CATEGORIES:");
    }
}
