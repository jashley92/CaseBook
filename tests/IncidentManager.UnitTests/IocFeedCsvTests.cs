using FluentAssertions;
using IncidentManager.Application.Export;
using IncidentManager.Domain.Enums;
using Xunit;

namespace IncidentManager.UnitTests;

public class IocFeedCsvTests
{
    private static readonly DateTimeOffset At = new(2026, 8, 14, 9, 5, 0, TimeSpan.Zero);

    [Fact]
    public void Header_row_and_short_feed_type_terms_are_emitted()
    {
        var rows = new[]
        {
            new IocFeedRow(EntityType.IpAddress, "203.0.113.10",
                new DateTimeOffset(2026, 8, 1, 0, 0, 0, TimeSpan.Zero),
                new DateTimeOffset(2026, 8, 10, 0, 0, 0, TimeSpan.Zero),
                new[] { "2026-0001" }, new[] { "SIEM" }),
            new IocFeedRow(EntityType.FileHash, "abc123",
                At, At, new[] { "2026-0002" }, Array.Empty<string>()),
        };

        var csv = IocFeedCsv.Build(rows, At);
        var lines = csv.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);

        lines[0].Should().StartWith("# CaseBook malicious-IOC feed");
        lines[1].Should().Be("type,indicator,disposition,first_seen_utc,last_seen_utc,case_count,cases,sources");
        csv.Should().Contain("ip,203.0.113.10,malicious,2026-08-01 00:00:00,2026-08-10 00:00:00,1,2026-0001,SIEM");
        csv.Should().Contain("filehash,abc123,malicious,");
    }

    [Fact]
    public void Multiple_cases_and_sources_are_semicolon_joined_and_quoted()
    {
        var rows = new[]
        {
            new IocFeedRow(EntityType.Domain, "evil.example", At, At,
                new[] { "2026-0001", "2026-0007" }, new[] { "SIEM", "EDR" }),
        };

        var csv = IocFeedCsv.Build(rows, At);

        // A field containing a comma-free "; " list still needs no quoting; assert the join shape.
        csv.Should().Contain("domain,evil.example,malicious,");
        csv.Should().Contain("2,2026-0001; 2026-0007,SIEM; EDR");
    }

    [Fact]
    public void A_value_containing_a_comma_is_rfc4180_quoted()
    {
        var rows = new[]
        {
            new IocFeedRow(EntityType.Url, "http://evil.example/a,b", At, At,
                new[] { "2026-0001" }, Array.Empty<string>()),
        };

        var csv = IocFeedCsv.Build(rows, At);
        csv.Should().Contain("url,\"http://evil.example/a,b\",malicious,");
    }

    [Fact]
    public void A_formula_injection_indicator_is_neutralised_as_text()
    {
        // S-01: an analyst may record an adversary-chosen indicator crafted as a spreadsheet formula.
        // It must reach the CSV as inert text (apostrophe-guarded), not a live =HYPERLINK/WEBSERVICE call.
        var rows = new[]
        {
            new IocFeedRow(EntityType.Domain, "=HYPERLINK(\"http://x\")", At, At,
                new[] { "2026-0001" }, Array.Empty<string>()),
        };

        var csv = IocFeedCsv.Build(rows, At);
        // Guarded with a leading ' and, because the value carries quotes, RFC-4180 quoted with doubling.
        csv.Should().Contain("domain,\"'=HYPERLINK(\"\"http://x\"\")\",malicious,");
    }
}
