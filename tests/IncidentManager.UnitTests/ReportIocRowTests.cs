using System.Globalization;
using FluentAssertions;
using IncidentManager.Application.Reporting;
using Xunit;

namespace IncidentManager.UnitTests;

public sealed class ReportIocRowTests
{
    [Fact]
    public void The_added_date_is_in_the_invariant_calendar_whatever_the_server_culture(/* BUG-537 */)
    {
        var row = new ReportIocRow("IP address", "203.0.113[.]7", "Malicious", null,
            new DateTimeOffset(2026, 3, 4, 23, 30, 0, TimeSpan.Zero), null, null);
        var was = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = new CultureInfo("th-TH");   // the Buddhist era: 2026 is 2569
            row.Added.Should().Be("2026-03-04");
        }
        finally { CultureInfo.CurrentCulture = was; }
    }
}
