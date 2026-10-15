using FluentAssertions;
using IncidentManager.Application.Security;
using IncidentManager.Web.Siem;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>F-18: the Windows Event Log transport's mapping and gating (no real Event Log writes).</summary>
public class EventLogTransportTests
{
    private static SecurityEvent Event(SecuritySeverity sev, SecurityOutcome outcome) => new()
    {
        EventId = 5301, Category = "DataAccess", Action = "CaseOpen", Severity = sev, Outcome = outcome,
        Actor = "analyst1", CaseNumber = "2026-01_Phish",
    };

    [Theory]
    [InlineData(SecuritySeverity.Info, SecurityOutcome.Success, EventLogLevel.Information)]
    [InlineData(SecuritySeverity.Info, SecurityOutcome.Deny, EventLogLevel.Warning)]
    [InlineData(SecuritySeverity.Warning, SecurityOutcome.Success, EventLogLevel.Warning)]
    [InlineData(SecuritySeverity.Critical, SecurityOutcome.Success, EventLogLevel.Error)]
    public void Severity_and_outcome_pick_the_entry_type(SecuritySeverity sev, SecurityOutcome outcome, EventLogLevel expected)
    {
        EventLogTransport.Map(Event(sev, outcome)).Level.Should().Be(expected);
    }

    [Fact]
    public void The_catalog_id_is_the_event_id_and_the_message_carries_the_json_body()
    {
        var (_, id, message) = EventLogTransport.Map(Event(SecuritySeverity.Info, SecurityOutcome.Success));

        id.Should().Be(5301);
        message.Should().StartWith("DataAccess/CaseOpen Success by analyst1 on 2026-01_Phish");
        message.Should().Contain("\"eventId\":5301").And.Contain("\"action\":\"CaseOpen\"");
    }

    [Fact]
    public void A_detail_too_long_for_an_entry_is_shortened_and_the_body_stays_json(/* REV-69 */)
    {
        var big = Event(SecuritySeverity.Warning, SecurityOutcome.Deny) with { Detail = new string('\\', 40_000) };   // escapes double

        var (_, _, message) = EventLogTransport.Map(big);

        message.Length.Should().BeLessThanOrEqualTo(EventLogTransport.MaxMessage);
        var json = message[(message.IndexOf('\n') + 1)..];
        System.Text.Json.JsonDocument.Parse(json).RootElement.GetProperty("detail").GetString().Should().EndWith("(shortened)");
    }

    private static EventLogTransport Seamed(Action<SiemEventLogOptions, SecurityEvent> write, bool sourceRegistered) =>
        new(new TestOptionsMonitor<SiemEventLogOptions>(new() { Enabled = true }), NullLogger<EventLogTransport>.Instance,
            write, _ => sourceRegistered);

    [Fact]
    public async Task The_test_send_reports_a_missing_source_instead_of_delivered(/* BUG-548 */)
    {
        var t = Seamed((_, _) => throw new System.Security.SecurityException("The source was not found."), sourceRegistered: false);

        var reason = await t.SendTestAsync(Event(SecuritySeverity.Info, SecurityOutcome.Success), default);

        reason.Should().Contain("CaseBook").And.Contain("New-EventLog");
        t.Enabled.Should().BeFalse("a missing source turns delivery off, as a real send does");
    }

    [Fact]
    public async Task The_test_send_reports_a_refused_entry_and_stays_on(/* BUG-548 */)
    {
        var t = Seamed((_, _) => throw new InvalidOperationException("Log full."), sourceRegistered: true);

        var reason = await t.SendTestAsync(Event(SecuritySeverity.Info, SecurityOutcome.Success), default);

        reason.Should().Contain("Log full.");
        t.Enabled.Should().BeTrue("REV-69: one refused entry doesn't stop later events");
    }

    [Fact]
    public async Task The_test_send_is_delivered_when_the_entry_is_written(/* BUG-548 */)
    {
        var written = new List<SecurityEvent>();
        var t = Seamed((_, e) => written.Add(e), sourceRegistered: true);

        (await t.SendTestAsync(Event(SecuritySeverity.Info, SecurityOutcome.Success), default)).Should().BeNull();
        await t.SendAsync(Event(SecuritySeverity.Info, SecurityOutcome.Success), default);

        written.Should().HaveCount(2, "the test and a real send share one write");
    }

    [Fact]
    public void It_is_off_unless_enabled()
    {
        var off = new EventLogTransport(new TestOptionsMonitor<SiemEventLogOptions>(new()), NullLogger<EventLogTransport>.Instance);
        off.Enabled.Should().BeFalse();
        off.Name.Should().Be("eventlog");
    }
}
