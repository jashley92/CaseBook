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
    public void It_is_off_unless_enabled()
    {
        var off = new EventLogTransport(new TestOptionsMonitor<SiemEventLogOptions>(new()), NullLogger<EventLogTransport>.Instance);
        off.Enabled.Should().BeFalse();
        off.Name.Should().Be("eventlog");
    }
}
