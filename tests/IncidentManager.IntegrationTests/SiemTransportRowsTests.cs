using FluentAssertions;
using IncidentManager.Application.Security;
using IncidentManager.Infrastructure.Siem;
using IncidentManager.Web.Siem;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// CAP-04 review: the Diagnostics delivery card picks its SIEM rows by whether a transport is switched on in its
/// settings, not by whether it's delivering, so one that stopped shows as failing with its reason instead of vanishing
/// behind "no transport is on".
/// </summary>
public class SiemTransportRowsTests
{
    private static readonly SecurityEvent Event = new()
    {
        EventId = 5301, Category = "DataAccess", Action = "CaseOpen", Severity = SecuritySeverity.Info,
        Outcome = SecurityOutcome.Success, Actor = "analyst1",
    };

    [Fact]
    public async Task An_event_log_whose_source_is_missing_stays_on_the_card_as_stopped()
    {
        var t = new EventLogTransport(new TestOptionsMonitor<SiemEventLogOptions>(new() { Enabled = true }),
            NullLogger<EventLogTransport>.Instance,
            (_, _) => throw new System.Security.SecurityException("The source was not found."), _ => false);
        SiemTransportRows.Pick([t]).Should().ContainSingle().Which.StoppedReason.Should().BeNull("it hasn't failed yet");

        await t.SendAsync(Event, default);

        t.Enabled.Should().BeFalse("a missing source stops delivery until restart");
        var row = SiemTransportRows.Pick([t]).Should().ContainSingle().Subject;
        row.Name.Should().Be("eventlog");
        row.StoppedReason.Should().StartWith("stopped until restart").And.Contain("event source 'CaseBook' missing");
    }

    [Fact]
    public void A_transport_on_without_its_address_shows_as_stopped_and_one_off_is_left_out()
    {
        var syslogNoHost = new SyslogTransport(new TestOptionsMonitor<SiemSyslogOptions>(new() { Enabled = true, Host = "" }),
            NullLogger<SyslogTransport>.Instance);
        var webhookNoUrl = new WebhookTransport(null!, new TestOptionsMonitor<SiemWebhookOptions>(new() { Enabled = true, Url = "" }),
            null!, NullLogger<WebhookTransport>.Instance);
        var webhookHttp = new WebhookTransport(null!, new TestOptionsMonitor<SiemWebhookOptions>(new() { Enabled = true, Url = "http://collector.example/x" }),
            null!, NullLogger<WebhookTransport>.Instance);
        var off = new EventLogTransport(new TestOptionsMonitor<SiemEventLogOptions>(new()), NullLogger<EventLogTransport>.Instance);

        var rows = SiemTransportRows.Pick([syslogNoHost, webhookNoUrl, webhookHttp, off]);

        rows.Select(r => r.Name).Should().Equal("syslog", "webhook", "webhook");
        rows[0].StoppedReason.Should().Contain("no collector host");
        rows[1].StoppedReason.Should().Contain("no collector URL");
        rows[2].StoppedReason.Should().Contain("refused");
    }

    [Fact]
    public void A_sending_transport_has_no_stopped_reason_and_one_whose_settings_throw_is_left_out(/* BUG-262 */)
    {
        var syslog = new SyslogTransport(new TestOptionsMonitor<SiemSyslogOptions>(new() { Enabled = true, Host = "siem.example" }),
            NullLogger<SyslogTransport>.Instance);

        SiemTransportRows.Pick([syslog, new Throwing()]).Should().ContainSingle()
            .Which.Should().Be(new SiemTransportRow("syslog", null));
    }

    private sealed class Throwing : ISecurityEventTransport
    {
        public string Name => "throws";
        public bool Enabled => throw new InvalidOperationException("bad options");
        public Task SendAsync(SecurityEvent e, CancellationToken ct) => Task.CompletedTask;
    }
}
