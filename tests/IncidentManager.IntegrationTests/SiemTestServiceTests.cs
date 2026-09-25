using FluentAssertions;
using IncidentManager.Application.Security;
using IncidentManager.Infrastructure.Siem;
using IncidentManager.Web.Siem;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>Diagnostics "Send test event": one labeled event per enabled transport, with a per-transport result.</summary>
public sealed class SiemTestServiceTests
{
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 9, 25, 12, 0, 0, TimeSpan.Zero));

    [Fact]
    public async Task Each_enabled_transport_gets_the_test_event_and_reports_its_result()
    {
        var ok = new FakeTransport("webhook", enabled: true, error: null);
        var bad = new FakeTransport("syslog", enabled: true, error: "Connection refused");
        var off = new FakeTransport("eventlog", enabled: false, error: null);
        var svc = new SiemTestService([ok, bad, off], new TestCurrentUser { UserId = "admin" }, _clock);

        var results = await svc.SendTestAsync();

        results.Should().HaveCount(2, "the disabled transport is skipped");
        results.Single(r => r.Transport == "Webhook").Delivered.Should().BeTrue();
        var syslog = results.Single(r => r.Transport == "Syslog (CEF)");
        syslog.Delivered.Should().BeFalse();
        syslog.Detail.Should().Be("Connection refused");
        ok.Sent.Should().ContainSingle().Which.EventId.Should().Be(SecurityEventIds.SiemTest);
        off.Sent.Should().BeEmpty();
    }

    private sealed class FakeTransport(string name, bool enabled, string? error) : ISecurityEventTransport
    {
        public List<SecurityEvent> Sent { get; } = new();
        public string Name => name;
        public bool Enabled => enabled;
        public Task SendAsync(SecurityEvent e, CancellationToken ct) { Sent.Add(e); return Task.CompletedTask; }
        public Task<string?> SendTestAsync(SecurityEvent e, CancellationToken ct) { Sent.Add(e); return Task.FromResult(error); }
    }
}
