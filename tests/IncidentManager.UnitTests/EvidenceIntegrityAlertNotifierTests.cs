using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Integrity;
using IncidentManager.Application.Security;
using IncidentManager.Infrastructure.Notifications;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace IncidentManager.UnitTests;

public class EvidenceIntegrityAlertNotifierTests
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 9, 0, 0, 0, TimeSpan.Zero);

    private static EvidenceVerificationResult Drift() => new(5, new[]
    {
        new EvidenceDrift(Guid.NewGuid(), Guid.NewGuid(), "2026-01_Phishing_Wave", "malware.bin",
            "aaaabbbb", "ccccdddd", EvidenceDriftKind.HashMismatch, "stored bytes hash ccccdddd… ≠ recorded aaaabbbb…")
    }, T0);

    private sealed class CapturingSecurityEventSink : ISecurityEventSink
    {
        public List<SecurityEvent> Events { get; } = new();
        public void Emit(SecurityEvent e) => Events.Add(e);
    }

    private static EvidenceIntegrityAlertNotifier Build(CapturingEmailSender sender,
        CapturingSecurityEventSink sink, params string[] recipients) =>
        new(sender, TestEmail.Composer(), TestEmail.EmptyConfig,
            new TestOptionsMonitor<EmailOptions>(new EmailOptions { IntegrityAlertDistribution = recipients }),
            sink, NullLogger<EvidenceIntegrityAlertNotifier>.Instance);

    [Fact]
    public async Task Emits_a_critical_5003_siem_event_on_drift_regardless_of_email()
    {
        var sink = new CapturingSecurityEventSink();
        var notifier = Build(new CapturingEmailSender(), sink); // no distribution configured

        await notifier.OnDriftDetectedAsync(Drift());

        var ev = sink.Events.Should().ContainSingle().Subject;
        ev.EventId.Should().Be(SecurityEventIds.EvidenceIntegrityDrift).And.Be(5003);
        ev.Severity.Should().Be(SecuritySeverity.Critical);
        ev.Category.Should().Be("Integrity");
    }

    [Fact]
    public async Task Emails_the_configured_integrity_distribution_with_the_offender_list()
    {
        var sender = new CapturingEmailSender();
        var notifier = Build(sender, new CapturingSecurityEventSink(), "secops@example.test");

        await notifier.OnDriftDetectedAsync(Drift());

        sender.Sent.Should().ContainSingle();
        sender.Sent[0].To.Should().Contain("secops@example.test");
        sender.Sent[0].Subject.Should().Contain("evidence");
        sender.Sent[0].HtmlBody.Should().Contain("malware.bin").And.Contain("2026-01_Phishing_Wave").And.Contain("<html");
    }

    [Fact]
    public async Task No_email_when_no_distribution_is_configured()
    {
        // The critical SIEM/log event still fires (asserted above); email is simply skipped.
        var sender = new CapturingEmailSender();
        var notifier = Build(sender, new CapturingSecurityEventSink()); // none configured

        await notifier.OnDriftDetectedAsync(Drift());

        sender.Sent.Should().BeEmpty();
    }

    [Fact]
    public async Task A_failing_email_sender_does_not_throw()
    {
        // Contract: the notifier must never throw — a delivery failure can't mask the drift.
        var sender = new CapturingEmailSender { Throw = true };
        var notifier = Build(sender, new CapturingSecurityEventSink(), "secops@example.test");

        var act = () => notifier.OnDriftDetectedAsync(Drift());

        await act.Should().NotThrowAsync();
    }
}
