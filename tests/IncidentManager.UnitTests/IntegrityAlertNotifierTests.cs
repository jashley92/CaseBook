using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Security;
using IncidentManager.Infrastructure.Notifications;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace IncidentManager.UnitTests;

public class IntegrityAlertNotifierTests
{
    private static readonly ChainVerificationResult Broken = ChainVerificationResult.Broken(42, "hash mismatch at 42");

    private sealed class CapturingEmailSender : IEmailSender
    {
        public List<(IReadOnlyCollection<string> To, string Subject, string Body)> Sent { get; } = new();
        public bool Throw { get; init; }
        public Task SendAsync(IReadOnlyCollection<string> to, string subject, string body, CancellationToken ct = default)
        {
            if (Throw) throw new InvalidOperationException("smtp down");
            Sent.Add((to, subject, body));
            return Task.CompletedTask;
        }
    }

    private sealed class NullSecurityEventSink : ISecurityEventSink
    {
        public void Emit(SecurityEvent e) { }
    }

    private static IntegrityAlertNotifier Build(CapturingEmailSender sender, params string[] recipients) =>
        new(sender, new TestOptionsMonitor<EmailOptions>(new EmailOptions { IntegrityAlertDistribution = recipients }),
            new NullSecurityEventSink(), NullLogger<IntegrityAlertNotifier>.Instance);

    [Fact]
    public async Task Emails_the_configured_integrity_distribution_on_a_break()
    {
        var sender = new CapturingEmailSender();
        var notifier = Build(sender, "secops@insurer.example");

        await notifier.OnChainBrokenAsync(Broken);

        sender.Sent.Should().ContainSingle();
        sender.Sent[0].To.Should().Contain("secops@insurer.example");
        sender.Sent[0].Subject.Should().Contain("integrity");
        sender.Sent[0].Body.Should().Contain("42");
    }

    [Fact]
    public async Task No_email_when_no_distribution_is_configured()
    {
        // The critical SIEM/log event still fires (not asserted here); email is simply skipped.
        var sender = new CapturingEmailSender();
        var notifier = Build(sender); // none configured

        await notifier.OnChainBrokenAsync(Broken);

        sender.Sent.Should().BeEmpty();
    }

    [Fact]
    public async Task A_failing_email_sender_does_not_throw()
    {
        // Contract: the notifier must never throw — a delivery failure can't be allowed to mask the break.
        var sender = new CapturingEmailSender { Throw = true };
        var notifier = Build(sender, "secops@insurer.example");

        var act = () => notifier.OnChainBrokenAsync(Broken);

        await act.Should().NotThrowAsync();
    }
}
