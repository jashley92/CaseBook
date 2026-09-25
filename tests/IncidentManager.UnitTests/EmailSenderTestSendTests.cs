using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Infrastructure.Notifications;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>Admin test sends report the relay outcome instead of swallowing it like notification sends do.</summary>
public sealed class EmailSenderTestSendTests
{
    private static readonly EmailMessage Msg = new(["admin@example.com"], "Test", "<p>Hi</p>", "Hi");

    private static EmailSender Sender(EmailOptions o) =>
        new(new TestOptionsMonitor<EmailOptions>(o), NullLogger<EmailSender>.Instance);

    [Fact]
    public async Task With_delivery_off_the_test_reports_disabled()
    {
        var outcome = await Sender(new EmailOptions { Enabled = false }).SendTestAsync(Msg);
        outcome.Status.Should().Be(EmailSendStatus.Disabled);
    }

    [Fact]
    public async Task An_unreachable_relay_is_reported_with_its_reason()
    {
        // Port 1 on loopback refuses the connection straight away.
        var sender = Sender(new EmailOptions { Enabled = true, SmtpHost = "127.0.0.1", SmtpPort = 1, EnableSsl = false });

        var outcome = await sender.SendTestAsync(Msg);

        outcome.Status.Should().Be(EmailSendStatus.Failed);
        outcome.Error.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public async Task Notification_sends_still_swallow_the_same_failure()
    {
        var sender = Sender(new EmailOptions { Enabled = true, SmtpHost = "127.0.0.1", SmtpPort = 1, EnableSsl = false });
        var act = () => sender.SendAsync(Msg);
        await act.Should().NotThrowAsync();
    }
}
