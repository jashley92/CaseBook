using System.Net;
using System.Net.Sockets;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Infrastructure.Notifications;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>BUG-99: a relay that accepts the connection and then says nothing doesn't hold a send forever.</summary>
public sealed class EmailSenderTimeoutTests
{
    private sealed class Monitor(EmailOptions o) : IOptionsMonitor<EmailOptions>
    {
        public EmailOptions CurrentValue => o;
        public EmailOptions Get(string? name) => o;
        public IDisposable? OnChange(Action<EmailOptions, string?> listener) => null;
    }

    [Fact]
    public async Task A_silent_relay_fails_the_send_after_the_timeout()
    {
        using var relay = new TcpListener(IPAddress.Loopback, 0);
        relay.Start();   // accepts connections, never sends the SMTP greeting
        var port = ((IPEndPoint)relay.LocalEndpoint).Port;
        var was = EmailSender.SendTimeout;
        EmailSender.SendTimeout = TimeSpan.FromSeconds(2);
        try
        {
            var sender = new EmailSender(new Monitor(new EmailOptions
            {
                Enabled = true, SmtpHost = "127.0.0.1", SmtpPort = port, EnableSsl = false, From = "casebook@example.test"
            }), NullLogger<EmailSender>.Instance);

            var started = DateTimeOffset.UtcNow;
            var outcome = await sender.SendTestAsync(new EmailMessage(["soc@example.test"], "Test", "<p>t</p>", "t"));

            outcome.Status.Should().Be(EmailSendStatus.Failed);
            outcome.Error.Should().Contain("didn't finish");
            (DateTimeOffset.UtcNow - started).Should().BeLessThan(TimeSpan.FromSeconds(20));
        }
        finally { EmailSender.SendTimeout = was; }
    }
}
