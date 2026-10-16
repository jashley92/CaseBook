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
    public async Task With_email_off_a_send_isnt_counted_as_delivered(/* WF-21 */)
    {
        var sender = new EmailSender(new Monitor(new EmailOptions { Enabled = false }), NullLogger<EmailSender>.Instance);

        using var watch = DeliveryWatch.Begin();
        await sender.SendAsync(["a@x.example"], "Reminder", "Body");

        watch.Failed.Should().BeTrue("a scan holds its reminder until email is on again");
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

    [Fact]
    public async Task After_a_relay_stalls_sends_fail_fast_and_are_held_for_retry_but_a_test_send_still_tries(/* BUG-576 */)
    {
        using var relay = new TcpListener(IPAddress.Loopback, 0);
        relay.Start();   // accepts connections, never sends the SMTP greeting
        var port = ((IPEndPoint)relay.LocalEndpoint).Port;
        var held = new List<TcpClient>();
        using var stop = new CancellationTokenSource();
        var accepting = Task.Run(async () =>
        {
            try { while (true) { var c = await relay.AcceptTcpClientAsync(stop.Token); lock (held) held.Add(c); } }
            catch (OperationCanceledException) { /* done */ }
        });
        int Connections() { lock (held) return held.Count; }
        var was = EmailSender.SendTimeout;
        EmailSender.SendTimeout = TimeSpan.FromSeconds(1);
        try
        {
            var sender = new EmailSender(new Monitor(new EmailOptions
            {
                Enabled = true, SmtpHost = "127.0.0.1", SmtpPort = port, EnableSsl = false, From = "casebook@example.test"
            }), NullLogger<EmailSender>.Instance);

            using (var first = DeliveryWatch.Begin())
            {
                await sender.SendAsync(["a@x.example"], "Assigned", "Body");
                first.Failed.Should().BeTrue();
            }
            await WaitForAsync(() => Connections() == 1);

            var started = DateTimeOffset.UtcNow;
            using (var second = DeliveryWatch.Begin())
            {
                await sender.SendAsync(["b@x.example"], "Mentioned", "Body");
                second.Failed.Should().BeTrue("a scan retries it and a breach alert goes to the outbox");
            }
            (DateTimeOffset.UtcNow - started).Should().BeLessThan(TimeSpan.FromMilliseconds(500), "the stalled relay isn't waited on again");
            await Task.Delay(200);
            Connections().Should().Be(1, "no connection is made while the relay is backed off");

            var outcome = await sender.SendTestAsync(new EmailMessage(["soc@example.test"], "Test", "<p>t</p>", "t"));
            outcome.Status.Should().Be(EmailSendStatus.Failed);
            await WaitForAsync(() => Connections() == 2);
        }
        finally
        {
            EmailSender.SendTimeout = was;
            await stop.CancelAsync();
            await accepting;
            lock (held) foreach (var c in held) c.Dispose();
        }
    }

    private static async Task WaitForAsync(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (!condition() && DateTime.UtcNow < deadline) await Task.Delay(20);
        condition().Should().BeTrue();
    }
}
