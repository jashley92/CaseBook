using System.Net;
using System.Net.Sockets;
using System.Text;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Infrastructure.Notifications;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>BUG-94/149: a relay that refuses some addresses delivered to the rest, so the send isn't a failure to retry.</summary>
public sealed class EmailSenderRefusedRecipientTests
{
    private sealed class Monitor(EmailOptions o) : IOptionsMonitor<EmailOptions>
    {
        public EmailOptions CurrentValue => o;
        public EmailOptions Get(string? name) => o;
        public IDisposable? OnChange(Action<EmailOptions, string?> listener) => null;
    }

    // Just enough SMTP: refuses RCPT for any address containing "gone", accepts the rest.
    private static async Task RelayAsync(TcpListener listener, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            using var client = await listener.AcceptTcpClientAsync(ct);
            using var stream = client.GetStream();
            using var reader = new StreamReader(stream, Encoding.ASCII);
            await using var writer = new StreamWriter(stream, Encoding.ASCII) { NewLine = "\r\n", AutoFlush = true };
            await writer.WriteLineAsync("220 relay.test ESMTP");
            while (await reader.ReadLineAsync(ct) is { } line)
            {
                var cmd = line.ToUpperInvariant();
                if (cmd.StartsWith("EHLO", StringComparison.Ordinal) || cmd.StartsWith("HELO", StringComparison.Ordinal)) await writer.WriteLineAsync("250 relay.test");
                else if (cmd.StartsWith("MAIL FROM", StringComparison.Ordinal)) await writer.WriteLineAsync("250 OK");
                else if (cmd.StartsWith("RCPT TO", StringComparison.Ordinal)) await writer.WriteLineAsync(cmd.Contains("GONE", StringComparison.Ordinal) ? "550 5.1.1 No such user" : "250 OK");
                else if (cmd == "DATA")
                {
                    await writer.WriteLineAsync("354 Go ahead");
                    while (await reader.ReadLineAsync(ct) is { } body && body != ".") { }
                    await writer.WriteLineAsync("250 Queued");
                }
                else if (cmd == "QUIT") { await writer.WriteLineAsync("221 Bye"); break; }
                else await writer.WriteLineAsync("250 OK");
            }
        }
    }

    [Theory]
    [InlineData(1)]   // one of three refused: SmtpClient throws the singular SmtpFailedRecipientException (BUG-149)
    [InlineData(2)]   // two of three: the plural SmtpFailedRecipientsException (BUG-94)
    public async Task Some_refused_addresses_are_a_partial_delivery_not_a_failure(int refused)
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var stop = new CancellationTokenSource();
        var relay = RelayAsync(listener, stop.Token);
        var sender = new EmailSender(new Monitor(new EmailOptions
        {
            Enabled = true, SmtpHost = "127.0.0.1", SmtpPort = ((IPEndPoint)listener.LocalEndpoint).Port, EnableSsl = false,
            From = "casebook@example.test"
        }), NullLogger<EmailSender>.Instance);
        var to = new[] { "ina@example.test", "gone1@example.test", refused == 2 ? "gone2@example.test" : "al@example.test" };

        bool failed;
        using (var watch = DeliveryWatch.Begin())
        {
            await sender.SendAsync(new EmailMessage(to, "Reminder", "<p>r</p>", "r"));
            failed = watch.Failed;
        }
        failed.Should().BeFalse("the others got it, so sending again would repeat it to them");

        using (var watch = DeliveryWatch.Begin())
        {
            await sender.SendAsync(new EmailMessage(["gone1@example.test"], "Reminder", "<p>r</p>", "r"));
            watch.Failed.Should().BeTrue("a send that reached nobody is a failure");
        }
        await stop.CancelAsync();
        try { await relay; } catch (OperationCanceledException) { }
    }
}
