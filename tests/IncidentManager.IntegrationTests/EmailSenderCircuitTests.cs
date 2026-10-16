using System.Net;
using System.Net.Sockets;
using System.Text;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Infrastructure.Notifications;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// BUG-607: the send let through as the probe when a relay's back-off ends hands its turn back however it ends. One that
/// reported neither "answered" nor "not answering" (no valid address, a bad From, the caller cancelling, a refusal) held
/// the turn for ten minutes, and every email meanwhile, critical-alert retries included, failed fast.
/// </summary>
public sealed class EmailSenderCircuitTests
{
    private sealed class ManualTime : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = new(2026, 10, 16, 9, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private static EmailOptions Options(int port, string from = "casebook@example.test") => new()
    {
        Enabled = true, SmtpHost = "127.0.0.1", SmtpPort = port, EnableSsl = false, From = from
    };

    // Backs the relay off, then lets the back-off run out: the next send is the probe.
    private static void BackOffAndExpire(OutboundCircuit circuit, ManualTime time, EmailOptions o)
    {
        var target = EmailSender.Target(o);
        for (var i = 0; i < 10 && circuit.TryEnter(target); i++) circuit.Failed(target);
        circuit.TryEnter(target).Should().BeFalse("the relay is backed off");
        time.Now += OutboundCircuit.MaxBackOff;
    }

    private static int ClosedPort()
    {
        using var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        return ((IPEndPoint)l.LocalEndpoint).Port;
    }

    [Theory]
    [InlineData("not an address", "casebook@example.test")]   // none of the recipients parses
    [InlineData("legal@example.test", "not an address")]      // the From doesn't
    public async Task A_probe_that_fails_before_sending_hands_the_turn_back(string to, string from)
    {
        var time = new ManualTime();
        var circuit = new OutboundCircuit(time);
        var o = Options(ClosedPort(), from);
        var sender = new EmailSender(new TestOptionsMonitor<EmailOptions>(o), NullLogger<EmailSender>.Instance, circuit);
        BackOffAndExpire(circuit, time, o);

        using (var watch = DeliveryWatch.Begin())
        {
            await sender.SendAsync([to], "Breach", "b");
            watch.Failed.Should().BeTrue();
        }

        circuit.TryEnter(EmailSender.Target(o)).Should().BeTrue("nothing reached the relay, so the next send is the probe");
    }

    [Fact]
    public async Task A_probe_the_caller_cancelled_hands_the_turn_back()
    {
        using var relay = new TcpListener(IPAddress.Loopback, 0);
        relay.Start();   // accepts, never greets
        var time = new ManualTime();
        var circuit = new OutboundCircuit(time);
        var o = Options(((IPEndPoint)relay.LocalEndpoint).Port);
        var sender = new EmailSender(new TestOptionsMonitor<EmailOptions>(o), NullLogger<EmailSender>.Instance, circuit);
        BackOffAndExpire(circuit, time, o);

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
        await sender.SendAsync(["legal@example.test"], "Breach", "b", cts.Token);

        circuit.TryEnter(EmailSender.Target(o)).Should().BeTrue("a cancelled send says nothing about the relay");
    }

    [Fact]
    public async Task A_probe_the_relay_refused_ends_the_back_off()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var stop = new CancellationTokenSource();
        var relay = RefusingRelayAsync(listener, stop.Token);
        var time = new ManualTime();
        var circuit = new OutboundCircuit(time);
        var o = Options(((IPEndPoint)listener.LocalEndpoint).Port);
        var sender = new EmailSender(new TestOptionsMonitor<EmailOptions>(o), NullLogger<EmailSender>.Instance, circuit);
        BackOffAndExpire(circuit, time, o);

        using (var watch = DeliveryWatch.Begin())
        {
            await sender.SendAsync(["legal@example.test"], "Breach", "b");
            watch.Failed.Should().BeTrue();
        }

        circuit.TryEnter(EmailSender.Target(o)).Should().BeTrue("it answered (auth required): it isn't hung");
        circuit.TryEnter(EmailSender.Target(o)).Should().BeTrue("and the back-off is over, not just the probe's turn");
        await stop.CancelAsync();
        try { await relay; } catch (OperationCanceledException) { /* stopped */ }
    }

    [Fact]
    public async Task A_probe_that_cant_reach_the_relay_backs_it_off_again()
    {
        var time = new ManualTime();
        var circuit = new OutboundCircuit(time);
        var o = Options(ClosedPort());
        var sender = new EmailSender(new TestOptionsMonitor<EmailOptions>(o), NullLogger<EmailSender>.Instance, circuit);
        BackOffAndExpire(circuit, time, o);

        using (var watch = DeliveryWatch.Begin()) await sender.SendAsync(["legal@example.test"], "Breach", "b");

        circuit.TryEnter(EmailSender.Target(o)).Should().BeFalse("connection refused: backed off again");
    }

    // Greets, then refuses the sender: "530 authentication required".
    private static async Task RefusingRelayAsync(TcpListener listener, CancellationToken ct)
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
                if (cmd.StartsWith("MAIL FROM", StringComparison.Ordinal)) await writer.WriteLineAsync("530 5.7.0 Authentication required");
                else if (cmd == "QUIT") { await writer.WriteLineAsync("221 Bye"); break; }
                else await writer.WriteLineAsync("250 relay.test");
            }
        }
    }
}
