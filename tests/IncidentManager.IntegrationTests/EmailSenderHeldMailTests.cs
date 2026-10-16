using System.Net;
using System.Net.Sockets;
using System.Text;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Infrastructure.Notifications;
using Microsoft.Extensions.Logging;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// BUG-608: while the relay is backed off, an email from a user's action (assign, mention, handoff), which nothing else
/// would try again, is held and sent when the relay answers, not dropped with a log line; a watched send (a scan, an
/// outbox retry) is reported as deferred, so the outbox doesn't spend a retry on it.
/// </summary>
public sealed class EmailSenderHeldMailTests : IDisposable
{
    private sealed class ManualTime : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = new(2026, 10, 16, 9, 0, 0, TimeSpan.Zero);
        public ManualTimer? Timer { get; private set; }
        public override DateTimeOffset GetUtcNow() => Now;
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period) =>
            Timer = new ManualTimer(callback, state);
    }

    private sealed class ManualTimer(TimerCallback callback, object? state) : ITimer
    {
        public TimeSpan? Due { get; private set; }
        public bool Change(TimeSpan dueTime, TimeSpan period)
        {
            Due = dueTime == Timeout.InfiniteTimeSpan ? null : dueTime;
            return true;
        }
        public void Fire()
        {
            Due = null;
            callback(state);
        }
        public void Dispose() { }
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class ListLogger : ILogger<EmailSender>
    {
        public readonly List<(LogLevel Level, string Message)> Entries = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            lock (Entries) Entries.Add((logLevel, formatter(state, exception)));
        }
    }

    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _relay;
    private int _delivered;
    private readonly ManualTime _time = new();
    private readonly OutboundCircuit _circuit;
    private readonly ListLogger _log = new();
    private readonly EmailSender _sender;
    private readonly string _target;

    public EmailSenderHeldMailTests()
    {
        _listener.Start();
        _relay = RelayAsync(_stop.Token);
        var o = new EmailOptions
        {
            Enabled = true, SmtpHost = "127.0.0.1", SmtpPort = ((IPEndPoint)_listener.LocalEndpoint).Port, EnableSsl = false,
            From = "casebook@example.test"
        };
        _circuit = new OutboundCircuit(_time);
        _sender = new EmailSender(new TestOptionsMonitor<EmailOptions>(o), _log, _circuit);
        _target = EmailSender.Target(o);
    }

    private int Delivered => Volatile.Read(ref _delivered);

    private void BackOff()
    {
        for (var i = 0; i < OutboundCircuit.FailuresToOpen; i++) _circuit.Failed(_target);
        _circuit.TryEnter(_target).Should().BeFalse();
    }

    [Fact]
    public async Task A_user_actions_email_is_held_while_the_relay_is_backed_off_and_sent_when_it_answers()
    {
        BackOff();

        await _sender.SendAsync(["assignee@example.test"], "Case assigned to you", "b");   // no watch: a user's action
        _sender.HeldCount.Should().Be(1);
        Delivered.Should().Be(0, "nothing is sent while the relay is backed off");
        _time.Timer!.Due.Should().Be(OutboundCircuit.FirstBackOff, "it's tried when the back-off ends");

        await _sender.DrainHeldAsync();
        Delivered.Should().Be(0, "still backed off: it stays held");
        _sender.HeldCount.Should().Be(1);

        _time.Now += OutboundCircuit.FirstBackOff;
        _time.Timer.Fire();
        await WaitForAsync(() => Delivered == 1);
        _sender.HeldCount.Should().Be(0);
        _circuit.TryEnter(_target).Should().BeTrue("the held email was the probe, and it went");
    }

    [Fact]
    public async Task A_watched_send_isnt_held_but_reported_as_deferred()
    {
        BackOff();

        using (var watch = DeliveryWatch.Begin())
        {
            await _sender.SendAsync(["legal@example.test"], "Breach", "b");
            watch.Failed.Should().BeTrue("a scan retries it");
            watch.Deferred.Should().BeTrue("nothing was tried, so an outbox doesn't spend a retry");
        }
        _sender.HeldCount.Should().Be(0, "its caller tries it again; holding it too would send it twice");
    }

    [Fact]
    public async Task Held_mail_goes_as_soon_as_the_relay_answers_again()
    {
        BackOff();
        await _sender.SendAsync(["a@example.test"], "Mentioned", "b");
        await _sender.SendAsync(["b@example.test"], "Handed over", "b");
        _sender.HeldCount.Should().Be(2);

        _time.Now += TimeSpan.FromSeconds(10);
        (await _sender.SendTestAsync(new EmailMessage(["admin@example.test"], "Test", "<p>t</p>", "t"))).Status
            .Should().Be(EmailSendStatus.Sent, "the admin's test always tries, and the relay answers: the back-off is over");
        _time.Timer!.Due.Should().Be(TimeSpan.Zero, "the held mail is sent straight after, not when the back-off would have ended");
        _time.Timer.Fire();
        await WaitForAsync(() => Delivered == 3);
        _sender.HeldCount.Should().Be(0);
    }

    [Fact]
    public async Task Held_mail_goes_straight_after_any_send_that_gets_through()
    {
        BackOff();
        await _sender.SendAsync(["a@example.test"], "Mentioned", "b");
        _circuit.Succeeded(_target);   // the chat test button, say, or a corrected relay that answered

        _time.Now += TimeSpan.FromSeconds(10);
        await _sender.SendAsync(["b@example.test"], "Handed over", "b");
        Delivered.Should().Be(1);
        _time.Timer!.Due.Should().Be(TimeSpan.Zero);
        _time.Timer.Fire();
        await WaitForAsync(() => Delivered == 2);
    }

    [Fact]
    public async Task Past_the_limit_the_newest_is_dropped_and_logged()
    {
        BackOff();
        for (var i = 0; i <= EmailSender.MaxHeld; i++) await _sender.SendAsync([$"u{i}@example.test"], "Assigned", "b");

        _sender.HeldCount.Should().Be(EmailSender.MaxHeld);
        lock (_log.Entries)
            _log.Entries.Should().ContainSingle(e => e.Level == LogLevel.Error && e.Message.Contains("was dropped", StringComparison.Ordinal));
    }

    [Fact]
    public async Task One_dropped_connection_doesnt_hold_anything(/* the back-off needs three in a row */)
    {
        _circuit.Failed(_target);
        await _sender.SendAsync(["assignee@example.test"], "Case assigned to you", "b");
        Delivered.Should().Be(1);
        _sender.HeldCount.Should().Be(0);
    }

    private static async Task WaitForAsync(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (!condition() && DateTime.UtcNow < deadline) await Task.Delay(20);
        condition().Should().BeTrue();
    }

    // Just enough SMTP to take a message; counts the messages taken.
    private async Task RelayAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                using var client = await _listener.AcceptTcpClientAsync(ct);
                using var stream = client.GetStream();
                using var reader = new StreamReader(stream, Encoding.ASCII);
                await using var writer = new StreamWriter(stream, Encoding.ASCII) { NewLine = "\r\n", AutoFlush = true };
                await writer.WriteLineAsync("220 relay.test ESMTP");
                while (await reader.ReadLineAsync(ct) is { } line)
                {
                    var cmd = line.ToUpperInvariant();
                    if (cmd == "DATA")
                    {
                        await writer.WriteLineAsync("354 Go ahead");
                        while (await reader.ReadLineAsync(ct) is { } body && body != ".") { }
                        Interlocked.Increment(ref _delivered);
                        await writer.WriteLineAsync("250 Queued");
                    }
                    else if (cmd == "QUIT") { await writer.WriteLineAsync("221 Bye"); break; }
                    else await writer.WriteLineAsync("250 relay.test");
                }
            }
        }
        catch (OperationCanceledException) { /* stopped */ }
    }

    public void Dispose()
    {
        _stop.Cancel();
        try { _relay.Wait(TimeSpan.FromSeconds(5)); } catch (AggregateException) { /* stopped */ }
        _listener.Stop();
        _listener.Dispose();
        _stop.Dispose();
        _sender.Dispose();
    }
}
