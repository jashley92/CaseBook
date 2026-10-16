using System.Net;
using System.Net.Sockets;
using System.Text;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
using IncidentManager.Infrastructure.Notifications;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// BUG-608: while the relay is backed off, an email from a user's action (assign, mention, handoff), which nothing else
/// would try again, is held and sent when the relay answers, not dropped with a log line; a watched send (a scan, an
/// outbox retry) is reported as deferred, so the outbox doesn't spend a retry on it.
/// BUG-617 (C20): held in the database, so a restart doesn't lose it; removed only once it went, was refused for good or
/// was given up after its tries; and held too when a send that was tried didn't reach the relay or was turned away for
/// now (BUG-626: a 4xx), not only while the relay is backed off.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1001", Justification = "The listener and token source are disposed in DisposeAsync (IAsyncLifetime).")]
public sealed class EmailSenderHeldMailTests : IAsyncLifetime
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
        public bool Has(LogLevel level, string text)
        {
            lock (Entries) return Entries.Exists(e => e.Level == level && e.Message.Contains(text, StringComparison.Ordinal));
        }
    }

    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _relay;
    private int _delivered;
    private readonly ManualTime _time = new();
    private readonly OutboundCircuit _circuit;
    private readonly ListLogger _log = new();
    private readonly EmailOptions _options;
    private readonly EmailSender _sender;
    private readonly string _target;
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"casebook-heldmail-{Guid.NewGuid():N}.db");
    private readonly ServiceProvider _services;

    // What the relay does: take mail, drop the connection at once, or answer every RCPT (except to fine@) with a code.
    private volatile string _mode = "ok";

    public EmailSenderHeldMailTests()
    {
        _listener.Start();
        _relay = RelayAsync(_stop.Token);
        _options = new EmailOptions
        {
            Enabled = true, SmtpHost = "127.0.0.1", SmtpPort = ((IPEndPoint)_listener.LocalEndpoint).Port, EnableSsl = false,
            From = "casebook@example.test"
        };
        // A file, not :memory:, so the drain (on its timer) and the test each get their own connection.
        _services = new ServiceCollection()
            .AddDbContextFactory<AppDbContext>(o => o.UseSqlite($"Data Source={_dbPath};Pooling=False"))
            .BuildServiceProvider();
        using (var db = _services.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContext()) db.Database.EnsureCreated();
        _circuit = new OutboundCircuit(_time);
        _sender = NewSender(_circuit);
        _target = EmailSender.Target(_options);
    }

    private EmailSender NewSender(OutboundCircuit circuit) =>
        new(new TestOptionsMonitor<EmailOptions>(_options), _log, circuit, _services.GetRequiredService<IServiceScopeFactory>());

    // The sender looks for mail held before a restart when it starts; here there's none.
    public Task InitializeAsync() => _sender.DrainHeldAsync();

    private int Delivered => Volatile.Read(ref _delivered);

    private Task<int> Held => _sender.HeldCountAsync();

    private async Task<List<HeldEmail>> HeldRowsAsync()
    {
        await using var db = await _services.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContextAsync();
        return await db.HeldEmails.AsNoTracking().OrderBy(h => h.Id).ToListAsync();
    }

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
        (await Held).Should().Be(1);
        Delivered.Should().Be(0, "nothing is sent while the relay is backed off");
        _time.Timer!.Due.Should().Be(OutboundCircuit.FirstBackOff, "it's tried when the back-off ends");

        await _sender.DrainHeldAsync();
        Delivered.Should().Be(0, "still backed off: it stays held");
        (await Held).Should().Be(1);

        _time.Now += OutboundCircuit.FirstBackOff;
        _time.Timer.Fire();
        await WaitForAsync(() => Delivered == 1);
        await WaitForAsync(async () => await Held == 0);
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
        (await Held).Should().Be(0, "its caller tries it again; holding it too would send it twice");
    }

    [Fact]
    public async Task A_watched_send_that_fails_isnt_held_either(/* BUG-617 */)
    {
        _mode = "drop";
        using (var watch = DeliveryWatch.Begin())
        {
            await _sender.SendAsync(["legal@example.test"], "Breach", "b");
            watch.Failed.Should().BeTrue();
        }
        (await Held).Should().Be(0, "its caller tries it again");
    }

    [Fact]
    public async Task Held_mail_goes_as_soon_as_the_relay_answers_again()
    {
        BackOff();
        await _sender.SendAsync(["a@example.test"], "Mentioned", "b");
        await _sender.SendAsync(["b@example.test"], "Handed over", "b");
        (await Held).Should().Be(2);

        _time.Now += TimeSpan.FromSeconds(10);
        (await _sender.SendTestAsync(new EmailMessage(["admin@example.test"], "Test", "<p>t</p>", "t"))).Status
            .Should().Be(EmailSendStatus.Sent, "the admin's test always tries, and the relay answers: the back-off is over");
        _time.Timer!.Due.Should().Be(TimeSpan.Zero, "the held mail is sent straight after, not when the back-off would have ended");
        _time.Timer.Fire();
        await WaitForAsync(() => Delivered == 3);
        await WaitForAsync(async () => await Held == 0);
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

        (await Held).Should().Be(EmailSender.MaxHeld);
        lock (_log.Entries)
            _log.Entries.Should().ContainSingle(e => e.Level == LogLevel.Error && e.Message.Contains("was dropped", StringComparison.Ordinal));
    }

    [Fact]
    public async Task One_dropped_connection_doesnt_hold_anything(/* the back-off needs three in a row */)
    {
        _circuit.Failed(_target);
        await _sender.SendAsync(["assignee@example.test"], "Case assigned to you", "b");
        Delivered.Should().Be(1);
        (await Held).Should().Be(0);
    }

    [Fact]
    public async Task A_drain_with_the_relay_still_down_keeps_every_held_email(/* BUG-617 */)
    {
        BackOff();
        await _sender.SendAsync(["a@example.test"], "Mentioned", "b");
        await _sender.SendAsync(["b@example.test"], "Assigned", "b");
        await _sender.SendAsync(["c@example.test"], "Handed over", "b");

        // The back-off ends and the drain's probe goes to a relay that's still down.
        _mode = "drop";
        _time.Now += OutboundCircuit.FirstBackOff;
        await _sender.DrainHeldAsync();
        var rows = await HeldRowsAsync();
        rows.Should().HaveCount(3, "the one tried wasn't sent, so it's kept (it was taken off before the try)");
        rows[0].RecipientList.Should().Equal("a@example.test");
        rows[0].Attempts.Should().Be(0, "it was tried, but a relay that's down doesn't use up a try (BUG-640)");
        _time.Timer!.Due.Should().BeGreaterThan(TimeSpan.Zero, "it's tried again when the relay's next back-off ends");

        _mode = "ok";
        _time.Now += OutboundCircuit.MaxBackOff;
        await _sender.DrainHeldAsync();
        Delivered.Should().Be(3);
        (await Held).Should().Be(0);
    }

    [Fact]
    public async Task An_unwatched_send_that_fails_before_the_back_off_opens_is_held(/* BUG-617 */)
    {
        _mode = "drop";   // one dropped connection: the relay isn't backed off yet
        await _sender.SendAsync(["assignee@example.test"], "Case assigned to you", "b");
        _circuit.TryEnter(_target).Should().BeTrue("one failure doesn't back the relay off");
        (await HeldRowsAsync()).Should().ContainSingle().Which.Attempts.Should().Be(0, "it didn't reach the relay (BUG-640)");
        _time.Timer!.Due.Should().Be(EmailSender.DrainFloor);

        _mode = "ok";
        _time.Now += EmailSender.DrainFloor;
        _time.Timer.Fire();
        await WaitForAsync(() => Delivered == 1);
        await WaitForAsync(async () => await Held == 0);
    }

    [Fact]
    public async Task A_transient_refusal_is_held_and_a_permanent_one_isnt(/* BUG-626 */)
    {
        _mode = "452";   // mailbox full: not now
        await _sender.SendAsync(["assignee@example.test"], "Case assigned to you", "b");
        (await Held).Should().Be(1, "a 4xx says try later, so it's kept for later");
        _circuit.TryEnter(_target).Should().BeTrue("the relay answered, so it isn't backed off");

        await _sender.DrainHeldAsync();
        (await HeldRowsAsync()).Should().ContainSingle().Which.Attempts.Should().Be(2, "still full: kept, and the try counted");

        _mode = "550";   // the mailbox is gone: never
        await _sender.SendAsync(["leaver@example.test"], "Mentioned", "b");
        (await Held).Should().Be(1, "a 5xx would only be refused again");

        await _sender.DrainHeldAsync();
        (await Held).Should().Be(0, "refused for good, so it's given up");
        _log.Has(LogLevel.Error, "refused a held email").Should().BeTrue("a given-up email leaves a record");
        Delivered.Should().Be(0);
    }

    [Fact]
    public async Task A_partial_delivery_counts_as_delivered_and_isnt_held(/* BUG-94 */)
    {
        _mode = "452";
        await _sender.SendAsync(["fine@example.test", "full@example.test"], "Case assigned to you", "b");
        Delivered.Should().Be(1);
        (await Held).Should().Be(0, "sending it again would repeat it to the one who got it");
    }

    [Fact]
    public async Task A_held_email_that_never_goes_is_given_up_after_its_tries(/* BUG-617 */)
    {
        _mode = "452";
        await _sender.SendAsync(["assignee@example.test"], "Case assigned to you", "b");
        await _sender.SendAsync(["other@example.test"], "Mentioned", "b");
        for (var i = 1; i < HeldEmail.MaxAttempts; i++)
        {
            (await HeldRowsAsync()).Should().HaveCount(2);
            await _sender.DrainHeldAsync();
        }
        var left = (await HeldRowsAsync()).Should().ContainSingle("the first was given up after its last try").Subject;
        left.RecipientList.Should().Equal("other@example.test");
        _log.Has(LogLevel.Error, $"after {HeldEmail.MaxAttempts} tries").Should().BeTrue();

        _mode = "ok";
        await _sender.DrainHeldAsync();
        Delivered.Should().Be(1, "the one behind it isn't held back for ever");

        lock (_log.Entries)
            _log.Entries.Should().NotContain(e => e.Message.Contains("@example.test", StringComparison.Ordinal)
                || e.Message.Contains("Case assigned", StringComparison.Ordinal), "CWE-359: counts, not addresses or subjects");
    }

    [Fact]
    public async Task A_relay_outage_doesnt_use_up_the_tries_and_only_age_gives_up(/* BUG-640 */)
    {
        BackOff();
        await _sender.SendAsync(["a@example.test"], "Mentioned", "b");
        await _sender.SendAsync(["b@example.test"], "Assigned", "b");
        await _sender.SendAsync(["c@example.test"], "Handed over", "b");
        var heldAt = _time.Now;

        // The relay stays down for a couple of hours: every back-off's probe fails to reach it.
        _mode = "drop";
        for (var probe = 0; probe < 20; probe++)
        {
            _time.Now += _circuit.RetryIn(_target);
            await _sender.DrainHeldAsync();
            var rows = await HeldRowsAsync();
            rows.Should().HaveCount(3, $"a relay that's down says nothing about the mail (probe {probe + 1})");
            rows[0].Attempts.Should().Be(0, "only a relay that answered 'not now' uses up a try");
        }
        (_time.Now - heldAt).Should().BeGreaterThan(TimeSpan.FromHours(2)).And.BeLessThan(HeldEmail.GiveUpUnreachedAfter);
        _log.Has(LogLevel.Error, "given up").Should().BeFalse();

        // Held longer than the age limit, with the relay still down: given up, and logged.
        _time.Now = heldAt + HeldEmail.GiveUpUnreachedAfter + _circuit.RetryIn(_target);
        await _sender.DrainHeldAsync();
        var left = await HeldRowsAsync();
        left.Should().HaveCount(2);
        left[0].RecipientList.Should().Equal("b@example.test");
        _log.Has(LogLevel.Error, "given up").Should().BeTrue("a given-up email leaves a record");

        _mode = "ok";
        _time.Now += _circuit.RetryIn(_target);
        await _sender.DrainHeldAsync();
        Delivered.Should().Be(2, "the rest go once the relay answers");
    }

    [Fact]
    public async Task A_new_sender_over_the_same_database_still_sends_held_mail(/* BUG-617: a restart */)
    {
        BackOff();
        await _sender.SendAsync(["assignee@example.test"], "Case assigned to you", "b");
        _sender.Dispose();

        var restarted = new ManualTime { Now = _time.Now + TimeSpan.FromMinutes(5) };
        using var after = NewSender(new OutboundCircuit(restarted));
        (await after.HeldCountAsync()).Should().Be(1, "it's in the database, not the old process's memory");
        restarted.Timer!.Due.Should().Be(EmailSender.DrainFloor, "the new sender looks for held mail when it starts");
        restarted.Timer.Fire();
        await WaitForAsync(() => Delivered == 1);
        await WaitForAsync(async () => await after.HeldCountAsync() == 0);
    }

    private static async Task WaitForAsync(Func<bool> condition) => await WaitForAsync(() => Task.FromResult(condition()));

    private static async Task WaitForAsync(Func<Task<bool>> condition)
    {
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (!await condition() && DateTime.UtcNow < deadline) await Task.Delay(20);
        (await condition()).Should().BeTrue();
    }

    // Just enough SMTP to take a message; counts the messages taken.
    private async Task RelayAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                using var client = await _listener.AcceptTcpClientAsync(ct);
                if (_mode == "drop") continue;   // closed before the greeting: the relay didn't answer
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
                    else if (cmd.StartsWith("RCPT TO:", StringComparison.Ordinal) && _mode != "ok" && !line.Contains("fine@", StringComparison.Ordinal))
                        await writer.WriteLineAsync($"{_mode} Not this one");
                    else if (cmd == "QUIT") { await writer.WriteLineAsync("221 Bye"); break; }
                    else await writer.WriteLineAsync("250 relay.test");
                }
            }
        }
        catch (OperationCanceledException) { /* stopped */ }
    }

    public async Task DisposeAsync()
    {
        _sender.Dispose();
        await _stop.CancelAsync();
        try { await _relay.WaitAsync(TimeSpan.FromSeconds(5)); } catch (OperationCanceledException) { /* stopped */ }
        _listener.Stop();
        _listener.Dispose();
        _stop.Dispose();
        await _services.DisposeAsync();
        try { File.Delete(_dbPath); } catch (IOException) { /* still open: the temp folder's cleanup has it */ }
    }
}
