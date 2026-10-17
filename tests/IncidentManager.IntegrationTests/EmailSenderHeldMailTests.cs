using System.Net;
using System.Net.Sockets;
using System.Text;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.ApiTokens;
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
            // With the exception, as a log sink writes it (BUG-657).
            lock (Entries) Entries.Add((logLevel, formatter(state, exception) + (exception is null ? "" : "\n" + exception)));
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
    private readonly System.Collections.Concurrent.ConcurrentQueue<string> _rcpts = new();   // the addresses it took

    // The directory of record: who is active, with which roles. Anyone not named is active as an Analyst.
    private sealed class Directory : ITokenOwnerCheck
    {
        public readonly System.Collections.Concurrent.ConcurrentDictionary<string, OwnerAccess> Answers = new();
        public Task<OwnerAccess?> CheckAsync(string ownerUserId, CancellationToken ct = default) =>
            Task.FromResult<OwnerAccess?>(Answers.GetValueOrDefault(ownerUserId, new OwnerAccess(true, new HashSet<string> { "Analyst" })));
    }

    private readonly Directory _directory = new();

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
            .AddSingleton<ITokenOwnerCheck>(_directory)   // BUG-654: who may see a case now
            .BuildServiceProvider();
        using (var db = _services.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContext()) db.Database.EnsureCreated();
        _monitor = new TestOptionsMonitor<EmailOptions>(_options);
        _circuit = new OutboundCircuit(_time);
        _sender = NewSender(_circuit);
        _target = EmailSender.Target(_options);
    }

    private readonly TestOptionsMonitor<EmailOptions> _monitor;

    private EmailSender NewSender(OutboundCircuit circuit) =>
        new(_monitor, _log, circuit, _services.GetRequiredService<IServiceScopeFactory>());

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

        _time.Now += OutboundCircuit.MaxBackOff;   // BUG-653: the held one's next try is due
        await _sender.DrainHeldAsync();
        (await Held).Should().Be(0, "refused for good, so it's given up");
        _log.Has(LogLevel.Error, "refused a held email").Should().BeTrue("a given-up email leaves a record");
        Delivered.Should().Be(0);
    }

    [Theory]
    [InlineData("550", true, 0)]    // 2 of 3 refused: the third got it
    [InlineData("550", false, 0)]   // 3 of 3 refused for good
    [InlineData("452", false, 1)]   // 3 of 3 refused for now
    public async Task Refused_recipients_dont_back_the_relay_off(string code, bool oneTakes, int attempts /* 0: not held */)
    {
        // BUG-650: SmtpClient reports several refused addresses with GeneralFailure, which read as a relay that didn't
        // answer: a few sends to a closed distribution backed the relay off, and the email was held as never tried.
        _mode = code;
        for (var i = 0; i < OutboundCircuit.FailuresToOpen; i++)
            await _sender.SendAsync([oneTakes ? "fine@example.test" : $"x{i}@example.test", $"y{i}@example.test", $"z{i}@example.test"],
                "Case assigned to you", "b");

        _circuit.TryEnter(_target).Should().BeTrue("the relay answered every time, so it isn't backed off");
        Delivered.Should().Be(oneTakes ? OutboundCircuit.FailuresToOpen : 0);
        var rows = await HeldRowsAsync();
        if (attempts == 0) rows.Should().BeEmpty(oneTakes ? "the others got it (BUG-94)" : "refused for good, so not held");
        else rows.Should().HaveCount(OutboundCircuit.FailuresToOpen).And.OnlyContain(h => h.Attempts == attempts, "a 4xx is a try");
    }

    [Theory]
    [InlineData(new[] { 550, 550 }, "Refused")]
    [InlineData(new[] { 550, 452 }, "Transient")]
    [InlineData(new[] { 451, 452 }, "Transient")]
    public void Several_refused_addresses_are_judged_by_their_own_codes(int[] codes, string expected /* BUG-650 */)
    {
        var many = new System.Net.Mail.SmtpFailedRecipientsException("refused",
            codes.Select((c, i) => new System.Net.Mail.SmtpFailedRecipientException((System.Net.Mail.SmtpStatusCode)c, $"r{i}@example.test")).ToArray());
        many.StatusCode.Should().Be(System.Net.Mail.SmtpStatusCode.GeneralFailure, "what SmtpClient gives the plural exception");
        EmailSender.Unreachable(many).Should().BeFalse("the relay answered");
        SendOutcomes.Of(many).ToString().Should().Be(expected);
    }

    [Theory]
    [InlineData("530")]        // the relay wants authentication: every email is refused at MAIL FROM
    [InlineData("bad From")]   // our own setting: no email can be composed
    public async Task A_session_or_settings_refusal_keeps_the_whole_queue(string fault /* BUG-652 */)
    {
        BackOff();
        await _sender.SendAsync(["a@example.test"], "Mentioned", "b");
        await _sender.SendAsync(["b@example.test"], "Assigned", "b");
        if (fault == "530") _mode = "530";
        else _options.From = "not an address";
        await _sender.SendAsync(["c@example.test"], "Handed over", "b");
        _time.Now += OutboundCircuit.FirstBackOff;
        await _sender.DrainHeldAsync();
        await _sender.DrainHeldAsync();
        var rows = await HeldRowsAsync();
        rows.Should().HaveCount(3, "a refusal that isn't about the addresses says nothing about the email: it's kept");
        rows.Should().OnlyContain(h => h.Attempts == 0);
        _log.Has(LogLevel.Error, "refused a held email").Should().BeFalse();
        _log.Has(LogLevel.Error, "can't be sent until").Should().BeTrue("someone must fix the relay or the settings");
        _time.Timer!.Due.Should().BeGreaterThan(TimeSpan.Zero, "tried again later");

        // Fixed in time: all go, in order.
        _mode = "ok";
        _options.From = "casebook@example.test";
        _time.Now += OutboundCircuit.MaxBackOff;
        await _sender.DrainHeldAsync();
        Delivered.Should().Be(3);
        (await Held).Should().Be(0);

        // Never fixed: the age limit ends it, as for a relay that can't be reached.
        if (fault == "530") _mode = "530";
        else _options.From = "not an address";
        await _sender.SendAsync(["d@example.test"], "Assigned", "b");
        (await Held).Should().Be(1, "a user's action's email is held under the refusal too");
        var dHeldAt = _time.Now;
        _time.Now = dHeldAt + HeldEmail.GiveUpUnreachedAfter - TimeSpan.FromHours(1);
        await _sender.DrainHeldAsync();
        (await Held).Should().Be(1, "only 24 hours after it was held");
        _log.Has(LogLevel.Error, "given up").Should().BeFalse();
        _time.Now = dHeldAt + HeldEmail.GiveUpUnreachedAfter + TimeSpan.FromMinutes(1);
        await _sender.DrainHeldAsync();
        (await Held).Should().Be(0);
        _log.Has(LogLevel.Error, "given up").Should().BeTrue();
        _options.From = "casebook@example.test";
    }

    [Theory]
    [InlineData("dlp@example.test")]    // 550 5.7.1 at the end of DATA: a DLP or transport rule
    [InlineData("spam@example.test")]   // 554 at the end of DATA: content rejected
    public async Task One_email_refused_for_its_content_doesnt_hold_the_queue(string refused /* BUG-659 */)
    {
        BackOff();
        await _sender.SendAsync([refused], "Mentioned", "b");
        await _sender.SendAsync(["b@example.test"], "Assigned", "b");
        await _sender.SendAsync(["c@example.test"], "Handed over", "b");
        var heldAt = _time.Now;

        _time.Now += OutboundCircuit.FirstBackOff;
        await _sender.DrainHeldAsync();
        Delivered.Should().Be(2, "the relay refused that message, not the session: the ones behind it go");
        var row = (await HeldRowsAsync()).Should().ContainSingle().Subject;
        row.RecipientList.Should().Equal(refused);
        row.Attempts.Should().Be(1, "the relay answered about this email, so it's a try");
        row.NextAttemptAtUtc.Should().BeAfter(_time.Now, "put back for later, as a 4xx is");
        _log.Has(LogLevel.Error, "can't be sent until").Should().BeFalse("the settings and sign-in are fine");
        _time.Timer!.Due.Should().Be(row.NextAttemptAtUtc - _time.Now, "it's tried again when its turn comes");

        // Still refused a day on: given up, and logged.
        _time.Now = heldAt + HeldEmail.GiveUpUnreachedAfter + TimeSpan.FromMinutes(1);
        await _sender.DrainHeldAsync();
        (await Held).Should().Be(0);
        _log.Has(LogLevel.Error, "given up").Should().BeTrue();
        _circuit.TryEnter(_target).Should().BeTrue("the relay answered every time, so it isn't backed off");
    }

    [Fact]
    public async Task A_message_too_large_for_the_relay_is_refused_for_good(/* BUG-659 */)
    {
        BackOff();
        await _sender.SendAsync(["big@example.test"], "Mentioned", "b");
        await _sender.SendAsync(["b@example.test"], "Assigned", "b");
        _time.Now += OutboundCircuit.FirstBackOff;
        await _sender.DrainHeldAsync();
        Delivered.Should().Be(1);
        (await Held).Should().Be(0, "552: the same message would only be refused again");
        _log.Has(LogLevel.Error, "refused a held email").Should().BeTrue("a given-up email leaves a record");

        await _sender.SendAsync(["big@example.test"], "Assigned", "b");
        (await Held).Should().Be(0, "nor is one sent now held");
    }

    [Theory]
    [InlineData(System.Net.Mail.SmtpStatusCode.ExceededStorageAllocation, "Refused")]   // 552: too large for the relay
    [InlineData(System.Net.Mail.SmtpStatusCode.MailboxUnavailable, "Blocked")]          // 550: at MAIL FROM it's the session's
    [InlineData(System.Net.Mail.SmtpStatusCode.TransactionFailed, "Blocked")]           // 554: may be the greeting's
    [InlineData(System.Net.Mail.SmtpStatusCode.MustIssueStartTlsFirst, "Blocked")]      // 530
    [InlineData(System.Net.Mail.SmtpStatusCode.MailboxNameNotAllowed, "Blocked")]       // 553: the sender
    public void A_refusal_of_the_message_itself_is_final_only_when_its_code_says_so(System.Net.Mail.SmtpStatusCode code, string expected /* BUG-659 */) =>
        SendOutcomes.Of(new System.Net.Mail.SmtpException(code, "refused")).ToString().Should().Be(expected);

    [Fact]
    public async Task The_log_doesnt_carry_the_addresses_a_relay_echoes(/* BUG-657, CWE-359 */)
    {
        _mode = "550";
        await _sender.SendAsync(["gone@example.test"], "Assigned", "b");
        await _sender.SendAsync(["gone1@example.test", "gone2@example.test"], "Assigned", "b");
        await _sender.SendAsync(["fine@example.test", "gone3@example.test"], "Assigned", "b");
        await _sender.SendAsync(["fine@example.test", "gone4@example.test", "gone5@example.test"], "Assigned", "b");
        (await _sender.SendTestAsync(new EmailMessage(["gone6@example.test"], "Test", "<p>t</p>", "t"))).Status.Should().Be(EmailSendStatus.Failed);
        lock (_log.Entries)
        {
            _log.Entries.Should().NotBeEmpty();
            _log.Entries.Should().NotContain(e => e.Message.Contains("@example.test", StringComparison.Ordinal),
                "the relay's reply names the address, so only the exception's type and SMTP status are logged");
            _log.Entries.Should().Contain(e => e.Message.Contains("550", StringComparison.Ordinal), "the status is still there");
        }
    }

    [Theory]
    [InlineData(true)]    // email turned on again: the reload says so
    [InlineData(false)]   // no word of it: the next send that goes
    public async Task Held_mail_waits_while_email_is_off(bool told /* BUG-651 */)
    {
        BackOff();
        await _sender.SendAsync(["a@example.test"], "Mentioned", "b");
        await _sender.SendAsync(["b@example.test"], "Assigned", "b");
        await _sender.SendAsync(["c@example.test"], "Handed over", "b");

        _options.Enabled = false;
        _time.Now += OutboundCircuit.FirstBackOff;
        await _sender.DrainHeldAsync();
        await _sender.DrainHeldAsync();
        (await HeldRowsAsync()).Should().HaveCount(3, "nothing is sent while email is off, so nothing is taken off (as the outbox, WF-92)");
        _time.Timer!.Due.Should().Be(OutboundCircuit.MaxBackOff, "it looks again now and then");

        _options.Enabled = true;
        if (told) _monitor.Change(_options);
        else await _sender.SendAsync(["d@example.test"], "Assigned", "b");
        _time.Timer.Due.Should().Be(TimeSpan.Zero, "the held mail goes straight away");
        _time.Timer.Fire();
        await WaitForAsync(() => Delivered == (told ? 3 : 4));
        await WaitForAsync(async () => await Held == 0);
    }

    [Fact]
    public async Task One_recipients_not_now_doesnt_hold_back_the_rest(/* BUG-653 */)
    {
        _mode = "452";
        await _sender.SendAsync(["full@example.test"], "Assigned", "b");    // tried: mailbox full, held
        BackOff();
        await _sender.SendAsync(["fine@example.test"], "Mentioned", "b");   // held behind it, untried
        _circuit.Succeeded(_target);

        await _sender.DrainHeldAsync();
        Delivered.Should().Be(1, "the one behind went; a recipient's 4xx is about that email only");
        var left = (await HeldRowsAsync()).Should().ContainSingle().Subject;
        left.RecipientList.Should().Equal("full@example.test");
        left.Attempts.Should().Be(2);
        left.NextAttemptAtUtc.Should().Be(_time.Now + EmailSender.DrainFloor * 2, "put back for its own back-off");
        _time.Timer!.Due.Should().Be(EmailSender.DrainFloor * 2, "the drain comes back when it's due");

        await _sender.DrainHeldAsync();
        (await HeldRowsAsync()).Single().Attempts.Should().Be(2, "not due yet, so not tried");

        _mode = "ok";
        _time.Now = left.NextAttemptAtUtc!.Value;
        await _sender.DrainHeldAsync();
        Delivered.Should().Be(2);
        (await Held).Should().Be(0);
    }

    private async Task<Guid> AddRestrictedCaseAsync(params string[] team)
    {
        await using var db = await _services.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContextAsync();
        var c = Case.Open(2026, 1, "Held Mail", "Held mail", IncidentManager.Domain.Enums.Classification.Incident,
            IncidentManager.Domain.Enums.Severity.High, IncidentManager.Domain.Enums.CaseOrigin.InternalDetection, "system", _time.Now);
        c.IsRestricted = true;
        foreach (var u in team) c.Assign(u, u, IncidentManager.Domain.Enums.CaseAssignmentRole.Analyst, "system", _time.Now);
        db.Cases.Add(c);
        await db.SaveChangesAsync();
        return c.Id;
    }

    [Fact]
    public async Task A_held_case_email_goes_only_to_those_who_may_still_see_the_case(/* BUG-654 */)
    {
        var caseId = await AddRestrictedCaseAsync("ann", "bob");
        BackOff();
        await _sender.SendAsync(new EmailMessage(["ann@example.test", "bob@example.test"], "Mentioned", "<p>b</p>", "b"), caseId, ["ann", "bob"]);
        await _sender.SendAsync(new EmailMessage(["bob@example.test"], "Handed over", "<p>b</p>", "b"), caseId, ["bob"]);
        await _sender.SendAsync(new EmailMessage(["ann@example.test"], "Assigned", "<p>b</p>", "b"), Guid.NewGuid(), ["ann"]);
        await _sender.SendAsync(["ops@example.test"], "Not about a case", "b");
        var rows = await HeldRowsAsync();
        rows.Should().HaveCount(4);
        rows[0].CaseId.Should().Be(caseId);
        rows[0].RecipientUserIds.Should().Be("ann;bob");
        rows[3].CaseId.Should().BeNull();

        // While they're held, Bob's account is disabled.
        _directory.Answers["bob"] = new OwnerAccess(false, new HashSet<string> { "Analyst" });
        _time.Now += OutboundCircuit.FirstBackOff;
        await _sender.DrainHeldAsync();

        (await Held).Should().Be(0);
        Delivered.Should().Be(2, "Ann's copy of the first, and the one not about a case; Bob's handoff and the gone case's aren't sent");
        _rcpts.Should().BeEquivalentTo(["ann@example.test", "ops@example.test"]);
        _log.Has(LogLevel.Information, "goes to 1 of its 2 recipient(s)").Should().BeTrue();
        _log.Has(LogLevel.Information, "none of its 1 recipient(s) may still see the case").Should().BeTrue();
        _log.Has(LogLevel.Information, "no longer exists").Should().BeTrue();
        _circuit.TryEnter(_target).Should().BeTrue("the probe's turn isn't kept by an email that wasn't sent");
    }

    private sealed class OptionsFactory(DbContextOptions<AppDbContext> options) : IDbContextFactory<AppDbContext>
    {
        public AppDbContext CreateDbContext() => new(options);
    }

    [SqlServerFact]
    public async Task On_SqlServer_a_row_put_back_waits_its_turn_and_a_case_email_is_checked_again(/* BUG-653, BUG-654 */)
    {
        using var sql = TestDatabase.Open(TestDatabase.SqlServer);
        await using var services = new ServiceCollection()
            .AddSingleton<IDbContextFactory<AppDbContext>>(new OptionsFactory(sql.Options))
            .AddSingleton<ITokenOwnerCheck>(_directory)
            .BuildServiceProvider();
        Guid caseId;
        await using (var db = sql.NewContext())
        {
            var c = Case.Open(2026, 1, "Held Mail", "Held mail", IncidentManager.Domain.Enums.Classification.Incident,
                IncidentManager.Domain.Enums.Severity.High, IncidentManager.Domain.Enums.CaseOrigin.InternalDetection, "system", _time.Now);
            c.Assign("ann", "Ann", IncidentManager.Domain.Enums.CaseAssignmentRole.Analyst, "system", _time.Now);
            db.Cases.Add(c);
            await db.SaveChangesAsync();
            caseId = c.Id;
        }
        var circuit = new OutboundCircuit(_time);
        using var sender = new EmailSender(_monitor, _log, circuit, services.GetRequiredService<IServiceScopeFactory>());

        _mode = "452";
        await sender.SendAsync(["full@example.test"], "Assigned", "b");
        for (var i = 0; i < OutboundCircuit.FailuresToOpen; i++) circuit.Failed(_target);
        await sender.SendAsync(new EmailMessage(["fine@example.test", "fine.bob@example.test"], "Mentioned", "<p>b</p>", "b"), caseId, ["ann", "bob"]);
        _directory.Answers["bob"] = new OwnerAccess(false, new HashSet<string> { "Analyst" });
        circuit.Succeeded(_target);

        await sender.DrainHeldAsync();
        Delivered.Should().Be(1);
        _rcpts.Should().Equal("fine@example.test");
        await using (var db = sql.NewContext())
        {
            var left = await db.HeldEmails.AsNoTracking().SingleAsync();
            left.Attempts.Should().Be(2);
            left.NextAttemptAtUtc.Should().Be(_time.Now + EmailSender.DrainFloor * 2);
        }
        _mode = "ok";
        _time.Now += EmailSender.DrainFloor * 2;
        await sender.DrainHeldAsync();
        Delivered.Should().Be(2);
        (await sender.HeldCountAsync()).Should().Be(0);
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
            _time.Now += OutboundCircuit.MaxBackOff;   // BUG-653: each waits out its own back-off
            await _sender.DrainHeldAsync();
        }
        (await Held).Should().Be(0, "each was given up after its last try");
        lock (_log.Entries)
            _log.Entries.Count(e => e.Level == LogLevel.Error && e.Message.Contains($"after {HeldEmail.MaxAttempts} tries", StringComparison.Ordinal))
                .Should().Be(2);
        Delivered.Should().Be(0);

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
                string? atEndOfData = null;   // BUG-659: the reply to the message itself, decided by who it's to
                while (await reader.ReadLineAsync(ct) is { } line)
                {
                    var cmd = line.ToUpperInvariant();
                    if (cmd == "DATA")
                    {
                        await writer.WriteLineAsync("354 Go ahead");
                        while (await reader.ReadLineAsync(ct) is { } body && body != ".") { }
                        if (atEndOfData is not null) await writer.WriteLineAsync(atEndOfData);
                        else
                        {
                            Interlocked.Increment(ref _delivered);
                            await writer.WriteLineAsync("250 Queued");
                        }
                    }
                    else if (cmd.StartsWith("MAIL FROM:", StringComparison.Ordinal) && _mode == "530")
                        await writer.WriteLineAsync("530 5.7.0 Authentication required");
                    // Echoing the address, as relays do (BUG-657).
                    else if (cmd.StartsWith("RCPT TO:", StringComparison.Ordinal) && _mode != "ok" && !line.Contains("fine@", StringComparison.Ordinal))
                        await writer.WriteLineAsync($"{_mode} {line["RCPT TO:".Length..].Trim()} Not this one");
                    else if (cmd.StartsWith("RCPT TO:", StringComparison.Ordinal))
                    {
                        if (line.Contains("dlp@", StringComparison.Ordinal)) atEndOfData = "550 5.7.1 Message refused by a transport rule";
                        else if (line.Contains("big@", StringComparison.Ordinal)) atEndOfData = "552 5.3.4 Message size exceeds fixed limit";
                        else if (line.Contains("spam@", StringComparison.Ordinal)) atEndOfData = "554 5.6.0 Message content rejected";
                        _rcpts.Enqueue(line["RCPT TO:".Length..].Trim().Trim('<', '>'));
                        await writer.WriteLineAsync("250 OK");
                    }
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
