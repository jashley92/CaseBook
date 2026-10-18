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
/// CAP-05: the sender signs in to a relay that wants AUTH, with the server's settings or the sign-in saved in
/// Administration. A refused sign-in (BUG-652's class) is a setting to fix, not a relay that's down: it isn't backed off,
/// the held mail is kept for the fix, the admin's test names it by its code without the relay's words, and the same
/// sign-in isn't tried again by every send and drain (each try with a wrong password counts towards the account's
/// lockout) until the settings change, a test gets through, or an hour passes. The age limit still ends a held email.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1001", Justification = "Disposed in DisposeAsync (IAsyncLifetime).")]
public sealed class EmailSenderSignInTests : IAsyncLifetime
{
    private sealed class ManualTime : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = new(2026, 10, 18, 9, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => Now;
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period) => new NoTimer();
        private sealed class NoTimer : ITimer
        {
            public bool Change(TimeSpan dueTime, TimeSpan period) => true;
            public void Dispose() { }
            public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        }
    }

    private sealed class ListLogger : ILogger<EmailSender>
    {
        public readonly List<(LogLevel Level, string Message)> Entries = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            lock (Entries) Entries.Add((logLevel, formatter(state, exception) + (exception is null ? "" : "\n" + exception)));
        }
        public bool Has(LogLevel level, string text)
        {
            lock (Entries) return Entries.Exists(e => e.Level == level && e.Message.Contains(text, StringComparison.Ordinal));
        }
    }

    // The saved sign-in, as the Administration form's store gives it (or refuses to, when it can't decrypt).
    private sealed class SavedSignIn : ISmtpSignInSource
    {
        public Func<(SmtpSignInMode, NetworkCredential?)> Answer { get; set; } = () => (SmtpSignInMode.None, null);
        public int Asked;
        public Task<(SmtpSignInMode Mode, NetworkCredential? Credentials)> ResolveAsync(CancellationToken ct)
        {
            Interlocked.Increment(ref Asked);
            return Task.FromResult(Answer());
        }
    }

    // S2068: the relay's account and password are made at run time.
    private readonly string _account = "casebook-" + Guid.NewGuid().ToString("N")[..8] + "@contoso.example";
    private readonly string _secret = "pw-" + Guid.NewGuid().ToString("N");
    private const string ReplyMarker = "relay-said-this";

    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _relay;
    private int _delivered;
    private int _authTries;
    private readonly ManualTime _time = new();
    private readonly OutboundCircuit _circuit;
    private readonly ListLogger _log = new();
    private readonly EmailOptions _options;
    private readonly TestOptionsMonitor<EmailOptions> _monitor;
    private readonly DeliveryHealth _health = new(new FixedClock(DateTimeOffset.UtcNow));
    private readonly SavedSignIn _saved = new();
    private readonly EmailSender _sender;
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"casebook-signin-{Guid.NewGuid():N}.db");
    private readonly ServiceProvider _services;

    public EmailSenderSignInTests()
    {
        _listener.Start();
        _relay = RelayAsync(_stop.Token);
        _options = new EmailOptions
        {
            Enabled = true, SmtpHost = "127.0.0.1", SmtpPort = ((IPEndPoint)_listener.LocalEndpoint).Port, EnableSsl = false,
            From = "casebook@example.test", SmtpUsername = _account, SmtpPassword = _secret,
        };
        _services = new ServiceCollection()
            .AddDbContextFactory<AppDbContext>(o => o.UseSqlite($"Data Source={_dbPath};Pooling=False"))
            .BuildServiceProvider();
        using (var db = _services.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContext()) db.Database.EnsureCreated();
        _monitor = new TestOptionsMonitor<EmailOptions>(_options);
        _circuit = new OutboundCircuit(_time);
        _sender = new EmailSender(_monitor, _log, _circuit, _services.GetRequiredService<IServiceScopeFactory>(), secrets: null,
            health: _health, signIns: _saved);
    }

    public Task InitializeAsync() => _sender.DrainHeldAsync();

    private int Delivered => Volatile.Read(ref _delivered);
    private int AuthTries => Volatile.Read(ref _authTries);
    private Task<int> Held => _sender.HeldCountAsync();
    private static EmailMessage Test(string to) => new([to], "Test", "<p>t</p>", "t");

    [Fact]
    public async Task It_signs_in_with_the_configured_account()
    {
        (await _sender.SendTestAsync(Test("admin@example.test"))).Status.Should().Be(EmailSendStatus.Sent);
        await _sender.SendAsync(["a@example.test"], "Assigned", "b");
        Delivered.Should().Be(2);
        AuthTries.Should().Be(2);
        _saved.Asked.Should().Be(0, "the server's configuration sets the sign-in, so it wins over the saved one");
        _health.Snapshot()[DeliveryHealth.Smtp].SuccessCount.Should().Be(2);
    }

    [Fact]
    public async Task A_refused_sign_in_is_named_by_its_code_and_not_backed_off()
    {
        _options.SmtpPassword = "wrong-" + Guid.NewGuid().ToString("N");
        var outcome = await _sender.SendTestAsync(Test("admin@example.test"));

        outcome.Status.Should().Be(EmailSendStatus.Failed);
        outcome.Error.Should().MatchRegex(@"refused the sign-in \(SMTP 53[05]\)")
            .And.NotContain(ReplyMarker, "the relay's own words aren't echoed (BUG-657)").And.NotContain(_account);
        _circuit.TryEnter(EmailSender.Target(_options)).Should().BeTrue("the relay answered: it isn't a relay that's down");
        var smtp = _health.Snapshot()[DeliveryHealth.Smtp];
        smtp.LastStatusCode.Should().BeOneOf(530, 535);
        smtp.LastFailure.Should().NotContain(ReplyMarker);
        smtp.BackedOffUntilUtc.Should().BeNull();
        lock (_log.Entries) _log.Entries.Should().NotContain(e => e.Message.Contains(ReplyMarker, StringComparison.Ordinal) || e.Message.Contains(_options.SmtpPassword, StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_refused_sign_in_holds_the_mail_without_trying_it_again_until_the_fix()
    {
        var right = _options.SmtpPassword;
        _options.SmtpPassword = "wrong-" + Guid.NewGuid().ToString("N");
        await _sender.SendAsync(["a@example.test"], "Mentioned", "b");
        AuthTries.Should().Be(1);
        (await Held).Should().Be(1, "a refused sign-in says nothing about the email: it's kept, not deleted");

        // Every later send and drain is held here rather than trying the wrong password again (the account's lockout).
        await _sender.SendAsync(["b@example.test"], "Assigned", "b");
        await _sender.DrainHeldAsync();
        await _sender.DrainHeldAsync();
        AuthTries.Should().Be(1, "the same sign-in isn't tried again by every send and drain");
        (await Held).Should().Be(2);
        (await HeldRows()).Should().OnlyContain(h => h.Attempts == 0 && h.NextAttemptAtUtc == null, "nothing is put back to find out whose fault it was (BUG-659)");
        _log.Has(LogLevel.Error, "can't be sent until the mail relay's sign-in is fixed").Should().BeTrue();
        _circuit.TryEnter(EmailSender.Target(_options)).Should().BeTrue("not backed off");

        // An hour on, one try.
        _time.Now += EmailSender.SignInRetryAfter;
        await _sender.DrainHeldAsync();
        AuthTries.Should().Be(2);

        // Fixed: the new sign-in is tried at once, and everything held goes, in order.
        _options.SmtpPassword = right;
        await _sender.DrainHeldAsync();
        Delivered.Should().Be(2);
        (await Held).Should().Be(0);
    }

    [Fact]
    public async Task Never_fixed_the_age_limit_ends_a_held_email_and_its_counted()
    {
        _options.SmtpPassword = "wrong-" + Guid.NewGuid().ToString("N");
        await _sender.SendAsync(["a@example.test"], "Mentioned", "b");
        _time.Now += HeldEmail.GiveUpUnreachedAfter + TimeSpan.FromMinutes(1);
        await _sender.DrainHeldAsync();
        (await Held).Should().Be(0, "a refused sign-in retries for a day at most, not for ever");
        _log.Has(LogLevel.Error, "given up").Should().BeTrue();
        _health.Snapshot()[DeliveryHealth.Smtp].GivenUp.Should().Be(1, "Diagnostics counts what the log line alone used to say");
    }

    [Fact]
    public async Task The_sign_in_saved_in_administration_is_used_when_the_server_sets_none()
    {
        _options.SmtpUsername = "";
        _options.SmtpPassword = "";
        var secret = _secret;
        _saved.Answer = () => (SmtpSignInMode.Password, new NetworkCredential(_account, secret));
        (await _sender.SendTestAsync(Test("admin@example.test"))).Status.Should().Be(EmailSendStatus.Sent);
        AuthTries.Should().Be(1);
        _saved.Asked.Should().Be(1, "read per send, so a change on the form applies without a restart");

        // A saved password that can't be decrypted here: fail closed, nothing sent, the mail held.
        _saved.Answer = () => throw new InvalidOperationException("The SMTP password saved in Administration can't be decrypted on this server.");
        await _sender.SendAsync(["a@example.test"], "Assigned", "b");
        AuthTries.Should().Be(1, "no send without the sign-in that was asked for");
        Delivered.Should().Be(1);
        (await Held).Should().Be(1);
        (await _sender.SendTestAsync(Test("admin@example.test"))).Error.Should().Contain("can't be decrypted");
    }

    private async Task<List<HeldEmail>> HeldRows()
    {
        await using var db = await _services.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContextAsync();
        return await db.HeldEmails.AsNoTracking().OrderBy(h => h.Id).ToListAsync();
    }

    // A relay that offers AUTH LOGIN, takes the one account and password, and refuses an unsigned MAIL FROM (as Exchange
    // does after a refused AUTH, which SmtpClient carries on from).
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
                var signedIn = false;
                while (await reader.ReadLineAsync(ct) is { } line)
                {
                    var cmd = line.ToUpperInvariant();
                    if (cmd.StartsWith("EHLO", StringComparison.Ordinal))
                    {
                        await writer.WriteLineAsync("250-relay.test");
                        await writer.WriteLineAsync("250-AUTH LOGIN");
                        await writer.WriteLineAsync("250 OK");
                    }
                    else if (cmd.StartsWith("AUTH LOGIN", StringComparison.Ordinal))
                    {
                        Interlocked.Increment(ref _authTries);
                        var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                        string user;
                        if (parts.Length > 2) user = Decode(parts[2]);
                        else
                        {
                            await writer.WriteLineAsync("334 VXNlcm5hbWU6");
                            user = Decode(await reader.ReadLineAsync(ct) ?? "");
                        }
                        await writer.WriteLineAsync("334 UGFzc3dvcmQ6");
                        var given = Decode(await reader.ReadLineAsync(ct) ?? "");
                        signedIn = user == _account && given == _secret;
                        await writer.WriteLineAsync(signedIn ? "235 2.7.0 Authentication successful"
                            : $"535 5.7.8 Error: authentication failed for <{user}> {ReplyMarker}");
                    }
                    else if (cmd.StartsWith("MAIL FROM:", StringComparison.Ordinal))
                        await writer.WriteLineAsync(signedIn ? "250 OK" : $"530 5.7.57 Client not authenticated {ReplyMarker}");
                    else if (cmd == "DATA")
                    {
                        await writer.WriteLineAsync("354 Go ahead");
                        while (await reader.ReadLineAsync(ct) is { } body && body != ".") { }
                        Interlocked.Increment(ref _delivered);
                        await writer.WriteLineAsync("250 Queued");
                    }
                    else if (cmd == "QUIT") { await writer.WriteLineAsync("221 Bye"); break; }
                    else await writer.WriteLineAsync("250 OK");
                }
            }
        }
        catch (OperationCanceledException) { /* stopped */ }
        catch (IOException) { /* a client went away mid-session */ }
    }

    private static string Decode(string b64)
    {
        try { return Encoding.UTF8.GetString(Convert.FromBase64String(b64.Trim())); }
        catch (FormatException) { return ""; }
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
