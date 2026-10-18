using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Config;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Notifications;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Secrets;
using IncidentManager.Infrastructure.Security;
using IncidentManager.Infrastructure.Siem;
using IncidentManager.Web.Notifications;
using IncidentManager.Web.Secrets;
using IncidentManager.Web.Siem;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// CAP-40: the team-chat webhook URL and the SIEM webhook token entered under Administration, as CAP-05's SMTP password is.
/// Each round-trips through Data Protection under its own purpose and is kept as ciphertext only; it's never returned to the
/// page, never in the configuration bundle, the audit trail or the log. The server's configuration wins when it sets one. A
/// value that won't decrypt here fails closed: the chat post isn't made and the SIEM event isn't sent unauthenticated. A save
/// applies to the next send without a restart, is audited (who, when, which secret, set/replaced/cleared) and goes to the
/// SIEM as 5403. The cards save and clear with the stamp they loaded, and a test send doesn't move it.
/// </summary>
public sealed class StoredSecretStoreTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"casebook-storedsecrets-{Guid.NewGuid():N}.db");
    private readonly ServiceProvider _services;
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 18, 9, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _admin = new() { UserId = "admin1", RoleSet = [AppRole.SysAdmin] };
    private readonly ChatOptions _chat = new() { Enabled = true, MaxAttempts = 1 };
    private readonly SiemWebhookOptions _webhook = new() { Enabled = true, Url = "https://siem.example/collector", MaxAttempts = 1 };
    private readonly CapturingSecurityEventSink _siem = new();
    private readonly RecordingAudit _audit = new();
    private readonly CountingLogger _log = new();
    private readonly IDataProtectionProvider _keys = new EphemeralDataProtectionProvider();
    private readonly StoredSecretStore _store;

    // S2068: made at run time, never a literal.
    private static string NewToken() => "tk-" + Guid.NewGuid().ToString("N");
    private static string NewHookUrl() => "https://hooks.example.com/services/" + Guid.NewGuid().ToString("N");

    private sealed class RecordingAudit : IAuditWriter
    {
        public readonly List<string> Summaries = [];
        public Task RecordAsync(AuditAction action, string entityType, string? entityId, string? caseNumber, string summary, CancellationToken ct = default)
        {
            Summaries.Add($"{action} {entityType} {entityId} {summary}");
            return Task.CompletedTask;
        }
    }

    private sealed class CountingLogger : ILogger<StoredSecretStore>
    {
        public readonly List<string> Errors = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (logLevel >= LogLevel.Warning) Errors.Add(formatter(state, exception) + exception);
        }
    }

    public StoredSecretStoreTests()
    {
        _services = new ServiceCollection()
            .AddDbContextFactory<AppDbContext>(o => o.UseSqlite($"Data Source={_dbPath};Pooling=False"))
            .BuildServiceProvider();
        using (var db = Factory.CreateDbContext()) db.Database.EnsureCreated();
        _store = new StoredSecretStore(_services.GetRequiredService<IServiceScopeFactory>(), _keys, _log);
    }

    private IDbContextFactory<AppDbContext> Factory => _services.GetRequiredService<IDbContextFactory<AppDbContext>>();

    private StoredSecretAdminService Admin(TestCurrentUser? user = null, IDbContextFactory<AppDbContext>? factory = null) =>
        new(_store, factory ?? Factory, new TestOptionsMonitor<ChatOptions>(_chat), new TestOptionsMonitor<SiemWebhookOptions>(_webhook),
            user ?? _admin, _audit, _clock, _siem);

    private async Task<StoredSecretRecord?> RowAsync(StoredSecretKind kind)
    {
        var name = StoredSecretDefinition.For(kind).Name;
        await using var db = await Factory.CreateDbContextAsync();
        return await db.StoredSecrets.AsNoTracking().SingleOrDefaultAsync(r => r.Name == name);
    }

    public void Dispose()
    {
        _services.Dispose();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { File.Delete(_dbPath); } catch (IOException) { /* the temp folder's cleanup has it */ }
    }

    // --- Storage ---

    [Theory]
    [InlineData(StoredSecretKind.ChatWebhookUrl)]
    [InlineData(StoredSecretKind.SiemWebhookToken)]
    public async Task A_value_round_trips_and_is_kept_only_as_ciphertext(StoredSecretKind kind)
    {
        var value = kind == StoredSecretKind.ChatWebhookUrl ? NewHookUrl() : NewToken();
        await Admin().SaveAsync(kind, "  " + value + " ", expectedStamp: "");

        (await _store.ResolveAsync(kind)).Should().Be(new StoredSecretValue(true, value));
        var row = await RowAsync(kind);
        row!.ProtectedValue.Should().NotBeNullOrEmpty().And.NotContain(value);
        row.SetBy.Should().Be("admin1");
        row.SetAtUtc.Should().Be(_clock.UtcNow);
        Encoding.UTF8.GetString(await File.ReadAllBytesAsync(_dbPath)).Should().NotContain(value, "the database file holds no plain value");

        var status = await Admin().GetAsync(kind);
        status.Set.Should().BeTrue();
        status.Unreadable.Should().BeFalse();
        typeof(StoredSecretStatus).GetProperties().Where(p => p.PropertyType == typeof(string)).Select(p => p.Name)
            .Should().BeEquivalentTo(["SetBy", "UpdatedBy", "Stamp"], "what the page is given carries no value or ciphertext");
        status.Stamp.Should().MatchRegex("^[0-9A-F]{64}$").And.NotContain(value).And.NotContain(row.ProtectedValue!);

        var other = kind == StoredSecretKind.ChatWebhookUrl ? StoredSecretKind.SiemWebhookToken : StoredSecretKind.ChatWebhookUrl;
        (await _store.ResolveAsync(other)).Should().Be(StoredSecretValue.NotSaved, "each secret has its own row");
    }

    [Fact]
    public void Each_secret_has_a_purpose_of_its_own()
    {
        StoredSecretDefinition.All.Select(d => d.Purpose).Should().OnlyHaveUniqueItems()
            .And.NotContain(SmtpSignInStore.Purpose, "the SMTP password's ciphertext never opens as one of these, nor these as it");
        var chat = _keys.CreateProtector(StoredSecretDefinition.ChatWebhookUrl.Purpose).Protect(NewHookUrl());
        var act = () => _keys.CreateProtector(StoredSecretDefinition.SiemWebhookToken.Purpose).Unprotect(chat);
        act.Should().Throw<System.Security.Cryptography.CryptographicException>();
    }

    [Fact]
    public async Task Replace_and_clear_are_audited_and_streamed_without_the_value()
    {
        var first = NewToken();
        var second = NewToken();
        await Admin().SaveAsync(StoredSecretKind.SiemWebhookToken, first);
        await Admin().SaveAsync(StoredSecretKind.SiemWebhookToken, second);
        var row = await RowAsync(StoredSecretKind.SiemWebhookToken);
        await Admin().ClearAsync(StoredSecretKind.SiemWebhookToken);

        (await _store.ResolveAsync(StoredSecretKind.SiemWebhookToken)).Saved.Should().BeFalse();
        (await RowAsync(StoredSecretKind.SiemWebhookToken))!.ProtectedValue.Should().BeNull("cleared, and the row says who cleared it");
        _audit.Summaries.Should().HaveCount(3);
        _audit.Summaries[0].Should().Be("Create StoredSecret Siem:Webhook:Token SIEM webhook token set in Administration.");
        _audit.Summaries[1].Should().Contain("token replaced");
        _audit.Summaries[2].Should().Contain("token cleared");
        _audit.Summaries.Should().NotContain(s => s.Contains(first, StringComparison.Ordinal) || s.Contains(second, StringComparison.Ordinal)
                                                  || s.Contains(row!.ProtectedValue!, StringComparison.Ordinal));
        _audit.Summaries.Should().NotContain(s => s.Contains(" AppSetting ", StringComparison.Ordinal), "a setting's History never lists it");
        _siem.Events.Should().HaveCount(3).And.OnlyContain(e => e.EventId == SecurityEventIds.SettingChanged && e.Detail == "Siem:Webhook:Token");
        _log.Errors.Should().BeEmpty();
    }

    [Fact]
    public async Task Clearing_when_nothing_is_saved_is_refused()
    {
        var clear = () => Admin().ClearAsync(StoredSecretKind.ChatWebhookUrl, expectedStamp: "");
        (await clear.Should().ThrowAsync<InvalidOperationException>()).Which.Message.Should().Contain("nothing to clear");
        _audit.Summaries.Should().BeEmpty();
    }

    [Fact]
    public async Task Only_an_administrator_may_save_or_clear()
    {
        var save = () => Admin(new TestCurrentUser { UserId = "analyst1" }).SaveAsync(StoredSecretKind.SiemWebhookToken, NewToken());
        await save.Should().ThrowAsync<ForbiddenException>();
        var clear = () => Admin(new TestCurrentUser { UserId = "analyst1" }).ClearAsync(StoredSecretKind.SiemWebhookToken);
        await clear.Should().ThrowAsync<ForbiddenException>();
        _siem.Events.Should().HaveCount(2).And.OnlyContain(e => e.EventId == SecurityEventIds.ActionRefused);
        (await RowAsync(StoredSecretKind.SiemWebhookToken)).Should().BeNull();
    }

    // --- Validation ---

    [Theory]
    [InlineData("http://hooks.example.com/abc", "http is only permitted to loopback")]
    [InlineData("ftp://hooks.example.com/abc", "unsupported scheme")]
    [InlineData("hooks.example.com/abc", "not an absolute URL")]
    [InlineData("", "Enter the team-chat webhook URL")]
    [InlineData("@cyberark:Safe=SOC;Object=Chat", "reference for the server's configuration")]
    public async Task A_chat_url_that_fails_the_https_check_is_refused_with_why_and_never_echoed(string url, string why)
    {
        var save = () => Admin().SaveAsync(StoredSecretKind.ChatWebhookUrl, url);
        var refused = (await save.Should().ThrowAsync<InvalidOperationException>()).Which;
        refused.Message.Should().Contain(why);
        if (url.Length > 0) refused.Message.Should().NotContain(url, "the refusal names why, not the URL");
        (await RowAsync(StoredSecretKind.ChatWebhookUrl)).Should().BeNull();
        _audit.Summaries.Should().BeEmpty();
        _log.Errors.Should().BeEmpty("nothing about a refused URL is logged");
    }

    [Fact]
    public async Task Http_to_this_server_itself_is_allowed_as_for_a_send()
    {
        await Admin().SaveAsync(StoredSecretKind.ChatWebhookUrl, "http://127.0.0.1:9000/hook-" + Guid.NewGuid().ToString("N"));
        (await _store.ResolveAsync(StoredSecretKind.ChatWebhookUrl)).Saved.Should().BeTrue();
    }

    [Fact]
    public async Task A_token_with_a_line_break_is_refused()
    {
        var save = () => Admin().SaveAsync(StoredSecretKind.SiemWebhookToken, NewToken() + "\r\nX-Injected: 1");
        (await save.Should().ThrowAsync<InvalidOperationException>()).Which.Message.Should().Contain("on one line");
    }

    // --- Server configuration wins ---

    [Theory]
    [InlineData("literal")]
    [InlineData("@cyberark:Safe=SIEM;Object=CaseBook-Webhook-Token")]
    [InlineData("@protected:v1:00:AAAA")]
    public async Task The_servers_configuration_wins_and_the_card_is_read_only(string form)
    {
        _webhook.Token = form == "literal" ? NewToken() : form;
        var admin = Admin();
        admin.SetInServerConfiguration(StoredSecretKind.SiemWebhookToken).Should().BeTrue();
        admin.SetInServerConfiguration(StoredSecretKind.ChatWebhookUrl).Should().BeFalse();
        admin.ServerConfigurationForm(StoredSecretKind.SiemWebhookToken).Should().NotContain(_webhook.Token);

        var save = () => admin.SaveAsync(StoredSecretKind.SiemWebhookToken, NewToken());
        (await save.Should().ThrowAsync<InvalidOperationException>()).Which.Message.Should().Contain("server's configuration");
        (await RowAsync(StoredSecretKind.SiemWebhookToken)).Should().BeNull();
    }

    [Fact]
    public async Task A_server_configured_token_is_sent_over_a_saved_one()
    {
        await Admin().SaveAsync(StoredSecretKind.SiemWebhookToken, NewToken());
        _webhook.Token = NewToken();   // set on the server afterwards
        var handler = new CapturingHandler();
        await Transport(handler).SendTestAsync(Event(), CancellationToken.None);
        handler.Requests.Single().Headers.Authorization!.Parameter.Should().Be(_webhook.Token);
    }

    // --- The senders read it per send: no restart ---

    [Fact]
    public async Task The_siem_webhook_sends_the_saved_token_and_a_change_applies_to_the_next_event()
    {
        var handler = new CapturingHandler();
        var transport = Transport(handler);
        await transport.SendTestAsync(Event(), CancellationToken.None);
        handler.Requests.Single().Headers.Authorization.Should().BeNull("no token anywhere: sent as before, without one");

        var first = NewToken();
        await Admin().SaveAsync(StoredSecretKind.SiemWebhookToken, first);
        (await transport.SendTestAsync(Event(), CancellationToken.None)).Should().BeNull();
        handler.Requests[^1].Headers.Authorization!.Parameter.Should().Be(first);

        var second = NewToken();
        await Admin().SaveAsync(StoredSecretKind.SiemWebhookToken, second);
        await transport.SendTestAsync(Event(), CancellationToken.None);
        handler.Requests[^1].Headers.Authorization!.Parameter.Should().Be(second, "the save drops what was kept");
    }

    [Fact]
    public async Task The_chat_notifier_posts_to_the_saved_url_and_a_change_applies_to_the_next_post()
    {
        var handler = new CapturingHandler();
        var chat = Notifier(handler);
        chat.Enabled.Should().BeFalse("no URL anywhere");
        chat.StoppedReason.Should().Contain("no webhook URL is set");

        var first = NewHookUrl();
        await Admin().SaveAsync(StoredSecretKind.ChatWebhookUrl, first);
        chat.Enabled.Should().BeTrue();
        chat.StoppedReason.Should().BeNull();
        (await chat.SendTestAsync(new ChatNotification("Test", "Hello"))).Should().BeNull();
        handler.Requests.Single().RequestUri!.ToString().Should().Be(first);

        var second = NewHookUrl();
        await Admin().SaveAsync(StoredSecretKind.ChatWebhookUrl, second);
        await chat.SendTestAsync(new ChatNotification("Test", "Hello"));
        handler.Requests[^1].RequestUri!.ToString().Should().Be(second);

        await Admin().ClearAsync(StoredSecretKind.ChatWebhookUrl);
        chat.Enabled.Should().BeFalse("cleared: chat is off again, without a restart");
    }

    // --- Fail closed ---

    [Fact]
    public async Task A_token_that_wont_decrypt_here_isnt_sent_unauthenticated_and_is_logged_once()
    {
        var token = NewToken();
        await Admin().SaveAsync(StoredSecretKind.SiemWebhookToken, token);
        // The database restored onto a server without the key ring it was saved with.
        var elsewhere = new StoredSecretStore(_services.GetRequiredService<IServiceScopeFactory>(), new EphemeralDataProtectionProvider(), _log);
        var handler = new CapturingHandler();
        var health = new DeliveryHealth(_clock);
        var transport = Transport(handler, elsewhere, health);

        var error = await transport.SendTestAsync(Event(), CancellationToken.None);
        await transport.SendAsync(Event(), CancellationToken.None);

        handler.Requests.Should().BeEmpty("no event goes without the token that was asked for");
        error.Should().Contain("can't be decrypted").And.Contain("Re-enter it");
        transport.StoppedReason.Should().Contain("can't be decrypted", "the delivery card shows it stopped, with why");
        SiemTransportRows.Pick([transport]).Single().StoppedReason.Should().Contain("re-enter it");
        health.Snapshot()[DeliveryHealth.Siem("webhook")].LastFailure.Should().Contain("can't be decrypted");
        (await elsewhere.StatusAsync(StoredSecretKind.SiemWebhookToken)).Unreadable.Should().BeTrue("Diagnostics says to re-enter it");
        _log.Errors.Should().ContainSingle("logged once, not on every event").Which.Should().NotContain(token).And.Contain("re-enter");
    }

    [Fact]
    public async Task A_server_token_that_wont_resolve_isnt_sent_unauthenticated_either()
    {
        _webhook.Token = string.Concat("@cyberark:Safe=SIEM;Object=", Guid.NewGuid().ToString("N"));   // S2068: made at run time
        var handler = new CapturingHandler();
        var error = await Transport(handler, secrets: new NothingResolves()).SendTestAsync(Event(), CancellationToken.None);
        handler.Requests.Should().BeEmpty("before CAP-40 this went without an auth header");
        error.Should().Contain("couldn't be resolved");
    }

    [Fact]
    public async Task A_chat_url_that_wont_decrypt_here_isnt_posted_and_counts_as_a_failure()
    {
        await Admin().SaveAsync(StoredSecretKind.ChatWebhookUrl, NewHookUrl());
        var elsewhere = new StoredSecretStore(_services.GetRequiredService<IServiceScopeFactory>(), new EphemeralDataProtectionProvider(), _log);
        var handler = new CapturingHandler();
        var health = new DeliveryHealth(_clock);
        var chat = Notifier(handler, elsewhere, health);

        chat.Enabled.Should().BeTrue("saved, so a scheduled broadcast fails and is tried again rather than being marked sent");
        chat.StoppedReason.Should().Contain("can't be decrypted");
        (await chat.SendTestAsync(new ChatNotification("Test", "Hello"))).Should().Contain("Re-enter it");
        int failures;
        using (var watch = DeliveryWatch.Begin())
        {
            await chat.SendAsync(new ChatNotification("Test", "Hello"));
            failures = watch.Failures;
        }
        failures.Should().Be(1);
        handler.Requests.Should().BeEmpty();
        health.Snapshot()[DeliveryHealth.Chat].LastFailure.Should().Contain("can't be decrypted");
        _log.Errors.Should().ContainSingle();
    }

    // --- Stale stamp and the first-save race ---

    [Fact]
    public async Task A_save_or_clear_from_a_card_loaded_before_another_save_is_refused_and_changes_nothing()
    {
        await Admin().SaveAsync(StoredSecretKind.SiemWebhookToken, NewToken(), expectedStamp: "");
        var loaded = await Admin().GetAsync(StoredSecretKind.SiemWebhookToken);   // A opens the card

        var other = new TestCurrentUser { UserId = "admin2", RoleSet = [AppRole.SysAdmin] };
        var b = NewToken();
        await Admin(other).SaveAsync(StoredSecretKind.SiemWebhookToken, b, (await Admin(other).GetAsync(StoredSecretKind.SiemWebhookToken)).Stamp);
        var afterB = await RowAsync(StoredSecretKind.SiemWebhookToken);

        var save = () => Admin().SaveAsync(StoredSecretKind.SiemWebhookToken, NewToken(), loaded.Stamp);
        var refused = (await save.Should().ThrowAsync<IncidentManager.Application.Cases.StaleEditException>()).Which;
        refused.Message.Should().Be(StoredSecretAdminService.ChangedSinceOpened(StoredSecretKind.SiemWebhookToken));
        refused.CurrentStamp.Should().Be((await Admin().GetAsync(StoredSecretKind.SiemWebhookToken)).Stamp);
        var clear = () => Admin().ClearAsync(StoredSecretKind.SiemWebhookToken, loaded.Stamp);
        await clear.Should().ThrowAsync<IncidentManager.Application.Cases.StaleEditException>();

        (await RowAsync(StoredSecretKind.SiemWebhookToken)).Should().BeEquivalentTo(afterB, "nothing was written");
        (await _store.ResolveAsync(StoredSecretKind.SiemWebhookToken)).Value.Should().Be(b);
        _audit.Summaries.Should().HaveCount(2, "the refused save and clear aren't audited as changes");
    }

    [Fact]
    public async Task A_first_save_from_a_card_that_saw_no_row_is_refused_once_one_is_saved()
    {
        (await Admin().GetAsync(StoredSecretKind.ChatWebhookUrl)).Stamp.Should().BeEmpty("no row yet: a first save expects none");
        await Admin().SaveAsync(StoredSecretKind.ChatWebhookUrl, NewHookUrl(), expectedStamp: "");
        var late = () => Admin().SaveAsync(StoredSecretKind.ChatWebhookUrl, NewHookUrl(), expectedStamp: "");
        await late.Should().ThrowAsync<IncidentManager.Application.Cases.StaleEditException>();
    }

    [Fact]
    public async Task A_cleared_and_saved_again_secret_still_refuses_a_card_from_before()
    {
        await Admin().SaveAsync(StoredSecretKind.SiemWebhookToken, NewToken());
        var loaded = await Admin().GetAsync(StoredSecretKind.SiemWebhookToken);
        await Admin().ClearAsync(StoredSecretKind.SiemWebhookToken, loaded.Stamp);
        var save = () => Admin().SaveAsync(StoredSecretKind.SiemWebhookToken, NewToken(), loaded.Stamp);
        await save.Should().ThrowAsync<IncidentManager.Application.Cases.StaleEditException>("the cleared row's stamp isn't the set one's");
    }

    [Fact]
    public async Task A_test_send_doesnt_move_the_stamp()
    {
        // The service side of the card's rule: sending doesn't write the row, so what the card loaded is still the stamp.
        await Admin().SaveAsync(StoredSecretKind.SiemWebhookToken, NewToken());
        var before = await Admin().GetAsync(StoredSecretKind.SiemWebhookToken);
        await Transport(new CapturingHandler()).SendTestAsync(Event(), CancellationToken.None);
        (await Admin().GetAsync(StoredSecretKind.SiemWebhookToken)).Stamp.Should().Be(before.Stamp);
    }

    // Plays the other administrator: their whole first save runs, and commits, just as this save is about to write.
    private sealed class OtherFirstSave(Func<Task> save) : Microsoft.EntityFrameworkCore.Diagnostics.DbCommandInterceptor
    {
        public bool Ran { get; private set; }

        private async Task RaceAsync(System.Data.Common.DbCommand command)
        {
            if (Ran || !command.CommandText.Contains("INSERT INTO \"StoredSecrets\"", StringComparison.Ordinal)) return;
            Ran = true;
            await save();
        }

        public override async ValueTask<Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<System.Data.Common.DbDataReader>> ReaderExecutingAsync(
            System.Data.Common.DbCommand command, Microsoft.EntityFrameworkCore.Diagnostics.CommandEventData eventData,
            Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<System.Data.Common.DbDataReader> result, CancellationToken cancellationToken = default)
        {
            await RaceAsync(command);
            return result;
        }

        public override async ValueTask<Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<int>> NonQueryExecutingAsync(
            System.Data.Common.DbCommand command, Microsoft.EntityFrameworkCore.Diagnostics.CommandEventData eventData,
            Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            await RaceAsync(command);
            return result;
        }
    }

    [Fact]
    public async Task Two_first_saves_at_once_one_lands_and_the_other_is_told_instead_of_an_error_page()
    {
        var b = NewToken();
        var other = new TestCurrentUser { UserId = "admin2", RoleSet = [AppRole.SysAdmin] };
        var race = new OtherFirstSave(() => Admin(other).SaveAsync(StoredSecretKind.SiemWebhookToken, b, expectedStamp: ""));
        var racing = new ServiceCollection()
            .AddDbContextFactory<AppDbContext>(o => o.UseSqlite($"Data Source={_dbPath};Pooling=False").AddInterceptors(race))
            .BuildServiceProvider();
        await using var _ = racing;

        var save = () => Admin(factory: racing.GetRequiredService<IDbContextFactory<AppDbContext>>())
            .SaveAsync(StoredSecretKind.SiemWebhookToken, NewToken(), expectedStamp: "");

        (await save.Should().ThrowAsync<InvalidOperationException>()).Which.Message
            .Should().Be("Someone else saved the SIEM webhook token just now; reload to see it.");
        race.Ran.Should().BeTrue();
        (await _store.ResolveAsync(StoredSecretKind.SiemWebhookToken)).Value.Should().Be(b, "the first to land is the one kept");
    }

    // --- Kept out of the bundle and the markup ---

    [Fact]
    public async Task The_configuration_bundle_doesnt_carry_them()
    {
        var url = NewHookUrl();
        var token = NewToken();
        await Admin().SaveAsync(StoredSecretKind.ChatWebhookUrl, url);
        await Admin().SaveAsync(StoredSecretKind.SiemWebhookToken, token);
        var rows = new[] { await RowAsync(StoredSecretKind.ChatWebhookUrl), await RowAsync(StoredSecretKind.SiemWebhookToken) };

        using var connection = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={_dbPath};Pooling=False");
        connection.Open();
        var options = new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection)
            .AddInterceptors(new AuditChainInterceptor(new HashChainService(), _admin, _clock, new CaseChangeNotifier())).Options;
        var workDir = Path.Combine(Path.GetTempPath(), "im-secret-bundle", Guid.NewGuid().ToString("N"));
        try
        {
            var signer = new RsaSealSigner(Options.Create(new SealSigningOptions { SigningKeyPath = Path.Combine(workDir, "k.pem"), AllowKeyGeneration = true }));
            var bundle = new ConfigBundleService(new TestDbContextFactory(options), signer, new NoOpAuditWriter(), _admin, _clock);
            var export = Encoding.UTF8.GetString((await bundle.ExportAsync()).Content);
            export.Should().NotContain(url).And.NotContain(token).And.NotContain("StoredSecret")
                .And.NotContain("Chat:Webhook:WebhookUrl").And.NotContain("Siem:Webhook:Token");
            foreach (var row in rows) export.Should().NotContain(row!.ProtectedValue!);
        }
        finally { try { Directory.Delete(workDir, recursive: true); } catch (IOException) { /* best effort */ } }
    }

    [Fact]
    public void The_cards_field_is_never_filled_from_the_server()
    {
        var card = Card();
        var field = Regex.Match(card, @"<input(?:(?!/>).)*?type=""password""(?:(?!/>).)*/>", RegexOptions.Singleline, TimeSpan.FromSeconds(1));
        field.Success.Should().BeTrue();
        field.Value.Should().NotContain("@bind").And.NotContain("value=", "write-only: what's typed is read on change, never rendered back");
        card.Should().NotContain("ProtectedValue").And.NotContain("ResolveAsync").And.NotContain("Peek(");
        Regex.Matches(card, @"<input", RegexOptions.None, TimeSpan.FromSeconds(1)).Should().HaveCount(1, "the secret's field is the card's only input");
    }

    [Fact]
    public void The_card_saves_with_the_stamp_it_loaded_and_a_test_send_doesnt_move_it()
    {
        // As CAP-05's review (C9): the stamp is what the admin saw. A test send refreshes the status for display; if it took
        // the newer stamp too, a stale card would save over another admin's newer value unrefused.
        var card = Card();
        card.Should().Contain("Secrets.SaveAsync(Kind, _newValue, _stamp)").And.Contain("Secrets.ClearAsync(Kind, _stamp)");
        Regex.Matches(card, @"_stamp\s*=(?!=)", RegexOptions.None, TimeSpan.FromSeconds(1)).Should().HaveCount(3,
            "set at its declaration, on a load, and on a reload the admin was told about");
        Regex.IsMatch(card, @"SendTestCore\(\)(?:(?!private ).)*ReloadStatusAsync\(takeStamp: false\)", RegexOptions.Singleline,
            TimeSpan.FromSeconds(1)).Should().BeTrue("a test send keeps the loaded stamp");
        Regex.IsMatch(card, @"SendTestCore\(\)(?:(?!private ).)*LoadAsync\(\)", RegexOptions.Singleline, TimeSpan.FromSeconds(1))
            .Should().BeFalse("a test send doesn't reload the stamp either");
        foreach (var guard in new[] { "_saving.Run(SaveCore)", "_clearing.Run(ClearCore)", "_testing.Run(SendTestCore)" })
            card.Should().Contain(guard, "C8: one save, clear or test at a time");
    }

    [Fact]
    public void Each_card_is_on_the_page_its_settings_live_on()
    {
        var admin = File.ReadAllText(Path.Combine(RepoRoot(), "src", "IncidentManager.Web", "Components", "Pages", "Admin.razor"));
        admin.Should().Contain("StoredSecretKind.ChatWebhookUrl").And.Contain("StoredSecretKind.SiemWebhookToken");
        admin.IndexOf("StoredSecretKind.ChatWebhookUrl\"", StringComparison.Ordinal).Should()
            .BeLessThan(admin.IndexOf("_activeId == \"server\"", StringComparison.Ordinal), "chat, with the notification settings");
        admin.IndexOf("StoredSecretKind.SiemWebhookToken\"", StringComparison.Ordinal).Should()
            .BeGreaterThan(admin.IndexOf("_activeId == \"server\"", StringComparison.Ordinal), "the SIEM token, with the SIEM rows in Server configuration");
    }

    // --- Helpers ---

    private static string Card() =>
        File.ReadAllText(Path.Combine(RepoRoot(), "src", "IncidentManager.Web", "Components", "Shared", "StoredSecretCard.razor"));

    private static SecurityEvent Event() => new() { EventId = SecurityEventIds.SiemTest, Category = "Diagnostics", Action = "SiemTest", Actor = "admin1" };

    private WebhookTransport Transport(CapturingHandler handler, StoredSecretStore? store = null, IDeliveryHealth? health = null,
        ISecretProvider? secrets = null) =>
        new(new StubFactory(handler), new TestOptionsMonitor<SiemWebhookOptions>(_webhook),
            secrets ?? new PassthroughSecretProvider(NullLogger<PassthroughSecretProvider>.Instance), NullLogger<WebhookTransport>.Instance,
            health, store ?? _store);

    private ChatWebhookNotifier Notifier(CapturingHandler handler, StoredSecretStore? store = null, IDeliveryHealth? health = null) =>
        new(new StubFactory(handler), new TestOptionsMonitor<ChatOptions>(_chat),
            new PassthroughSecretProvider(NullLogger<PassthroughSecretProvider>.Instance), NullLogger<ChatWebhookNotifier>.Instance,
            health: health, stored: store ?? _store);

    private sealed class NothingResolves : ISecretProvider
    {
        public ValueTask<string?> ResolveAsync(string? configuredValue, CancellationToken ct = default) => new((string?)null);
    }

    private sealed class CapturingHandler : HttpMessageHandler
    {
        public readonly List<HttpRequestMessage> Requests = [];
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Requests.Add(request);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }

    private sealed class StubFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }

    private static string RepoRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "IncidentManager.sln"))) return dir.FullName;
        throw new InvalidOperationException("Couldn't find the repo root (IncidentManager.sln).");
    }
}
