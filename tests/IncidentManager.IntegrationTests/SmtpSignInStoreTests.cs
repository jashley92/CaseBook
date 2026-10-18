using System.Text;
using System.Text.RegularExpressions;
using FluentAssertions;
using IncidentManager.Application.Config;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Notifications;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using IncidentManager.Web.Notifications;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// CAP-05: the sign-in entered under Administration. The password round-trips through Data Protection and is kept as
/// ciphertext only; it's never returned to the page (the status carries none, and the form's field is never filled), never
/// in the configuration bundle, the audit trail or the log. The server's configuration wins when it sets a sign-in. A
/// password that won't decrypt here (a database restored without its key ring) fails closed, logged once. A save applies
/// to the next send without a restart, is audited (who, when, the mode, what became of the password) and goes to the SIEM
/// as 5403.
/// </summary>
public sealed class SmtpSignInStoreTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"casebook-smtpsignin-{Guid.NewGuid():N}.db");
    private readonly ServiceProvider _services;
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 18, 9, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _admin = new() { UserId = "admin1", RoleSet = [AppRole.SysAdmin] };
    private readonly EmailOptions _email = new();
    private readonly CapturingSecurityEventSink _siem = new();
    private readonly RecordingAudit _audit = new();
    private readonly CountingLogger _log = new();
    private readonly IDataProtectionProvider _keys = new EphemeralDataProtectionProvider();
    private readonly SmtpSignInStore _store;

    private static string NewSecret() => "pw-" + Guid.NewGuid().ToString("N");   // S2068: made at run time

    private sealed class RecordingAudit : IncidentManager.Application.Abstractions.IAuditWriter
    {
        public readonly List<string> Summaries = [];
        public Task RecordAsync(AuditAction action, string entityType, string? entityId, string? caseNumber, string summary, CancellationToken ct = default)
        {
            Summaries.Add($"{action} {entityType} {entityId} {summary}");
            return Task.CompletedTask;
        }
    }

    private sealed class CountingLogger : ILogger<SmtpSignInStore>
    {
        public readonly List<string> Errors = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (logLevel >= LogLevel.Warning) Errors.Add(formatter(state, exception) + exception);
        }
    }

    public SmtpSignInStoreTests()
    {
        _services = new ServiceCollection()
            .AddDbContextFactory<AppDbContext>(o => o.UseSqlite($"Data Source={_dbPath};Pooling=False"))
            .BuildServiceProvider();
        using (var db = Factory.CreateDbContext()) db.Database.EnsureCreated();
        _store = new SmtpSignInStore(_services.GetRequiredService<IServiceScopeFactory>(), _keys, _log);
    }

    private IDbContextFactory<AppDbContext> Factory => _services.GetRequiredService<IDbContextFactory<AppDbContext>>();

    private SmtpSignInAdminService Admin(TestCurrentUser? user = null) =>
        new(_store, Factory, new TestOptionsMonitor<EmailOptions>(_email), user ?? _admin, _audit, _clock, _siem);

    private async Task<SmtpSignInRecord?> RowAsync()
    {
        await using var db = await Factory.CreateDbContextAsync();
        return await db.SmtpSignIns.AsNoTracking().SingleOrDefaultAsync();
    }

    public void Dispose()
    {
        _services.Dispose();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { File.Delete(_dbPath); } catch (IOException) { /* the temp folder's cleanup has it */ }
    }

    [Fact]
    public async Task The_password_round_trips_and_is_kept_only_as_ciphertext()
    {
        var secret = NewSecret();
        await Admin().SaveAsync(SmtpSignInMode.Password, " casebook@contoso.example ", secret);

        var (mode, credentials) = await _store.ResolveAsync(CancellationToken.None);
        mode.Should().Be(SmtpSignInMode.Password);
        credentials!.UserName.Should().Be("casebook@contoso.example");
        credentials.Password.Should().Be(secret);

        var row = await RowAsync();
        row!.ProtectedPassword.Should().NotBeNullOrEmpty().And.NotContain(secret);
        row.PasswordSetBy.Should().Be("admin1");
        row.PasswordSetAtUtc.Should().Be(_clock.UtcNow);
        var raw = await File.ReadAllBytesAsync(_dbPath);
        Encoding.UTF8.GetString(raw).Should().NotContain(secret, "the database file holds no plain password");

        var status = await Admin().GetAsync();
        status.PasswordSet.Should().BeTrue();
        status.PasswordUnreadable.Should().BeFalse();
        typeof(SmtpSignInStatus).GetProperties().Where(p => p.PropertyType == typeof(string)).Select(p => p.Name)
            .Should().BeEquivalentTo(["Username", "PasswordSetBy", "UpdatedBy", "Stamp"], "what the page is given carries no password or ciphertext");
        // CAP-05 review: the stale-edit stamp is a hash of the row, not the row: neither the password nor its ciphertext.
        status.Stamp.Should().MatchRegex("^[0-9A-F]{64}$").And.NotContain(secret).And.NotContain(row.ProtectedPassword!);
    }

    [Fact]
    public async Task Saving_again_without_a_password_keeps_it_and_none_or_windows_clears_it()
    {
        var secret = NewSecret();
        await Admin().SaveAsync(SmtpSignInMode.Password, "casebook@contoso.example", secret);
        await Admin().SaveAsync(SmtpSignInMode.Password, "other@contoso.example", null);
        (await _store.ResolveAsync(CancellationToken.None)).Credentials!.Password.Should().Be(secret, "an empty field means keep it");

        await Admin().SaveAsync(SmtpSignInMode.Integrated, "ignored", null);
        (await _store.ResolveAsync(CancellationToken.None)).Should().Be((SmtpSignInMode.Integrated, (System.Net.NetworkCredential?)null));
        (await RowAsync())!.ProtectedPassword.Should().BeNull("Windows signs in with no password at all");
        await Admin().ClearAsync();
        (await _store.ResolveAsync(CancellationToken.None)).Mode.Should().Be(SmtpSignInMode.None);
    }

    [Theory]
    [InlineData("", true)]        // no username
    [InlineData("u", false)]      // no password, and none saved
    [InlineData("a\nb", true)]    // a line break
    public async Task A_password_sign_in_needs_its_username_and_password(string user, bool withSecret)
    {
        var save = () => Admin().SaveAsync(SmtpSignInMode.Password, user, withSecret ? NewSecret() : null);
        await save.Should().ThrowAsync<InvalidOperationException>();
        (await RowAsync()).Should().BeNull("nothing half-made is saved");
    }

    [Fact]
    public async Task A_key_ring_that_cant_protect_is_a_worded_refusal_not_a_dead_circuit()
    {
        // CAP-40 review: Data Protection wraps a key ring it can't write in a CryptographicException, which the form didn't catch.
        var broken = new SmtpSignInStore(_services.GetRequiredService<IServiceScopeFactory>(), new ThrowingProtection(), _log);
        var admin = new SmtpSignInAdminService(broken, Factory, new TestOptionsMonitor<EmailOptions>(_email), _admin, _audit, _clock, _siem);
        var secret = NewSecret();
        var save = () => admin.SaveAsync(SmtpSignInMode.Password, "casebook@contoso.example", secret);
        var refused = (await save.Should().ThrowAsync<InvalidOperationException>()).Which;
        refused.Message.Should().Contain("couldn't be encrypted").And.Contain("DataProtection:KeyPath").And.NotContain(secret);
        (await RowAsync()).Should().BeNull("nothing was written");
        _audit.Summaries.Should().BeEmpty();
    }

    private sealed class ThrowingProtection : IDataProtectionProvider, IDataProtector
    {
        public IDataProtector CreateProtector(string purpose) => this;
        public byte[] Protect(byte[] plaintext) =>
            throw new System.Security.Cryptography.CryptographicException("An error occurred during a cryptographic operation.",
                new UnauthorizedAccessException("Access to the key ring path is denied (test)."));
        public byte[] Unprotect(byte[] protectedData) => throw new System.Security.Cryptography.CryptographicException("test");
    }

    [Fact]
    public async Task Only_an_administrator_may_save_it()
    {
        var save = () => Admin(new TestCurrentUser { UserId = "analyst1" }).SaveAsync(SmtpSignInMode.Password, "u", NewSecret());
        await save.Should().ThrowAsync<ForbiddenException>();
        _siem.Events.Should().ContainSingle(e => e.EventId == SecurityEventIds.ActionRefused);
    }

    [Fact]
    public async Task A_save_is_audited_and_streamed_without_the_password()
    {
        var secret = NewSecret();
        await Admin().SaveAsync(SmtpSignInMode.Password, "casebook@contoso.example", secret);
        await Admin().SaveAsync(SmtpSignInMode.Password, "casebook@contoso.example", NewSecret());

        _audit.Summaries.Should().HaveCount(2);
        _audit.Summaries[0].Should().Contain("username and password").And.Contain("password set");
        _audit.Summaries[1].Should().Contain("password replaced");
        var row = await RowAsync();
        _audit.Summaries.Should().NotContain(s => s.Contains(secret, StringComparison.Ordinal) || s.Contains(row!.ProtectedPassword!, StringComparison.Ordinal));
        _siem.Events.Should().HaveCount(2).And.OnlyContain(e => e.EventId == SecurityEventIds.SettingChanged);
        _siem.Events.Select(e => e.Detail + e.TargetId).Should().NotContain(d => d != null && d.Contains(secret, StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_change_applies_to_the_next_send_without_a_restart()
    {
        await Admin().SaveAsync(SmtpSignInMode.Integrated, null, null);
        (await _store.ResolveAsync(CancellationToken.None)).Mode.Should().Be(SmtpSignInMode.Integrated);   // read and kept
        await Admin().SaveAsync(SmtpSignInMode.None, null, null);
        (await _store.ResolveAsync(CancellationToken.None)).Mode.Should().Be(SmtpSignInMode.None, "the save drops what was kept");
    }

    [Fact]
    public async Task A_save_from_a_form_loaded_before_another_save_is_refused_and_changes_nothing(/* CAP-05 review */)
    {
        var first = NewSecret();
        await Admin().SaveAsync(SmtpSignInMode.Password, "casebook@contoso.example", first, expectedStamp: "");
        var loaded = await Admin().GetAsync();   // A opens the form

        // B saves a new username and a new password.
        var second = NewSecret();
        var other = new TestCurrentUser { UserId = "admin2", RoleSet = [AppRole.SysAdmin] };
        await Admin(other).SaveAsync(SmtpSignInMode.Password, "relay-b@contoso.example", second, (await Admin(other).GetAsync()).Stamp);
        var afterB = await RowAsync();

        // A saves without typing a password: "keep it" would pair A's old username with B's password.
        var save = () => Admin().SaveAsync(SmtpSignInMode.Password, loaded.Username, null, loaded.Stamp);
        var refused = (await save.Should().ThrowAsync<IncidentManager.Application.Cases.StaleEditException>()).Which;
        refused.Message.Should().Be(SmtpSignInAdminService.ChangedSinceOpened);
        refused.CurrentStamp.Should().Be((await Admin().GetAsync()).Stamp);

        (await RowAsync()).Should().BeEquivalentTo(afterB, "nothing was written");
        var (_, credentials) = await _store.ResolveAsync(CancellationToken.None);
        credentials!.UserName.Should().Be("relay-b@contoso.example");
        credentials.Password.Should().Be(second);
        _audit.Summaries.Should().HaveCount(2, "the refused save isn't audited as a change");

        // Clear from the stale form is refused too; with the stamp reloaded, Save goes through and the stamp moves on.
        var clear = () => Admin().ClearAsync(loaded.Stamp);
        await clear.Should().ThrowAsync<IncidentManager.Application.Cases.StaleEditException>();
        var reloaded = await Admin().GetAsync();
        await Admin().SaveAsync(SmtpSignInMode.Password, "casebook@contoso.example", null, reloaded.Stamp);
        (await Admin().GetAsync()).Stamp.Should().NotBe(reloaded.Stamp);
    }

    [Fact]
    public async Task A_first_save_from_a_form_that_saw_no_row_is_refused_once_one_is_saved(/* CAP-05 review */)
    {
        (await Admin().GetAsync()).Stamp.Should().BeEmpty("no row yet: a first save expects none");
        await Admin().SaveAsync(SmtpSignInMode.Integrated, null, null, expectedStamp: "");
        var late = () => Admin().SaveAsync(SmtpSignInMode.Password, "u@contoso.example", NewSecret(), expectedStamp: "");
        await late.Should().ThrowAsync<IncidentManager.Application.Cases.StaleEditException>();
        (await RowAsync())!.Mode.Should().Be(nameof(SmtpSignInMode.Integrated));
    }

    // Plays the other administrator: their whole first save runs, and commits, just as this save is about to write.
    private sealed class OtherFirstSave(Func<Task> save) : Microsoft.EntityFrameworkCore.Diagnostics.DbCommandInterceptor,
        Microsoft.EntityFrameworkCore.Diagnostics.IDbTransactionInterceptor
    {
        public bool Ran { get; private set; }

        private async Task RaceAsync()
        {
            if (Ran) return;
            Ran = true;
            await save();
        }

        public async ValueTask<Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<System.Data.Common.DbTransaction>> TransactionStartingAsync(
            System.Data.Common.DbConnection connection, Microsoft.EntityFrameworkCore.Diagnostics.TransactionStartingEventData eventData,
            Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<System.Data.Common.DbTransaction> result, CancellationToken cancellationToken = default)
        {
            await RaceAsync();
            return result;
        }

        public override async ValueTask<Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<System.Data.Common.DbDataReader>> ReaderExecutingAsync(
            System.Data.Common.DbCommand command, Microsoft.EntityFrameworkCore.Diagnostics.CommandEventData eventData,
            Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<System.Data.Common.DbDataReader> result, CancellationToken cancellationToken = default)
        {
            if (command.CommandText.Contains("INSERT INTO \"SmtpSignIns\"", StringComparison.Ordinal)) await RaceAsync();
            return result;
        }

        public override async ValueTask<Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<int>> NonQueryExecutingAsync(
            System.Data.Common.DbCommand command, Microsoft.EntityFrameworkCore.Diagnostics.CommandEventData eventData,
            Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (command.CommandText.Contains("INSERT INTO \"SmtpSignIns\"", StringComparison.Ordinal)) await RaceAsync();
            return result;
        }
    }

    [Fact]
    public async Task Two_first_saves_at_once_one_lands_and_the_other_is_told_instead_of_an_error_page(/* CAP-05 review */)
    {
        var b = NewSecret();
        var other = new TestCurrentUser { UserId = "admin2", RoleSet = [AppRole.SysAdmin] };
        // Both forms opened on no row; B's save lands between A's read and A's insert.
        var race = new OtherFirstSave(() => Admin(other).SaveAsync(SmtpSignInMode.Password, "relay-b@contoso.example", b, expectedStamp: ""));
        var racing = new ServiceCollection()
            .AddDbContextFactory<AppDbContext>(o => o.UseSqlite($"Data Source={_dbPath};Pooling=False").AddInterceptors(race))
            .BuildServiceProvider();
        await using var _ = racing;
        var a = new SmtpSignInAdminService(_store, racing.GetRequiredService<IDbContextFactory<AppDbContext>>(),
            new TestOptionsMonitor<EmailOptions>(_email), _admin, _audit, _clock, _siem);

        var save = () => a.SaveAsync(SmtpSignInMode.Password, "relay-a@contoso.example", NewSecret(), expectedStamp: "");

        (await save.Should().ThrowAsync<InvalidOperationException>()).Which.Message
            .Should().Be("Someone else saved the email sign-in just now; reload to see it.");
        race.Ran.Should().BeTrue();
        var (_, credentials) = await _store.ResolveAsync(CancellationToken.None);
        credentials!.UserName.Should().Be("relay-b@contoso.example", "the first to land is the one kept");
        credentials.Password.Should().Be(b);
    }

    [Fact]
    public async Task The_servers_configuration_wins_and_the_form_is_read_only()
    {
        _email.SmtpUseDefaultCredentials = true;
        var admin = Admin();
        admin.SetInServerConfiguration.Should().BeTrue();
        var save = () => admin.SaveAsync(SmtpSignInMode.Password, "u", NewSecret());
        (await save.Should().ThrowAsync<InvalidOperationException>()).Which.Message.Should().Contain("server's configuration");
        (await RowAsync()).Should().BeNull();
    }

    [Fact]
    public async Task A_password_that_wont_decrypt_here_fails_closed_and_is_logged_once()
    {
        var secret = NewSecret();
        await Admin().SaveAsync(SmtpSignInMode.Password, "casebook@contoso.example", secret);
        // The database restored onto a server without the key ring it was saved with.
        var elsewhere = new SmtpSignInStore(_services.GetRequiredService<IServiceScopeFactory>(), new EphemeralDataProtectionProvider(), _log);

        var resolve = () => elsewhere.ResolveAsync(CancellationToken.None);
        (await resolve.Should().ThrowAsync<InvalidOperationException>()).Which.Message.Should().Contain("Re-enter the SMTP password");
        await resolve.Should().ThrowAsync<InvalidOperationException>();
        (await elsewhere.StatusAsync()).PasswordUnreadable.Should().BeTrue("Diagnostics says to re-enter it");
        _log.Errors.Should().ContainSingle("logged once, not on every send").Which.Should().NotContain(secret);
    }

    [Fact]
    public async Task The_configuration_bundle_doesnt_carry_it()
    {
        var secret = NewSecret();
        await Admin().SaveAsync(SmtpSignInMode.Password, "casebook-relay@contoso.example", secret);
        var row = await RowAsync();

        using var connection = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={_dbPath};Pooling=False");
        connection.Open();
        var hasher = new HashChainService();
        var options = new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection)
            .AddInterceptors(new AuditChainInterceptor(hasher, _admin, _clock, new CaseChangeNotifier())).Options;
        var factory = new TestDbContextFactory(options);
        var workDir = Path.Combine(Path.GetTempPath(), "im-smtp-bundle", Guid.NewGuid().ToString("N"));
        try
        {
            var signer = new RsaSealSigner(Options.Create(new SealSigningOptions { SigningKeyPath = Path.Combine(workDir, "k.pem"), AllowKeyGeneration = true }));
            var bundle = new ConfigBundleService(factory, signer, new NoOpAuditWriter(), _admin, _clock);
            var export = Encoding.UTF8.GetString((await bundle.ExportAsync()).Content);
            export.Should().NotContain(secret).And.NotContain(row!.ProtectedPassword!).And.NotContain("casebook-relay@contoso.example")
                .And.NotContain("SmtpSignIn", "server-side sign-in isn't editable configuration that travels between instances (ADR 0007)");
        }
        finally { try { Directory.Delete(workDir, recursive: true); } catch (IOException) { /* best effort */ } }
    }

    [Fact]
    public void The_forms_password_field_is_never_filled_from_the_server()
    {
        var root = RepoRoot();
        var card = File.ReadAllText(Path.Combine(root, "src", "IncidentManager.Web", "Components", "Shared", "EmailSignInCard.razor"));
        var field = Regex.Match(card, @"<input(?:(?!/>).)*?type=""password""(?:(?!/>).)*/>", RegexOptions.Singleline, TimeSpan.FromSeconds(1));
        field.Success.Should().BeTrue();
        field.Value.Should().NotContain("@bind").And.NotContain("value=", "write-only: what's typed is read on change, never rendered back");
        card.Should().NotContain("ProtectedPassword");
    }

    [Fact]
    public void The_form_saves_with_the_stamp_it_loaded_and_a_test_email_doesnt_move_it()
    {
        // CAP-05 review (C9): the stamp is what the admin saw. A test email refreshes the status for display; if it took
        // the newer stamp too, a stale form would save its old username over another admin's new password unrefused.
        var card = File.ReadAllText(Path.Combine(RepoRoot(), "src", "IncidentManager.Web", "Components", "Shared", "EmailSignInCard.razor"));
        card.Should().Contain("SignIns.SaveAsync(_mode, _username, _newPassword, _stamp)").And.Contain("SignIns.ClearAsync(_stamp)");
        Regex.Matches(card, @"_stamp\s*=(?!=)", RegexOptions.None, TimeSpan.FromSeconds(1)).Should().HaveCount(3,
            "set at its declaration, on a load of the entries, and on a reload the admin was told about");
        Regex.IsMatch(card, @"SendTestCore\(\)(?:(?!private ).)*ReloadStatusAsync\(takeStamp: false\)", RegexOptions.Singleline,
            TimeSpan.FromSeconds(1)).Should().BeTrue("a test email keeps the loaded stamp");
    }

    private static string RepoRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "IncidentManager.sln"))) return dir.FullName;
        throw new InvalidOperationException("Couldn't find the repo root (IncidentManager.sln).");
    }
}
