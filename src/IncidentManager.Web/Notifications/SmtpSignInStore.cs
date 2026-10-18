using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Common;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Common;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Notifications;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace IncidentManager.Web.Notifications;

/// <summary>
/// CAP-05: the saved sign-in as Administration shows it. Never the password: whether one is set, when and by whom, and
/// whether it opens on this server (<see cref="PasswordUnreadable"/>: a database restored without its Data Protection keys).
/// CAP-05 review: <see cref="Stamp"/> is the row as it was read ("" for none), for the form to hand back on Save.
/// </summary>
public sealed record SmtpSignInStatus(SmtpSignInMode Mode, string Username, bool PasswordSet, DateTimeOffset? PasswordSetAtUtc,
    string? PasswordSetBy, DateTimeOffset? UpdatedAtUtc, string? UpdatedBy, bool PasswordUnreadable, string Stamp = "")
{
    public static readonly SmtpSignInStatus None = new(SmtpSignInMode.None, "", false, null, null, null, null, false);
}

/// <summary>
/// CAP-05: the mail relay sign-in saved in Administration, for the email sender (singleton). The password is encrypted
/// with ASP.NET Core Data Protection under its own purpose, so only this app, with the key ring in
/// <c>DataProtection:KeyPath</c>, can open it; the database holds ciphertext only. Read per send (kept for a few
/// seconds, and dropped at once when the form saves), so a change applies without a restart. Fail closed: a password
/// that won't decrypt is unavailable, logged once, and the mail is held as for a relay that refuses it.
/// </summary>
public sealed class SmtpSignInStore : ISmtpSignInSource
{
    /// <summary>The Data Protection purpose: a password protected for anything else doesn't open here, nor this elsewhere.</summary>
    public const string Purpose = "CaseBook.Secrets.Smtp.v1";
    private static readonly TimeSpan Keep = TimeSpan.FromSeconds(30);

    private readonly IServiceScopeFactory _scopes;   // the context factory is scoped; this is a singleton
    private readonly IDataProtector _protector;
    private readonly ILogger<SmtpSignInStore> _logger;
    private readonly ConcurrentDictionary<string, byte> _reported = new(StringComparer.Ordinal);
    private readonly object _gate = new();
    private readonly LatestWins _order = new();   // C21: a read that began before a save never publishes over it
    private (SmtpSignInRecord? Row, long At)? _cached;

    public SmtpSignInStore(IServiceScopeFactory scopes, IDataProtectionProvider protection, ILogger<SmtpSignInStore> logger)
    {
        _scopes = scopes;
        _protector = protection.CreateProtector(Purpose);
        _logger = logger;
    }

    /// <summary>The ciphertext of <paramref name="password"/> (the form's save).</summary>
    internal string Protect(string password) => _protector.Protect(password);

    /// <summary>Drops what's kept, so the next send reads the row the form just saved.</summary>
    public void Invalidate() => _order.TryPublish(_order.Begin(), () => { lock (_gate) _cached = null; });

    /// <summary>
    /// The saved sign-in. <paramref name="fresh"/> reads the row now rather than what's kept (the form: its stamp must be
    /// the row's, or a save from it would be refused as stale on a server that didn't make the change).
    /// </summary>
    public async Task<SmtpSignInStatus> StatusAsync(bool fresh = false, CancellationToken ct = default)
    {
        var row = await RowAsync(ct, fresh);
        if (row is null) return SmtpSignInStatus.None;
        return new SmtpSignInStatus(ModeOf(row) ?? SmtpSignInMode.Invalid, row.Username, row.ProtectedPassword is not null,
            row.PasswordSetAtUtc, row.PasswordSetBy, row.UpdatedAtUtc, row.UpdatedBy,
            row.ProtectedPassword is { } p && Open(p) is null, StampOf(row));
    }

    /// <summary>
    /// CAP-05 review: what the form writes back over (the mode, the username, the password's ciphertext) and when, hashed
    /// so the page never holds the ciphertext. "" when there's no row: a first save expects none.
    /// </summary>
    internal static string StampOf(SmtpSignInRecord? row) => row is null ? "" :
        Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(string.Join('\n', row.Mode, row.Username,
            row.ProtectedPassword ?? "", row.UpdatedAtUtc.UtcTicks.ToString(System.Globalization.CultureInfo.InvariantCulture), row.UpdatedBy))));

    public async Task<(SmtpSignInMode Mode, NetworkCredential? Credentials)> ResolveAsync(CancellationToken ct)
    {
        var row = await RowAsync(ct);
        switch (row is null ? SmtpSignInMode.None : ModeOf(row))
        {
            case SmtpSignInMode.None: return (SmtpSignInMode.None, null);
            case SmtpSignInMode.Integrated: return (SmtpSignInMode.Integrated, null);
            case SmtpSignInMode.Password: break;
            default: throw new InvalidOperationException("The email sign-in saved in Administration isn't one CaseBook knows. Save it again.");
        }
        if (string.IsNullOrWhiteSpace(row!.Username) || row.ProtectedPassword is null)
            throw new InvalidOperationException("The email sign-in saved in Administration has no username or password. Enter them under " +
                                                "Administration, Settings, Notifications, Email sign-in.");
        var password = Open(row.ProtectedPassword)
            ?? throw new InvalidOperationException("The SMTP password saved in Administration can't be decrypted on this server (its Data " +
                                                   "Protection keys aren't here, as after a database restored elsewhere). Re-enter the SMTP " +
                                                   "password under Administration, Settings, Notifications, Email sign-in.");
        return (SmtpSignInMode.Password, new NetworkCredential(row.Username, password));
    }

    // The password, or null (logged once per value, never its content) when it doesn't decrypt here.
    private string? Open(string ciphertext)
    {
        try
        {
            var password = _protector.Unprotect(ciphertext);
            _reported.TryRemove(ciphertext, out _);
            return password;
        }
        catch (CryptographicException ex)
        {
            if (_reported.TryAdd(ciphertext, 0))
                _logger.LogError("The SMTP password saved in Administration can't be decrypted ({Failure}): the Data Protection key ring " +
                                 "it was saved with isn't in DataProtection:KeyPath. Email that signs in is held; re-enter the password " +
                                 "under Administration, Settings, Notifications, Email sign-in.", ex.GetType().Name);
            return null;
        }
    }

    internal static SmtpSignInMode? ModeOf(SmtpSignInRecord row) =>
        EnumNames.TryParse<SmtpSignInMode>(row.Mode, out var m) && m != SmtpSignInMode.Invalid ? m : null;

    private async Task<SmtpSignInRecord?> RowAsync(CancellationToken ct, bool fresh = false)
    {
        lock (_gate)
            if (!fresh && _cached is { } c && Environment.TickCount64 - c.At < Keep.TotalMilliseconds) return c.Row;
        var ticket = _order.Begin();
        await using var scope = _scopes.CreateAsyncScope();
        await using var db = await scope.ServiceProvider.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContextAsync(ct);
        var row = await db.SmtpSignIns.AsNoTracking().FirstOrDefaultAsync(r => r.Id == SmtpSignInRecord.SingletonId, ct);
        _order.TryPublish(ticket, () => { lock (_gate) _cached = (row, Environment.TickCount64); });
        return row;
    }
}

/// <summary>
/// CAP-05: the Email sign-in form's service (scoped: it acts as the signed-in administrator). Saves the mode, the username
/// and, only when one is typed, a new password; the password is never read back. Refused while the server's
/// configuration sets the sign-in (it wins). The audit trail records who changed it, when and to which mode, and whether
/// the password was replaced or cleared; never the password. SIEM 5403 (SettingChanged) as for any setting.
/// </summary>
public sealed class SmtpSignInAdminService(
    SmtpSignInStore store,
    IDbContextFactory<AppDbContext> db,
    IOptionsMonitor<EmailOptions> email,
    ICurrentUser user,
    IAuditWriter audit,
    IClock clock,
    ISecurityEventSink? siem = null)
{
    /// <summary>The setting name the SIEM and the audit trail know the change by.</summary>
    public const string SettingKey = "Email:SignIn";

    /// <summary>Whether server configuration sets the sign-in, so the form is read-only.</summary>
    public bool SetInServerConfiguration => SmtpSignIn.InServerConfig(email.CurrentValue);

    /// <summary>The saved sign-in, read now (not what the sender keeps), with the stamp a save hands back.</summary>
    public Task<SmtpSignInStatus> GetAsync(CancellationToken ct = default) => store.StatusAsync(fresh: true, ct);

    /// <summary>CAP-05 review: the words for a save refused because the sign-in changed since the form loaded it.</summary>
    public const string ChangedSinceOpened =
        "Someone changed the email sign-in since you opened it, so nothing was saved: it would have undone that. What's " +
        "saved now is shown, with your entries kept; check them, then save again.";

    /// <summary>
    /// Saves the sign-in. <paramref name="newPassword"/> replaces the saved one when given; otherwise a password sign-in
    /// keeps the one saved. None and Windows clear the username and password (they're different ways to sign in).
    /// CAP-05 review: <paramref name="expectedStamp"/> is the <see cref="SmtpSignInStatus.Stamp"/> the form loaded ("" when
    /// there was no row). A row changed since is refused (<see cref="StaleEditException"/>): otherwise a stale form's Save
    /// that keeps the password would pair its old username with the password someone else just saved. Null skips the check.
    /// </summary>
    public async Task SaveAsync(SmtpSignInMode mode, string? username, string? newPassword, string? expectedStamp = null,
        CancellationToken ct = default)
    {
        Require();
        if (SetInServerConfiguration)
            throw new InvalidOperationException("The email sign-in is set in the server's configuration, which wins; change it there.");
        if (mode is not (SmtpSignInMode.None or SmtpSignInMode.Password or SmtpSignInMode.Integrated))
            throw new InvalidOperationException("Choose none, a username and password, or Windows.");
        var name = (username ?? "").Trim();
        if (mode == SmtpSignInMode.Password)
        {
            if (name.Length == 0) throw new InvalidOperationException("Enter the username to sign in to the relay as.");
            if (name.Length > SmtpSignInRecord.UsernameMax || name.Any(char.IsControl))
                throw new InvalidOperationException($"The username must be at most {SmtpSignInRecord.UsernameMax} characters, without line breaks.");
        }

        await using var context = await db.CreateDbContextAsync(ct);
        var row = await context.SmtpSignIns.FirstOrDefaultAsync(r => r.Id == SmtpSignInRecord.SingletonId, ct);
        var current = SmtpSignInStore.StampOf(row);
        if (expectedStamp is not null && !string.Equals(current, expectedStamp, StringComparison.Ordinal))
            throw new StaleEditException(current, ChangedSinceOpened);
        var adding = row is null;
        row ??= new SmtpSignInRecord();
        var before = adding ? SmtpSignInMode.None : SmtpSignInStore.ModeOf(row) ?? SmtpSignInMode.Invalid;
        var nameChanged = !string.Equals(row.Username, mode == SmtpSignInMode.Password ? name : "", StringComparison.Ordinal);
        string passwordChange;
        var now = clock.UtcNow;
        var who = TextFit.Cap(user.UserId, 256, marker: "")!;
        if (mode != SmtpSignInMode.Password)
        {
            passwordChange = row.ProtectedPassword is null ? "none" : "cleared";
            row.Username = "";
            row.ProtectedPassword = null;
            row.PasswordSetAtUtc = null;
            row.PasswordSetBy = null;
        }
        else if (!string.IsNullOrEmpty(newPassword))
        {
            passwordChange = row.ProtectedPassword is null ? "set" : "replaced";
            row.Username = name;
            row.ProtectedPassword = store.Protect(newPassword);
            row.PasswordSetAtUtc = now;
            row.PasswordSetBy = who;
        }
        else
        {
            if (row.ProtectedPassword is null) throw new InvalidOperationException("Enter the password for that username.");
            passwordChange = "kept";
            row.Username = name;
        }
        row.Mode = mode.ToString();
        row.UpdatedAtUtc = now;
        row.UpdatedBy = who;
        if (adding) context.SmtpSignIns.Add(row);
        try { await context.SaveChangesAsync(ct); }
        catch (DbUpdateException ex) when (adding)
        {
            // CAP-05 review (as BUG-459): another administrator's first save landed between the read above and this insert
            // (the primary key refused it). Worded, so the card says so instead of the circuit failing.
            await using var recheck = await db.CreateDbContextAsync(ct);
            if (await recheck.SmtpSignIns.AnyAsync(r => r.Id == SmtpSignInRecord.SingletonId, ct))
                throw new InvalidOperationException("Someone else saved the email sign-in just now; reload to see it.", ex);
            throw;
        }
        store.Invalidate();   // the next send uses it: no restart

        // Who, when (the entry's own), the mode and what became of the password: never the password or its ciphertext.
        await audit.RecordAsync(adding ? AuditAction.Create : AuditAction.Update, "EmailSignIn", SettingKey, null,
            $"Email sign-in changed from {Label(before)} to {Label(mode)}" + (nameChanged ? ", with a new username" : "") +
            $"; password {passwordChange}.", ct);
        siem?.Emit(SecurityEvents.SettingChanged(SettingKey, user.UserId, user.UserPrincipalName));
    }

    /// <summary>Clears the saved password and signs in with none: the form's Clear (with the stamp it loaded, as for Save).</summary>
    public Task ClearAsync(string? expectedStamp = null, CancellationToken ct = default) =>
        SaveAsync(SmtpSignInMode.None, null, null, expectedStamp, ct);

    private static string Label(SmtpSignInMode m) => m switch
    {
        SmtpSignInMode.Password => "username and password",
        SmtpSignInMode.Integrated => "Windows (the app-pool account)",
        SmtpSignInMode.None => "none",
        _ => "unrecognised",
    };

    // As AdminActionPermissions.Require does for the Application services: Administer, a refusal streamed to the SIEM.
    private void Require([System.Runtime.CompilerServices.CallerMemberName] string action = "")
    {
        if (user.Has(Permission.Administer)) return;
        var key = $"{nameof(SmtpSignInAdminService)}.{action}";
        siem?.Emit(SecurityEvents.ActionRefused(user.UserId, user.UserPrincipalName, Permission.Administer, key));
        throw new ForbiddenException(Permission.Administer, key);
    }
}
