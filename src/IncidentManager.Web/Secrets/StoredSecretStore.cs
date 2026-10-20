using System.Collections.Concurrent;
using System.Security.Cryptography;
using IncidentManager.Application.Common;
using IncidentManager.Domain.Entities;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Web.Secrets;

/// <summary>CAP-40: the secrets an administrator may enter in Administration in place of server configuration.</summary>
public enum StoredSecretKind
{
    /// <summary><c>Chat:Webhook:WebhookUrl</c>: the team-chat incoming webhook, whose URL is the channel's credential.</summary>
    ChatWebhookUrl,
    /// <summary><c>Siem:Webhook:Token</c>: the SIEM collector's bearer token or API key.</summary>
    SiemWebhookToken,
    /// <summary>CAP-36: a team's own chat webhook URL, one row per team (<see cref="StoredSecretStore.TeamWebhookName"/>). Not
    /// in <see cref="StoredSecretDefinition.All"/>: it's entered on the Teams page, not as a server-configuration secret.</summary>
    TeamChatWebhookUrl,
}

/// <summary>
/// CAP-40: one enterable secret. <see cref="Name"/> is the configuration key it stands in for (and its row's key);
/// <see cref="Purpose"/> is its own Data Protection purpose, so a value protected for one secret never opens as another
/// (nor as the SMTP password). <see cref="Label"/> is how the page, the audit trail and the log name it, and
/// <see cref="Where"/> is where it's re-entered.
/// </summary>
public sealed record StoredSecretDefinition(StoredSecretKind Kind, string Name, string Purpose, string Label, string Where, int MaxLength)
{
    public static readonly StoredSecretDefinition ChatWebhookUrl = new(StoredSecretKind.ChatWebhookUrl, "Chat:Webhook:WebhookUrl",
        "CaseBook.Secrets.ChatWebhookUrl.v1", "team-chat webhook URL", "Administration, Settings, Notifications, Team chat webhook", 2048);

    public static readonly StoredSecretDefinition SiemWebhookToken = new(StoredSecretKind.SiemWebhookToken, "Siem:Webhook:Token",
        "CaseBook.Secrets.SiemWebhookToken.v1", "SIEM webhook token", "Administration, Integrations, SIEM webhook token", 4096);

    /// <summary>CAP-36: a team's chat webhook URL. <see cref="Name"/> is the pattern; each team's row is
    /// <see cref="StoredSecretStore.TeamWebhookName"/>, protected under <see cref="Purpose"/> with the team's id as a
    /// sub-purpose, so one team's URL never opens as another's (nor as the shared one).</summary>
    public static readonly StoredSecretDefinition TeamChatWebhookUrl = new(StoredSecretKind.TeamChatWebhookUrl, "Teams:{team}:ChatWebhookUrl",
        "CaseBook.Secrets.TeamChatWebhookUrl.v1", "team's chat webhook URL", "Administration, Teams, the team's chat webhook", 2048);

    /// <summary>The server-configuration secrets (one row each). CAP-36: a team's webhook isn't one of them.</summary>
    public static IReadOnlyList<StoredSecretDefinition> All { get; } = [ChatWebhookUrl, SiemWebhookToken];

    public static StoredSecretDefinition For(StoredSecretKind kind) => kind switch
    {
        StoredSecretKind.ChatWebhookUrl => ChatWebhookUrl,
        StoredSecretKind.SiemWebhookToken => SiemWebhookToken,
        StoredSecretKind.TeamChatWebhookUrl => TeamChatWebhookUrl,
        _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, null),
    };
}

/// <summary>
/// CAP-40: a saved secret as Administration shows it. Never the value: whether one is set, when and by whom, and whether it
/// opens on this server (<see cref="Unreadable"/>: a database restored without its Data Protection keys). <see cref="Stamp"/>
/// is the row as it was read ("" for none), for the form to hand back on Save and Clear (as CAP-05's review added).
/// CAP-40 review: <see cref="Unread"/> is "can't tell": the database didn't answer and nothing was read before, which isn't
/// "not saved" (a sender that took it so would mark a scheduled chat broadcast done rather than try it again).
/// </summary>
public sealed record StoredSecretStatus(StoredSecretKind Kind, bool Set, DateTimeOffset? SetAtUtc, string? SetBy,
    DateTimeOffset? UpdatedAtUtc, string? UpdatedBy, bool Unreadable, string Stamp = "", bool Unread = false)
{
    public static StoredSecretStatus None(StoredSecretKind kind) => new(kind, false, null, null, null, null, false);

    /// <summary>CAP-40 review: the database couldn't be read, and nothing was read before it stopped answering.</summary>
    public static StoredSecretStatus CantTell(StoredSecretKind kind) => None(kind) with { Unread = true };
}

/// <summary>CAP-40: what a send gets: whether a value is saved, and the value, or null when it's saved but won't open here.</summary>
public readonly record struct StoredSecretValue(bool Saved, string? Value)
{
    public static readonly StoredSecretValue NotSaved = new(false, null);

    /// <summary>
    /// CAP-40 review: the database couldn't be read, and nothing was read before it stopped answering. Not saved as far as
    /// this server knows (the SIEM webhook sends without a token, as it did before one could be saved), but a sender that
    /// needs the value to send at all (the chat webhook) counts it a failure, so what it carried is tried again.
    /// </summary>
    public static readonly StoredSecretValue CantTell = new(false, null) { Unread = true };

    /// <summary>Saved but can't be decrypted on this server: fail closed, the dependent send isn't made.</summary>
    public bool Unreadable => Saved && Value is null;

    /// <summary>CAP-40 review: see <see cref="CantTell"/>.</summary>
    public bool Unread { get; init; }
}

/// <summary>
/// CAP-40: the secrets saved in Administration (singleton), generalising CAP-05's <c>SmtpSignInStore</c> to a row per secret.
/// Each value is encrypted with ASP.NET Core Data Protection under its own purpose, so only this app, with the key ring in
/// <c>DataProtection:KeyPath</c>, can open it; the database holds ciphertext only. Read per send (the table, a row or two,
/// is kept for a few seconds and dropped at once when the form saves), so a change applies without a restart. Fail
/// closed: a value that won't decrypt is unavailable, logged once, and the chat post or SIEM event isn't sent with it.
/// CAP-40 review (C10): a read is time-limited (<see cref="DefaultReadLimit"/>), and a database that doesn't answer is answered
/// from the rows last read (kept past <see cref="DefaultKeep"/> for this), or as "can't tell" when nothing was. It's asked again only
/// after <see cref="RetryAfter"/>, so an outage costs a send one bounded wait every few seconds, not a connect timeout each.
/// </summary>
public sealed class StoredSecretStore
{
    /// <summary>How long a read stands before a send reads again (a save drops it at once).</summary>
    public static readonly TimeSpan DefaultKeep = TimeSpan.FromSeconds(30);

    /// <summary>CAP-40 review (C10): the longest a send waits on the table before answering from what it last read.</summary>
    public static readonly TimeSpan DefaultReadLimit = TimeSpan.FromSeconds(3);

    /// <summary>CAP-40 review: after a read that failed, how long the last answer stands before the database is asked again.</summary>
    internal static readonly TimeSpan RetryAfter = TimeSpan.FromSeconds(10);

    private readonly IServiceScopeFactory _scopes;   // the context factory is scoped; this is a singleton
    private readonly Dictionary<StoredSecretKind, IDataProtector> _protectors;
    private readonly IDataProtector _teamProtector;   // CAP-36: a team's webhook, with the team's id as a sub-purpose
    private readonly ILogger<StoredSecretStore> _logger;
    private readonly ConcurrentDictionary<string, byte> _reported = new(StringComparer.Ordinal);
    private readonly object _gate = new();
    private readonly LatestWins _order = new();   // C21: a read that began before a save never publishes over it
    private (IReadOnlyDictionary<string, StoredSecretRecord> Rows, long At)? _cached;   // CAP-40 review: kept past _keep, for an outage
    private long? _failedAt;       // CAP-40 review: when a read last failed (until one succeeds), for RetryAfter
    private int _outageReported;   // CAP-40 review: an outage is logged once, until a read succeeds
    private readonly TimeSpan _readLimit;
    private readonly TimeSpan _keep;

    public StoredSecretStore(IServiceScopeFactory scopes, IDataProtectionProvider protection, ILogger<StoredSecretStore> logger,
        TimeSpan? readLimit = null, TimeSpan? keep = null)
    {
        _readLimit = readLimit ?? DefaultReadLimit;
        _keep = keep ?? DefaultKeep;
        _scopes = scopes;
        _protectors = StoredSecretDefinition.All.ToDictionary(d => d.Kind, d => protection.CreateProtector(d.Purpose));
        _teamProtector = protection.CreateProtector(StoredSecretDefinition.TeamChatWebhookUrl.Purpose);
        _logger = logger;
    }

    /// <summary>The ciphertext of <paramref name="value"/> under <paramref name="kind"/>'s purpose (the form's save).</summary>
    internal string Protect(StoredSecretKind kind, string value) => _protectors[kind].Protect(value);

    // --- CAP-36: a team's own chat webhook URL, a row per team in the same table, kept and read as the others are ---

    /// <summary>CAP-36: the row (and configuration-style name) of <paramref name="teamId"/>'s chat webhook URL.</summary>
    public static string TeamWebhookName(Guid teamId) => $"Teams:{teamId:N}:ChatWebhookUrl";

    private IDataProtector TeamProtector(Guid teamId) => _teamProtector.CreateProtector(teamId.ToString("N"));

    /// <summary>CAP-36: the ciphertext of a team's webhook URL (the Teams page's save).</summary>
    internal string ProtectTeamWebhook(Guid teamId, string value) => TeamProtector(teamId).Protect(value);

    /// <summary>CAP-36: the team's saved webhook URL for a post: not saved, the value, saved but unreadable, or can't tell
    /// (the database not answering, as <see cref="ResolveAsync"/>).</summary>
    public async Task<StoredSecretValue> ResolveTeamWebhookAsync(Guid teamId, CancellationToken ct = default)
    {
        if (await RowsAsync(ct).ConfigureAwait(false) is not { } rows) return StoredSecretValue.CantTell;
        var row = rows.GetValueOrDefault(TeamWebhookName(teamId));
        return row?.ProtectedValue is { } p ? new StoredSecretValue(true, OpenTeam(teamId, p)) : StoredSecretValue.NotSaved;
    }

    /// <summary>CAP-36: the team's saved webhook as the Teams page shows it, read now when <paramref name="fresh"/>.</summary>
    public async Task<StoredSecretStatus> TeamWebhookStatusAsync(Guid teamId, bool fresh = false, CancellationToken ct = default)
    {
        var rows = await RowsAsync(ct, fresh).ConfigureAwait(false);
        if (rows is null) return StoredSecretStatus.CantTell(StoredSecretKind.TeamChatWebhookUrl);
        var row = rows.GetValueOrDefault(TeamWebhookName(teamId));
        return row is null
            ? StoredSecretStatus.None(StoredSecretKind.TeamChatWebhookUrl)
            : new StoredSecretStatus(StoredSecretKind.TeamChatWebhookUrl, row.ProtectedValue is not null, row.SetAtUtc, row.SetBy,
                row.UpdatedAtUtc, row.UpdatedBy, row.ProtectedValue is { } p && OpenTeam(teamId, p) is null, StampOf(row));
    }

    /// <summary>CAP-36: whether a webhook URL is saved for <paramref name="teamId"/> (from what's kept): where its posts go.</summary>
    public bool TeamWebhookSaved(Guid teamId) =>
        Rows()?.GetValueOrDefault(TeamWebhookName(teamId))?.ProtectedValue is not null;

    /// <summary>CAP-36: whether any team has a webhook URL saved (from what's kept): chat posts without a shared one.</summary>
    public bool AnyTeamWebhookSaved() =>
        Rows()?.Values.Any(r => r.ProtectedValue is not null && r.Name.StartsWith("Teams:", StringComparison.Ordinal)) == true;

    private string? OpenTeam(Guid teamId, string ciphertext)
    {
        try
        {
            var value = TeamProtector(teamId).Unprotect(ciphertext);
            _reported.TryRemove(ciphertext, out _);
            return value;
        }
        catch (CryptographicException ex)
        {
            if (_reported.TryAdd(ciphertext, 0))
                _logger.LogError("A team's chat webhook URL saved in Administration can't be decrypted ({Failure}): the Data Protection " +
                                 "key ring it was saved with isn't in DataProtection:KeyPath. Nothing is posted to it; re-enter it under {Where}.",
                    ex.GetType().Name, StoredSecretDefinition.TeamChatWebhookUrl.Where);
            return null;
        }
    }

    /// <summary>
    /// Drops what's kept, so the next send reads the row the form just saved. CAP-40 review: the rows from before the save
    /// go too, so an outage that follows it never answers with the value it replaced or cleared ("can't tell" instead).
    /// </summary>
    public void Invalidate() => _order.TryPublish(_order.Begin(), () =>
    {
        lock (_gate)
        {
            _cached = null;
            _failedAt = null;
        }
    });

    /// <summary>
    /// The saved secret's status. <paramref name="fresh"/> reads the row now rather than what's kept (the form: its stamp
    /// must be the row's, or a save from it would be refused as stale on a server that didn't make the change).
    /// </summary>
    public async Task<StoredSecretStatus> StatusAsync(StoredSecretKind kind, bool fresh = false, CancellationToken ct = default) =>
        StatusOf(kind, await RowsAsync(ct, fresh).ConfigureAwait(false));

    /// <summary>
    /// The status from what's kept, read now (synchronously) only when nothing recent is: for the senders' <c>Enabled</c> and
    /// the delivery card's <c>StoppedReason</c>, which are properties. The table is a row per secret.
    /// </summary>
    public StoredSecretStatus Peek(StoredSecretKind kind) => StatusOf(kind, Rows());

    /// <summary>
    /// The saved value for a send: <see cref="StoredSecretValue.NotSaved"/>, the value, or saved-but-unreadable. CAP-40 review:
    /// waits at most the read limit, and never throws for a database that can't be reached: what was last read answers, or
    /// <see cref="StoredSecretValue.CantTell"/> when nothing was.
    /// </summary>
    public async Task<StoredSecretValue> ResolveAsync(StoredSecretKind kind, CancellationToken ct = default)
    {
        if (await RowsAsync(ct).ConfigureAwait(false) is not { } rows) return StoredSecretValue.CantTell;
        var row = rows.GetValueOrDefault(StoredSecretDefinition.For(kind).Name);
        return row?.ProtectedValue is { } p ? new StoredSecretValue(true, Open(kind, p)) : StoredSecretValue.NotSaved;
    }

    private StoredSecretStatus StatusOf(StoredSecretKind kind, IReadOnlyDictionary<string, StoredSecretRecord>? rows) => rows is null
        ? StoredSecretStatus.CantTell(kind)
        : StatusOf(kind, rows.GetValueOrDefault(StoredSecretDefinition.For(kind).Name));

    private StoredSecretStatus StatusOf(StoredSecretKind kind, StoredSecretRecord? row) => row is null
        ? StoredSecretStatus.None(kind)
        : new StoredSecretStatus(kind, row.ProtectedValue is not null, row.SetAtUtc, row.SetBy, row.UpdatedAtUtc, row.UpdatedBy,
            row.ProtectedValue is { } p && Open(kind, p) is null, StampOf(row));

    /// <summary>
    /// What the form writes over (the ciphertext, or none) and when, hashed so the page never holds the ciphertext. "" when
    /// there's no row: a first save expects none.
    /// </summary>
    internal static string StampOf(StoredSecretRecord? row) => row is null ? "" :
        Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(string.Join('\n', row.Name, row.ProtectedValue ?? "",
            row.UpdatedAtUtc.UtcTicks.ToString(System.Globalization.CultureInfo.InvariantCulture), row.UpdatedBy))));

    // The value, or null (logged once per value, never its content) when it doesn't decrypt here.
    private string? Open(StoredSecretKind kind, string ciphertext)
    {
        try
        {
            var value = _protectors[kind].Unprotect(ciphertext);
            _reported.TryRemove(ciphertext, out _);
            return value;
        }
        catch (CryptographicException ex)
        {
            var d = StoredSecretDefinition.For(kind);
            if (_reported.TryAdd(ciphertext, 0))
                _logger.LogError("The {Secret} saved in Administration can't be decrypted ({Failure}): the Data Protection key ring it " +
                                 "was saved with isn't in DataProtection:KeyPath. Nothing is sent with it; re-enter it under {Where}.",
                    d.Label, ex.GetType().Name, d.Where);
            return null;
        }
    }

    // What's kept, when it answers: recent rows; or, after a read that failed less than RetryAfter ago, the rows last read
    // (null: can't tell). A fresh read (the form's) always goes to the database.
    private bool TryKept(bool fresh, out IReadOnlyDictionary<string, StoredSecretRecord>? rows)
    {
        lock (_gate)
        {
            var now = Environment.TickCount64;
            if (!fresh && _cached is { } c && now - c.At < _keep.TotalMilliseconds)
            {
                rows = c.Rows;
                return true;
            }
            if (!fresh && _failedAt is { } failed && now - failed < RetryAfter.TotalMilliseconds)
            {
                rows = _cached?.Rows;
                return true;
            }
        }
        rows = null;
        return false;
    }

    private void Publish(long ticket, IReadOnlyDictionary<string, StoredSecretRecord> rows) =>
        _order.TryPublish(ticket, () =>
        {
            lock (_gate)
            {
                _cached = (rows, Environment.TickCount64);
                _failedAt = null;
            }
        });

    // CAP-40 review: the rows, read now or (the database not answering) last read; null when it can't be read and nothing
    // was before (can't tell). A fresh read (the form's) throws instead: its stamp must be the row's, never an older copy's.
    private async Task<IReadOnlyDictionary<string, StoredSecretRecord>?> RowsAsync(CancellationToken ct, bool fresh = false)
    {
        if (TryKept(fresh, out var kept)) return kept;
        var ticket = _order.Begin();
        try
        {
            var rows = await ReadAsync(ct).ConfigureAwait(false);
            Publish(ticket, rows);
            Interlocked.Exchange(ref _outageReported, 0);
            return rows;
        }
        catch (Exception ex) when (!fresh && IsOutage(ex, ct))
        {
            IReadOnlyDictionary<string, StoredSecretRecord>? last;
            lock (_gate)
            {
                _failedAt = Environment.TickCount64;
                last = _cached?.Rows;
            }
            if (Interlocked.Exchange(ref _outageReported, 1) == 0)
                _logger.LogWarning("The secrets saved in Administration couldn't be read ({Failure}); sends use {What} until the " +
                                   "database answers.", ex.GetType().Name, last is null ? "none (nothing was read before)" : "what was last read");
            return last;
        }
    }

    // A database that's down, refusing, or slower than the read limit. The caller's own cancellation isn't one.
    private static bool IsOutage(Exception ex, CancellationToken ct) =>
        ex is System.Data.Common.DbException or InvalidOperationException or TimeoutException
        || (ex is OperationCanceledException && !ct.IsCancellationRequested);

    // C10: the read, bounded by the read limit even where the provider doesn't honour cancellation while it connects (the
    // read is then left to finish or fail on its own, observed, and what it returns is dropped).
    private async Task<IReadOnlyDictionary<string, StoredSecretRecord>> ReadAsync(CancellationToken ct)
    {
        var limit = CancellationTokenSource.CreateLinkedTokenSource(ct);
        limit.CancelAfter(_readLimit);
        var read = ReadCoreAsync(limit.Token);
        _ = read.ContinueWith(t => { _ = t.Exception; limit.Dispose(); }, CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        return await read.WaitAsync(_readLimit, ct).ConfigureAwait(false);
    }

    private async Task<IReadOnlyDictionary<string, StoredSecretRecord>> ReadCoreAsync(CancellationToken ct)
    {
        await using var scope = _scopes.CreateAsyncScope();
        await using var db = await scope.ServiceProvider.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContextAsync(ct);
        return (await db.StoredSecrets.AsNoTracking().ToListAsync(ct)).ToDictionary(r => r.Name, StringComparer.Ordinal);
    }

    // A property's read: a database that can't be reached answers with what was last read (or can't tell), rather than
    // throwing into a notification or the delivery card; the send itself reads again and says why it didn't go. CAP-40
    // review (C10): bounded as a send's read is, and run on the pool, so the property's caller waits at most the read limit.
    private IReadOnlyDictionary<string, StoredSecretRecord>? Rows() =>
        TryKept(false, out var kept) ? kept : Task.Run(() => RowsAsync(CancellationToken.None)).GetAwaiter().GetResult();
}
