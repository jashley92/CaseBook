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
        "CaseBook.Secrets.SiemWebhookToken.v1", "SIEM webhook token", "Administration, Server configuration, SIEM webhook token", 4096);

    public static IReadOnlyList<StoredSecretDefinition> All { get; } = [ChatWebhookUrl, SiemWebhookToken];

    public static StoredSecretDefinition For(StoredSecretKind kind) => kind switch
    {
        StoredSecretKind.ChatWebhookUrl => ChatWebhookUrl,
        StoredSecretKind.SiemWebhookToken => SiemWebhookToken,
        _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, null),
    };
}

/// <summary>
/// CAP-40: a saved secret as Administration shows it. Never the value: whether one is set, when and by whom, and whether it
/// opens on this server (<see cref="Unreadable"/>: a database restored without its Data Protection keys). <see cref="Stamp"/>
/// is the row as it was read ("" for none), for the form to hand back on Save and Clear (as CAP-05's review added).
/// </summary>
public sealed record StoredSecretStatus(StoredSecretKind Kind, bool Set, DateTimeOffset? SetAtUtc, string? SetBy,
    DateTimeOffset? UpdatedAtUtc, string? UpdatedBy, bool Unreadable, string Stamp = "")
{
    public static StoredSecretStatus None(StoredSecretKind kind) => new(kind, false, null, null, null, null, false);
}

/// <summary>CAP-40: what a send gets: whether a value is saved, and the value, or null when it's saved but won't open here.</summary>
public readonly record struct StoredSecretValue(bool Saved, string? Value)
{
    public static readonly StoredSecretValue NotSaved = new(false, null);

    /// <summary>Saved but can't be decrypted on this server: fail closed, the dependent send isn't made.</summary>
    public bool Unreadable => Saved && Value is null;
}

/// <summary>
/// CAP-40: the secrets saved in Administration (singleton), generalising CAP-05's <c>SmtpSignInStore</c> to a row per secret.
/// Each value is encrypted with ASP.NET Core Data Protection under its own purpose, so only this app, with the key ring in
/// <c>DataProtection:KeyPath</c>, can open it; the database holds ciphertext only. Read per send (the table, a row or two,
/// is kept for a few seconds and dropped at once when the form saves), so a change applies without a restart. Fail
/// closed: a value that won't decrypt is unavailable, logged once, and the chat post or SIEM event isn't sent with it.
/// </summary>
public sealed class StoredSecretStore
{
    private static readonly TimeSpan Keep = TimeSpan.FromSeconds(30);

    private readonly IServiceScopeFactory _scopes;   // the context factory is scoped; this is a singleton
    private readonly Dictionary<StoredSecretKind, IDataProtector> _protectors;
    private readonly ILogger<StoredSecretStore> _logger;
    private readonly ConcurrentDictionary<string, byte> _reported = new(StringComparer.Ordinal);
    private readonly object _gate = new();
    private readonly LatestWins _order = new();   // C21: a read that began before a save never publishes over it
    private (IReadOnlyDictionary<string, StoredSecretRecord> Rows, long At)? _cached;

    public StoredSecretStore(IServiceScopeFactory scopes, IDataProtectionProvider protection, ILogger<StoredSecretStore> logger)
    {
        _scopes = scopes;
        _protectors = StoredSecretDefinition.All.ToDictionary(d => d.Kind, d => protection.CreateProtector(d.Purpose));
        _logger = logger;
    }

    /// <summary>The ciphertext of <paramref name="value"/> under <paramref name="kind"/>'s purpose (the form's save).</summary>
    internal string Protect(StoredSecretKind kind, string value) => _protectors[kind].Protect(value);

    /// <summary>Drops what's kept, so the next send reads the row the form just saved.</summary>
    public void Invalidate() => _order.TryPublish(_order.Begin(), () => { lock (_gate) _cached = null; });

    /// <summary>
    /// The saved secret's status. <paramref name="fresh"/> reads the row now rather than what's kept (the form: its stamp
    /// must be the row's, or a save from it would be refused as stale on a server that didn't make the change).
    /// </summary>
    public async Task<StoredSecretStatus> StatusAsync(StoredSecretKind kind, bool fresh = false, CancellationToken ct = default) =>
        StatusOf(kind, (await RowsAsync(ct, fresh)).GetValueOrDefault(StoredSecretDefinition.For(kind).Name));

    /// <summary>
    /// The status from what's kept, read now (synchronously) only when nothing recent is: for the senders' <c>Enabled</c> and
    /// the delivery card's <c>StoppedReason</c>, which are properties. The table is a row per secret.
    /// </summary>
    public StoredSecretStatus Peek(StoredSecretKind kind) =>
        StatusOf(kind, Rows().GetValueOrDefault(StoredSecretDefinition.For(kind).Name));

    /// <summary>The saved value for a send: <see cref="StoredSecretValue.NotSaved"/>, the value, or saved-but-unreadable.</summary>
    public async Task<StoredSecretValue> ResolveAsync(StoredSecretKind kind, CancellationToken ct = default)
    {
        var row = (await RowsAsync(ct)).GetValueOrDefault(StoredSecretDefinition.For(kind).Name);
        return row?.ProtectedValue is { } p ? new StoredSecretValue(true, Open(kind, p)) : StoredSecretValue.NotSaved;
    }

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

    private bool TryKept(bool fresh, out IReadOnlyDictionary<string, StoredSecretRecord> rows)
    {
        lock (_gate)
            if (!fresh && _cached is { } c && Environment.TickCount64 - c.At < Keep.TotalMilliseconds)
            {
                rows = c.Rows;
                return true;
            }
        rows = null!;
        return false;
    }

    private void Publish(long ticket, IReadOnlyDictionary<string, StoredSecretRecord> rows) =>
        _order.TryPublish(ticket, () => { lock (_gate) _cached = (rows, Environment.TickCount64); });

    private async Task<IReadOnlyDictionary<string, StoredSecretRecord>> RowsAsync(CancellationToken ct, bool fresh = false)
    {
        if (TryKept(fresh, out var kept)) return kept;
        var ticket = _order.Begin();
        await using var scope = _scopes.CreateAsyncScope();
        await using var db = await scope.ServiceProvider.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContextAsync(ct);
        var rows = (await db.StoredSecrets.AsNoTracking().ToListAsync(ct)).ToDictionary(r => r.Name, StringComparer.Ordinal);
        Publish(ticket, rows);
        return rows;
    }

    // A property's read: a database that can't be reached answers with what was last read (or nothing saved), rather than
    // throwing into a notification or the delivery card; the send itself reads again and says why it didn't go.
    private IReadOnlyDictionary<string, StoredSecretRecord> Rows()
    {
        if (TryKept(false, out var kept)) return kept;
        var ticket = _order.Begin();
        try
        {
            using var scope = _scopes.CreateScope();
            using var db = scope.ServiceProvider.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContext();
            var rows = db.StoredSecrets.AsNoTracking().ToList().ToDictionary(r => r.Name, StringComparer.Ordinal);
            Publish(ticket, rows);
            return rows;
        }
        catch (Exception ex) when (ex is System.Data.Common.DbException or InvalidOperationException)
        {
            lock (_gate) return _cached?.Rows ?? new Dictionary<string, StoredSecretRecord>(StringComparer.Ordinal);
        }
    }
}
