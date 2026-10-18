using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Common;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Notifications;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Secrets;
using IncidentManager.Infrastructure.Siem;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace IncidentManager.Web.Secrets;

/// <summary>
/// CAP-40: the service behind the secret cards (scoped: it acts as the signed-in administrator), CAP-05's Email sign-in
/// pattern for a single value. Saves a new value only when one is typed; the value is never read back. Refused while the
/// server's configuration sets the secret (it wins: a literal, a <c>@cyberark:</c> reference or a <c>@protected:</c> value).
/// The chat webhook URL passes the same https check as a send (S-06) before it's saved. The audit trail records who, when,
/// which secret and whether it was set, replaced or cleared; never the value. SIEM 5403 (SettingChanged) as for any setting.
/// </summary>
public sealed class StoredSecretAdminService(
    StoredSecretStore store,
    IDbContextFactory<AppDbContext> db,
    IOptionsMonitor<ChatOptions> chat,
    IOptionsMonitor<SiemWebhookOptions> siemWebhook,
    ICurrentUser user,
    IAuditWriter audit,
    IClock clock,
    ISecurityEventSink? siem = null)
{
    /// <summary>The audit trail's entity type for these changes (not <c>AppSetting</c>, so a setting's History never lists them).</summary>
    public const string AuditEntity = "StoredSecret";

    /// <summary>The value server configuration sets for <paramref name="kind"/>, or blank (never shown: only its form).</summary>
    private string ServerValue(StoredSecretKind kind) => kind switch
    {
        StoredSecretKind.ChatWebhookUrl => chat.CurrentValue.WebhookUrl,
        StoredSecretKind.SiemWebhookToken => siemWebhook.CurrentValue.Token,
        _ => "",
    };

    /// <summary>Whether server configuration sets the secret, so the card is read-only.</summary>
    public bool SetInServerConfiguration(StoredSecretKind kind) => !string.IsNullOrWhiteSpace(ServerValue(kind));

    /// <summary>The form server configuration writes it in, for the read-only card: never the value or the reference.</summary>
    public string ServerConfigurationForm(StoredSecretKind kind) => ServerValue(kind) switch
    {
        var v when string.IsNullOrWhiteSpace(v) => "not set",
        var v when ProtectedSecret.IsProtected(v) => "a @protected: value, encrypted to a certificate",
        var v when SecretReference.IsReference(v) => "a CyberArk reference",
        _ => "plain text in the configuration file",
    };

    /// <summary>The saved secret, read now (not what the senders keep), with the stamp a save hands back.</summary>
    public Task<StoredSecretStatus> GetAsync(StoredSecretKind kind, CancellationToken ct = default) => store.StatusAsync(kind, fresh: true, ct);

    /// <summary>The words for a save or clear refused because the secret changed since the card loaded it.</summary>
    public static string ChangedSinceOpened(StoredSecretKind kind) =>
        $"Someone changed the {StoredSecretDefinition.For(kind).Label} since you opened it, so nothing was saved: it would have " +
        "undone that. What's saved now is shown; check it, then try again.";

    /// <summary>Why <paramref name="value"/> can't be saved as <paramref name="kind"/>, or null. Never repeats the value.</summary>
    public static string? Problem(StoredSecretKind kind, string value)
    {
        var d = StoredSecretDefinition.For(kind);
        if (value.Length == 0) return $"Enter the {d.Label}.";
        if (value.Length > d.MaxLength || value.Any(char.IsControl))
            return $"The {d.Label} must be at most {d.MaxLength} characters, on one line.";
        if (SecretReference.IsReference(value) || ProtectedSecret.IsProtected(value))
            return "That's a reference for the server's configuration file. Enter the value itself here, or put the reference in " +
                   $"{d.Name} on the server.";
        // S-06, as a send checks it: https, or http only to this server itself, so the URL never crosses the network in clear.
        if (kind == StoredSecretKind.ChatWebhookUrl && !SiemWebhookUrl.IsAcceptable(value, out var reason))
            return $"The webhook URL was refused ({reason}). Use an https URL.";
        return null;
    }

    /// <summary>
    /// Saves <paramref name="newValue"/> as the secret (set, or replaced). <paramref name="expectedStamp"/> is the
    /// <see cref="StoredSecretStatus.Stamp"/> the card loaded ("" when there was no row): a row changed since is refused
    /// (<see cref="StaleEditException"/>), so a stale card can't put back a value someone else just replaced or cleared.
    /// Null skips the check.
    /// </summary>
    public Task SaveAsync(StoredSecretKind kind, string? newValue, string? expectedStamp = null, CancellationToken ct = default)
    {
        Require();
        var value = (newValue ?? "").Trim();
        if (Problem(kind, value) is { } problem) throw new InvalidOperationException(problem);
        return WriteAsync(kind, value, expectedStamp, ct);
    }

    /// <summary>Clears the saved secret: the card's Clear (with the stamp it loaded, as for Save).</summary>
    public Task ClearAsync(StoredSecretKind kind, string? expectedStamp = null, CancellationToken ct = default)
    {
        Require();
        return WriteAsync(kind, null, expectedStamp, ct);
    }

    private async Task WriteAsync(StoredSecretKind kind, string? value, string? expectedStamp, CancellationToken ct)
    {
        var d = StoredSecretDefinition.For(kind);
        if (SetInServerConfiguration(kind))
            throw new InvalidOperationException($"The {d.Label} is set in the server's configuration ({d.Name}), which wins; change it there.");

        await using var context = await db.CreateDbContextAsync(ct);
        var row = await context.StoredSecrets.FirstOrDefaultAsync(r => r.Name == d.Name, ct);
        var current = StoredSecretStore.StampOf(row);
        if (expectedStamp is not null && !string.Equals(current, expectedStamp, StringComparison.Ordinal))
            throw new StaleEditException(current, ChangedSinceOpened(kind));
        if (value is null && row?.ProtectedValue is null)
            throw new InvalidOperationException($"No {d.Label} is saved, so there's nothing to clear.");

        var adding = row is null;
        row ??= new StoredSecretRecord { Name = d.Name };
        var now = clock.UtcNow;
        var who = TextFit.Cap(user.UserId, 256, marker: "")!;
        string change;
        if (value is null)
        {
            change = "cleared";
            row.ProtectedValue = null;
            row.SetAtUtc = null;
            row.SetBy = null;
        }
        else
        {
            change = row.ProtectedValue is null ? "set" : "replaced";
            row.ProtectedValue = store.Protect(kind, value);
            row.SetAtUtc = now;
            row.SetBy = who;
        }
        row.UpdatedAtUtc = now;
        row.UpdatedBy = who;
        if (adding) context.StoredSecrets.Add(row);
        try { await context.SaveChangesAsync(ct); }
        catch (DbUpdateException ex) when (adding)
        {
            // As CAP-05's review (BUG-459's class): another administrator's first save landed between the read above and
            // this insert (the primary key refused it). Worded, so the card says so instead of the circuit failing.
            await using var recheck = await db.CreateDbContextAsync(ct);
            if (await recheck.StoredSecrets.AnyAsync(r => r.Name == d.Name, ct))
                throw new InvalidOperationException($"Someone else saved the {d.Label} just now; reload to see it.", ex);
            throw;
        }
        store.Invalidate();   // the next send uses it: no restart

        // Who, when (the entry's own), which secret and what became of it: never the value or its ciphertext.
        await audit.RecordAsync(adding ? AuditAction.Create : AuditAction.Update, AuditEntity, d.Name, null,
            $"{char.ToUpperInvariant(d.Label[0])}{d.Label[1..]} {change} in Administration.", ct);
        siem?.Emit(SecurityEvents.SettingChanged(d.Name, user.UserId, user.UserPrincipalName));
    }

    // As AdminActionPermissions.Require does for the Application services: Administer, a refusal streamed to the SIEM.
    private void Require([System.Runtime.CompilerServices.CallerMemberName] string action = "")
    {
        if (user.Has(Permission.Administer)) return;
        var key = $"{nameof(StoredSecretAdminService)}.{action}";
        siem?.Emit(SecurityEvents.ActionRefused(user.UserId, user.UserPrincipalName, Permission.Administer, key));
        throw new ForbiddenException(Permission.Administer, key);
    }
}
