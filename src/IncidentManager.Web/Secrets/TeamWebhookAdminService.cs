using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Common;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Siem;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Web.Secrets;

/// <summary>
/// CAP-36: a team's own chat webhook URL, entered on the Teams page (scoped: it acts as the signed-in administrator). CAP-40's
/// secret card, a row per team: the value is write-only, kept encrypted by Data Protection (<see cref="StoredSecretStore"/>),
/// passes the same https check as a send (S-06), and is never in the team's row, its hash, the audit trail or the
/// configuration bundle. The audit trail records who, when, which team and whether it was set, replaced or cleared; SIEM
/// 5403 (SettingChanged) names the secret, as for the shared one. A stale card (C9) is refused.
/// </summary>
public sealed class TeamWebhookAdminService(
    StoredSecretStore store,
    IDbContextFactory<AppDbContext> db,
    ICurrentUser user,
    IAuditWriter audit,
    IClock clock,
    ISecurityEventSink? siem = null)
{
    /// <summary>The saved webhook of <paramref name="teamId"/>, read now, with the stamp a save hands back.</summary>
    public Task<StoredSecretStatus> GetAsync(Guid teamId, CancellationToken ct = default) => store.TeamWebhookStatusAsync(teamId, fresh: true, ct);

    /// <summary>Why <paramref name="value"/> can't be saved as a team's webhook URL, or null. Never repeats the value.</summary>
    public static string? Problem(string value)
    {
        var d = StoredSecretDefinition.TeamChatWebhookUrl;
        if (value.Length == 0) return "Enter the team's webhook URL.";
        if (value.Length > d.MaxLength || value.Any(char.IsControl)) return $"The webhook URL must be at most {d.MaxLength} characters, on one line.";
        if (Infrastructure.Secrets.SecretReference.IsReference(value) || Infrastructure.Secrets.ProtectedSecret.IsProtected(value))
            return "That's a reference for the server's configuration file. Enter the webhook URL itself here.";
        return SiemWebhookUrl.IsAcceptable(value, out var reason) ? null : $"The webhook URL was refused ({reason}). Use an https URL.";
    }

    /// <summary>Saves <paramref name="newValue"/> as the team's webhook (set or replaced); <paramref name="expectedStamp"/> as
    /// CAP-40's (null skips the check).</summary>
    public Task SaveAsync(Guid teamId, string? newValue, string? expectedStamp = null, CancellationToken ct = default)
    {
        Require();
        var value = (newValue ?? "").Trim();
        if (Problem(value) is { } problem) throw new InvalidOperationException(problem);
        return WriteAsync(teamId, value, expectedStamp, ct);
    }

    /// <summary>Clears the team's webhook: its posts go to the shared channel again.</summary>
    public Task ClearAsync(Guid teamId, string? expectedStamp = null, CancellationToken ct = default)
    {
        Require();
        return WriteAsync(teamId, null, expectedStamp, ct);
    }

    private async Task WriteAsync(Guid teamId, string? value, string? expectedStamp, CancellationToken ct)
    {
        var name = StoredSecretStore.TeamWebhookName(teamId);
        await using var context = await db.CreateDbContextAsync(ct);
        var team = await context.Teams.AsNoTracking().Where(t => t.Id == teamId).Select(t => t.Name).FirstOrDefaultAsync(ct)
                   ?? throw new InvalidOperationException("That team no longer exists. Reload the page.");
        var row = await context.StoredSecrets.FirstOrDefaultAsync(r => r.Name == name, ct);
        var current = StoredSecretStore.StampOf(row);
        if (expectedStamp is not null && !string.Equals(current, expectedStamp, StringComparison.Ordinal))
            throw new StaleEditException(current, $"Someone changed {team}'s webhook URL since you opened it, so nothing was saved: it " +
                                                  "would have undone that. What's saved now is shown; check it, then try again.");
        if (value is null && row?.ProtectedValue is null)
            throw new InvalidOperationException($"No webhook URL is saved for {team}, so there's nothing to clear.");

        var adding = row is null;
        row ??= new StoredSecretRecord { Name = name };
        var now = clock.UtcNow;
        var who = TextFit.Cap(user.UserId, 256, marker: "")!;
        string change;
        if (value is null)
        {
            change = "cleared";
            (row.ProtectedValue, row.SetAtUtc, row.SetBy) = (null, null, null);
        }
        else
        {
            change = row.ProtectedValue is null ? "set" : "replaced";
            row.ProtectedValue = Protect(teamId, value);
            (row.SetAtUtc, row.SetBy) = (now, who);
        }
        (row.UpdatedAtUtc, row.UpdatedBy) = (now, who);
        if (adding) context.StoredSecrets.Add(row);
        try { await context.SaveChangesAsync(ct); }
        catch (DbUpdateException ex) when (adding)
        {
            // As CAP-40's card (BUG-459's class): another administrator's first save for this team landed in between.
            await using var recheck = await db.CreateDbContextAsync(ct);
            if (await recheck.StoredSecrets.AnyAsync(r => r.Name == name, ct))
                throw new InvalidOperationException($"Someone else saved {team}'s webhook URL just now; reload to see it.", ex);
            throw;
        }
        store.Invalidate();   // the next post uses it: no restart

        // Who, when, which team and what became of it: never the value or its ciphertext.
        await audit.RecordAsync(adding ? AuditAction.Create : AuditAction.Update, StoredSecretAdminService.AuditEntity, name, null,
            $"Chat webhook URL for the team \"{TextFit.Cap(team, Team.NameMax, "")}\" {change} in Administration.", ct);
        siem?.Emit(SecurityEvents.SettingChanged(name, user.UserId, user.UserPrincipalName));
    }

    // As CAP-40's review: a key ring that can't be read or written is a worded refusal, not a dead circuit.
    private string Protect(Guid teamId, string value)
    {
        try { return store.ProtectTeamWebhook(teamId, value); }
        catch (System.Security.Cryptography.CryptographicException ex)
        {
            throw new InvalidOperationException(
                $"The webhook URL couldn't be encrypted on this server ({(ex.InnerException ?? ex).GetType().Name}), so nothing was saved. " +
                "Check that the Data Protection key ring (DataProtection:KeyPath) is there and the app pool can write to it; see Diagnostics.", ex);
        }
    }

    // As StoredSecretAdminService: Administer, a refusal streamed to the SIEM.
    private void Require([System.Runtime.CompilerServices.CallerMemberName] string action = "")
    {
        if (user.Has(Permission.Administer)) return;
        var key = $"{nameof(TeamWebhookAdminService)}.{action}";
        siem?.Emit(SecurityEvents.ActionRefused(user.UserId, user.UserPrincipalName, Permission.Administer, key));
        throw new ForbiddenException(Permission.Administer, key);
    }
}
