using IncidentManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Infrastructure.Notifications;

/// <summary>
/// CAP-04: how many emails are held for the relay (BUG-617) and since when, for the Diagnostics card. Counts and a time
/// only: never a recipient or a subject. Bounded and time-limited (C10): the count stops past <see cref="EmailSender.MaxHeld"/>
/// (the table never holds more), and a database that doesn't answer in <paramref name="limit"/> gives an answer that says so
/// rather than holding the page.
/// </summary>
public sealed record HeldEmailSummary(int Count, bool AtLeast, DateTimeOffset? OldestUtc, string? Problem)
{
    public static readonly TimeSpan DefaultLimit = TimeSpan.FromSeconds(5);

    public static async Task<HeldEmailSummary> ReadAsync(IDbContextFactory<AppDbContext> factory, TimeSpan limit, CancellationToken ct = default)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        // A limit already past cancels now: CancelAfter(0) cancels on a timer thread a moment later, so the check below
        // could run first, and a provider that doesn't check the token (SQLite) would then answer.
        if (limit <= TimeSpan.Zero) timeout.Cancel();
        else timeout.CancelAfter(limit);
        try
        {
            timeout.Token.ThrowIfCancellationRequested();   // a limit already past: say so, whether or not the provider checks
            await using var db = await factory.CreateDbContextAsync(timeout.Token);
            var count = await db.HeldEmails.AsNoTracking().Take(EmailSender.MaxHeld + 1).CountAsync(timeout.Token);
            var oldest = count == 0 ? null
                : await db.HeldEmails.AsNoTracking().OrderBy(h => h.Id).Select(h => (DateTimeOffset?)h.HeldAtUtc).FirstOrDefaultAsync(timeout.Token);
            return new HeldEmailSummary(Math.Min(count, EmailSender.MaxHeld), count > EmailSender.MaxHeld, oldest, null);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new HeldEmailSummary(0, false, null, $"the database didn't answer within {limit.TotalSeconds:0} seconds");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new HeldEmailSummary(0, false, null, $"couldn't be read ({ex.GetType().Name})");
        }
    }
}
