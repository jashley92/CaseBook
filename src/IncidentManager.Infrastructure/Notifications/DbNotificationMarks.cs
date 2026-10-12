using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace IncidentManager.Infrastructure.Notifications;

/// <summary>
/// BUG-95: the scans' sent marks, kept in <c>NotificationMarks</c> so an IIS recycle or a deploy doesn't resend every
/// active reminder, digest and the executive report. Read once into memory, then written through. The key is the
/// table's primary key, so when two app processes overlap (BUG-137) only the one whose insert lands sends; the other
/// reads the clash as "already sent". If the database can't be reached the mark is kept in memory only and a warning
/// logged: a reminder sent twice is better than one never sent.
/// </summary>
public sealed class DbNotificationMarks(IServiceScopeFactory scopes, IClock clock, ILogger<DbNotificationMarks> log)
    : INotificationMarks
{
    private readonly object _gate = new();
    private HashSet<string>? _keys;
    private readonly HashSet<string> _unsaved = new(StringComparer.Ordinal);   // marked while the table couldn't be read
    private DateTimeOffset _prunedAt;

    public bool TryAdd(string key)
    {
        if (key.Length > NotificationMark.MaxKeyLength) key = key[..NotificationMark.MaxKeyLength];
        lock (_gate)
        {
            if (!Loaded().Add(key)) return false;
        }
        try
        {
            using var scope = scopes.CreateScope();
            using var db = scope.ServiceProvider.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContext();
            PruneIfDue(db);
            db.NotificationMarks.Add(new NotificationMark { Key = key, SentAtUtc = clock.UtcNow });
            db.SaveChanges();
            return true;
        }
        catch (DbUpdateException) when (Exists(key))
        {
            return false;   // another process recorded it first, and sends it
        }
        catch (Exception ex)
        {
            log.LogWarning(ex, "Couldn't record a sent notification; a restart may send it again.");
            return true;
        }
    }

    public void Remove(string key)
    {
        if (key.Length > NotificationMark.MaxKeyLength) key = key[..NotificationMark.MaxKeyLength];
        lock (_gate) Loaded().Remove(key);
        try
        {
            using var scope = scopes.CreateScope();
            using var db = scope.ServiceProvider.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContext();
            db.NotificationMarks.Where(m => m.Key == key).ExecuteDelete();
        }
        catch (Exception ex)
        {
            log.LogWarning(ex, "Couldn't clear an undelivered notification's mark; it may not be retried after a restart.");
        }
    }

    private bool Exists(string key)
    {
        try
        {
            using var scope = scopes.CreateScope();
            using var db = scope.ServiceProvider.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContext();
            return db.NotificationMarks.AsNoTracking().Any(m => m.Key == key);
        }
        catch (Exception)
        {
            return false;
        }
    }

    // Call under _gate. A failed load is retried on the next call rather than remembered as "nothing sent"; what was
    // marked meanwhile is kept in memory and joins the loaded set.
    private HashSet<string> Loaded()
    {
        if (_keys is not null) return _keys;
        try
        {
            using var scope = scopes.CreateScope();
            using var db = scope.ServiceProvider.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContext();
            PruneIfDue(db);
            _keys = db.NotificationMarks.AsNoTracking().Select(m => m.Key).ToHashSet(StringComparer.Ordinal);
            _keys.UnionWith(_unsaved);
            return _keys;
        }
        catch (Exception ex)
        {
            log.LogWarning(ex, "Couldn't read the sent-notification marks; reminders may be sent again.");
            return _unsaved;
        }
    }

    private void PruneIfDue(AppDbContext db)
    {
        var now = clock.UtcNow;
        if (now - _prunedAt < TimeSpan.FromDays(1)) return;
        _prunedAt = now;
        var cutoff = now - NotificationMark.Keep;
        db.NotificationMarks.Where(m => m.SentAtUtc < cutoff).ExecuteDelete();
    }
}
