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
/// logged: a reminder sent twice is better than one never sent. BUG-147: a mark recorded inside a
/// <see cref="NotificationMarkBatch"/> is written unconfirmed and confirmed when the scan's sends are done; unconfirmed
/// marks found at start-up were left by a process that stopped mid-send, and are cleared.
/// </summary>
public sealed class DbNotificationMarks(IServiceScopeFactory scopes, IClock clock, ILogger<DbNotificationMarks> log)
    : INotificationMarks
{
    private readonly object _gate = new();
    private HashSet<string>? _keys;
    private readonly HashSet<string> _unsaved = new(StringComparer.Ordinal);   // marked while the table couldn't be read
    private DateTimeOffset _prunedAt;
    private readonly Dictionary<string, DateTimeOffset> _renewed = new(StringComparer.Ordinal);   // WF-22

    // WF-22: a mark a scan finds still in place is for an item that still qualifies (a task overdue for months, a breached
    // deadline never reported). Its time is renewed, at most every RenewEvery, so the 180-day prune, which goes by that
    // time, doesn't drop it and resend the reminder after the next restart.
    private static readonly TimeSpan RenewEvery = TimeSpan.FromDays(30);

    public bool TryAdd(string key)
    {
        if (key.Length > NotificationMark.MaxKeyLength) key = key[..NotificationMark.MaxKeyLength];
        bool added, renew = false;
        lock (_gate)
        {
            added = Loaded().Add(key);
            if (added) _renewed[key] = clock.UtcNow;   // BUG-295: so the in-memory prune knows its age
            if (!added)
            {
                var now = clock.UtcNow;
                renew = !_renewed.TryGetValue(key, out var at) || now - at >= RenewEvery;
                if (renew) _renewed[key] = now;
            }
        }
        if (!added)
        {
            if (renew) Renew(key);
            return false;
        }
        var batch = NotificationMarkBatch.Current;
        try
        {
            using var scope = scopes.CreateScope();
            using var db = scope.ServiceProvider.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContext();
            PruneIfDue(db);
            var now = clock.UtcNow;
            db.NotificationMarks.Add(new NotificationMark { Key = key, SentAtUtc = now, ConfirmedAtUtc = batch is null ? now : null });
            db.SaveChanges();
            batch?.Claimed(this, key);
            return true;
        }
        catch (DbUpdateException) when (Exists(key))
        {
            // Another process recorded it first, and sends it. BUG-157: the table, not this process's copy, says so: if
            // that send fails and the other process clears the mark, the next scan here records it and sends.
            lock (_gate) Loaded().Remove(key);
            return false;
        }
        catch (Exception ex)
        {
            log.LogWarning(ex, "Couldn't record a sent notification; a restart may send it again.");
            batch?.Claimed(this, key);
            return true;
        }
    }

    private void Renew(string key)
    {
        try
        {
            using var scope = scopes.CreateScope();
            using var db = scope.ServiceProvider.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContext();
            var now = clock.UtcNow;
            db.NotificationMarks.Where(m => m.Key == key).ExecuteUpdate(u => u.SetProperty(m => m.SentAtUtc, now));
        }
        catch (Exception ex)
        {
            log.LogWarning(ex, "Couldn't renew a sent notification's mark; it may be sent again after it's pruned.");
        }
    }

    public void Remove(string key)
    {
        if (key.Length > NotificationMark.MaxKeyLength) key = key[..NotificationMark.MaxKeyLength];
        lock (_gate) Loaded().Remove(key);
        NotificationMarkBatch.Current?.Released(this, key);
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

    public void RemovePrefix(string prefix)
    {
        lock (_gate) Loaded().RemoveWhere(k => k.StartsWith(prefix, StringComparison.Ordinal));
        try
        {
            using var scope = scopes.CreateScope();
            using var db = scope.ServiceProvider.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContext();
            db.NotificationMarks.Where(m => m.Key.StartsWith(prefix)).ExecuteDelete();
        }
        catch (Exception ex)
        {
            log.LogWarning(ex, "Couldn't clear re-armed notification marks; those reminders may not be sent again until a restart.");
        }
    }

    public void Confirm(IReadOnlyCollection<string> keys)
    {
        if (keys.Count == 0) return;
        try
        {
            using var scope = scopes.CreateScope();
            using var db = scope.ServiceProvider.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContext();
            var now = clock.UtcNow;
            foreach (var chunk in keys.Chunk(200))
                db.NotificationMarks.Where(m => chunk.Contains(m.Key) && m.ConfirmedAtUtc == null)
                    .ExecuteUpdate(s => s.SetProperty(m => m.ConfirmedAtUtc, now));
        }
        catch (Exception ex)
        {
            log.LogWarning(ex, "Couldn't confirm sent notifications; a restart may send them again.");
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
            // BUG-147: read once, before this process records anything, so an unconfirmed mark here is a send another
            // process claimed and never finished. Cleared, so it's sent (twice at worst, rather than never).
            var stranded = db.NotificationMarks.Where(m => m.ConfirmedAtUtc == null).ExecuteDelete();
            if (stranded > 0)
                log.LogWarning("Cleared {Count} notification mark(s) left by a send that didn't finish; they'll be sent again.", stranded);
            // WF-22: each mark's time is when it was last renewed, so a scan after a restart renews only those due.
            var loaded = db.NotificationMarks.AsNoTracking().Select(m => new { m.Key, m.SentAtUtc }).ToList();
            _keys = loaded.Select(m => m.Key).ToHashSet(StringComparer.Ordinal);
            foreach (var m in loaded) _renewed[m.Key] = m.SentAtUtc;
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
        // BUG-295: and the same marks from memory. The process can run for months (BUG-137 turned off the periodic
        // recycle), and the sets kept every key ever recorded.
        lock (_gate)
        {
            foreach (var key in _renewed.Where(r => r.Value < cutoff).Select(r => r.Key).ToList())
            {
                _renewed.Remove(key);
                _keys?.Remove(key);
            }
        }
    }
}
