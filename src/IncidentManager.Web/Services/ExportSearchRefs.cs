using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace IncidentManager.Web.Services;

/// <summary>
/// CAP-17: keeps a list search out of an export's URL. A download is a real request, so its URL lands in the web server's
/// log and the browser's history, and a search can be an indicator or a person's name (C7 of the business rules). The page
/// holds the text here, for the signed-in user, and links to the export with an opaque reference; the export reads it back
/// for the same user only. In memory, an hour each, a few per user and a bounded total, so nothing here grows without
/// limit. Singleton.
/// </summary>
public sealed class ExportSearchRefs(TimeProvider? time = null)
{
    public static readonly TimeSpan Lifetime = TimeSpan.FromHours(1);
    public const int PerUser = 20;
    public const int MaxTotal = 5000;

    private readonly TimeProvider _time = time ?? TimeProvider.System;
    private readonly ConcurrentDictionary<string, (string UserId, string Text, DateTimeOffset Expires, long Seq)> _held = new(StringComparer.Ordinal);
    private readonly Lock _gate = new();
    private long _seq;   // the order they were held in, oldest first, when their expiries tie

    /// <summary>A reference to <paramref name="text"/> for <paramref name="userId"/>; the same one while it's held.</summary>
    public string Hold(string userId, string text)
    {
        var now = _time.GetUtcNow();
        lock (_gate)
        {
            Prune(now);
            foreach (var (key, v) in _held)
                if (v.UserId == userId && v.Text == text && v.Expires > now)
                {
                    _held[key] = v with { Expires = now + Lifetime };   // still in use: kept as long as the page is
                    return key;
                }
            var mine = _held.Where(kv => kv.Value.UserId == userId).OrderBy(kv => kv.Value.Expires).ThenBy(kv => kv.Value.Seq).ToList();
            foreach (var old in mine.Take(Math.Max(0, mine.Count - PerUser + 1))) _held.TryRemove(old.Key, out _);
            if (_held.Count >= MaxTotal)
                foreach (var old in _held.OrderBy(kv => kv.Value.Expires).ThenBy(kv => kv.Value.Seq).Take(_held.Count - MaxTotal + 1).ToList())
                    _held.TryRemove(old.Key, out _);
            var id = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
            _held[id] = (userId, text, now + Lifetime, ++_seq);
            return id;
        }
    }

    /// <summary>The text held under <paramref name="reference"/> for this user, or null (another user's, expired, or none).</summary>
    public string? Read(string userId, string? reference)
    {
        if (string.IsNullOrEmpty(reference) || !_held.TryGetValue(reference, out var v)) return null;
        return v.UserId == userId && v.Expires > _time.GetUtcNow() ? v.Text : null;
    }

    private void Prune(DateTimeOffset now)
    {
        foreach (var (key, v) in _held)
            if (v.Expires <= now) _held.TryRemove(key, out _);
    }
}
