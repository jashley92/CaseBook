using System.Globalization;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Compliance;
using Microsoft.EntityFrameworkCore;

namespace IncidentManager.Application.Notifications;

/// <summary>
/// CAP-10: the nightly count of closed cases past retention, as Diagnostics and the monthly email show it. Across every
/// case but exercises (a background count has no viewer to scope for), so the review list, which is the administrator's
/// own need-to-know view, can show fewer.
/// </summary>
/// <param name="Years">The retention setting it was counted with; 0 means the review is off and nothing was counted.</param>
/// <param name="Due">Closed, not-archived cases closed before the cut-off.</param>
/// <param name="UnderHold">Of those, how many are under a legal hold (they can't be archived until it's released).</param>
public sealed record RetentionReviewCount(DateTimeOffset CountedAtUtc, int Years, int Due, int UnderHold);

/// <summary>CAP-10: the latest nightly count, for Diagnostics. In memory: a restart counts again within minutes.</summary>
public sealed class RetentionReviewState
{
    private RetentionReviewCount? _last;

    public RetentionReviewCount? Last => Volatile.Read(ref _last);

    public void Record(RetentionReviewCount count) => Volatile.Write(ref _last, count);
}

/// <summary>CAP-10: which months' retention-review emails have gone (in the database, like the other trackers, BUG-95).</summary>
public interface IRetentionReviewTracker
{
    /// <summary>True only the first time a month is marked sent.</summary>
    bool TryMarkSent(int year, int month);

    /// <summary>BUG-08: un-marks a month whose email wasn't delivered, so the next scan sends it again.</summary>
    void Forget(int year, int month);
}

/// <inheritdoc />
public sealed class RetentionReviewTracker(INotificationMarks? marks = null) : IRetentionReviewTracker
{
    private readonly INotificationMarks _marks = marks ?? new InMemoryNotificationMarks();

    private static string Key(int year, int month) => string.Create(CultureInfo.InvariantCulture, $"retention-review|{year:D4}-{month:D2}");

    public bool TryMarkSent(int year, int month) => _marks.TryAdd(Key(year, month));

    public void Forget(int year, int month) => _marks.Remove(Key(year, month));
}

/// <summary>
/// CAP-10: counts the closed cases past <c>Retention:CaseYears</c> for Diagnostics and, when the email is on, tells the
/// Legal / Privacy distribution once a calendar month (in the organization's time zone) that some are waiting. Only counts
/// and tells (ADR 0004): it archives nothing and deletes nothing; a person reviews the list and archives. The month is
/// marked sent only once the email was delivered (BUG-08), so a failed send goes again on the next scan. A month with
/// nothing due sends nothing.
/// </summary>
public sealed class RetentionReviewScanner(
    IAppDbContextFactory factory,
    ICaseNotifications notifications,
    IRetentionReviewTracker tracker,
    RetentionReviewState state,
    IClock clock,
    IOrganizationTimeZone? zone = null)
{
    /// <summary>Counts what's due with <paramref name="years"/> (0 or less: off, nothing counted) and records it.</summary>
    public async Task<RetentionReviewCount> CountAsync(int years, CancellationToken ct = default)
    {
        var now = clock.UtcNow;
        years = Math.Clamp(years, 0, RetentionReviewService.MaxYears);
        if (years == 0)
        {
            var off = new RetentionReviewCount(now, 0, 0, 0);
            state.Record(off);
            return off;
        }
        using var db = factory.CreateDbContext();
        var due = RetentionReviewService.Due(db.Cases.AsNoTracking(), RetentionReviewService.Cutoff(now, years));
        var all = await due.CountAsync(ct);
        var held = all == 0 ? 0 : await due.CountAsync(c => c.LegalHold, ct);
        var count = new RetentionReviewCount(now, years, all, held);
        state.Record(count);
        return count;
    }

    /// <summary>
    /// The nightly pass: counts, then, when <paramref name="email"/> is on and something is due, sends this month's email
    /// if it hasn't gone. Returns the count, and whether the email went.
    /// </summary>
    public async Task<(RetentionReviewCount Count, bool Emailed)> ScanAsync(int years, bool email, CancellationToken ct = default)
    {
        var count = await CountAsync(years, ct);
        if (!email || count.Due == 0) return (count, false);

        var (year, month) = ZonedMonths.Of(count.CountedAtUtc, zone?.Current ?? TimeZoneInfo.Utc);
        using var marks = NotificationMarkBatch.Begin();   // BUG-147: confirmed once the email has gone
        if (!tracker.TryMarkSent(year, month)) return (count, false);

        using var watch = DeliveryWatch.Begin();
        try { await notifications.OnRetentionReviewDueAsync(count, ct); }
        catch
        {
            tracker.Forget(year, month);
            throw;
        }
        if (watch.Failed) { tracker.Forget(year, month); return (count, false); }
        marks.Complete();
        return (count, true);
    }
}
