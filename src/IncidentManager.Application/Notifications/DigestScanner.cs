using System.Globalization;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Work;
using IncidentManager.Domain.Enums;

namespace IncidentManager.Application.Notifications;

/// <summary>
/// Assembles and sends each opted-in user's consolidated work digest (PROD-39): one grouped email of their
/// open, dated follow-up items (overdue / today / this week), on the cadence they chose — in place of a
/// scatter of per-item reminders. The item assembly reuses <see cref="AgendaService.GetFeedItemsAsync"/>
/// (the same self-scoped feed that backs the per-user calendar), so a user only ever sees their own work.
/// Read-only over case data — it records nothing and never changes case state, so it stays out of the audit
/// chain. Sends once per period via <see cref="IDigestTracker"/>. The scheduled hosted service calls
/// <see cref="ScanAndNotifyAsync"/> on a regular cadence.
/// </summary>
public sealed class DigestScanner(
    UserNotificationPreferenceService prefs,
    AgendaService agenda,
    ICaseNotifications notifications,
    IDigestTracker tracker,
    IClock clock)
{
    /// <summary>Sends a digest to each subscriber who has items and hasn't been sent one this period. Returns
    /// how many digests were sent.</summary>
    public async Task<int> ScanAndNotifyAsync(CancellationToken ct = default)
    {
        var subscribers = await prefs.ListSubscribersAsync(ct);
        if (subscribers.Count == 0) return 0;

        var now = clock.UtcNow;
        var sent = 0;

        foreach (var sub in subscribers)
        {
            var items = await agenda.GetFeedItemsAsync(sub.UserId, ct);

            var overdue = Band(items, now, Bucket.Overdue);
            var today = Band(items, now, Bucket.Today);
            var thisWeek = Band(items, now, Bucket.ThisWeek);
            if (overdue.Count == 0 && today.Count == 0 && thisWeek.Count == 0)
                continue; // nothing worth a digest → don't send, and don't consume the period slot

            // Once per period: only mark (and thus consume the slot) when we actually have something to send.
            if (!tracker.TryMarkSent(sub.UserId, sub.Cadence, PeriodKey(sub.Cadence, now)))
                continue;

            await notifications.OnDigestAsync(new UserDigest(sub.UserId, sub.Cadence, overdue, today, thisWeek), ct);
            sent++;
        }

        return sent;
    }

    private enum Bucket { Overdue, Today, ThisWeek }

    /// <summary>The dated feed items falling in a band, as digest items, in due order. Mirrors
    /// <see cref="AgendaService"/>'s UTC calendar-day banding.</summary>
    private static IReadOnlyList<DigestItem> Band(IReadOnlyList<AgendaItem> items, DateTimeOffset now, Bucket band)
    {
        var startOfTomorrow = now.UtcDateTime.Date.AddDays(1);
        return items
            .Where(i => i.DueAtUtc is { } d && InBand(d, now, startOfTomorrow, band))
            .OrderBy(i => i.DueAtUtc)
            .Select(i => new DigestItem(i.CaseNumber, i.Title, i.Severity, i.DueAtUtc!.Value))
            .ToList();
    }

    private static bool InBand(DateTimeOffset due, DateTimeOffset now, DateTime startOfTomorrow, Bucket band) => band switch
    {
        Bucket.Overdue => due < now,
        Bucket.Today => due >= now && due.UtcDateTime < startOfTomorrow,
        Bucket.ThisWeek => due.UtcDateTime >= startOfTomorrow && due.UtcDateTime < startOfTomorrow.AddDays(6),
        _ => false
    };

    /// <summary>The period a digest belongs to: the UTC date for Daily, the ISO year-week for Weekly.</summary>
    private static string PeriodKey(DigestCadence cadence, DateTimeOffset now) => cadence == DigestCadence.Weekly
        ? string.Create(CultureInfo.InvariantCulture, $"{ISOWeek.GetYear(now.UtcDateTime)}-W{ISOWeek.GetWeekOfYear(now.UtcDateTime):00}")
        : now.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
}
