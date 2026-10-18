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
/// <see cref="ScanAndNotifyAsync"/> on a regular cadence. Days and weeks follow the organization's reporting time
/// zone, so "today" ends at local midnight and a new day's digest goes out after it, not at UTC midnight.
/// </summary>
public sealed class DigestScanner(
    UserNotificationPreferenceService prefs,
    AgendaService agenda,
    ICaseNotifications notifications,
    IDigestTracker tracker,
    IClock clock,
    IOrganizationTimeZone? zone = null,
    IUserDirectory? users = null,
    ApiTokens.ITokenOwnerCheck? owners = null,
    IRoleDirectory? roles = null,
    IAppDbContextFactory? factory = null)
{
    /// <summary>CAP-01: <c>Notifications:DigestScan:ImportWaitingHours</c>'s default: imports waiting longer than a day.</summary>
    public const int DefaultImportWaitingHours = 24;

    /// <summary>Sends a digest to each subscriber who has items and hasn't been sent one this period. Returns
    /// how many digests were sent.</summary>
    public Task<int> ScanAndNotifyAsync(CancellationToken ct = default) => ScanAndNotifyAsync(DefaultImportWaitingHours, ct);

    /// <param name="importWaitingHours">CAP-01: a reviewer's digest says how many imports have waited for review longer
    /// than this; 0 leaves the line out.</param>
    public async Task<int> ScanAndNotifyAsync(int importWaitingHours, CancellationToken ct = default)
    {
        var subscribers = await prefs.ListSubscribersAsync(ct);
        if (subscribers.Count == 0) return 0;

        var now = clock.UtcNow;
        var tz = zone?.Current ?? TimeZoneInfo.Utc;
        var sent = 0;
        var audience = new ReminderAudience(users, roles, owners);

        foreach (var sub in subscribers)
        {
            // REV-51: as the calendar feed refuses them (BUG-20), no digest for someone who holds no CaseBook role, or whose
            // account the directory says is disabled or no longer maps to any role: a leaver kept getting case numbers,
            // titles and tasks (restricted ones included) every day. BUG-377: a role that grants ViewCases, not just any role.
            if (!await audience.EntitledAsync(sub.UserId, ct)) continue;

            var items = await agenda.GetFeedItemsAsync(sub.UserId, ct);

            var overdue = Band(items, now, tz, AgendaBucketKind.Overdue);
            var today = Band(items, now, tz, AgendaBucketKind.Today);
            var thisWeek = Band(items, now, tz, AgendaBucketKind.ThisWeek);
            // CAP-01: and, for someone who reviews imports, the ones they'd see that have waited too long.
            var imports = importWaitingHours > 0 && factory is not null
                ? await Import.PendingImportQueue.WaitingForAsync(factory, sub.UserId, TimeSpan.FromHours(importWaitingHours), now,
                    users, roles, audience, ct)
                : Import.PendingImportCount.None;
            if (overdue.Count == 0 && today.Count == 0 && thisWeek.Count == 0 && imports.Count == 0)
                continue; // nothing worth a digest → don't send, and don't consume the period slot

            // Once per period: only mark (and thus consume the slot) when we actually have something to send. BUG-147:
            // the mark is kept only if the send finishes.
            using var marks = NotificationMarkBatch.Begin();
            if (!tracker.TryMarkSent(sub.UserId, sub.Cadence, PeriodKey(sub.Cadence, ZonedDays.Of(now, tz))))
                continue;

            // BUG-08: a digest that wasn't delivered is un-marked, so the next scan sends it again.
            using var watch = DeliveryWatch.Begin();
            await notifications.OnDigestAsync(new UserDigest(sub.UserId, sub.Cadence, overdue, today, thisWeek,
                imports, importWaitingHours), ct);
            if (watch.Failed) { tracker.Forget(sub.UserId, sub.Cadence, PeriodKey(sub.Cadence, ZonedDays.Of(now, tz))); continue; }
            marks.Complete();
            sent++;
        }

        return sent;
    }

    /// <summary>The dated feed items falling in a band, as digest items, in due order. Uses the agenda's banding.</summary>
    private static IReadOnlyList<DigestItem> Band(IReadOnlyList<AgendaItem> items, DateTimeOffset now, TimeZoneInfo zone,
        AgendaBucketKind band) =>
        items
            .Where(i => i.DueAtUtc is not null && AgendaService.Bucket(i.DueAtUtc, now, zone) == band)
            .OrderBy(i => i.DueAtUtc)
            .Select(i => new DigestItem(i.CaseNumber, i.Title, i.Severity, i.DueAtUtc!.Value))
            .ToList();

    /// <summary>The period a digest belongs to: the local date for Daily, the ISO year-week for Weekly.</summary>
    private static string PeriodKey(DigestCadence cadence, DateOnly today)
    {
        var day = today.ToDateTime(TimeOnly.MinValue);
        return cadence == DigestCadence.Weekly
            ? string.Create(CultureInfo.InvariantCulture, $"{ISOWeek.GetYear(day)}-W{ISOWeek.GetWeekOfYear(day):00}")
            : today.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
    }
}
