using FluentAssertions;
using IncidentManager.Application.Notifications;
using IncidentManager.Infrastructure.Notifications;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>BUG-95/137: the scans' sent marks survive a restart, and two processes don't both send.</summary>
public sealed class NotificationMarkTests : IDisposable
{
    private readonly SqliteConnection _connection = new("Data Source=:memory:");
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 12, 9, 0, 0, TimeSpan.Zero));
    private readonly ServiceProvider _services;

    public NotificationMarkTests()
    {
        _connection.Open();
        _services = new ServiceCollection()
            .AddDbContextFactory<AppDbContext>(o => o.UseSqlite(_connection))
            .BuildServiceProvider();
        using var db = _services.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContext();
        db.Database.EnsureCreated();
    }

    // A fresh store is what a restarted (or a second, overlapping) app process holds.
    private DbNotificationMarks Process() =>
        new(_services.GetRequiredService<IServiceScopeFactory>(), _clock, NullLogger<DbNotificationMarks>.Instance);

    [Fact]
    public void A_reminder_marked_sent_isnt_sent_again_after_a_restart()
    {
        var item = Guid.NewGuid();
        var due = _clock.UtcNow.AddDays(-1);

        new OverdueActionItemTracker(Process()).TryMarkNotified(item, due).Should().BeTrue();

        var restarted = new OverdueActionItemTracker(Process());
        restarted.TryMarkNotified(item, due).Should().BeFalse("the mark is in the database");
        restarted.TryMarkNotified(item, due.AddDays(1)).Should().BeTrue("a new due date is a fresh reminder");
    }

    [Fact]
    public void Of_two_processes_only_the_first_to_mark_sends()
    {
        var first = new DigestTracker(Process());
        var second = new DigestTracker(Process());
        second.TryMarkSent("someone", Domain.Enums.DigestCadence.Daily, "2026-10-11");   // loads its view of the table

        first.TryMarkSent("ana", Domain.Enums.DigestCadence.Daily, "2026-10-12").Should().BeTrue();
        second.TryMarkSent("ANA", Domain.Enums.DigestCadence.Daily, "2026-10-12").Should().BeFalse("the other process sent it");
    }

    [Fact]
    public void A_mark_the_other_process_won_and_then_cleared_is_sent_by_this_one(/* BUG-157 */)
    {
        var first = new DigestTracker(Process());
        var second = new DigestTracker(Process());
        second.TryMarkSent("someone", Domain.Enums.DigestCadence.Daily, "2026-10-11");   // loads its view of the table

        first.TryMarkSent("ana", Domain.Enums.DigestCadence.Daily, "2026-10-12").Should().BeTrue();
        second.TryMarkSent("ana", Domain.Enums.DigestCadence.Daily, "2026-10-12").Should().BeFalse();
        first.Forget("ana", Domain.Enums.DigestCadence.Daily, "2026-10-12");   // its send failed

        second.TryMarkSent("ana", Domain.Enums.DigestCadence.Daily, "2026-10-12").Should().BeTrue("the next scan here sends it");
    }

    [Fact]
    public void An_undelivered_mark_is_forgotten_across_restarts_and_old_marks_are_pruned()
    {
        var c = Guid.NewGuid();
        var marks = Process();
        var tracker = new StaleCaseTracker(marks);
        tracker.TryMarkNotified(c, _clock.UtcNow).Should().BeTrue();
        tracker.Forget(c, _clock.UtcNow);   // the send failed
        new StaleCaseTracker(Process()).TryMarkNotified(c, _clock.UtcNow).Should().BeTrue("the next scan tries again");

        _clock.UtcNow = _clock.UtcNow.AddDays(200);
        new StaleCaseTracker(Process()).TryMarkNotified(Guid.NewGuid(), _clock.UtcNow);   // prunes on load
        using var db = _services.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContext();
        db.NotificationMarks.Should().ContainSingle("marks older than 180 days are pruned");
    }

    [Fact]
    public void A_reminder_that_still_qualifies_isnt_pruned_and_resent(/* WF-22 */)
    {
        var item = Guid.NewGuid();
        var due = _clock.UtcNow.AddDays(-1);
        var marks = Process();
        new OverdueActionItemTracker(marks).TryMarkNotified(item, due).Should().BeTrue();

        // Still overdue: every scan finds the mark for the next months.
        for (var day = 1; day <= 190; day++)
        {
            _clock.UtcNow = _clock.UtcNow.AddDays(1);
            new OverdueActionItemTracker(marks).TryMarkNotified(item, due).Should().BeFalse();
        }

        // A restart prunes marks older than 180 days by their time, which the scans kept renewing.
        var restarted = new OverdueActionItemTracker(Process());
        restarted.TryMarkNotified(Guid.NewGuid(), _clock.UtcNow);
        restarted.TryMarkNotified(item, due).Should().BeFalse("the owner was already reminded");
    }

    [Fact]
    public void A_mark_claimed_by_a_scan_is_kept_only_once_the_scan_completes(/* BUG-147 */)
    {
        var done = Guid.NewGuid();
        var abandoned = Guid.NewGuid();
        var tracker = new StaleCaseTracker(Process());

        using (var batch = Application.Abstractions.NotificationMarkBatch.Begin())
        {
            tracker.TryMarkNotified(done, _clock.UtcNow).Should().BeTrue();
            batch.Complete();
        }
        using (Application.Abstractions.NotificationMarkBatch.Begin())
            tracker.TryMarkNotified(abandoned, _clock.UtcNow).Should().BeTrue();   // the scan threw before completing

        var restarted = new StaleCaseTracker(Process());
        restarted.TryMarkNotified(done, _clock.UtcNow).Should().BeFalse("its send finished");
        restarted.TryMarkNotified(abandoned, _clock.UtcNow).Should().BeTrue("its send never finished");
    }

    [Fact]
    public async Task A_claim_left_by_a_process_that_stopped_mid_send_is_cleared_at_the_next_start(/* BUG-147 */)
    {
        var c = Guid.NewGuid();
        // A scan claims the mark and the process dies before the send returns: the batch is never completed or disposed.
        await Task.Run(() =>
        {
            Application.Abstractions.NotificationMarkBatch.Begin();
            new StaleCaseTracker(Process()).TryMarkNotified(c, _clock.UtcNow).Should().BeTrue();
        });
        using (var db = _services.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContext())
            db.NotificationMarks.Single().ConfirmedAtUtc.Should().BeNull();

        new StaleCaseTracker(Process()).TryMarkNotified(c, _clock.UtcNow).Should().BeTrue("the restart clears the stranded claim");
    }

    [Fact]
    public void A_mark_recorded_outside_a_scan_batch_is_confirmed_at_once()
    {
        new DigestTracker(Process()).TryMarkSent("ana", Domain.Enums.DigestCadence.Daily, "2026-10-12").Should().BeTrue();
        new DigestTracker(Process()).TryMarkSent("ana", Domain.Enums.DigestCadence.Daily, "2026-10-12").Should().BeFalse();
    }

    public void Dispose()
    {
        _services.Dispose();
        _connection.Dispose();
    }
}
