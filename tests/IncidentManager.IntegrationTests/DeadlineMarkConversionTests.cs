using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Notifications;
using IncidentManager.Application.Sla;
using IncidentManager.Infrastructure.Notifications;
using IncidentManager.Infrastructure.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>BUG-619: a deadline mark kept in the database by v1.6.12 (no jurisdiction) is converted once, and holds.</summary>
public sealed class DeadlineMarkConversionTests : IDisposable
{
    private readonly SqliteConnection _connection = new("Data Source=:memory:");
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 12, 9, 0, 0, TimeSpan.Zero));
    private readonly ServiceProvider _services;

    public DeadlineMarkConversionTests()
    {
        _connection.Open();
        _services = new ServiceCollection()
            .AddDbContextFactory<AppDbContext>(o => o.UseSqlite(_connection))
            .BuildServiceProvider();
        using var db = _services.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContext();
        db.Database.EnsureCreated();
    }

    // A fresh store is what a restarted app process holds.
    private DbNotificationMarks Process() =>
        new(_services.GetRequiredService<IServiceScopeFactory>(), _clock, NullLogger<DbNotificationMarks>.Instance);

    [Fact]
    public void A_legacy_mark_converted_by_a_scan_that_stopped_mid_send_still_holds_after_a_restart()
    {
        var id = Guid.NewGuid();
        var due = _clock.UtcNow.AddHours(-2);
        Process().TryAdd(DeadlineIdentity.LegacyKey(id, SlaState.Breached, due));   // sent by v1.6.12

        using (NotificationMarkBatch.Begin())   // the scan stops before its sends finish
            new DeadlineReminderTracker(Process()).MarkNotified(id, ["NY", "NJ"], SlaState.Breached, due).Should().BeEmpty();

        var restarted = new DeadlineReminderTracker(Process());
        restarted.MarkNotified(id, ["NY", "NJ"], SlaState.Breached, due).Should().BeEmpty("they were reminded before the upgrade");
        restarted.MarkNotified(id, ["NY", "NJ", "CA"], SlaState.Breached, due).Should().Equal("CA");
        using var db = _services.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContext();
        db.NotificationMarks.AsNoTracking().Select(m => m.Key).ToList()
            .Should().NotContain(DeadlineIdentity.LegacyKey(id, SlaState.Breached, due), "it was converted");
    }

    public void Dispose()
    {
        _services.Dispose();
        _connection.Dispose();
    }
}
