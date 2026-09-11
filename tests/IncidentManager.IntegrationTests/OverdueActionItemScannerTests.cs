using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Notifications;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Security;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// E-03b: the overdue after-action scanner selects items past their due date (open/in-progress only),
/// notifies the newly-overdue ones, and — via the notify-once tracker — does not re-notify on a second pass.
/// Read-only: it must not write to the audit chain.
/// </summary>
public sealed class OverdueActionItemScannerTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 9, 10, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();

    public OverdueActionItemScannerTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        using var db = NewContext();
        db.Database.EnsureCreated();
    }

    private AppDbContext NewContext() =>
        new(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new IncidentManager.Infrastructure.Realtime.CaseChangeNotifier()))
            .Options);

    private IAppDbContextFactory NewFactory() =>
        new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new IncidentManager.Infrastructure.Realtime.CaseChangeNotifier()))
            .Options);

    private sealed class CapturingNotifications : ICaseNotifications
    {
        public List<OverdueActionItem> Received { get; } = new();
        public int Calls { get; private set; }
        public Task OnReclassifiedAsync(Case c, Classification? from, Classification to, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnAssignedAsync(Case c, string a, string b, CaseAssignmentRole role, string by, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnActionItemsOverdueAsync(IReadOnlyList<OverdueActionItem> items, CancellationToken ct = default)
        {
            Calls++;
            Received.AddRange(items);
            return Task.CompletedTask;
        }
    }

    private Guid SeedCaseWithItems()
    {
        using var db = NewContext();
        var c = Case.Open(2026, 1, "Case", "A case", Classification.Incident, Severity.High,
            CaseOrigin.InternalDetection, "ic1", _clock.UtcNow);
        var past = _clock.UtcNow.AddDays(-1);
        var future = _clock.UtcNow.AddDays(1);
        c.ActionItems.Add(new ActionItem { CaseId = c.Id, Title = "Overdue open", Owner = "analyst1", DueAtUtc = past, Status = ActionItemStatus.Open });
        c.ActionItems.Add(new ActionItem { CaseId = c.Id, Title = "Overdue done", Owner = "analyst1", DueAtUtc = past, Status = ActionItemStatus.Done });
        c.ActionItems.Add(new ActionItem { CaseId = c.Id, Title = "Not yet due", Owner = "analyst1", DueAtUtc = future, Status = ActionItemStatus.Open });
        c.ActionItems.Add(new ActionItem { CaseId = c.Id, Title = "No due date", Owner = "analyst1", DueAtUtc = null, Status = ActionItemStatus.Open });
        db.Cases.Add(c);
        db.SaveChanges();
        return c.Id;
    }

    private OverdueActionItemScanner NewScanner(ICaseNotifications notifications, IOverdueActionItemTracker tracker) =>
        new(NewFactory(), notifications, tracker, _clock);

    [Fact]
    public async Task Notifies_only_open_overdue_items()
    {
        SeedCaseWithItems();
        var notifications = new CapturingNotifications();

        var count = await NewScanner(notifications, new OverdueActionItemTracker()).ScanAndNotifyAsync();

        count.Should().Be(1);
        notifications.Received.Should().ContainSingle()
            .Which.Title.Should().Be("Overdue open");
        notifications.Received[0].CaseNumber.Should().StartWith("2026-01");
        notifications.Received[0].OwnerUserId.Should().Be("analyst1");
    }

    [Fact]
    public async Task A_second_pass_does_not_re_notify()
    {
        SeedCaseWithItems();
        var notifications = new CapturingNotifications();
        var tracker = new OverdueActionItemTracker();     // shared across passes, like the singleton in DI
        var scanner = NewScanner(notifications, tracker);

        (await scanner.ScanAndNotifyAsync()).Should().Be(1);
        (await scanner.ScanAndNotifyAsync()).Should().Be(0);   // already reminded

        notifications.Calls.Should().Be(1);                    // only the first pass dispatched
    }

    public void Dispose() => _connection.Dispose();
}
