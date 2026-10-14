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
        public List<EscalatedActionItem> Escalated { get; } = new();
        public Task OnActionItemsEscalatedAsync(IReadOnlyList<EscalatedActionItem> items, CancellationToken ct = default)
        {
            Escalated.AddRange(items);
            return Task.CompletedTask;
        }
        public int Calls { get; private set; }
        public Task OnReclassifiedAsync(Case c, Classification? from, Classification to, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnAssignedAsync(Case c, string a, string b, CaseAssignmentRole role, string by, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnActionItemsOverdueAsync(IReadOnlyList<OverdueActionItem> items, CancellationToken ct = default)
        {
            Calls++;
            Received.AddRange(items);
            return Task.CompletedTask;
        }
        public Task OnActionItemsDueSoonAsync(IReadOnlyList<DueSoonActionItem> items, int leadHours, CancellationToken ct = default) => Task.CompletedTask;
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

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task A_closed_or_archived_case_gets_no_reminders(bool closed, bool archived /* BUG-12 */)
    {
        var id = SeedCaseWithItems();
        using (var db = NewContext())
        {
            if (closed) await db.Cases.Where(c => c.Id == id).ExecuteUpdateAsync(u => u.SetProperty(c => c.Phase, CasePhase.Closed));
            if (archived) await db.Cases.Where(c => c.Id == id).ExecuteUpdateAsync(u => u.SetProperty(c => c.IsArchived, true));
        }
        var notifications = new CapturingNotifications();

        (await NewScanner(notifications, new OverdueActionItemTracker()).ScanAndNotifyAsync()).Should().Be(0);
        notifications.Received.Should().BeEmpty();
    }

    [Fact]
    public async Task On_a_restricted_case_an_owner_off_the_team_is_not_told_the_IC_is(/* BUG-96 */)
    {
        var id = SeedCaseWithItems();   // "Overdue open" is owned by analyst1, who isn't on the team
        using (var db = NewContext())
            await db.Cases.Where(c => c.Id == id).ExecuteUpdateAsync(u => u.SetProperty(c => c.IsRestricted, true));
        var notifications = new CapturingNotifications();

        await NewScanner(notifications, new OverdueActionItemTracker()).ScanAndNotifyAsync();

        var item = notifications.Received.Should().ContainSingle().Subject;
        item.OwnerUserId.Should().BeNull("the reminder names a restricted case they can't open, so it goes to the IC");
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

    [Fact]
    public async Task Items_that_stay_overdue_escalate_once_per_tier(/* PROD-03 */)
    {
        SeedCaseWithItems();                               // "Overdue open" is 24h past due
        var notifications = new CapturingNotifications();
        var scanner = NewScanner(notifications, new OverdueActionItemTracker());
        var policy = new OverdueEscalationPolicy(IncidentCommanderAfterHours: 12, ManagersAfterHours: 48);

        (await scanner.ScanAndNotifyAsync(policy)).Should().Be(2);   // first reminder + IC tier
        notifications.Escalated.Should().ContainSingle()
            .Which.Tier.Should().Be(OverdueEscalationTier.IncidentCommander);

        (await scanner.ScanAndNotifyAsync(policy)).Should().Be(0, "each tier is sent once");

        _clock.UtcNow = _clock.UtcNow.AddDays(2);          // now 72h overdue (and "Not yet due" has lapsed too)
        await scanner.ScanAndNotifyAsync(policy);
        var first = notifications.Escalated.Where(e => e.Item.Title == "Overdue open").ToList();
        first.Select(e => e.Tier).Should().Equal(OverdueEscalationTier.IncidentCommander, OverdueEscalationTier.Managers);
        first[1].HoursOverdue.Should().Be(72);
    }

    [Fact]
    public async Task Without_a_policy_or_with_tiers_off_nothing_escalates(/* PROD-03 */)
    {
        SeedCaseWithItems();
        var notifications = new CapturingNotifications();

        await NewScanner(notifications, new OverdueActionItemTracker()).ScanAndNotifyAsync();
        await NewScanner(notifications, new OverdueActionItemTracker()).ScanAndNotifyAsync(new OverdueEscalationPolicy(0, 0));

        notifications.Escalated.Should().BeEmpty();
    }

    [Fact]
    public async Task An_owner_or_IC_who_no_longer_holds_ViewCases_is_not_reminded(/* BUG-377 */)
    {
        var id = SeedCaseWithItems();   // owner analyst1
        using (var db = NewContext())
            await db.Cases.Where(c => c.Id == id).ExecuteUpdateAsync(u => u.SetProperty(c => c.IncidentCommander, "ic1"));
        var notifications = new CapturingNotifications();
        var users = new EntitlementUsers(("analyst1", "Reports"), ("ic1", "Analyst"));

        await new OverdueActionItemScanner(NewFactory(), notifications, new OverdueActionItemTracker(), _clock, users, new EntitlementRoles())
            .ScanAndNotifyAsync();

        var item = notifications.Received.Should().ContainSingle().Subject;
        item.OwnerUserId.Should().BeNull("moved to a role without ViewCases, so the reminder falls to the IC");
        item.IncidentCommanderUserId.Should().Be("ic1");

        var leaverIc = new CapturingNotifications();
        await new OverdueActionItemScanner(NewFactory(), leaverIc, new OverdueActionItemTracker(), _clock,
                new EntitlementUsers(("analyst1", "Analyst"), ("ic1", "")), new EntitlementRoles())
            .ScanAndNotifyAsync();
        var kept = leaverIc.Received.Should().ContainSingle().Subject;
        kept.OwnerUserId.Should().Be("analyst1");
        kept.IncidentCommanderUserId.Should().BeNull("an IC who holds no role isn't a fallback any more");
    }

    public void Dispose() => _connection.Dispose();
}
