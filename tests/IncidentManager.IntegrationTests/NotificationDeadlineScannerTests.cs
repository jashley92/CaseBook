using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
using IncidentManager.Application.Compliance;
using IncidentManager.Application.Notifications;
using IncidentManager.Application.Sla;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// PROD-37: the regulatory notification-deadline scanner selects open, un-reported ladder cases whose
/// deadline is at-risk or breached, reminds each case's incident commander + assignees, and — via the
/// per-band notify-once tracker — does not re-notify on a second pass. Read-only and feature-gated; it must
/// not write to the audit chain or change case state.
/// </summary>
public sealed class NotificationDeadlineScannerTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 9, 20, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();
    private readonly StubSettings _settings = new();

    public NotificationDeadlineScannerTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        using var db = NewContext();
    }

    private AppDbContext NewContext()
    {
        var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options);
        db.Database.EnsureCreated();
        return db;
    }

    private IAppDbContextFactory NewFactory() =>
        new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options);

    private NotificationDeadlineService NewDeadlines() =>
        new(NewFactory(), _settings, new NotificationRuleService(NewFactory(), _user, _clock), _clock);

    private NotificationDeadlineScanner NewScanner(ICaseNotifications notifications, IDeadlineReminderTracker tracker) =>
        new(NewFactory(), NewDeadlines(), _settings, notifications, tracker);

    private sealed class CapturingNotifications : ICaseNotifications
    {
        public List<DeadlineReminder> Received { get; } = new();
        public int Calls { get; private set; }
        public Task OnReclassifiedAsync(Case c, Classification? from, Classification to, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnAssignedAsync(Case c, string a, string b, CaseAssignmentRole role, string by, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnActionItemsOverdueAsync(IReadOnlyList<OverdueActionItem> items, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnActionItemsDueSoonAsync(IReadOnlyList<DueSoonActionItem> items, int leadHours, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnDeadlineApproachingAsync(IReadOnlyList<DeadlineReminder> reminders, CancellationToken ct = default)
        {
            Calls++;
            Received.AddRange(reminders);
            return Task.CompletedTask;
        }
    }

    /// <summary>A material Breach whose SSN element triggers "NY" (72h rule), with the determination decided
    /// far enough in the past that the clock is already <paramref name="hoursAgo"/> into its window, plus an
    /// IC and an analyst assignee. Under the Determination basis the clock starts at the decision instant.</summary>
    private async Task<Guid> SeedMaterialBreachAsync(int hoursAgo)
    {
        await using var db = NewContext();
        db.DataElements.Add(new DataElement
        {
            Key = "SSN", Label = "Social Security number", NotificationJurisdictions = "NY",
            IsActive = true, IsSystem = false, CreatedBy = "system", CreatedAtUtc = _clock.UtcNow
        });
        var c = Case.Open(2026, 1, "Breach", "Breach case", Classification.Breach, Severity.High,
            CaseOrigin.InternalDetection, "alice", _clock.UtcNow);
        c.SetImpactAssessment(500, new[] { "SSN" }, "NY", "alice", _clock.UtcNow);
        c.RecordMateriality(MaterialityStatus.Material, "Disclosure Committee", _clock.UtcNow.AddHours(-hoursAgo),
            "Reasonable likelihood of harm.", "alice", _clock.UtcNow);
        c.Assign("ic1", "IC One", CaseAssignmentRole.IncidentCommander, "alice", _clock.UtcNow);
        c.Assign("analyst1", "Analyst One", CaseAssignmentRole.Analyst, "alice", _clock.UtcNow);
        db.Cases.Add(c);
        await db.SaveChangesAsync();
        return c.Id;
    }

    private async Task SaveNyRuleAsync() =>
        await new NotificationRuleService(NewFactory(), _user, _clock)
            .SaveAsync(null, "NY", "New York (NYDFS Part 500)", 72);

    private void EnableClock() =>
        _settings.Current = new NotificationDeadlineSettings(true, NotificationStartBasis.Determination, 72, 80);

    [Fact]
    public async Task Reminds_a_breached_case_addressing_the_ic_and_assignees()
    {
        await SeedMaterialBreachAsync(hoursAgo: 80);   // past the 72h window → Breached
        await SaveNyRuleAsync();
        EnableClock();
        var notifications = new CapturingNotifications();

        var count = await NewScanner(notifications, new DeadlineReminderTracker()).ScanAndNotifyAsync();

        count.Should().Be(1);
        var reminder = notifications.Received.Should().ContainSingle().Subject;
        reminder.State.Should().Be(SlaState.Breached);
        reminder.CaseNumber.Should().StartWith("2026-01");
        reminder.JurisdictionLabel.Should().Contain("New York");
        reminder.RecipientUserIds.Should().BeEquivalentTo(new[] { "ic1", "analyst1" });
    }

    [Fact]
    public async Task Reminds_an_at_risk_case()
    {
        await SeedMaterialBreachAsync(hoursAgo: 60);   // 60h of 72h, past the 80% (57.6h) mark → AtRisk
        await SaveNyRuleAsync();
        EnableClock();
        var notifications = new CapturingNotifications();

        (await NewScanner(notifications, new DeadlineReminderTracker()).ScanAndNotifyAsync()).Should().Be(1);
        notifications.Received.Single().State.Should().Be(SlaState.AtRisk);
    }

    [Fact]
    public async Task Does_not_remind_an_on_track_case()
    {
        await SeedMaterialBreachAsync(hoursAgo: 1);     // just decided → well inside the window
        await SaveNyRuleAsync();
        EnableClock();
        var notifications = new CapturingNotifications();

        (await NewScanner(notifications, new DeadlineReminderTracker()).ScanAndNotifyAsync()).Should().Be(0);
        notifications.Calls.Should().Be(0);
    }

    [Fact]
    public async Task Does_nothing_when_the_feature_is_off()
    {
        await SeedMaterialBreachAsync(hoursAgo: 80);
        await SaveNyRuleAsync();
        _settings.Current = NotificationDeadlineSettings.Off;
        var notifications = new CapturingNotifications();

        (await NewScanner(notifications, new DeadlineReminderTracker()).ScanAndNotifyAsync()).Should().Be(0);
        notifications.Calls.Should().Be(0);
    }

    [Fact]
    public async Task A_second_pass_in_the_same_band_does_not_re_notify()
    {
        await SeedMaterialBreachAsync(hoursAgo: 80);
        await SaveNyRuleAsync();
        EnableClock();
        var notifications = new CapturingNotifications();
        var tracker = new DeadlineReminderTracker();          // shared across passes, like the DI singleton
        var scanner = NewScanner(notifications, tracker);

        (await scanner.ScanAndNotifyAsync()).Should().Be(1);
        (await scanner.ScanAndNotifyAsync()).Should().Be(0);  // already reminded for the Breached band
        notifications.Calls.Should().Be(1);
    }

    [Fact]
    public async Task A_reported_case_is_not_reminded()
    {
        var id = await SeedMaterialBreachAsync(hoursAgo: 80);
        await SaveNyRuleAsync();
        EnableClock();
        await using (var db = NewContext())
        {
            var c = await db.Cases.FirstAsync(x => x.Id == id);
            c.MarkReported(_clock.UtcNow, "alice", _clock.UtcNow);
            await db.SaveChangesAsync();
        }
        var notifications = new CapturingNotifications();

        (await NewScanner(notifications, new DeadlineReminderTracker()).ScanAndNotifyAsync()).Should().Be(0);
    }

    private sealed class StubSettings : INotificationDeadlineSettingsProvider
    {
        public NotificationDeadlineSettings Current { get; set; } = NotificationDeadlineSettings.Off;
    }

    public void Dispose() => _connection.Dispose();
}
