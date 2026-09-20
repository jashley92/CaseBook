using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Notifications;
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
/// PROD-38: the stale-case scanner nudges open cases that have gone quiet past their severity's threshold,
/// addresses the IC + assignees, honours the per-severity thresholds (and 0 = disabled), re-arms when new
/// activity is recorded, and — via the notify-once tracker — does not re-nudge the same quiet spell. It must
/// not write to the audit chain or change case state.
/// </summary>
public sealed class StaleCaseScannerTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 9, 20, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();

    // Everything is quiet unless a threshold says otherwise; a generous default set for the common cases.
    private static readonly StaleThresholdDays Thresholds = new(Informational: 0, Low: 21, Medium: 10, High: 5, Critical: 2);

    public StaleCaseScannerTests()
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

    private StaleCaseScanner NewScanner(ICaseNotifications notifications, IStaleCaseTracker tracker) =>
        new(NewFactory(), notifications, tracker, _clock);

    private void Advance(TimeSpan by) => _clock.UtcNow = _clock.UtcNow.Add(by);

    private sealed class CapturingNotifications : ICaseNotifications
    {
        public List<StaleCaseReminder> Received { get; } = new();
        public int Calls { get; private set; }
        public Task OnReclassifiedAsync(Case c, Classification? from, Classification to, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnAssignedAsync(Case c, string a, string b, CaseAssignmentRole role, string by, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnActionItemsOverdueAsync(IReadOnlyList<OverdueActionItem> items, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnActionItemsDueSoonAsync(IReadOnlyList<DueSoonActionItem> items, int leadHours, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnCasesStaleAsync(IReadOnlyList<StaleCaseReminder> reminders, CancellationToken ct = default)
        {
            Calls++;
            Received.AddRange(reminders);
            return Task.CompletedTask;
        }
    }

    /// <summary>Opens a case (created "now"), with an IC and an analyst assignee.</summary>
    private Guid SeedCase(Severity severity)
    {
        using var db = NewContext();
        var c = Case.Open(2026, 1, "Case", "A case", Classification.Incident, severity,
            CaseOrigin.InternalDetection, "alice", _clock.UtcNow);
        c.Assign("ic1", "IC One", CaseAssignmentRole.IncidentCommander, "alice", _clock.UtcNow);
        c.Assign("analyst1", "Analyst One", CaseAssignmentRole.Analyst, "alice", _clock.UtcNow);
        db.Cases.Add(c);
        db.SaveChanges();
        return c.Id;
    }

    /// <summary>Records a note on the case through a tracked context, so the audit interceptor stamps a
    /// fresh audit entry (with the case number) at the current clock — i.e. genuine "activity".</summary>
    private async Task AddNoteAsync(Guid id)
    {
        await using var db = NewContext();
        var c = await db.Cases.Include(x => x.Notes).FirstAsync(x => x.Id == id);
        c.Notes.Add(new AnalystNote { CaseId = c.Id, Body = "Working it.", CreatedBy = "alice", CreatedAtUtc = _clock.UtcNow });
        await db.SaveChangesAsync();
    }

    [Fact]
    public async Task Nudges_a_quiet_case_past_its_threshold_addressing_ic_and_assignees()
    {
        SeedCase(Severity.High);            // 5-day threshold
        Advance(TimeSpan.FromDays(6));
        var notifications = new CapturingNotifications();

        var count = await NewScanner(notifications, new StaleCaseTracker()).ScanAndNotifyAsync(Thresholds);

        count.Should().Be(1);
        var reminder = notifications.Received.Should().ContainSingle().Subject;
        reminder.CaseNumber.Should().StartWith("2026-01");
        reminder.DaysInactive.Should().BeGreaterThanOrEqualTo(6);
        reminder.ThresholdDays.Should().Be(5);
        reminder.RecipientUserIds.Should().BeEquivalentTo(new[] { "ic1", "analyst1" });
    }

    [Fact]
    public async Task Does_not_nudge_a_case_still_within_its_threshold()
    {
        SeedCase(Severity.Low);             // 21-day threshold
        Advance(TimeSpan.FromDays(6));      // quiet, but well inside 21 days
        var notifications = new CapturingNotifications();

        (await NewScanner(notifications, new StaleCaseTracker()).ScanAndNotifyAsync(Thresholds)).Should().Be(0);
        notifications.Calls.Should().Be(0);
    }

    [Fact]
    public async Task A_severity_with_a_zero_threshold_is_never_nudged()
    {
        SeedCase(Severity.Informational);   // threshold 0 → disabled
        Advance(TimeSpan.FromDays(60));
        var notifications = new CapturingNotifications();

        (await NewScanner(notifications, new StaleCaseTracker()).ScanAndNotifyAsync(Thresholds)).Should().Be(0);
    }

    [Fact]
    public async Task New_activity_re_arms_the_nudge()
    {
        var id = SeedCase(Severity.High);
        Advance(TimeSpan.FromDays(6));
        var notifications = new CapturingNotifications();
        var tracker = new StaleCaseTracker();          // shared across passes, like the DI singleton
        var scanner = NewScanner(notifications, tracker);

        (await scanner.ScanAndNotifyAsync(Thresholds)).Should().Be(1);
        (await scanner.ScanAndNotifyAsync(Thresholds)).Should().Be(0);   // same quiet spell → no re-nudge

        await AddNoteAsync(id);            // audited activity at the current clock → last-activity advances
        Advance(TimeSpan.FromDays(6));     // goes quiet again

        (await scanner.ScanAndNotifyAsync(Thresholds)).Should().Be(1);   // fresh quiet spell → nudged again
        notifications.Calls.Should().Be(2);
    }

    [Fact]
    public async Task Closed_and_archived_cases_are_not_nudged()
    {
        var id = SeedCase(Severity.Critical);
        await using (var db = NewContext())
        {
            var c = await db.Cases.FirstAsync(x => x.Id == id);
            c.ChangePhase(CasePhase.Closed, "done", "alice", _clock.UtcNow);
            await db.SaveChangesAsync();
        }
        Advance(TimeSpan.FromDays(30));
        var notifications = new CapturingNotifications();

        (await NewScanner(notifications, new StaleCaseTracker()).ScanAndNotifyAsync(Thresholds)).Should().Be(0);
    }

    public void Dispose() => _connection.Dispose();
}
