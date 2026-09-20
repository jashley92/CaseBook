using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Notifications;
using IncidentManager.Application.Work;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// PROD-39: the digest scanner sends each opted-in user one consolidated email of their open dated items
/// (overdue / today / this week), once per period; users who haven't opted in, or have no items, get nothing.
/// Also covers the per-user preference store (opt-in cadence + subscriber list). Read-only; no case state.
/// </summary>
public sealed class DigestScannerTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 9, 10, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();   // analyst1

    public DigestScannerTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        using var db = NewContext();
        db.Database.EnsureCreated();
    }

    private AppDbContext NewContext() =>
        new(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options);

    private IAppDbContextFactory NewFactory() =>
        new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options);

    private sealed class FakeDirectory : IUserDirectory
    {
        private readonly Dictionary<string, UserSummary> _u = new(StringComparer.OrdinalIgnoreCase)
        {
            ["analyst1"] = new("analyst1", "Analyst One", "analyst1@contoso.example", "analyst1@contoso.example", ""),
            ["bob"] = new("bob", "Bob Builder", "bob@contoso.example", "bob@contoso.example", ""),
        };
        public Task TouchAsync(string id, string n, string? u, string? e, string r, CancellationToken ct = default) => Task.CompletedTask;
        public IReadOnlyList<UserSummary> All() => _u.Values.ToList();
        public UserSummary? Resolve(string id) => _u.GetValueOrDefault(id);
        public string DisplayFor(string? id) => id is not null && _u.TryGetValue(id, out var s) ? s.DisplayName : (id ?? "—");
        public string? EmailFor(string id) => _u.GetValueOrDefault(id)?.Email;
        public void Invalidate() { }
    }

    private sealed class CapturingNotifications : ICaseNotifications
    {
        public List<UserDigest> Digests { get; } = new();
        public Task OnReclassifiedAsync(Case c, Classification? from, Classification to, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnAssignedAsync(Case c, string a, string b, CaseAssignmentRole role, string by, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnActionItemsOverdueAsync(IReadOnlyList<OverdueActionItem> items, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnActionItemsDueSoonAsync(IReadOnlyList<DueSoonActionItem> items, int leadHours, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnDigestAsync(UserDigest digest, CancellationToken ct = default) { Digests.Add(digest); return Task.CompletedTask; }
    }

    private UserNotificationPreferenceService NewPrefs() => new(NewFactory(), _user, _clock);
    private AgendaService NewAgenda() => new(NewFactory(), _user, new FakeDirectory(), _clock);
    private DigestScanner NewScanner(ICaseNotifications n, IDigestTracker t) =>
        new(NewPrefs(), NewAgenda(), n, t, _clock);

    /// <summary>A visible case with one item per band owned by analyst1, plus noise (later/undated/done).</summary>
    private void SeedItemsForAnalyst1()
    {
        using var db = NewContext();
        var now = _clock.UtcNow;
        var a = Case.Open(2026, 1, "Case A", "Visible case", Classification.Incident, Severity.High,
            CaseOrigin.InternalDetection, "ic1", now);
        a.ActionItems.Add(new ActionItem { CaseId = a.Id, Title = "Overdue", Owner = "analyst1", DueAtUtc = now.AddDays(-1), Status = ActionItemStatus.Open });
        a.ActionItems.Add(new ActionItem { CaseId = a.Id, Title = "Today", Owner = "analyst1", DueAtUtc = now.AddHours(2), Status = ActionItemStatus.Open });
        a.ActionItems.Add(new ActionItem { CaseId = a.Id, Title = "ThisWeek", Owner = "analyst1", DueAtUtc = now.AddDays(3), Status = ActionItemStatus.Open });
        a.ActionItems.Add(new ActionItem { CaseId = a.Id, Title = "Later", Owner = "analyst1", DueAtUtc = now.AddDays(30), Status = ActionItemStatus.Open });
        a.ActionItems.Add(new ActionItem { CaseId = a.Id, Title = "Undated", Owner = "analyst1", DueAtUtc = null, Status = ActionItemStatus.Open });
        a.ActionItems.Add(new ActionItem { CaseId = a.Id, Title = "Done", Owner = "analyst1", DueAtUtc = now.AddDays(-1), Status = ActionItemStatus.Done });
        db.Cases.Add(a);
        db.SaveChanges();
    }

    private async Task OptInAsync(string userId, DigestCadence cadence)
    {
        var prev = _user.UserId;
        _user.UserId = userId;
        await NewPrefs().SetMyDigestCadenceAsync(cadence);
        _user.UserId = prev;
    }

    [Fact]
    public async Task Sends_a_digest_to_an_opted_in_user_grouped_by_band()
    {
        SeedItemsForAnalyst1();
        await OptInAsync("analyst1", DigestCadence.Daily);
        var n = new CapturingNotifications();

        var sent = await NewScanner(n, new DigestTracker()).ScanAndNotifyAsync();

        sent.Should().Be(1);
        var d = n.Digests.Should().ContainSingle().Subject;
        d.UserId.Should().Be("analyst1");
        d.Overdue.Should().ContainSingle().Which.TaskTitle.Should().Be("Overdue");
        d.DueToday.Should().ContainSingle().Which.TaskTitle.Should().Be("Today");
        d.DueThisWeek.Should().ContainSingle().Which.TaskTitle.Should().Be("ThisWeek");
        d.TotalItems.Should().Be(3); // later / undated / done excluded
    }

    [Fact]
    public async Task Sends_nothing_when_no_one_has_opted_in()
    {
        SeedItemsForAnalyst1();
        var n = new CapturingNotifications();

        (await NewScanner(n, new DigestTracker()).ScanAndNotifyAsync()).Should().Be(0);
        n.Digests.Should().BeEmpty();
    }

    [Fact]
    public async Task An_opted_in_user_with_no_items_is_skipped()
    {
        SeedItemsForAnalyst1();
        await OptInAsync("analyst1", DigestCadence.Daily); // has items
        await OptInAsync("bob", DigestCadence.Weekly);     // no items

        var n = new CapturingNotifications();
        (await NewScanner(n, new DigestTracker()).ScanAndNotifyAsync()).Should().Be(1);
        n.Digests.Should().ContainSingle().Which.UserId.Should().Be("analyst1");
    }

    [Fact]
    public async Task A_second_pass_in_the_same_period_does_not_re_send()
    {
        SeedItemsForAnalyst1();
        await OptInAsync("analyst1", DigestCadence.Daily);
        var n = new CapturingNotifications();
        var tracker = new DigestTracker();               // shared across passes, like the DI singleton
        var scanner = NewScanner(n, tracker);

        (await scanner.ScanAndNotifyAsync()).Should().Be(1);
        (await scanner.ScanAndNotifyAsync()).Should().Be(0);   // same day → already sent
        n.Digests.Should().HaveCount(1);
    }

    [Fact]
    public async Task The_preference_store_round_trips_and_lists_only_subscribers()
    {
        (await NewPrefs().GetMyDigestCadenceAsync()).Should().Be(DigestCadence.Off);  // default

        await OptInAsync("analyst1", DigestCadence.Weekly);
        (await NewPrefs().GetMyDigestCadenceAsync()).Should().Be(DigestCadence.Weekly);

        await OptInAsync("bob", DigestCadence.Off);   // explicitly off
        var subs = await NewPrefs().ListSubscribersAsync();
        subs.Should().ContainSingle().Which.UserId.Should().Be("analyst1");
    }

    [Fact]
    public async Task Full_preferences_round_trip()
    {
        (await NewPrefs().GetMineAsync()).Should().Be(new NotificationPrefsView(DigestCadence.Off, false, false, false));

        await NewPrefs().SetMineAsync(new NotificationPrefsView(DigestCadence.Weekly, SuppressAssignment: true, SuppressOverdue: false, SuppressDueSoon: true));

        (await NewPrefs().GetMineAsync()).Should().Be(
            new NotificationPrefsView(DigestCadence.Weekly, true, false, true));
    }

    // --- PROD-16: the singleton provider the notifier reads (incl. the digest → per-item overlay) ---

    private sealed class ScopeFactory(Func<AppDbContext> make) : IServiceScopeFactory, IServiceScope, IServiceProvider
    {
        public IServiceScope CreateScope() => this;
        public IServiceProvider ServiceProvider => this;
        public void Dispose() { }
        public object? GetService(Type t) => t == typeof(AppDbContext) ? make() : null;
    }

    private IncidentManager.Infrastructure.Notifications.NotificationPreferenceProvider NewProvider() =>
        new(new ScopeFactory(NewContext));

    [Fact]
    public async Task Provider_returns_nothing_suppressed_when_there_is_no_preference_row()
    {
        (await NewProvider().GetAsync("nobody")).Should().Be(NotificationSuppression.None);
    }

    [Fact]
    public async Task Provider_reflects_explicit_opt_outs()
    {
        await NewPrefs().SetMineAsync(new NotificationPrefsView(DigestCadence.Off, SuppressAssignment: true, SuppressOverdue: false, SuppressDueSoon: true));

        var s = await NewProvider().GetAsync("analyst1");
        s.Assignment.Should().BeTrue();
        s.Overdue.Should().BeFalse();
        s.DueSoon.Should().BeTrue();
    }

    [Fact]
    public async Task Provider_folds_in_the_digest_overlay_suppressing_per_item_overdue_and_due_soon()
    {
        // On a digest, but no explicit per-item opt-outs → overdue/due-soon are still suppressed (the digest covers them).
        await NewPrefs().SetMineAsync(new NotificationPrefsView(DigestCadence.Daily, SuppressAssignment: false, SuppressOverdue: false, SuppressDueSoon: false));

        var s = await NewProvider().GetAsync("analyst1");
        s.Overdue.Should().BeTrue();
        s.DueSoon.Should().BeTrue();
        s.Assignment.Should().BeFalse();   // assignment isn't a digest item, so it's unaffected
    }

    public void Dispose() => _connection.Dispose();
}
