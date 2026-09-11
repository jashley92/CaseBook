using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Notifications;
using Xunit;

namespace IncidentManager.UnitTests;

public class CaseNotificationsTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 8, 12, 0, 0, TimeSpan.Zero);

    private static Case NewCase() => Case.Open(
        2026, 1, "Vendor Breach", "Vendor data breach",
        Classification.Incident, Severity.High, CaseOrigin.InternalDetection, "ic1", Now);

    /// <summary>A minimal in-memory user directory: id → (display, email).</summary>
    private sealed class FakeUserDirectory : IUserDirectory
    {
        private readonly Dictionary<string, (string Name, string? Email)> _users = new(StringComparer.OrdinalIgnoreCase);
        public FakeUserDirectory Add(string id, string name, string? email) { _users[id] = (name, email); return this; }

        public string? EmailFor(string userId) => _users.TryGetValue(userId, out var u) ? u.Email : null;
        public string DisplayFor(string? userId) =>
            userId is not null && _users.TryGetValue(userId, out var u) ? u.Name : (userId ?? "—");
        public UserSummary? Resolve(string userId) =>
            _users.TryGetValue(userId, out var u) ? new UserSummary(userId, u.Name, null, u.Email, "") : null;
        public IReadOnlyList<UserSummary> All() => [];
        public Task TouchAsync(string userId, string displayName, string? upn, string? email, string rolesCsv, CancellationToken ct = default) => Task.CompletedTask;
        public void Invalidate() { }
    }

    private static CaseNotifications Build(CapturingEmailSender sender, EmailOptions options, IUserDirectory? users = null) =>
        new(sender, TestEmail.Composer(), users ?? new FakeUserDirectory(), TestEmail.EmptyConfig,
            new TestOptionsMonitor<EmailOptions>(options));

    // --- Breach escalation (E-03) ----------------------------------------------

    [Fact]
    public async Task Escalating_to_breach_emails_the_legal_distribution()
    {
        var sender = new CapturingEmailSender();
        var notifications = Build(sender, new EmailOptions { LegalDistribution = ["legal@insurer.example"] });

        await notifications.OnReclassifiedAsync(NewCase(), Classification.Incident, Classification.Breach);

        sender.Sent.Should().ContainSingle();
        sender.Sent[0].To.Should().Contain("legal@insurer.example");
        sender.Sent[0].Subject.Should().Contain("Breach");
    }

    [Fact]
    public async Task A_non_breach_reclassification_sends_nothing()
    {
        var sender = new CapturingEmailSender();
        var notifications = Build(sender, new EmailOptions { LegalDistribution = ["legal@insurer.example"] });

        await notifications.OnReclassifiedAsync(NewCase(), Classification.AdverseEvent, Classification.Incident);

        sender.Sent.Should().BeEmpty();
    }

    [Fact]
    public async Task No_email_when_the_distribution_is_empty()
    {
        var sender = new CapturingEmailSender();
        var notifications = Build(sender, new EmailOptions()); // no recipients configured

        await notifications.OnReclassifiedAsync(NewCase(), Classification.Incident, Classification.Breach);

        sender.Sent.Should().BeEmpty();
    }

    [Fact]
    public async Task An_administered_distribution_change_takes_effect_at_runtime()
    {
        var sender = new CapturingEmailSender();
        var monitor = new TestOptionsMonitor<EmailOptions>(
            new EmailOptions { LegalDistribution = ["old@insurer.example"] });
        var notifications = new CaseNotifications(sender, TestEmail.Composer(), new FakeUserDirectory(), TestEmail.EmptyConfig, monitor);

        // Admin edits the Legal distribution after the service is already constructed.
        monitor.CurrentValue = new EmailOptions { LegalDistribution = ["new@insurer.example"] };

        await notifications.OnReclassifiedAsync(NewCase(), Classification.Incident, Classification.Breach);

        sender.Sent.Should().ContainSingle();
        sender.Sent[0].To.Should().Contain("new@insurer.example").And.NotContain("old@insurer.example");
    }

    // --- Assignment (E-03b) ----------------------------------------------------

    [Fact]
    public async Task Assignment_emails_the_assignee_when_enabled()
    {
        var sender = new CapturingEmailSender();
        var users = new FakeUserDirectory().Add("analyst1", "Alice Analyst", "alice@insurer.example").Add("ic1", "Ivan IC", "ivan@insurer.example");
        var notifications = Build(sender, new EmailOptions { AssignmentNotifications = true }, users);

        await notifications.OnAssignedAsync(NewCase(), "analyst1", "Alice Analyst", CaseAssignmentRole.Analyst, "ic1");

        sender.Sent.Should().ContainSingle();
        sender.Sent[0].To.Should().ContainSingle().Which.Should().Be("alice@insurer.example");
        sender.Sent[0].Subject.Should().Contain("2026-01");
    }

    [Fact]
    public async Task Assignment_sends_nothing_when_the_toggle_is_off()
    {
        var sender = new CapturingEmailSender();
        var users = new FakeUserDirectory().Add("analyst1", "Alice", "alice@insurer.example");
        var notifications = Build(sender, new EmailOptions { AssignmentNotifications = false }, users);

        await notifications.OnAssignedAsync(NewCase(), "analyst1", "Alice", CaseAssignmentRole.Analyst, "ic1");

        sender.Sent.Should().BeEmpty();
    }

    [Fact]
    public async Task Assignment_skips_a_self_assignment()
    {
        var sender = new CapturingEmailSender();
        var users = new FakeUserDirectory().Add("analyst1", "Alice", "alice@insurer.example");
        var notifications = Build(sender, new EmailOptions { AssignmentNotifications = true }, users);

        await notifications.OnAssignedAsync(NewCase(), "analyst1", "Alice", CaseAssignmentRole.Analyst, "analyst1");

        sender.Sent.Should().BeEmpty();
    }

    [Fact]
    public async Task Assignment_sends_nothing_when_the_assignee_has_no_email()
    {
        var sender = new CapturingEmailSender();
        var users = new FakeUserDirectory().Add("analyst1", "Alice", null); // no address on file
        var notifications = Build(sender, new EmailOptions { AssignmentNotifications = true }, users);

        await notifications.OnAssignedAsync(NewCase(), "analyst1", "Alice", CaseAssignmentRole.Analyst, "ic1");

        sender.Sent.Should().BeEmpty();
    }

    // --- Overdue after-action (E-03b) ------------------------------------------

    private static OverdueActionItem Overdue(string caseNo, string? owner, string? ic, string title = "Patch the box") =>
        new(Guid.NewGuid(), caseNo, "A case", ic, Guid.NewGuid(), title, Now, owner);

    [Fact]
    public async Task Overdue_groups_items_by_recipient_and_sends_one_email_each()
    {
        var sender = new CapturingEmailSender();
        var users = new FakeUserDirectory()
            .Add("alice", "Alice", "alice@insurer.example")
            .Add("bob", "Bob", "bob@insurer.example");
        var notifications = Build(sender, new EmailOptions(), users);

        await notifications.OnActionItemsOverdueAsync(
        [
            Overdue("2026-01", "alice", "ic1", "Task A"),
            Overdue("2026-02", "alice", "ic1", "Task B"),
            Overdue("2026-03", "bob", "ic1", "Task C"),
        ]);

        sender.Sent.Should().HaveCount(2);                       // one per distinct recipient
        var alice = sender.Sent.Single(s => s.To.Contains("alice@insurer.example"));
        alice.HtmlBody.Should().Contain("Task A").And.Contain("Task B");
        sender.Sent.Should().ContainSingle(s => s.To.Contains("bob@insurer.example"));
    }

    [Fact]
    public async Task Overdue_falls_back_to_the_incident_commander_when_the_owner_is_unreachable()
    {
        var sender = new CapturingEmailSender();
        var users = new FakeUserDirectory().Add("ic1", "Ivan IC", "ivan@insurer.example"); // owner "ghost" unknown
        var notifications = Build(sender, new EmailOptions(), users);

        await notifications.OnActionItemsOverdueAsync([Overdue("2026-01", "ghost", "ic1")]);

        sender.Sent.Should().ContainSingle();
        sender.Sent[0].To.Should().ContainSingle().Which.Should().Be("ivan@insurer.example");
    }

    [Fact]
    public async Task Overdue_skips_an_item_with_no_reachable_recipient()
    {
        var sender = new CapturingEmailSender();
        var notifications = Build(sender, new EmailOptions(), new FakeUserDirectory()); // nobody resolves

        await notifications.OnActionItemsOverdueAsync([Overdue("2026-01", "ghost", "ic-gone")]);

        sender.Sent.Should().BeEmpty();
    }

    // --- Due soon (E-03d) ------------------------------------------------------

    private static DueSoonActionItem DueSoon(string caseNo, string? owner, string? ic, string title = "Patch the box") =>
        new(Guid.NewGuid(), caseNo, "A case", ic, Guid.NewGuid(), title, Now.AddHours(6), owner);

    [Fact]
    public async Task Due_soon_groups_items_by_recipient_and_sends_one_email_each()
    {
        var sender = new CapturingEmailSender();
        var users = new FakeUserDirectory()
            .Add("alice", "Alice", "alice@insurer.example")
            .Add("bob", "Bob", "bob@insurer.example");
        var notifications = Build(sender, new EmailOptions(), users);

        await notifications.OnActionItemsDueSoonAsync(
        [
            DueSoon("2026-01", "alice", "ic1", "Task A"),
            DueSoon("2026-02", "alice", "ic1", "Task B"),
            DueSoon("2026-03", "bob", "ic1", "Task C"),
        ], leadHours: 24);

        sender.Sent.Should().HaveCount(2);                       // one per distinct recipient
        var alice = sender.Sent.Single(s => s.To.Contains("alice@insurer.example"));
        alice.HtmlBody.Should().Contain("Task A").And.Contain("Task B").And.Contain("24");
        sender.Sent.Should().ContainSingle(s => s.To.Contains("bob@insurer.example"));
    }

    [Fact]
    public async Task Due_soon_falls_back_to_the_incident_commander_when_the_owner_is_unreachable()
    {
        var sender = new CapturingEmailSender();
        var users = new FakeUserDirectory().Add("ic1", "Ivan IC", "ivan@insurer.example"); // owner "ghost" unknown
        var notifications = Build(sender, new EmailOptions(), users);

        await notifications.OnActionItemsDueSoonAsync([DueSoon("2026-01", "ghost", "ic1")], leadHours: 24);

        sender.Sent.Should().ContainSingle();
        sender.Sent[0].To.Should().ContainSingle().Which.Should().Be("ivan@insurer.example");
    }

    [Fact]
    public async Task Due_soon_skips_an_item_with_no_reachable_recipient()
    {
        var sender = new CapturingEmailSender();
        var notifications = Build(sender, new EmailOptions(), new FakeUserDirectory()); // nobody resolves

        await notifications.OnActionItemsDueSoonAsync([DueSoon("2026-01", "ghost", "ic-gone")], leadHours: 24);

        sender.Sent.Should().BeEmpty();
    }
}
