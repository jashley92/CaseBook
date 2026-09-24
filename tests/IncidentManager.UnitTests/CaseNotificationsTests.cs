using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Notifications;
using Microsoft.Extensions.Configuration;
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
        private readonly Dictionary<string, string> _roles = new(StringComparer.OrdinalIgnoreCase);
        public FakeUserDirectory Add(string id, string name, string? email, string roles = "")
        {
            _users[id] = (name, email);
            _roles[id] = roles;
            return this;
        }

        public string? EmailFor(string userId) => _users.TryGetValue(userId, out var u) ? u.Email : null;
        public string DisplayFor(string? userId) =>
            userId is not null && _users.TryGetValue(userId, out var u) ? u.Name : (userId ?? "—");
        public UserSummary? Resolve(string userId) =>
            _users.TryGetValue(userId, out var u) ? new UserSummary(userId, u.Name, null, u.Email, "") : null;
        public IReadOnlyList<UserSummary> All() =>
            _users.Select(kv => new UserSummary(kv.Key, kv.Value.Name, null, kv.Value.Email, _roles[kv.Key])).ToList();
        public Task TouchAsync(string userId, string displayName, string? upn, string? email, string rolesCsv, CancellationToken ct = default) => Task.CompletedTask;
        public void Invalidate() { }
    }

    private static CaseNotifications Build(CapturingEmailSender sender, EmailOptions options,
        IUserDirectory? users = null, IChatNotifier? chat = null, IConfiguration? config = null,
        INotificationPreferenceProvider? prefs = null) =>
        new(sender, TestEmail.Composer(), users ?? new FakeUserDirectory(), config ?? TestEmail.EmptyConfig,
            new TestOptionsMonitor<EmailOptions>(options), chat ?? new NullChatNotifier(), prefs ?? new FakePrefs());

    /// <summary>A configurable per-user opt-out provider (PROD-16); default is "nothing suppressed".</summary>
    private sealed class FakePrefs : INotificationPreferenceProvider
    {
        private readonly Dictionary<string, NotificationSuppression> _s = new(StringComparer.OrdinalIgnoreCase);
        public FakePrefs Set(string userId, bool assignment = false, bool overdue = false, bool dueSoon = false)
        { _s[userId] = new NotificationSuppression(assignment, overdue, dueSoon); return this; }
        public Task<NotificationSuppression> GetAsync(string userId, CancellationToken ct = default) =>
            Task.FromResult(_s.GetValueOrDefault(userId, NotificationSuppression.None));
    }

    /// <summary>Captures chat broadcasts so PROD-02 tests can assert on them.</summary>
    private sealed class CapturingChatNotifier : IChatNotifier
    {
        public bool Enabled { get; init; } = true;
        public List<ChatNotification> Sent { get; } = new();
        public Task SendAsync(ChatNotification message, CancellationToken ct = default) { Sent.Add(message); return Task.CompletedTask; }
    }

    // Config with the given chat notification types turned on (Notifications:Chat:{type}).
    private static IConfiguration ChatConfig(params string[] onTypes) =>
        TestEmail.Config(onTypes.Select(t => ($"Notifications:Chat:{t}", "true")).ToArray());

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
        var notifications = new CaseNotifications(sender, TestEmail.Composer(), new FakeUserDirectory(), TestEmail.EmptyConfig, monitor, new NullChatNotifier(), new FakePrefs());

        // Admin edits the Legal distribution after the service is already constructed.
        monitor.CurrentValue = new EmailOptions { LegalDistribution = ["new@insurer.example"] };

        await notifications.OnReclassifiedAsync(NewCase(), Classification.Incident, Classification.Breach);

        sender.Sent.Should().ContainSingle();
        sender.Sent[0].To.Should().Contain("new@insurer.example").And.NotContain("old@insurer.example");
    }

    // --- Assignment (E-03b) ----------------------------------------------------

    // ---- PROD-03: overdue escalation chain ----

    private static OverdueActionItem Item(string? owner, string? ic = "ic1") =>
        new(Guid.NewGuid(), "2026-01_Vendor", "Vendor breach", ic, Guid.NewGuid(), "Rotate keys", Now.AddDays(-3), owner);

    private static FakeUserDirectory Team() => new FakeUserDirectory()
        .Add("owner1", "Olive Owner", "olive@insurer.example", "Analyst")
        .Add("ic1", "Ivan IC", "ivan@insurer.example", "IncidentCommander")
        .Add("mgr1", "Mia Manager", "mia@insurer.example", "Manager")
        .Add("mgr2", "Max Manager", "max@insurer.example", "Manager, SysAdmin");

    [Fact]
    public async Task Escalation_tiers_reach_the_ic_then_every_manager()
    {
        var sender = new CapturingEmailSender();
        var notifications = Build(sender, new EmailOptions(), Team());
        var item = Item("owner1");

        await notifications.OnActionItemsEscalatedAsync(
            [new EscalatedActionItem(item, OverdueEscalationTier.IncidentCommander, 50)]);
        sender.Sent.Should().ContainSingle().Which.To.Should().Equal("ivan@insurer.example");
        sender.Sent[0].HtmlBody.Should().Contain("the incident commander").And.Contain("Olive Owner").And.Contain("2 days overdue");

        sender.Sent.Clear();
        await notifications.OnActionItemsEscalatedAsync(
            [new EscalatedActionItem(item, OverdueEscalationTier.Managers, 130)]);
        sender.Sent.SelectMany(m => m.To).Should().BeEquivalentTo("mia@insurer.example", "max@insurer.example");
        sender.Sent.Should().OnlyContain(m => m.HtmlBody.Contains("a manager"));
    }

    [Fact]
    public async Task The_ic_step_is_skipped_when_the_ic_already_got_the_first_reminder()
    {
        var sender = new CapturingEmailSender();
        var notifications = Build(sender, new EmailOptions(), Team());

        // No owner: the first overdue reminder already went to the IC, so escalating "to the IC" would repeat it.
        await notifications.OnActionItemsEscalatedAsync(
            [new EscalatedActionItem(Item(owner: null), OverdueEscalationTier.IncidentCommander, 50)]);

        sender.Sent.Should().BeEmpty();
    }

    [Fact]
    public async Task Escalations_honour_the_overdue_opt_out()
    {
        var sender = new CapturingEmailSender();
        var prefs = new FakePrefs().Set("mgr1", overdue: true);
        var notifications = Build(sender, new EmailOptions(), Team(), prefs: prefs);

        await notifications.OnActionItemsEscalatedAsync(
            [new EscalatedActionItem(Item("owner1"), OverdueEscalationTier.Managers, 130)]);

        sender.Sent.SelectMany(m => m.To).Should().Equal("max@insurer.example");
    }

    [Fact]
    public async Task The_executive_report_goes_to_every_manager_with_the_headline_figures(/* PROD-15 */)
    {
        var sender = new CapturingEmailSender();
        var notifications = Build(sender, new EmailOptions(), Team());
        var snap = new IncidentManager.Application.Dashboards.ProgramSnapshot(12, 9, 5, [], [],
            new(null, null, 0), new(3, 2.5, 4), new(null, null, 0),
            [new(IncidentManager.Application.Sla.SlaClock.Containment, 3, 1)],
            1, 1, new(null, null, 0), 2, 3, 1, 0, 4, 1, []);
        var report = new IncidentManager.Application.Dashboards.ProgramReport(
            new IncidentManager.Application.Dashboards.ProgramPeriod(2026, 2), snap, snap, [], false, Now);

        await notifications.OnExecutiveReportAsync(report);

        sender.Sent.Should().ContainSingle();
        sender.Sent[0].To.Should().BeEquivalentTo("mia@insurer.example", "max@insurer.example");
        sender.Sent[0].Subject.Should().Contain("Q2 2026");
        sender.Sent[0].HtmlBody.Should().Contain("Cases opened").And.Contain(">12<").And.Contain("75%").And.Contain("2.5 h");
    }

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

    // --- Per-user opt-out (PROD-16) --------------------------------------------

    [Fact]
    public async Task Assignment_respects_the_assignees_opt_out()
    {
        var sender = new CapturingEmailSender();
        var users = new FakeUserDirectory().Add("analyst1", "Alice", "alice@insurer.example");
        var prefs = new FakePrefs().Set("analyst1", assignment: true); // opted out of assignment emails
        var n = Build(sender, new EmailOptions { AssignmentNotifications = true }, users, prefs: prefs);

        await n.OnAssignedAsync(NewCase(), "analyst1", "Alice", CaseAssignmentRole.Analyst, "ic1");

        sender.Sent.Should().BeEmpty();
    }

    [Fact]
    public async Task A_mandatory_type_overrides_the_users_opt_out()
    {
        var sender = new CapturingEmailSender();
        var users = new FakeUserDirectory().Add("analyst1", "Alice", "alice@insurer.example");
        var prefs = new FakePrefs().Set("analyst1", assignment: true); // opted out...
        var config = TestEmail.Config(("Notifications:Mandatory:Assignment", "true")); // ...but the org enforces it
        var n = Build(sender, new EmailOptions { AssignmentNotifications = true }, users, config: config, prefs: prefs);

        await n.OnAssignedAsync(NewCase(), "analyst1", "Alice", CaseAssignmentRole.Analyst, "ic1");

        sender.Sent.Should().ContainSingle();
    }

    [Fact]
    public async Task Overdue_skips_a_recipient_who_opted_out_but_still_emails_the_others()
    {
        var sender = new CapturingEmailSender();
        var users = new FakeUserDirectory()
            .Add("alice", "Alice", "alice@insurer.example")
            .Add("bob", "Bob", "bob@insurer.example");
        var prefs = new FakePrefs().Set("alice", overdue: true); // Alice opted out (e.g. relies on her digest)
        var n = Build(sender, new EmailOptions(), users, prefs: prefs);

        await n.OnActionItemsOverdueAsync(
        [
            Overdue("2026-01", "alice", "ic1", "Task A"),
            Overdue("2026-02", "bob", "ic1", "Task C"),
        ]);

        sender.Sent.Should().ContainSingle().Which.To.Should().Contain("bob@insurer.example");
    }

    [Fact]
    public async Task Due_soon_respects_the_recipients_opt_out()
    {
        var sender = new CapturingEmailSender();
        var users = new FakeUserDirectory().Add("alice", "Alice", "alice@insurer.example");
        var prefs = new FakePrefs().Set("alice", dueSoon: true);
        var n = Build(sender, new EmailOptions(), users, prefs: prefs);

        await n.OnActionItemsDueSoonAsync([DueSoon("2026-01", "alice", "ic1")], leadHours: 24);

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

    // --- Chat channel (PROD-02) ------------------------------------------------

    [Fact]
    public async Task Breach_escalation_posts_to_chat_when_enabled_even_without_a_legal_distribution()
    {
        var sender = new CapturingEmailSender();
        var chat = new CapturingChatNotifier();
        var n = Build(sender, new EmailOptions(), chat: chat, config: ChatConfig("BreachEscalations"));

        await n.OnReclassifiedAsync(NewCase(), Classification.Incident, Classification.Breach);

        sender.Sent.Should().BeEmpty();               // no Legal distribution → no email
        chat.Sent.Should().ContainSingle();
        chat.Sent[0].Title.Should().Contain("Breach");
        chat.Sent[0].Urgency.Should().Be(ChatUrgency.Alert);
    }

    [Fact]
    public async Task Breach_escalation_does_not_post_to_chat_when_the_type_is_off()
    {
        var sender = new CapturingEmailSender();
        var chat = new CapturingChatNotifier();
        var n = Build(sender, new EmailOptions { LegalDistribution = ["legal@insurer.example"] }, chat: chat); // empty config → chat off

        await n.OnReclassifiedAsync(NewCase(), Classification.Incident, Classification.Breach);

        sender.Sent.Should().ContainSingle();         // email still goes
        chat.Sent.Should().BeEmpty();
    }

    [Fact]
    public async Task Assignment_posts_to_chat_independent_of_the_email_toggle_and_address()
    {
        var sender = new CapturingEmailSender();
        var chat = new CapturingChatNotifier();
        var users = new FakeUserDirectory().Add("analyst1", "Alice", null); // no address on file
        var n = Build(sender, new EmailOptions { AssignmentNotifications = false }, users, chat, ChatConfig("Assignments"));

        await n.OnAssignedAsync(NewCase(), "analyst1", "Alice", CaseAssignmentRole.Analyst, "ic1");

        sender.Sent.Should().BeEmpty();               // email toggle off + no address
        chat.Sent.Should().ContainSingle();
        chat.Sent[0].Title.Should().Contain("assigned");
    }

    [Fact]
    public async Task Assignment_chat_skips_a_self_assignment()
    {
        var chat = new CapturingChatNotifier();
        var n = Build(new CapturingEmailSender(), new EmailOptions(), chat: chat, config: ChatConfig("Assignments"));

        await n.OnAssignedAsync(NewCase(), "me", "Me", CaseAssignmentRole.Analyst, "me");

        chat.Sent.Should().BeEmpty();
    }

    [Fact]
    public async Task Overdue_posts_a_single_chat_summary_when_enabled()
    {
        var chat = new CapturingChatNotifier();
        var users = new FakeUserDirectory().Add("alice", "Alice", "alice@insurer.example");
        var n = Build(new CapturingEmailSender(), new EmailOptions(), users, chat, ChatConfig("OverdueReminders"));

        await n.OnActionItemsOverdueAsync([Overdue("2026-01", "alice", "ic1", "A"), Overdue("2026-02", "alice", "ic1", "B")]);

        chat.Sent.Should().ContainSingle();
        chat.Sent[0].Title.Should().Contain("2");      // count of newly-overdue items
    }

    [Fact]
    public async Task Chat_is_not_posted_when_the_notifier_is_disabled()
    {
        var chat = new CapturingChatNotifier { Enabled = false };
        var n = Build(new CapturingEmailSender(), new EmailOptions(), chat: chat, config: ChatConfig("BreachEscalations"));

        await n.OnReclassifiedAsync(NewCase(), Classification.Incident, Classification.Breach);

        chat.Sent.Should().BeEmpty();                  // ChatOn() short-circuits on !Enabled
    }

    // --- Mentions (PROD-04) ----------------------------------------------------

    [Fact]
    public async Task Mention_emails_each_mentioned_user_except_the_author()
    {
        var sender = new CapturingEmailSender();
        var users = new FakeUserDirectory()
            .Add("alice", "Alice", "alice@insurer.example")
            .Add("bob", "Bob", "bob@insurer.example")
            .Add("author", "Author", "author@insurer.example");
        var n = Build(sender, new EmailOptions(), users);

        await n.OnMentionedAsync(NewCase(), "author", ["alice", "bob", "author"], "please take a look");

        sender.Sent.Should().HaveCount(2);
        sender.Sent.Should().Contain(s => s.To.Contains("alice@insurer.example"));
        sender.Sent.Should().Contain(s => s.To.Contains("bob@insurer.example"));
        sender.Sent.Should().NotContain(s => s.To.Contains("author@insurer.example"));  // author never notified
        sender.Sent[0].Subject.Should().Contain("mentioned");
    }

    [Fact]
    public async Task Mention_skips_a_user_with_no_email()
    {
        var sender = new CapturingEmailSender();
        var users = new FakeUserDirectory().Add("alice", "Alice", null);
        var n = Build(sender, new EmailOptions(), users);

        await n.OnMentionedAsync(NewCase(), "author", ["alice"], "hi");

        sender.Sent.Should().BeEmpty();
    }

    [Fact]
    public async Task Mention_posts_to_chat_when_enabled()
    {
        var chat = new CapturingChatNotifier();
        var users = new FakeUserDirectory().Add("alice", "Alice", "alice@insurer.example");
        var n = Build(new CapturingEmailSender(), new EmailOptions(), users, chat, ChatConfig("Mentions"));

        await n.OnMentionedAsync(NewCase(), "author", ["alice"], "ping");

        chat.Sent.Should().ContainSingle();
        chat.Sent[0].Title.Should().Contain("Mention");
    }
}
