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
        { _s[userId] = new NotificationSuppression(assignment, overdue, dueSoon, Escalation: overdue); return this; }
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

    /// <summary>Delivers to every address but one, reporting that one as failed the way the SMTP sender does.</summary>
    private sealed class OneDeadMailbox(string dead) : IEmailSender
    {
        public List<string> Attempts { get; } = new();
        public Task SendAsync(EmailMessage message, CancellationToken ct = default)
        {
            Attempts.AddRange(message.To);
            if (message.To.Contains(dead)) DeliveryWatch.ReportFailure();
            return Task.CompletedTask;
        }
        public Task SendAsync(IReadOnlyCollection<string> to, string subject, string body, CancellationToken ct = default) =>
            SendAsync(new EmailMessage(to, subject, body, body), ct);
    }

    [Fact]
    public async Task A_retried_deadline_reminder_goes_only_to_the_recipient_it_did_not_reach(/* BUG-148 */)
    {
        var sender = new OneDeadMailbox("gone@insurer.example");
        var users = new FakeUserDirectory().Add("ic1", "Ina", "ina@insurer.example").Add("a1", "Al", "al@insurer.example")
            .Add("a2", "Gone", "gone@insurer.example");
        var n = new CaseNotifications(sender, TestEmail.Composer(), users, TestEmail.EmptyConfig,
            new TestOptionsMonitor<EmailOptions>(new EmailOptions()), new NullChatNotifier(), new FakePrefs(),
            sent: new InMemoryNotificationMarks());
        var c = NewCase();
        var reminder = new DeadlineReminder(c.Id, c.CaseNumber, c.Title, c.Severity, ["ic1", "a1", "a2"],
            IncidentManager.Application.Sla.SlaState.AtRisk, [new("NY", "NYDFS")], Now.AddHours(10), TimeSpan.FromHours(10));

        bool retry;
        using (var watch = DeliveryWatch.Begin())
        {
            await n.OnDeadlineApproachingAsync([reminder]);
            retry = watch.ShouldRetry(c.Id.ToString());
        }
        retry.Should().BeTrue("one recipient wasn't reached, so the scan tries the case again");
        sender.Attempts.Should().BeEquivalentTo(["ina@insurer.example", "al@insurer.example", "gone@insurer.example"]);

        sender.Attempts.Clear();
        await n.OnDeadlineApproachingAsync([reminder]);   // the next scan
        sender.Attempts.Should().Equal(["gone@insurer.example"], "those it reached aren't sent it again");
    }

    [Fact]
    public async Task A_regulator_that_joins_a_clock_already_sent_is_sent_and_only_it(/* BUG-619 */)
    {
        var sender = new CapturingEmailSender();
        var chat = new CapturingChatNotifier();
        var users = new FakeUserDirectory().Add("ic1", "Ina", "ina@insurer.example");
        var n = new CaseNotifications(sender, TestEmail.Composer(), users, ChatConfig("DeadlineReminders"),
            new TestOptionsMonitor<EmailOptions>(new EmailOptions()), chat, new FakePrefs(), sent: new InMemoryNotificationMarks());
        var c = NewCase();
        var ny = new DeadlineReminder(c.Id, c.CaseNumber, c.Title, c.Severity, ["ic1"],
            IncidentManager.Application.Sla.SlaState.Breached, [new("NY", "NYDFS")], Now.AddHours(-8), TimeSpan.FromHours(-8));
        await n.OnDeadlineApproachingAsync([ny]);

        // CA comes into play on the same clock (the default window): same band, same due time.
        await n.OnDeadlineApproachingAsync([ny with { Jurisdictions = [new("NY", "NYDFS"), new("CA", "California")] }]);

        sender.Sent.Should().HaveCount(2);
        sender.Sent[1].HtmlBody.Should().Contain("California: past deadline").And.NotContain("NYDFS");
        chat.Sent.Should().HaveCount(2, "the channel is told about CA too");
    }

    [Fact]
    public async Task A_recipient_sent_a_reminder_before_the_upgrade_isnt_sent_it_again(/* BUG-619, owner decision */)
    {
        var sender = new CapturingEmailSender();
        var users = new FakeUserDirectory().Add("ic1", "Ina", "ina@insurer.example");
        var marks = new InMemoryNotificationMarks();
        var n = new CaseNotifications(sender, TestEmail.Composer(), users, TestEmail.EmptyConfig,
            new TestOptionsMonitor<EmailOptions>(new EmailOptions()), new NullChatNotifier(), new FakePrefs(), sent: marks);
        var c = NewCase();
        var due = Now.AddHours(-8);
        // As v1.6.12 marked it for this recipient: no jurisdiction in the key.
        var hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData("ina@insurer.example"u8.ToArray()))[..20];
        marks.TryAdd($"to|{IncidentManager.Application.Notifications.DeadlineIdentity.LegacyKey(c.Id, IncidentManager.Application.Sla.SlaState.Breached, due)}|{hash}");
        var ny = new DeadlineReminder(c.Id, c.CaseNumber, c.Title, c.Severity, ["ic1"],
            IncidentManager.Application.Sla.SlaState.Breached, [new("NY", "NYDFS"), new("NJ", "New Jersey")], due, TimeSpan.FromHours(-8));

        await n.OnDeadlineApproachingAsync([ny]);
        sender.Sent.Should().BeEmpty("the regulators on that clock were sent to this recipient before");

        await n.OnDeadlineApproachingAsync([ny with { Jurisdictions = [new("CA", "California")] }]);
        sender.Sent.Should().ContainSingle().Which.HtmlBody.Should().Contain("California: past deadline");
    }

    [Fact]
    public async Task A_case_with_two_deadlines_needing_attention_lists_both(/* BUG-191 */)
    {
        var sender = new CapturingEmailSender();
        var users = new FakeUserDirectory().Add("ic1", "Ina", "ina@insurer.example");
        var n = new CaseNotifications(sender, TestEmail.Composer(), users, TestEmail.EmptyConfig,
            new TestOptionsMonitor<EmailOptions>(new EmailOptions()), new NullChatNotifier(), new FakePrefs(),
            sent: new InMemoryNotificationMarks());
        var c = NewCase();
        var ny = new DeadlineReminder(c.Id, c.CaseNumber, c.Title, c.Severity, ["ic1"],
            IncidentManager.Application.Sla.SlaState.Breached, [new("NY", "NYDFS")], Now.AddHours(-8), TimeSpan.FromHours(-8));
        var ca = ny with { State = IncidentManager.Application.Sla.SlaState.AtRisk, Jurisdictions = [new("CA", "California")],
            DueAtUtc = Now.AddHours(16), Remaining = TimeSpan.FromHours(16) };

        await n.OnDeadlineApproachingAsync([ny, ca]);

        var body = sender.Sent.Should().ContainSingle().Subject.HtmlBody;
        body.Should().Contain("NYDFS: past deadline").And.Contain("California: at risk");
    }

    [Fact]
    public async Task Deadline_and_stale_links_name_their_list_rather_than_the_default_view(/* BUG-593 */)
    {
        var sender = new CapturingEmailSender();
        var chat = new CapturingChatNotifier();
        var users = new FakeUserDirectory().Add("ic1", "Ina", "ina@insurer.example");
        var config = TestEmail.Config(("App:BaseUrl", "https://casebook.example/"),
            ("Notifications:Chat:DeadlineReminders", "true"), ("Notifications:Chat:StaleReminders", "true"));
        var n = new CaseNotifications(sender, TestEmail.Composer(), users, config,
            new TestOptionsMonitor<EmailOptions>(new EmailOptions()), chat, new FakePrefs(), sent: new InMemoryNotificationMarks());
        var (a, b) = (NewCase(), NewCase());
        var ny = new DeadlineReminder(a.Id, a.CaseNumber, a.Title, a.Severity, ["ic1"],
            IncidentManager.Application.Sla.SlaState.AtRisk, [new("NY", "NYDFS")], Now.AddHours(10), TimeSpan.FromHours(10));

        await n.OnDeadlineApproachingAsync([ny, ny with { CaseId = b.Id, CaseNumber = b.CaseNumber }]);
        chat.Sent.Single().Url.Should().Be("https://casebook.example/cases?notify=true", "the at-risk list takes in closed cases still owing a notice");
        sender.Sent.Single().HtmlBody.Should().Contain("https://casebook.example/cases?notify=true");

        await n.OnCasesStaleAsync([new StaleCaseReminder(a.Id, a.CaseNumber, a.Title, a.Severity, ["ic1"], Now.AddDays(-9), 9, 7),
            new StaleCaseReminder(b.Id, b.CaseNumber, b.Title, b.Severity, ["ic1"], Now.AddDays(-8), 8, 7)]);
        chat.Sent.Last().Url.Should().Be("https://casebook.example/cases?sort=updated&dir=asc");
        sender.Sent.Last().HtmlBody.Should().Contain("https://casebook.example/cases?sort=updated&amp;dir=asc");
    }

    [Fact]
    public async Task A_deadline_reminder_nobody_could_be_sent_is_tried_again_and_broadcast_once(/* BUG-156 */)
    {
        var sender = new CapturingEmailSender();
        var chat = new CapturingChatNotifier();
        var users = new FakeUserDirectory().Add("ic1", "Ina", null);   // no address on file yet
        var n = new CaseNotifications(sender, TestEmail.Composer(), users, ChatConfig("DeadlineReminders"),
            new TestOptionsMonitor<EmailOptions>(new EmailOptions()), chat, new FakePrefs(), sent: new InMemoryNotificationMarks());
        var c = NewCase();
        var nobody = new DeadlineReminder(c.Id, c.CaseNumber, c.Title, c.Severity, [],
            IncidentManager.Application.Sla.SlaState.AtRisk, [new("NY", "NYDFS")], Now.AddHours(10), TimeSpan.FromHours(10));
        var noAddress = nobody with { CaseId = Guid.NewGuid(), RecipientUserIds = ["ic1"] };

        using (var watch = DeliveryWatch.Begin())
        {
            await n.OnDeadlineApproachingAsync([nobody, noAddress]);
            watch.Failed.Should().BeFalse("nothing failed");
            watch.ShouldRetry(nobody.CaseId.ToString()).Should().BeTrue("no incident commander or assignee yet");
            watch.ShouldRetry(noAddress.CaseId.ToString()).Should().BeTrue("its commander has no address on file");
        }
        sender.Sent.Should().BeEmpty();

        await n.OnDeadlineApproachingAsync([nobody, noAddress]);   // the next scan
        chat.Sent.Should().ContainSingle("the team channel isn't told twice about the same reminder");
    }

    [Fact]
    public async Task An_escalation_retried_for_one_manager_is_posted_to_the_channel_once(/* REV-52 */)
    {
        var sender = new CapturingEmailSender();
        var chat = new CapturingChatNotifier();
        var n = new CaseNotifications(sender, TestEmail.Composer(), Team(), ChatConfig("OverdueReminders"),
            new TestOptionsMonitor<EmailOptions>(new EmailOptions()), chat, new FakePrefs(), sent: new InMemoryNotificationMarks());
        var escalated = new EscalatedActionItem(Item("owner1"), OverdueEscalationTier.Managers, 130);

        await n.OnActionItemsEscalatedAsync([escalated]);
        await n.OnActionItemsEscalatedAsync([escalated]);   // the next scan, retrying a failed email

        chat.Sent.Should().ContainSingle();
    }

    /// <summary>Fails the first post (as the webhook notifier reports a 429), then posts.</summary>
    private sealed class FlakyChatNotifier : IChatNotifier
    {
        private int _calls;
        public bool Enabled => true;
        public List<ChatNotification> Posted { get; } = new();
        public Task SendAsync(ChatNotification message, CancellationToken ct = default)
        {
            if (_calls++ == 0) DeliveryWatch.ReportFailure();
            else Posted.Add(message);
            return Task.CompletedTask;
        }
    }

    [Fact]
    public async Task A_failed_channel_post_is_tried_again_by_the_next_scan(/* WF-20 */)
    {
        var chat = new FlakyChatNotifier();
        var n = new CaseNotifications(new CapturingEmailSender(), TestEmail.Composer(), Team(), ChatConfig("OverdueReminders"),
            new TestOptionsMonitor<EmailOptions>(new EmailOptions()), chat, new FakePrefs(), sent: new InMemoryNotificationMarks());
        var escalated = new EscalatedActionItem(Item("owner1"), OverdueEscalationTier.Managers, 130);

        using (var scan = DeliveryWatch.Begin())
        {
            await n.OnActionItemsEscalatedAsync([escalated]);
            scan.ShouldRetry(escalated.Item.ActionItemId.ToString()).Should().BeTrue("its post didn't go");
        }
        await n.OnActionItemsEscalatedAsync([escalated]);   // the next scan

        chat.Posted.Should().ContainSingle();
    }

    [Fact]
    public async Task Retrying_a_failed_channel_post_doesnt_email_the_owner_again(/* WF-20 follow-up */)
    {
        var sender = new CapturingEmailSender();
        var chat = new FlakyChatNotifier();
        var n = new CaseNotifications(sender, TestEmail.Composer(), Team(), ChatConfig("OverdueReminders"),
            new TestOptionsMonitor<EmailOptions>(new EmailOptions()), chat, new FakePrefs(), sent: new InMemoryNotificationMarks());
        var item = Item("owner1");

        await n.OnActionItemsOverdueAsync([item]);   // the post fails, so the scan tries the item again
        await n.OnActionItemsOverdueAsync([item]);

        chat.Posted.Should().ContainSingle();
        sender.Sent.Should().ContainSingle("the owner was emailed the first time");
    }

    [Fact]
    public async Task An_escalation_or_executive_report_nobody_can_receive_is_tried_again(/* WF-17 */)
    {
        var noManagers = new FakeUserDirectory().Add("owner1", "Owner One", "owner1@x.example", "Analyst");
        var n = new CaseNotifications(new CapturingEmailSender(), TestEmail.Composer(), noManagers, TestEmail.EmptyConfig,
            new TestOptionsMonitor<EmailOptions>(new EmailOptions()), new NullChatNotifier(), new FakePrefs(), sent: new InMemoryNotificationMarks());
        var escalated = new EscalatedActionItem(Item("owner1"), OverdueEscalationTier.Managers, 130);

        using (var scan = DeliveryWatch.Begin())
        {
            await n.OnActionItemsEscalatedAsync([escalated]);
            scan.ShouldRetry(escalated.Item.ActionItemId.ToString()).Should().BeTrue("no manager could be sent it");
        }

        using var quarter = DeliveryWatch.Begin();
        var snap = new IncidentManager.Application.Dashboards.ProgramSnapshot(12, 9, 5, [], [],
            new(null, null, 0), new(3, 2.5, 4), new(null, null, 0),
            [new(IncidentManager.Application.Sla.SlaClock.Containment, 3, 1)],
            1, 1, new(null, null, 0), 2, 3, 1, 0, 4, 1, []);
        await n.OnExecutiveReportAsync(new IncidentManager.Application.Dashboards.ProgramReport(
            new IncidentManager.Application.Dashboards.ProgramPeriod(2026, 2), snap, snap, [], false, Now));
        quarter.Failed.Should().BeTrue("the quarter isn't reported until someone receives it");
    }

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

    [Theory]
    [InlineData(null)]
    [InlineData("Tag")]
    public async Task An_exercise_escalation_is_sent_marked_EXERCISE_by_default(string? mode /* BUG-100 */)
    {
        var sender = new CapturingEmailSender();
        var chat = new CapturingChatNotifier();
        var config = TestEmail.Config(("Notifications:Chat:BreachEscalations", "true"), ("Notifications:ExerciseEscalation", mode ?? ""));
        var n = new CaseNotifications(sender, TestEmail.Composer(), new FakeUserDirectory(), config,
            new TestOptionsMonitor<EmailOptions>(new EmailOptions { LegalDistribution = ["legal@insurer.example"] }),
            chat, new FakePrefs(), exercise: new IncidentManager.Infrastructure.Notifications.ConfigurationExerciseEscalationPolicy(config));
        var c = Case.Open(2026, 1, "Tabletop", "Ransomware tabletop", Classification.Incident, Severity.High,
            CaseOrigin.InternalDetection, "ic1", Now, isExercise: true);

        await n.OnReclassifiedAsync(c, Classification.Incident, Classification.Breach);

        sender.Sent.Should().ContainSingle().Which.Subject.Should().StartWith("EXERCISE: ");
        sender.Sent[0].HtmlBody.Should().Contain("not a real breach");
        sender.Sent[0].TextBody.Should().StartWith("EXERCISE.");
        chat.Sent.Should().ContainSingle().Which.Title.Should().StartWith("EXERCISE: ");
    }

    /// <summary>Fails every compose, as a broken admin template or branding read can (BUG-293).</summary>
    private sealed class ThrowingComposer : IEmailComposer
    {
        public Task<EmailMessage> ComposeAsync(string templateId, IReadOnlyCollection<string> to, IReadOnlyDictionary<string, string> tokens,
            string? ctaUrl = null, IReadOnlyDictionary<string, string>? htmlTokens = null, CancellationToken ct = default) =>
            throw new InvalidOperationException("template broken");
        public Task<(string Subject, string Html)> PreviewAsync(string templateId, string subject, string bodyHtml, CancellationToken ct = default) =>
            throw new NotSupportedException();
        public Task<EmailMessage> ComposeSampleAsync(string templateId, IReadOnlyCollection<string> to, string? draftSubject = null,
            string? draftBody = null, CancellationToken ct = default) => throw new NotSupportedException();
    }

    private static int Count(string s, string part)
    {
        var n = 0;
        for (var i = s.IndexOf(part, StringComparison.Ordinal); i >= 0; i = s.IndexOf(part, i + part.Length, StringComparison.Ordinal)) n++;
        return n;
    }

    public static TheoryData<string> ExerciseBreachPaths => new() { "default", "template-without-token", "fallback" };

    [Theory]
    [MemberData(nameof(ExerciseBreachPaths))]
    public async Task An_exercise_breach_email_carries_the_EXERCISE_note_once_in_both_bodies(string path /* BUG-515 */)
    {
        var sender = new CapturingEmailSender();
        var composer = path switch
        {
            "fallback" => (IEmailComposer)new ThrowingComposer(),
            "template-without-token" => TestEmail.Composer((IncidentManager.Application.Admin.EmailTemplateCatalog.BodyKey("breach"),
                "<h1>Breach</h1><p>{{CaseNumber}} needs a look.</p>")),
            _ => TestEmail.Composer(),
        };
        var n = new CaseNotifications(sender, composer, new FakeUserDirectory(), TestEmail.EmptyConfig,
            new TestOptionsMonitor<EmailOptions>(new EmailOptions { LegalDistribution = ["legal@insurer.example"] }),
            new NullChatNotifier(), new FakePrefs());
        var c = Case.Open(2026, 1, "Tabletop", "Ransomware tabletop", Classification.Incident, Severity.High,
            CaseOrigin.InternalDetection, "ic1", Now, isExercise: true);

        await n.OnReclassifiedAsync(c, Classification.Incident, Classification.Breach);

        var m = sender.Sent.Should().ContainSingle().Subject;
        m.Subject.Should().StartWith("EXERCISE: ");
        Count(m.HtmlBody, "not a real breach").Should().Be(1, "the HTML body is marked once on the {0} path", path);
        Count(m.TextBody, "not a real breach").Should().Be(1, "the text body is marked once on the {0} path", path);
        m.TextBody.Should().StartWith("EXERCISE.");
    }

    [Fact]
    public async Task A_real_breach_email_carries_no_EXERCISE_note(/* BUG-515 */)
    {
        var sender = new CapturingEmailSender();
        var n = new CaseNotifications(sender, new ThrowingComposer(), new FakeUserDirectory(), TestEmail.EmptyConfig,
            new TestOptionsMonitor<EmailOptions>(new EmailOptions { LegalDistribution = ["legal@insurer.example"] }),
            new NullChatNotifier(), new FakePrefs());

        await n.OnReclassifiedAsync(NewCase(), Classification.Incident, Classification.Breach);

        var m = sender.Sent.Should().ContainSingle().Subject;
        m.HtmlBody.Should().NotContain("EXERCISE");
        m.TextBody.Should().NotContain("EXERCISE");
    }

    [Fact]
    public async Task An_exercise_escalation_sends_nothing_when_the_organization_skips_them(/* BUG-100 */)
    {
        var sender = new CapturingEmailSender();
        var chat = new CapturingChatNotifier();
        var config = TestEmail.Config(("Notifications:Chat:BreachEscalations", "true"), ("Notifications:ExerciseEscalation", "Skip"));
        var n = new CaseNotifications(sender, TestEmail.Composer(), new FakeUserDirectory(), config,
            new TestOptionsMonitor<EmailOptions>(new EmailOptions { LegalDistribution = ["legal@insurer.example"] }),
            chat, new FakePrefs(), exercise: new IncidentManager.Infrastructure.Notifications.ConfigurationExerciseEscalationPolicy(config));
        var c = Case.Open(2026, 1, "Tabletop", "Ransomware tabletop", Classification.Incident, Severity.High,
            CaseOrigin.InternalDetection, "ic1", Now, isExercise: true);

        await n.OnReclassifiedAsync(c, Classification.Incident, Classification.Breach);
        sender.Sent.Should().BeEmpty();
        chat.Sent.Should().BeEmpty();

        await n.OnReclassifiedAsync(NewCase(), Classification.Incident, Classification.Breach);
        sender.Sent.Should().ContainSingle("a real case is never skipped").Which.Subject.Should().NotContain("EXERCISE");
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

    private sealed class NewYork : IncidentManager.Application.Abstractions.IOrganizationTimeZone
    {
        public TimeZoneInfo Current { get; } = TimeZoneInfo.FindSystemTimeZoneById("America/New_York");
    }

    [Fact]
    public async Task Reminders_give_the_due_time_in_the_organizations_zone(/* BUG-102 */)
    {
        var sender = new CapturingEmailSender();
        var notifications = new CaseNotifications(sender, TestEmail.Composer(), Team(), TestEmail.EmptyConfig,
            new TestOptionsMonitor<EmailOptions>(new EmailOptions()), new NullChatNotifier(), new FakePrefs(), zone: new NewYork());
        var dueLateEvening = new DateTimeOffset(2026, 9, 9, 3, 59, 0, TimeSpan.Zero);   // 23:59 on the 8th in New York

        await notifications.OnActionItemsOverdueAsync([Item("owner1") with { DueAtUtc = dueLateEvening }]);

        sender.Sent.Single().HtmlBody.Should().Contain("2026-09-08 23:59 (UTC-04:00)").And.NotContain("2026-09-09");
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
    public async Task An_escalation_names_the_real_owner_when_the_reminder_fell_to_the_IC(/* BUG-427 */)
    {
        var sender = new CapturingEmailSender();
        var notifications = Build(sender, new EmailOptions(), Team());
        // The owner is no longer entitled, so the scanner routed the reminder to the IC (OwnerUserId null).
        var item = Item(owner: null) with { WrittenOwner = "owner1" };

        await notifications.OnActionItemsEscalatedAsync([new EscalatedActionItem(item, OverdueEscalationTier.Managers, 130)]);

        sender.Sent.Should().NotBeEmpty();
        sender.Sent.Should().OnlyContain(m => m.HtmlBody.Contains("owner Olive Owner") && !m.HtmlBody.Contains("Ivan IC"));

        // Routing is unchanged: the IC got the first reminder, so the IC step is still skipped.
        sender.Sent.Clear();
        await notifications.OnActionItemsEscalatedAsync([new EscalatedActionItem(item, OverdueEscalationTier.IncidentCommander, 50)]);
        sender.Sent.Should().BeEmpty();
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

    private sealed class Directory(Dictionary<string, IncidentManager.Application.ApiTokens.OwnerAccess?> now)
        : IncidentManager.Application.ApiTokens.ITokenOwnerCheck
    {
        public Task<IncidentManager.Application.ApiTokens.OwnerAccess?> CheckAsync(string ownerUserId, CancellationToken ct = default) =>
            Task.FromResult(now.GetValueOrDefault(ownerUserId));
    }

    [Fact]
    public async Task A_manager_the_directory_no_longer_holds_as_one_gets_no_escalation_or_report(/* REV-50 */)
    {
        var sender = new CapturingEmailSender();
        var directory = new Directory(new()
        {
            ["mgr1"] = new(true, new HashSet<string> { "Analyst" }),   // demoted since their last sign-in
            ["mgr2"] = null,                                            // the directory can't say: the mirror stands
        });
        var notifications = new CaseNotifications(sender, TestEmail.Composer(), Team(), TestEmail.EmptyConfig,
            new TestOptionsMonitor<EmailOptions>(new EmailOptions()), new NullChatNotifier(), new FakePrefs(), owners: directory);

        await notifications.OnActionItemsEscalatedAsync(
            [new EscalatedActionItem(Item("owner1"), OverdueEscalationTier.Managers, 130)]);

        sender.Sent.SelectMany(m => m.To).Should().Equal("max@insurer.example");
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
    public async Task Chat_about_a_restricted_case_names_no_case_details()
    {
        // S-13: the shared channel isn't a restricted case's audience — no number, title or comment text.
        var chat = new CapturingChatNotifier();
        var n = Build(new CapturingEmailSender(), new EmailOptions(), chat: chat,
            config: ChatConfig("BreachEscalations", "Mentions", "Assignments"));
        var c = NewCase();
        c.IsRestricted = true;

        await n.OnReclassifiedAsync(c, Classification.Incident, Classification.Breach);
        await n.OnMentionedAsync(c, "author", ["alice"], "the insider is J. Smith", Guid.NewGuid());
        await n.OnAssignedAsync(c, "bob", "Bob", CaseAssignmentRole.Analyst, "author");

        chat.Sent.Should().HaveCount(3);
        foreach (var m in chat.Sent)
        {
            (m.Title + " " + m.Text).Should().Contain("restricted case")
                .And.NotContain(c.CaseNumber).And.NotContain(c.Title).And.NotContain("J. Smith");
        }
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

        await n.OnMentionedAsync(NewCase(), "author", ["alice", "bob", "author"], "please take a look", Guid.NewGuid());

        sender.Sent.Should().HaveCount(2);
        sender.Sent.Should().Contain(s => s.To.Contains("alice@insurer.example"));
        sender.Sent.Should().Contain(s => s.To.Contains("bob@insurer.example"));
        sender.Sent.Should().NotContain(s => s.To.Contains("author@insurer.example"));  // author never notified
        sender.Sent[0].Subject.Should().Contain("mentioned");
    }

    [Fact]
    public async Task A_mention_email_links_to_the_note()
    {
        var sender = new CapturingEmailSender();
        var users = new FakeUserDirectory().Add("alice", "Alice", "alice@insurer.example");
        var n = Build(sender, new EmailOptions(), users, config: TestEmail.Config(("App:BaseUrl", "https://casebook.example")));
        var c = NewCase();
        var noteId = Guid.NewGuid();

        await n.OnMentionedAsync(c, "author", ["alice"], "the export is in Evidence", noteId);

        sender.Sent.Single().HtmlBody.Should().Contain($"https://casebook.example/cases/{c.Id}?tab=Notes&amp;note={noteId}")
            .And.Contain("the export is in Evidence").And.Contain("in a note");
    }

    [Fact]
    public async Task A_handoff_emails_the_recipient_but_not_a_self_handoff()
    {
        var sender = new CapturingEmailSender();
        var users = new FakeUserDirectory().Add("bob", "Bob", "bob@insurer.example").Add("author", "Author", "author@insurer.example");
        var n = Build(sender, new EmailOptions(), users);

        await n.OnHandedOffAsync(NewCase(), "author", "bob", "Where it stands: contained.\nStill open: block domains.");
        await n.OnHandedOffAsync(NewCase(), "author", "author", "to myself");

        sender.Sent.Should().ContainSingle();
        sender.Sent[0].To.Should().Contain("bob@insurer.example");
        sender.Sent[0].Subject.Should().Contain("handed");
        sender.Sent[0].HtmlBody.Should().Contain("Still open: block domains.");
    }

    [Fact]
    public async Task A_user_actions_email_names_its_case_and_recipient_so_held_mail_is_checked_again(/* BUG-654 */)
    {
        var sender = new CapturingEmailSender();
        var users = new FakeUserDirectory().Add("alice", "Alice", "alice@insurer.example").Add("bob", "Bob", "bob@insurer.example")
            .Add("author", "Author", "author@insurer.example");
        var n = Build(sender, new EmailOptions { AssignmentNotifications = true }, users);
        var c = NewCase();

        await n.OnMentionedAsync(c, "author", ["alice", "bob"], "look", Guid.NewGuid());
        await n.OnHandedOffAsync(c, "author", "bob", "over to you");
        await n.OnAssignedAsync(c, "alice", "Alice", CaseAssignmentRole.Analyst, "author");

        sender.Sent.Should().HaveCount(4);
        sender.About.Should().HaveCount(4).And.OnlyContain(a => a.HasValue && a.Value.CaseId == c.Id);
        sender.About.Select(a => string.Join(",", a!.Value.UserIds)).Should().Equal("alice", "bob", "bob", "alice");
    }

    [Fact]
    public async Task Mention_skips_a_user_with_no_email()
    {
        var sender = new CapturingEmailSender();
        var users = new FakeUserDirectory().Add("alice", "Alice", null);
        var n = Build(sender, new EmailOptions(), users);

        await n.OnMentionedAsync(NewCase(), "author", ["alice"], "hi", Guid.NewGuid());

        sender.Sent.Should().BeEmpty();
    }

    [Fact]
    public async Task Mention_posts_to_chat_when_enabled()
    {
        var chat = new CapturingChatNotifier();
        var users = new FakeUserDirectory().Add("alice", "Alice", "alice@insurer.example");
        var n = Build(new CapturingEmailSender(), new EmailOptions(), users, chat, ChatConfig("Mentions"));

        await n.OnMentionedAsync(NewCase(), "author", ["alice"], "ping", Guid.NewGuid());

        chat.Sent.Should().ContainSingle();
        chat.Sent[0].Title.Should().Contain("Mention");
    }

    // INV-39: Markdown in a note or handoff reaches email and chat as plain text — labels, not entity:/evidence: ids.
    [Fact]
    public async Task Mention_and_handoff_emails_and_chat_carry_plain_text_not_markdown_links()
    {
        var sender = new CapturingEmailSender();
        var chat = new CapturingChatNotifier();
        var users = new FakeUserDirectory().Add("alice", "Alice", "alice@insurer.example").Add("bob", "Bob", "bob@insurer.example");
        var n = Build(sender, new EmailOptions(), users, chat, ChatConfig("Mentions"));
        var entity = Guid.NewGuid();
        var evidence = Guid.NewGuid();
        var md = $"**Session** from [Jane Doe (Finance)](entity:{entity}), see [signin.csv](evidence:{evidence}).";

        await n.OnMentionedAsync(NewCase(), "author", ["alice"], md, Guid.NewGuid());
        await n.OnHandedOffAsync(NewCase(), "author", "bob", "Where it stands: " + md);

        foreach (var body in sender.Sent.Select(m => m.HtmlBody).Append(chat.Sent.Single().Text))
        {
            body.Should().Contain("Jane Doe (Finance)").And.Contain("signin.csv");
            body.Should().NotContain("entity:").And.NotContain("evidence:").And.NotContain("**").And.NotContain("](");
        }
        sender.Sent.Should().HaveCount(2);
    }

    // ── CAP-01: an API import waiting for review ───────────────────────────────────────────────────────────────

    private static ImportSubmission Submission(bool restricted = false, Guid? target = null, bool exercise = false) =>
        new(Guid.NewGuid(), "xsiam-svc", "XSIAM", "New case: Suspicious OAuth consent grant (14 items)", 14, target,
            restricted, exercise, ["rev1", "rev2"]);

    [Fact]
    public async Task An_import_sends_nothing_while_its_toggles_are_off()
    {
        var sender = new CapturingEmailSender();
        var chat = new CapturingChatNotifier();
        var users = new FakeUserDirectory().Add("rev1", "Robin", "robin@insurer.example").Add("rev2", "Sam", "sam@insurer.example");
        await Build(sender, new EmailOptions(), users, chat).OnImportSubmittedAsync(Submission());

        sender.Sent.Should().BeEmpty("import emails are off by default");
        chat.Sent.Should().BeEmpty("and so is the chat post");
    }

    [Fact]
    public async Task An_import_emails_each_reviewer_and_posts_to_chat_without_a_restricted_targets_summary()
    {
        var sender = new CapturingEmailSender();
        var chat = new CapturingChatNotifier();
        var users = new FakeUserDirectory().Add("rev1", "Robin", "robin@insurer.example").Add("rev2", "Sam", "sam@insurer.example");
        var config = TestEmail.Config(("Notifications:Chat:ImportSubmissions", "true"), ("Notifications:ImportSubmitted:Email", "true"),
            ("App:BaseUrl", "https://casebook.example"));
        var n = new CaseNotifications(sender, TestEmail.Composer(), users, config,
            new TestOptionsMonitor<EmailOptions>(new EmailOptions()), chat, new FakePrefs());

        var open = Submission();
        await n.OnImportSubmittedAsync(open);
        chat.Sent.Should().ContainSingle().Which.Text.Should().Contain("Suspicious OAuth consent grant").And.Contain("XSIAM");
        chat.Sent[0].Url.Should().Be($"https://casebook.example/cases/import?pending={open.PendingImportId}");
        sender.Sent.Select(m => m.To.Single()).Should().Equal("robin@insurer.example", "sam@insurer.example");
        sender.Sent[0].Subject.Should().Contain("Suspicious OAuth consent grant");
        sender.Sent[0].HtmlBody.Should().Contain("Robin").And.Contain("XSIAM").And.Contain("Nothing has been written");

        chat.Sent.Clear();
        sender.Sent.Clear();
        var caseId = Guid.NewGuid();
        await n.OnImportSubmittedAsync(Submission(restricted: true, target: caseId) with { Summary = "Into 2026-77_Secret (3 items)" });
        var post = chat.Sent.Should().ContainSingle().Subject;
        (post.Title + " " + post.Text).Should().Contain("restricted case").And.NotContain("2026-77_Secret").And.NotContain("XSIAM");
        sender.Sent.Should().HaveCount(2, "the reviewers named are already those who may see it");
        sender.About.Should().OnlyContain(a => a!.Value.CaseId == caseId, "held mail is checked against the case again");
    }

    [Fact]
    public async Task An_exercise_import_is_marked_EXERCISE()
    {
        var chat = new CapturingChatNotifier();
        var n = Build(new CapturingEmailSender(), new EmailOptions(), chat: chat, config: ChatConfig("ImportSubmissions"));
        await n.OnImportSubmittedAsync(Submission(exercise: true));
        chat.Sent.Single().Title.Should().StartWith(ExerciseMarking.Prefix);
    }

    [Fact]
    public async Task A_digest_says_how_many_imports_have_waited_even_with_no_tasks()
    {
        var sender = new CapturingEmailSender();
        var users = new FakeUserDirectory().Add("rev1", "Robin", "robin@insurer.example");
        var n = Build(sender, new EmailOptions(), users);

        await n.OnDigestAsync(new UserDigest("rev1", DigestCadence.Daily, [], [], [],
            new IncidentManager.Application.Import.PendingImportCount(3, false, Now.AddHours(-30)), 24));

        sender.Sent.Should().ContainSingle().Which.HtmlBody.Should().Contain("3 imports have waited more than 24 hours");
        sender.Sent.Clear();
        await n.OnDigestAsync(new UserDigest("rev1", DigestCadence.Daily, [], [], []));
        sender.Sent.Should().BeEmpty("nothing to say");
    }

    [Fact]
    public async Task A_digest_of_imports_only_says_so_and_a_digest_with_items_is_as_before(/* CAP-01 review */)
    {
        var sender = new CapturingEmailSender();
        var users = new FakeUserDirectory().Add("rev1", "Robin", "robin@insurer.example");
        var n = Build(sender, new EmailOptions(), users);
        var waiting = new IncidentManager.Application.Import.PendingImportCount(3, false, Now.AddHours(-30));

        await n.OnDigestAsync(new UserDigest("rev1", DigestCadence.Daily, [], [], [], waiting, 24));

        var importsOnly = sender.Sent.Should().ContainSingle().Subject;
        importsOnly.Subject.Should().Be("3 API imports waiting for your review").And.NotContain("0 open");
        importsOnly.HtmlBody.Should().NotContain("open follow-up items across", "it has none")
            .And.Contain("3 imports have waited more than 24 hours");
        importsOnly.TextBody.Should().Contain("no open follow-up items");

        sender.Sent.Clear();
        var item = new DigestItem("2026-01_Phishing_Wave", "Reset credentials", Severity.High, Now.AddHours(-2));
        await n.OnDigestAsync(new UserDigest("rev1", DigestCadence.Daily, [item], [], [], waiting, 24));

        var normal = sender.Sent.Should().ContainSingle().Subject;
        normal.Subject.Should().Be("Your CaseBook work digest: 1 open");
        normal.HtmlBody.Should().Contain("Here are your open follow-up items across the cases you're working")
            .And.Contain("Reset credentials").And.Contain("3 imports have waited more than 24 hours");
    }

    // --- CAP-10: the monthly retention-review notice ------------------------------------------------------------------

    [Fact]
    public async Task The_retention_review_email_tells_legal_the_counts_and_names_no_case()
    {
        var sender = new CapturingEmailSender();
        var notifications = Build(sender, new EmailOptions { LegalDistribution = ["legal@insurer.example", "privacy@insurer.example"] });

        using var month = DeliveryWatch.Begin();
        await notifications.OnRetentionReviewDueAsync(new IncidentManager.Application.Notifications.RetentionReviewCount(Now, 7, 12, 1));

        month.Failed.Should().BeFalse();
        var sent = sender.Sent.Should().ContainSingle().Subject;
        sent.To.Should().BeEquivalentTo("legal@insurer.example", "privacy@insurer.example");
        sent.Subject.Should().Be("Retention review: 12 cases past retention");
        sent.HtmlBody.Should().Contain("7 years").And.Contain("12 cases").And.Contain("Nothing is archived or deleted automatically");
        sent.TextBody.Should().Contain("under a legal hold").And.Contain(": 1");
    }

    [Fact]
    public async Task With_no_legal_distribution_the_retention_month_isnt_told()
    {
        var sender = new CapturingEmailSender();
        using var month = DeliveryWatch.Begin();

        await Build(sender, new EmailOptions()).OnRetentionReviewDueAsync(
            new IncidentManager.Application.Notifications.RetentionReviewCount(Now, 7, 3, 0));

        sender.Sent.Should().BeEmpty();
        month.Failed.Should().BeTrue("the scan tries again once a distribution is set");
    }

    // --- CAP-36: chat routed by the case's team ---

    /// <summary>Captures chat posts; the teams in <see cref="Own"/> have a webhook of their own.</summary>
    private sealed class RoutingChatNotifier : IChatNotifier
    {
        public HashSet<Guid> Own { get; } = [];
        public bool Enabled => true;
        public List<ChatNotification> Sent { get; } = new();
        public bool RoutesTeam(Guid teamId) => Own.Contains(teamId);
        public Task SendAsync(ChatNotification message, CancellationToken ct = default) { Sent.Add(message); return Task.CompletedTask; }
    }

    [Fact]
    public async Task A_cases_chat_posts_name_its_team_so_they_go_to_its_channel()
    {
        var chat = new RoutingChatNotifier();
        var notifications = Build(new CapturingEmailSender(), new EmailOptions(), chat: chat,
            config: ChatConfig("Assignments", "BreachEscalations", "Mentions", "ImportSubmissions"));
        var team = Guid.NewGuid();
        var c = NewCase();
        c.SetTeam(team, "ic1", Now);

        await notifications.OnAssignedAsync(c, "analyst1", "Alice Analyst", CaseAssignmentRole.Analyst, "ic1");
        await notifications.OnReclassifiedAsync(c, Classification.Incident, Classification.Breach);
        await notifications.OnMentionedAsync(c, "ic1", ["analyst1"], "Look at this", Guid.NewGuid());
        await notifications.OnImportSubmittedAsync(new ImportSubmission(Guid.NewGuid(), "apitoken:xsiam", "XSIAM", "Into 2026-01",
            3, c.Id, false, false, [], team));

        chat.Sent.Should().HaveCount(4);
        chat.Sent.Should().OnlyContain(m => m.TeamId == team, "the notifier picks the team's webhook, or the shared one");
    }

    [Fact]
    public async Task A_scan_summary_is_split_one_post_per_channel()
    {
        var chat = new RoutingChatNotifier();
        var own = Guid.NewGuid();
        var withoutWebhook = Guid.NewGuid();
        chat.Own.Add(own);
        var notifications = Build(new CapturingEmailSender(), new EmailOptions(), chat: chat, config: ChatConfig("OverdueReminders"));

        await notifications.OnActionItemsOverdueAsync([
            Item("owner1") with { TeamId = own }, Item("owner1") with { TeamId = own },
            Item("owner1") with { TeamId = withoutWebhook }, Item("owner1")]);

        chat.Sent.Should().HaveCount(2, "the team with its own webhook, and the shared channel for the rest");
        chat.Sent[0].TeamId.Should().BeNull("the shared channel's post first");
        chat.Sent[0].Title.Should().StartWith("2 tasks overdue", "a team without a webhook of its own posts with the cases with none");
        chat.Sent[1].TeamId.Should().Be(own);
        chat.Sent[1].Title.Should().StartWith("2 tasks overdue");
    }
}
