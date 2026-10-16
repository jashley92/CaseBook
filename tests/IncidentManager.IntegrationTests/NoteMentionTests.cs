using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Security;
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
/// INV-37: a note can @mention teammates. S-13: on a restricted case only people who can see it are offered and
/// notified, so an analyst outside the team never receives the note excerpt; an open case can mention anyone with
/// case access. An edit notifies only the people it newly mentions. A handoff can email the person taking it on.
/// </summary>
public sealed class NoteMentionTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 9, 24, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { UserId = "ic", RoleSet = [AppRole.Analyst] };
    private readonly Directory _dir = new();
    private readonly Capture _notifications = new();

    public NoteMentionTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        using var db = new AppDbContext(Options());
        db.Database.EnsureCreated();
    }

    private DbContextOptions<AppDbContext> Options() => new DbContextOptionsBuilder<AppDbContext>()
        .UseSqlite(_connection)
        .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
        .Options;

    // BUG-597: what the directory of record says now (null: it can't say, so the mirror stands).
    private readonly Dictionary<string, IncidentManager.Application.ApiTokens.OwnerAccess?> _ad = new();

    private CaseService Svc()
    {
        var db = new AppDbContext(Options());
        return new CaseService(new TestDbContextFactory(Options()), _user, _clock, new CaseNumberGenerator(db), new CreateCaseValidator(),
            _notifications, new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets(),
            users: _dir, roles: new CodeRoles(),
            audience: new IncidentManager.Application.Notifications.ReminderAudience(_dir, new CodeRoles(), new Ad(_ad)));
    }

    private sealed class Ad(Dictionary<string, IncidentManager.Application.ApiTokens.OwnerAccess?> answers)
        : IncidentManager.Application.ApiTokens.ITokenOwnerCheck
    {
        public Task<IncidentManager.Application.ApiTokens.OwnerAccess?> CheckAsync(string ownerUserId, CancellationToken ct = default) =>
            Task.FromResult(answers.GetValueOrDefault(ownerUserId));
    }

    private static IncidentManager.Application.ApiTokens.OwnerAccess Left() => new(false, new HashSet<string> { "Analyst" });

    [Fact]
    public async Task A_leaver_the_directory_has_disabled_is_not_emailed_a_mention_or_a_handoff(/* BUG-597 */)
    {
        var id = await SeedAsync(restricted: false);
        _ad["outsider"] = Left();   // still "Analyst" in the mirror, from their last sign-in

        await Svc().AddNoteAsync(id, "@Teammate @Outsider see this", ["teammate", "outsider"]);
        _notifications.Mentioned.Should().Equal("teammate");
        await using (var db = new AppDbContext(Options()))
            (await db.Notes.SingleAsync()).MentionsCsv.Should().Be("teammate,outsider", "the note still records who it mentions");

        await Svc().EditNoteAsync(id, (await CurrentNote()).Id, "@Teammate @Outsider @Legal see this", ["teammate", "outsider", "legal"]);
        _notifications.Mentioned.Should().Equal("teammate", "legal");

        await Svc().HandOffAsync(id, "outsider", "Over to you.", reassignMyOpenTasks: false, notify: true);
        _notifications.HandedOff.Should().BeEmpty();
        _ad["teammate"] = null;   // the directory can't say: the mirror stands (WF-57)
        await Svc().HandOffAsync(id, "teammate", "Over to you.", reassignMyOpenTasks: false, notify: true);
        _notifications.HandedOff.Should().Equal("teammate");
    }

    [Fact]
    public async Task An_assignment_is_announced_only_to_someone_entitled_to_the_case(/* BUG-596 */)
    {
        var id = await SeedAsync(restricted: true);
        _dir.Add(new("norole", "No role", null, null, ""));
        _dir.Add(new("leaver", "Leaver", null, null, "Analyst"));
        _ad["leaver"] = Left();

        await Svc().AssignAsync(id, "norole", "No role", CaseAssignmentRole.Analyst);
        await Svc().ReassignAsync(id, "teammate", "leaver", "Leaver", CaseAssignmentRole.Analyst);   // joins as teammate leaves
        await Svc().Invoking(s => s.UnassignAsync(id, "leaver")).Should().NotThrowAsync();
        await Svc().AssignAsync(id, "leaver", "Leaver", CaseAssignmentRole.Analyst);
        await Svc().AddAssigneeAsync(id, "stranger", "Not in the mirror", CaseAssignmentRole.Analyst);
        _notifications.Assigned.Should().BeEmpty("none of them can open the case, so none is told about it");

        await Svc().AssignAsync(id, "outsider", "Outsider", CaseAssignmentRole.Analyst);
        _notifications.Assigned.Should().Equal(["outsider"], "joining a restricted case's team lets them see it");
        await Svc().AssignAsync(id, "ic", "IC", CaseAssignmentRole.IncidentCommander);
        _notifications.Assigned.Should().Equal(["outsider"], "a self-assignment isn't announced, as before");
    }

    private async Task<Guid> SeedAsync(bool restricted)
    {
        await using var db = new AppDbContext(Options());
        var c = Case.Open(2026, 3, "Insider", "Insider matter", Classification.Incident, Severity.High,
            CaseOrigin.InternalDetection, "ic", _clock.UtcNow);
        c.IncidentCommander = "ic";
        c.IsRestricted = restricted;
        c.Assign("teammate", "Teammate", CaseAssignmentRole.Analyst, "ic", _clock.UtcNow);
        db.Cases.Add(c);
        await db.SaveChangesAsync();
        return c.Id;
    }

    [Fact]
    public async Task A_restricted_case_only_mentions_and_notifies_its_audience()
    {
        var id = await SeedAsync(restricted: true);

        (await Svc().MentionableAsync(id)).Select(u => u.UserId)
            .Should().BeEquivalentTo(["teammate", "legal"], "the team and a cleared role, not an outside analyst");

        await Svc().AddNoteAsync(id, "@Teammate @Outsider @Legal see this", ["teammate", "outsider", "legal", "ic"]);

        _notifications.Mentioned.Should().BeEquivalentTo(["teammate", "legal"], "never the outsider, never the author");
        await using var db = new AppDbContext(Options());
        (await db.Notes.SingleAsync()).MentionsCsv.Should().Be("teammate,legal");
    }

    [Fact]
    public async Task An_open_case_mentions_anyone_with_case_access()
    {
        var id = await SeedAsync(restricted: false);

        (await Svc().MentionableAsync(id)).Select(u => u.UserId)
            .Should().BeEquivalentTo(["teammate", "legal", "outsider"]);
    }

    [Fact]
    public async Task An_edit_notifies_only_the_people_it_newly_mentions_and_links_the_new_version()
    {
        var id = await SeedAsync(restricted: false);
        await Svc().AddNoteAsync(id, "@Teammate the export is in Evidence", ["teammate"]);
        Guid first;
        await using (var db = new AppDbContext(Options())) first = (await db.Notes.SingleAsync()).Id;
        _notifications.Mentioned.Clear();

        await Svc().EditNoteAsync(id, first, "@Teammate the export is in Evidence (fixed typo)", ["teammate"]);
        _notifications.Mentioned.Should().BeEmpty("fixing a typo doesn't email them again");

        await Svc().EditNoteAsync(id, (await CurrentNote()).Id, "@Teammate @Outsider the export is in Evidence", ["teammate", "outsider"]);
        _notifications.Mentioned.Should().Equal("outsider");
        _notifications.NoteIds.Last().Should().Be((await CurrentNote()).Id, "the email links to the version that mentioned them");
        (await CurrentNote()).MentionsCsv.Should().Be("teammate,outsider");
    }

    [Fact]
    public async Task Notes_with_mentions_are_audited_and_the_chain_stays_valid()
    {
        var id = await SeedAsync(restricted: false);
        await Svc().AddNoteAsync(id, "plain note");
        await Svc().AddNoteAsync(id, "@Teammate look", ["teammate"]);

        await using var db = new AppDbContext(Options());
        var chain = await db.AuditLog.OrderBy(a => a.Sequence).ToListAsync();
        _hasher.VerifyChain(chain).IsValid.Should().BeTrue();
        var plain = await db.Notes.SingleAsync(n => n.Body == "plain note");
        plain.BuildCanonicalContent().Should().NotContain("mentions", "a note without mentions keeps its exact hash");
        (await db.Notes.AllAsync(n => n.RowHash != null)).Should().BeTrue();
    }

    [Fact]
    public async Task A_handoff_emails_the_recipient_only_when_asked_and_only_if_they_can_see_the_case()
    {
        var id = await SeedAsync(restricted: true);

        await Svc().HandOffAsync(id, "teammate", "Where it stands: contained.", reassignMyOpenTasks: false, notify: true);
        await Svc().HandOffAsync(id, "teammate", "Second handoff, not emailed.", reassignMyOpenTasks: false);
        // BUG-48: someone outside a restricted case can't take it on (nor its tasks); add them to the team first.
        await Svc().Invoking(s => s.HandOffAsync(id, "outsider", "To someone outside the restricted case.", reassignMyOpenTasks: true, notify: true))
            .Should().ThrowAsync<InvalidOperationException>().WithMessage("*can't see this restricted case*");

        _notifications.HandedOff.Should().Equal("teammate");
    }

    [Fact]
    public async Task A_handoff_moves_the_tasks_owned_under_any_of_my_identifiers(/* REV-17 */)
    {
        var id = await SeedAsync(restricted: false);
        _user.UserPrincipalName = "ic@corp.example";
        await Svc().AddActionItemAsync(id, "By id", "ic", null);
        await Svc().AddActionItemAsync(id, "By UPN", "IC@corp.example", null);
        await Svc().AddActionItemAsync(id, "Someone else's", "teammate", null);

        var moved = await Svc().HandOffAsync(id, "teammate", "Over to you.", reassignMyOpenTasks: true);

        moved.Should().Be(2);
        await using var db = new AppDbContext(Options());
        (await db.ActionItems.Where(t => t.CaseId == id).Select(t => t.Owner).ToListAsync()).Should().OnlyContain(o => o == "teammate");
    }

    private async Task<AnalystNote> CurrentNote()
    {
        await using var db = new AppDbContext(Options());
        return await db.Notes.SingleAsync(n => n.IsCurrent);
    }

    /// <summary>Resolves built-in role names to their code-defined permissions.</summary>
    private sealed class CodeRoles : IRoleDirectory
    {
        public IReadOnlySet<Permission> PermissionsForRoles(IEnumerable<string> roleNames) =>
            RoleDefinitions.PermissionsForRoleNames(roleNames);
        public IReadOnlySet<string> RolesForGroups(IEnumerable<string> adGroups) => new HashSet<string>();
        public void Invalidate() { }
    }

    private sealed class Directory : IUserDirectory
    {
        private readonly List<UserSummary> _all =
        [
            new("ic", "IC", null, null, "Analyst"),
            new("teammate", "Teammate", null, null, "Analyst"),
            new("outsider", "Outsider", null, null, "Analyst"),
            new("legal", "Legal", null, null, "LegalPrivacy"),
        ];
        public void Add(UserSummary u) => _all.Add(u);
        public Task TouchAsync(string userId, string displayName, string? upn, string? email, string rolesCsv, CancellationToken ct = default) => Task.CompletedTask;
        public IReadOnlyList<UserSummary> All() => _all;
        public UserSummary? Resolve(string userId) => _all.FirstOrDefault(u => u.UserId == userId);
        public string DisplayFor(string? userId) => userId ?? "—";
        public string? EmailFor(string userId) => null;
        public void Invalidate() { }
    }

    private sealed class Capture : ICaseNotifications
    {
        public List<string> Mentioned { get; } = new();
        public List<Guid> NoteIds { get; } = new();
        public List<string> HandedOff { get; } = new();
        public Task OnReclassifiedAsync(Case c, Classification? from, Classification to, CancellationToken ct = default) => Task.CompletedTask;
        public List<string> Assigned { get; } = new();
        public Task OnAssignedAsync(Case c, string assigneeUserId, string assigneeDisplayName, CaseAssignmentRole role, string assignedByUserId, CancellationToken ct = default)
        {
            Assigned.Add(assigneeUserId);
            return Task.CompletedTask;
        }
        public Task OnActionItemsOverdueAsync(IReadOnlyList<OverdueActionItem> items, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnActionItemsDueSoonAsync(IReadOnlyList<DueSoonActionItem> items, int leadHours, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnMentionedAsync(Case c, string byUserId, IReadOnlyCollection<string> mentionedUserIds, string noteExcerpt, Guid noteId, CancellationToken ct = default)
        {
            Mentioned.AddRange(mentionedUserIds);
            NoteIds.Add(noteId);
            return Task.CompletedTask;
        }
        public Task OnHandedOffAsync(Case c, string byUserId, string toUserId, string handoff, CancellationToken ct = default)
        {
            HandedOff.Add(toUserId);
            return Task.CompletedTask;
        }
    }

    public void Dispose() => _connection.Dispose();
}
