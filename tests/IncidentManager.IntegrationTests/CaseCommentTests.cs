using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Security;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>PROD-04: durable threaded case comments — persistence, threading, mentions, audit chain.</summary>
public sealed class CaseCommentTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 8, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();
    private readonly StubUserDirectory _dir = new();
    private readonly CapturingCaseNotifications _notifications = new();

    public CaseCommentTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        using var db = new AppDbContext(Options());
        db.Database.EnsureCreated();
    }

    private DbContextOptions<AppDbContext> Options() =>
        new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new IncidentManager.Infrastructure.Realtime.CaseChangeNotifier()))
            .Options;

    private AppDbContext NewContext() => new(Options());
    private CaseCommentService NewService() =>
        new(new TestDbContextFactory(Options()), _user, _clock, _dir, _notifications);

    private async Task<Guid> SeededCaseIdAsync()
    {
        await using var db = NewContext();
        await DevDataSeeder.SeedAsync(db, _clock);
        return (await db.Cases.FirstAsync(c => c.CaseNumber == "2026-01_Phishing_Wave")).Id;
    }

    [Fact]
    public async Task A_comment_persists_and_lists_with_its_author()
    {
        var caseId = await SeededCaseIdAsync();
        _user.UserId = "alice";
        await NewService().AddAsync(caseId, "Kicking off triage.", parentId: null, mentionUserIds: null);

        var list = await NewService().ListAsync(caseId);
        var c = list.Should().ContainSingle().Subject;
        c.Body.Should().Be("Kicking off triage.");
        c.AuthorUserId.Should().Be("alice");
        c.ParentId.Should().BeNull();
    }

    [Fact]
    public async Task A_reply_to_a_reply_is_normalised_to_one_level()
    {
        var caseId = await SeededCaseIdAsync();
        var svc = NewService();
        var top = await svc.AddAsync(caseId, "Top-level", null, null);
        var reply = await NewService().AddAsync(caseId, "First reply", top, null);
        var nested = await NewService().AddAsync(caseId, "Reply to the reply", reply, null);

        var list = await NewService().ListAsync(caseId);
        list.Single(c => c.Id == reply).ParentId.Should().Be(top);
        list.Single(c => c.Id == nested).ParentId.Should().Be(top);   // flattened onto the thread, not the reply
    }

    [Fact]
    public async Task Mentions_are_recorded_and_the_notifier_is_called_without_the_author()
    {
        var caseId = await SeededCaseIdAsync();
        _user.UserId = "author";
        await NewService().AddAsync(caseId, "@here please review", null, ["alice", "bob", "author"]);

        // The author is dropped from the stored mentions and from the notification.
        _notifications.Mentions.Should().ContainSingle();
        _notifications.Mentions[0].By.Should().Be("author");
        _notifications.Mentions[0].To.Should().BeEquivalentTo("alice", "bob");

        var listed = (await NewService().ListAsync(caseId)).Single();
        listed.Mentions.Should().BeEquivalentTo("alice", "bob");   // resolved to names by the stub (identity)
    }

    [Fact]
    public async Task No_notification_when_there_are_no_mentions()
    {
        var caseId = await SeededCaseIdAsync();
        await NewService().AddAsync(caseId, "just a note", null, null);
        _notifications.Mentions.Should().BeEmpty();
    }

    [Fact]
    public async Task An_empty_comment_is_rejected()
    {
        var caseId = await SeededCaseIdAsync();
        var act = async () => await NewService().AddAsync(caseId, "   ", null, null);
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task Comments_are_audited_and_the_chain_stays_valid()
    {
        var caseId = await SeededCaseIdAsync();
        await NewService().AddAsync(caseId, "one", null, null);
        await NewService().AddAsync(caseId, "two", null, null);

        await using var db = NewContext();
        // Each comment produced an audit line carrying the case number, and the chain verifies intact.
        (await db.AuditLog.CountAsync(a => a.EntityType == "CaseComment" && a.CaseNumber == "2026-01_Phishing_Wave"))
            .Should().Be(2);
        var chain = await db.AuditLog.OrderBy(a => a.Sequence).ToListAsync();
        _hasher.VerifyChain(chain).IsValid.Should().BeTrue();
        // And the rows are hash-chained (RowHash set).
        (await db.CaseComments.AllAsync(c => c.RowHash != null)).Should().BeTrue();
    }

    /// <summary>Identity directory — resolves an id to itself for the mention-name projection.</summary>
    private sealed class StubUserDirectory : IUserDirectory
    {
        public Task TouchAsync(string userId, string displayName, string? upn, string? email, string rolesCsv, CancellationToken ct = default) => Task.CompletedTask;
        public IReadOnlyList<UserSummary> All() => Array.Empty<UserSummary>();
        public UserSummary? Resolve(string userId) => null;
        public string DisplayFor(string? userId) => userId ?? "—";
        public string? EmailFor(string userId) => null;
        public void Invalidate() { }
    }

    /// <summary>Captures mention notifications; the other triggers are no-ops.</summary>
    private sealed class CapturingCaseNotifications : ICaseNotifications
    {
        public List<(string By, IReadOnlyList<string> To, string Excerpt)> Mentions { get; } = new();
        public Task OnReclassifiedAsync(Case c, Classification? from, Classification to, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnAssignedAsync(Case c, string assigneeUserId, string assigneeDisplayName, CaseAssignmentRole role, string assignedByUserId, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnActionItemsOverdueAsync(IReadOnlyList<OverdueActionItem> items, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnActionItemsDueSoonAsync(IReadOnlyList<DueSoonActionItem> items, int leadHours, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnMentionedAsync(Case c, string byUserId, IReadOnlyCollection<string> mentionedUserIds, string commentExcerpt, CancellationToken ct = default)
        {
            Mentions.Add((byUserId, mentionedUserIds.ToList(), commentExcerpt));
            return Task.CompletedTask;
        }
    }

    public void Dispose() => _connection.Dispose();
}
