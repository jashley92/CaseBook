using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Evidence;
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
/// S-09: need-to-know applies to writes, not just reads. Someone taken off a restricted case (while it's still open in
/// their browser, say) can't keep writing to it: case edits, discussion and task comments, and evidence uploads all
/// refuse a case the caller can't see, and its comments read back as empty.
/// </summary>
public sealed class WriteNeedToKnowTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 9, 24, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new() { UserId = "outsider", RoleSet = [AppRole.Analyst] };

    public WriteNeedToKnowTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
    }

    private DbContextOptions<AppDbContext> Options() => new DbContextOptionsBuilder<AppDbContext>()
        .UseSqlite(_connection)
        .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
        .Options;

    private AppDbContext NewContext()
    {
        var db = new AppDbContext(Options());
        db.Database.EnsureCreated();
        return db;
    }

    private TestDbContextFactory Factory() => new(Options());

    private CaseService NewCases() =>
        new(Factory(), _user, _clock, new CaseNumberGenerator(NewContext()), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());

    /// <summary>A restricted case the acting analyst is not on, with one action item.</summary>
    private async Task<(Guid CaseId, Guid ItemId)> SeedRestrictedAsync()
    {
        await using var db = NewContext();
        var c = Case.Open(2026, 9, "Insider", "Insider matter",
            Classification.Incident, Severity.High, CaseOrigin.InternalDetection, "ic-1", _clock.UtcNow);
        c.IncidentCommander = "ic-1";
        c.IsRestricted = true;
        var item = new ActionItem { CaseId = c.Id, Title = "Interview", CreatedBy = "ic-1", CreatedAtUtc = _clock.UtcNow };
        c.ActionItems.Add(item);
        db.Cases.Add(c);
        await db.SaveChangesAsync();
        return (c.Id, item.Id);
    }

    [Fact]
    public async Task Case_edits_refuse_a_restricted_case_the_caller_cannot_see()
    {
        var (id, _) = await SeedRestrictedAsync();
        var cases = NewCases();

        await FluentActions.Awaiting(() => cases.AddNoteAsync(id, "still here"))
            .Should().ThrowAsync<InvalidOperationException>().WithMessage("*not accessible*");
        await FluentActions.Awaiting(() => cases.ChangeSeverityAsync(id, Severity.Low, "downgrade"))
            .Should().ThrowAsync<InvalidOperationException>();

        await using var db = NewContext();
        (await db.Notes.CountAsync()).Should().Be(0);
    }

    [Fact]
    public async Task Discussion_and_task_comments_are_scoped()
    {
        var (id, itemId) = await SeedRestrictedAsync();
        var discussion = new CaseCommentService(Factory(), _user, _clock, new StubUserDirectory(), new NoOpCaseNotifications());
        var taskComments = new ActionItemCommentService(Factory(), _user, _clock, new StubUserDirectory());

        await FluentActions.Awaiting(() => discussion.AddAsync(id, "hello", null, null))
            .Should().ThrowAsync<InvalidOperationException>();
        await FluentActions.Awaiting(() => taskComments.AddAsync(id, itemId, "hello"))
            .Should().ThrowAsync<InvalidOperationException>();

        // Seed a comment as the IC, then confirm the outsider reads nothing back.
        _user.UserId = "ic-1";
        await discussion.AddAsync(id, "privileged detail", null, null);
        _user.UserId = "outsider";
        (await discussion.ListAsync(id)).Should().BeEmpty();
    }

    [Fact]
    public async Task View_only_roles_can_comment_on_cases_they_can_see()
    {
        // S-16: discussion is open to anyone who can see the case — deliberately ViewCases, not EditCases.
        var (id, itemId) = await SeedRestrictedAsync();
        _user.UserId = "ic-1";                 // on the case, so it's visible
        _user.RoleSet = [AppRole.Manager];     // view-only
        var discussion = new CaseCommentService(Factory(), _user, _clock, new StubUserDirectory(), new NoOpCaseNotifications());
        var taskComments = new ActionItemCommentService(Factory(), _user, _clock, new StubUserDirectory());

        (await discussion.AddAsync(id, "question for the team", null, null)).Should().NotBeEmpty();
        (await taskComments.AddAsync(id, itemId, "who owns this?")).Should().NotBeEmpty();

        _user.RoleSet = [];                     // no CaseBook role at all
        await FluentActions.Awaiting(() => discussion.AddAsync(id, "hi", null, null))
            .Should().ThrowAsync<IncidentManager.Application.Security.ForbiddenException>();
    }

    [Fact]
    public async Task Evidence_upload_is_scoped_and_needs_edit_rights()
    {
        var (id, _) = await SeedRestrictedAsync();
        var store = new CountingStore();
        var evidence = new EvidenceService(Factory(), store, _user, _clock, new NoOpAuditWriter());

        await FluentActions.Awaiting(() => evidence.UploadAsync(id, "a.txt", "text/plain", new MemoryStream([1]), null))
            .Should().ThrowAsync<InvalidOperationException>();
        store.Saves.Should().Be(0, "no bytes are stored for a case the caller can't see");

        _user.RoleSet = [AppRole.Manager]; // view-only
        _user.UserId = "ic-1";             // even on the case
        await FluentActions.Awaiting(() => evidence.UploadAsync(id, "a.txt", "text/plain", new MemoryStream([1]), null))
            .Should().ThrowAsync<IncidentManager.Application.Security.ForbiddenException>();
    }

    private sealed class CountingStore : IEvidenceStore
    {
        public int Saves { get; private set; }
        public Task<StoredEvidence> SaveAsync(Guid caseId, Stream content, CancellationToken ct = default)
        {
            Saves++;
            return Task.FromResult(new StoredEvidence("x", "00", 1));
        }
        public Task<Stream> OpenReadAsync(string storagePath, CancellationToken ct = default) => throw new NotSupportedException();
    }

    private sealed class StubUserDirectory : IUserDirectory
    {
        public Task TouchAsync(string userId, string displayName, string? upn, string? email, string rolesCsv, CancellationToken ct = default) => Task.CompletedTask;
        public IReadOnlyList<UserSummary> All() => Array.Empty<UserSummary>();
        public UserSummary? Resolve(string userId) => null;
        public string DisplayFor(string? userId) => userId ?? "—";
        public string? EmailFor(string userId) => null;
        public void Invalidate() { }
    }


    public void Dispose() => _connection.Dispose();
}
