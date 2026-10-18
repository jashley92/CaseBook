using System.Text.Json;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Import;
using IncidentManager.Application.Notifications;
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

/// <summary>Resolves built-in role names to their code-defined permissions.</summary>
internal sealed class BuiltInRoles : IRoleDirectory
{
    public IReadOnlySet<Permission> PermissionsForRoles(IEnumerable<string> roleNames) => RoleDefinitions.PermissionsForRoleNames(roleNames);
    public IReadOnlySet<string> RolesForGroups(IEnumerable<string> adGroups) => new HashSet<string>();
    public void Invalidate() { }
}

/// <summary>
/// Captures (or refuses) the CAP-01 import notification. CAP-01 review: it's told in the background, so a test waits for
/// it (<see cref="NextAsync"/>); <see cref="Hold"/>, when set, keeps every notice waiting until it completes (a stalled relay).
/// </summary>
internal sealed class CapturingImportNotifications : ICaseNotifications
{
    private readonly List<ImportSubmission> _submissions = [];
    private readonly System.Threading.Channels.Channel<ImportSubmission> _told = System.Threading.Channels.Channel.CreateUnbounded<ImportSubmission>();
    private readonly System.Threading.Channels.Channel<ImportSubmission> _started = System.Threading.Channels.Channel.CreateUnbounded<ImportSubmission>();

    public bool Throw { get; init; }
    public Task? Hold { get; init; }

    public IReadOnlyList<ImportSubmission> Submissions { get { lock (_submissions) return _submissions.ToList(); } }

    /// <summary>The next notice told, waiting up to ten seconds for it.</summary>
    public async Task<ImportSubmission> NextAsync() =>
        await _told.Reader.ReadAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));

    /// <summary>The next notice begun (before <see cref="Hold"/>), waiting up to ten seconds for it.</summary>
    public async Task<ImportSubmission> StartedAsync() =>
        await _started.Reader.ReadAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));

    public async Task OnImportSubmittedAsync(ImportSubmission submission, CancellationToken ct = default)
    {
        _started.Writer.TryWrite(submission);
        if (Hold is { } hold) await hold;
        if (Throw) throw new InvalidOperationException("relay down");
        lock (_submissions) _submissions.Add(submission);
        _told.Writer.TryWrite(submission);
    }

    public Task OnReclassifiedAsync(Case c, Classification? from, Classification to, CancellationToken ct = default) => Task.CompletedTask;
    public Task OnAssignedAsync(Case c, string assigneeUserId, string assigneeDisplayName, CaseAssignmentRole role,
        string assignedByUserId, CancellationToken ct = default) => Task.CompletedTask;
    public Task OnActionItemsOverdueAsync(IReadOnlyList<OverdueActionItem> items, CancellationToken ct = default) => Task.CompletedTask;
    public Task OnActionItemsDueSoonAsync(IReadOnlyList<DueSoonActionItem> items, int leadHours, CancellationToken ct = default) => Task.CompletedTask;
}

/// <summary>
/// CAP-01: an API import that lands is told to the people who can confirm it (scoped as the queue is), counted for the
/// Desk, the sidebar badge and the digest, and never applied by any of that (ADR 0004). CAP-06: applying it is 5515.
/// </summary>
public sealed class ImportReviewNoticeTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 10, 12, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _submitter = new() { UserId = "xsiam-svc", RoleSet = [AppRole.SysAdmin] };
    private readonly PendingImportSignal _signal = new();

    // Who could be told: two analysts and a cleared IC (EditCases), a manager (view only), and the restricted case's team.
    private readonly ListedUserDirectory _users = new(
        ListedUserDirectory.User("rev1", "Analyst"),
        ListedUserDirectory.User("outsider", "Analyst"),
        ListedUserDirectory.User("cleared", "IncidentCommander"),
        ListedUserDirectory.User("mgr", "Manager"),
        ListedUserDirectory.User("ic1", "Analyst"),
        ListedUserDirectory.User("teammate", "Analyst"));

    public ImportReviewNoticeTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        using var db = new AppDbContext(Options());
        db.Database.EnsureCreated();
    }

    private DbContextOptions<AppDbContext> Options() => new DbContextOptionsBuilder<AppDbContext>()
        .UseSqlite(_connection)
        .AddInterceptors(new AuditChainInterceptor(_hasher, _submitter, _clock, new CaseChangeNotifier()))
        .Options;

    private TestDbContextFactory Factory() => new(Options());

    private CaseImportService Import(ICurrentUser user, ICaseNotifications? notifications = null, ISecurityEventSink? siem = null)
    {
        var db = new AppDbContext(Options());
        var cases = new CaseService(Factory(), user, _clock, new CaseNumberGenerator(db), new CreateCaseValidator(),
            new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());
        return new CaseImportService(Factory(), user, _clock, cases, notifications: notifications, users: _users,
            roles: new BuiltInRoles(), signal: _signal, siem: siem);
    }

    private static string Doc(Guid? into = null) => JsonSerializer.Serialize(new CaseImportDocument
    {
        Format = CaseImportJson.FormatTag,
        Origin = "XSIAM",
        Target = into is { } id ? new() { CaseId = id }
            : new() { NewCase = new() { Title = "Suspicious OAuth consent grant", Classification = "Incident", Severity = "High" } },
        Entities = [new() { Type = "Domain", Value = "evil.example.com" }],
    }, CaseImportJson.Options);

    private async Task<Guid> SubmitAsync(CaseImportService svc, string json) =>
        (await svc.SubmitAsync(json, CaseImportService.Parse(json).Document!)).Id;

    private async Task<Case> RestrictedCaseAsync()
    {
        await using var db = new AppDbContext(Options());
        var c = Case.Open(2026, 77, "Secret", "Restricted matter", Classification.Incident, Severity.High,
            CaseOrigin.InternalDetection, "xsiam-svc", _clock.UtcNow.AddDays(-1));
        c.IsRestricted = true;
        c.IncidentCommander = "ic1";
        c.Assign("teammate", "Teammate", CaseAssignmentRole.Analyst, "ic1", _clock.UtcNow.AddDays(-1));
        db.Cases.Add(c);
        await db.SaveChangesAsync();
        return c;
    }

    [Fact]
    public async Task A_submission_is_told_to_everyone_who_can_confirm_it_and_nothing_is_applied()
    {
        var told = new CapturingImportNotifications();
        var raised = 0;
        _signal.Changed += () => raised++;

        var id = await SubmitAsync(Import(_submitter, told), Doc());

        var s = await told.NextAsync();   // CAP-01 review: told in the background
        told.Submissions.Should().ContainSingle();
        s.PendingImportId.Should().Be(id);
        s.ReviewerUserIds.Should().BeEquivalentTo(["rev1", "outsider", "cleared", "ic1", "teammate"], "EditCases, not the manager");
        s.IsRestricted.Should().BeFalse();
        s.Summary.Should().Contain("Suspicious OAuth consent grant");
        s.Origin.Should().Be("XSIAM");
        raised.Should().Be(1, "the open pages' badges count again");
        await using var db = new AppDbContext(Options());
        (await db.Cases.CountAsync()).Should().Be(0, "ADR 0004: telling people applies nothing");
    }

    [Fact]
    public async Task One_into_a_restricted_case_is_told_only_to_that_cases_audience_and_flagged_for_chat()
    {
        var c = await RestrictedCaseAsync();
        var told = new CapturingImportNotifications();

        await SubmitAsync(Import(_submitter, told), Doc(c.Id));

        var s = await told.NextAsync();
        s.TargetCaseId.Should().Be(c.Id);
        s.IsRestricted.Should().BeTrue();
        s.ReviewerUserIds.Should().BeEquivalentTo(["ic1", "teammate", "cleared"], "not the analyst who isn't on it");
    }

    [Fact]
    public async Task A_notification_that_fails_never_fails_the_submission()
    {
        var told = new CapturingImportNotifications { Throw = true };
        var svc = Import(_submitter, told);
        var id = await SubmitAsync(svc, Doc());
        (await told.StartedAsync()).PendingImportId.Should().Be(id);

        await using var db = new AppDbContext(Options());
        (await db.PendingImports.SingleAsync(p => p.Id == id)).Status.Should().Be(PendingImportStatus.Pending);
    }

    [Fact]
    public async Task A_stalled_notification_holds_up_neither_the_response_nor_the_next_submission(/* CAP-01 review */)
    {
        var relay = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var told = new CapturingImportNotifications { Hold = relay.Task };
        var svc = Import(_submitter, told);
        var a = Doc();
        var b = JsonSerializer.Serialize(new CaseImportDocument
        {
            Format = CaseImportJson.FormatTag, Origin = "XSIAM",
            Target = new() { NewCase = new() { Title = "Impossible travel sign-in", Classification = "Incident", Severity = "Medium" } },
        }, CaseImportJson.Options);

        // A is answered while its notice is stuck on the relay.
        var first = await svc.SubmitOnceAsync(a, CaseImportService.Parse(a).Document!).WaitAsync(TimeSpan.FromSeconds(10));
        (await told.StartedAsync()).PendingImportId.Should().Be(first.Id);

        // B, through the same submit gate, isn't held up by A's notice, nor is A's retry. B's caller then stops waiting,
        // which its notice, already handed off, doesn't hear of.
        using var gaveUp = new CancellationTokenSource();
        var submitB = svc.SubmitOnceAsync(b, CaseImportService.Parse(b).Document!, gaveUp.Token);
        var retryA = svc.SubmitOnceAsync(a, CaseImportService.Parse(a).Document!);
        var second = await submitB.WaitAsync(TimeSpan.FromSeconds(10));
        await gaveUp.CancelAsync();
        (await retryA.WaitAsync(TimeSpan.FromSeconds(10))).AlreadyQueued.Should().BeTrue();
        second.AlreadyQueued.Should().BeFalse();
        (await told.StartedAsync()).PendingImportId.Should().Be(second.Id);
        told.Submissions.Should().BeEmpty("both notices are still waiting on the relay");

        // The relay answers: both notices go, B's though its caller stopped waiting, and A's only once.
        relay.SetResult();
        var sent = new[] { await told.NextAsync(), await told.NextAsync() };
        sent.Select(s => s.PendingImportId).Should().BeEquivalentTo([first.Id, second.Id]);
        sent.Should().OnlyContain(s => s.ReviewerUserIds.Contains("rev1"));
        told.Submissions.Should().HaveCount(2, "the retry queued nothing, so told nobody");
    }

    /// <summary>SqlClient's report of a query it cancelled: a <see cref="System.Data.Common.DbException"/>, not an OperationCanceledException.</summary>
    internal sealed class CancelledBySqlServer() : System.Data.Common.DbException("Operation cancelled by user.");

    // Stalls the count of waiting imports until its token is cancelled, then fails as SQL Server does.
    private sealed class StallsLikeSqlServer : Microsoft.EntityFrameworkCore.Diagnostics.DbCommandInterceptor
    {
        public override async ValueTask<Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<System.Data.Common.DbDataReader>> ReaderExecutingAsync(
            System.Data.Common.DbCommand command, Microsoft.EntityFrameworkCore.Diagnostics.CommandEventData eventData,
            Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<System.Data.Common.DbDataReader> result,
            CancellationToken cancellationToken = default)
        {
            if (!command.CommandText.Contains("PendingImports", StringComparison.Ordinal)) return result;
            try { await Task.Delay(Timeout.Infinite, cancellationToken); }
            catch (OperationCanceledException) { }
            throw new CancelledBySqlServer();
        }
    }

    [Fact]
    public async Task A_count_that_runs_out_of_time_shows_nothing_even_when_SQL_Server_reports_it_as_a_SqlException(/* CAP-01 review */)
    {
        var stalled = new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection).AddInterceptors(new StallsLikeSqlServer()).Options);
        var reviewer = new TestCurrentUser { UserId = "rev1", RoleSet = [AppRole.Analyst] };

        (await new PendingImportQueue(stalled, reviewer).WaitingAsync().WaitAsync(TimeSpan.FromSeconds(15)))
            .Should().BeNull("the badge and the Desk show nothing rather than fail");

        // The caller's own cancellation isn't taken for the time limit: it isn't swallowed.
        using var stop = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        var act = () => new PendingImportQueue(stalled, reviewer).WaitingAsync(stop.Token);
        await act.Should().ThrowAsync<System.Data.Common.DbException>();
    }

    [Fact]
    public async Task The_badge_count_is_the_queues_own_scope_and_only_for_reviewers()
    {
        var c = await RestrictedCaseAsync();
        var svc = Import(_submitter);
        await SubmitAsync(svc, Doc());
        _clock.UtcNow = _clock.UtcNow.AddMinutes(5);
        await SubmitAsync(svc, Doc(c.Id));

        var outsider = new TestCurrentUser { UserId = "outsider", RoleSet = [AppRole.Analyst] };
        var teammate = new TestCurrentUser { UserId = "teammate", RoleSet = [AppRole.Analyst] };
        var manager = new TestCurrentUser { UserId = "mgr", RoleSet = [AppRole.Manager] };

        var forOutsider = await new PendingImportQueue(Factory(), outsider).WaitingAsync();
        forOutsider!.Count.Should().Be(1, "the restricted case's submission is its audience's");
        forOutsider.OldestUtc.Should().Be(_clock.UtcNow.AddMinutes(-5));
        (await new PendingImportQueue(Factory(), teammate).WaitingAsync())!.Count.Should().Be(2);
        (await new PendingImportQueue(Factory(), manager).WaitingAsync()).Should().Be(PendingImportCount.None, "a manager can't confirm one");
        (await new PendingImportQueue(Factory(), outsider).WaitingAsync())!.Count
            .Should().Be(await Import(outsider).CountPendingAsync(), "the badge and the queue agree");
    }

    [Fact]
    public async Task The_badge_count_stops_at_its_cap()
    {
        await using (var db = new AppDbContext(Options()))
        {
            for (var i = 0; i < PendingImportQueue.CountCap + 5; i++)
                db.PendingImports.Add(new PendingImport { SubmittedBy = "xsiam-svc", SubmittedAtUtc = _clock.UtcNow.AddMinutes(-i),
                    Summary = "New case", RawJson = "{}", Status = PendingImportStatus.Pending });
            await db.SaveChangesAsync();
        }
        var count = await new PendingImportQueue(Factory(), new TestCurrentUser { UserId = "rev1" }).WaitingAsync();
        count!.Count.Should().Be(PendingImportQueue.CountCap);
        count.More.Should().BeTrue();
    }

    [Fact]
    public async Task The_digest_counts_only_imports_waiting_too_long_that_the_reviewer_could_see()
    {
        var c = await RestrictedCaseAsync();
        var svc = Import(_submitter);
        await SubmitAsync(svc, Doc());
        await SubmitAsync(svc, Doc(c.Id));
        _clock.UtcNow = _clock.UtcNow.AddHours(30);
        await SubmitAsync(svc, Doc());   // fresh: not yet waiting too long

        var audience = new ReminderAudience(_users, new BuiltInRoles());
        async Task<int> For(string user) => (await PendingImportQueue.WaitingForAsync(Factory(), user, TimeSpan.FromHours(24),
            _clock.UtcNow, _users, new BuiltInRoles(), audience)).Count;

        (await For("outsider")).Should().Be(1);
        (await For("teammate")).Should().Be(2);
        (await For("mgr")).Should().Be(0, "a manager doesn't review imports");
        (await PendingImportQueue.WaitingForAsync(Factory(), "teammate", TimeSpan.Zero, _clock.UtcNow, _users, new BuiltInRoles(), audience))
            .Count.Should().Be(0, "0 hours leaves the line out");
    }

    [Fact]
    public async Task Applying_a_queued_import_emits_5515_naming_the_pending_import()
    {
        var siem = new CapturingSecurityEventSink();
        var reviewer = new TestCurrentUser { UserId = "rev1", RoleSet = [AppRole.Analyst] };
        var id = await SubmitAsync(Import(_submitter), Doc());
        var svc = Import(reviewer, siem: siem);
        var preview = (await svc.BuildPreviewForPendingAsync(id))!;
        var claim = await svc.ClaimPendingAsync(id);

        var result = await svc.ApplyAsync(preview, id);
        await svc.MarkPendingAppliedAsync(id, result, claim);

        var e = siem.Events.Should().ContainSingle(x => x.EventId == SecurityEventIds.ImportApplied).Subject;
        e.CaseNumber.Should().Be(result.CaseNumber);
        (e.TargetType, e.TargetId).Should().Be(("PendingImport", id.ToString()));
        e.Detail.Should().Be("createdCase=true");
        e.Actor.Should().Be("rev1");
    }

    public void Dispose() => _connection.Dispose();
}
