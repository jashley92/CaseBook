using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Cases;
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
/// Case linking / campaign grouping (E-14): typed links between two cases, need-to-know scoped,
/// deduped, and captured by the tamper-evident audit chain.
/// </summary>
public sealed class CaseLinkTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 8, 14, 0, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();

    public CaseLinkTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _user.RoleSet = [AppRole.SysAdmin]; // sees all + may edit (F-21); tests override to a lesser role for scoping
    }

    private AppDbContext NewContext()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options;
        var db = new AppDbContext(options);
        db.Database.EnsureCreated();
        return db;
    }

    private IAppDbContextFactory NewFactory() =>
        new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
            .Options);

    private CaseService NewService(AppDbContext db) =>
        new(NewFactory(), _user, _clock, new CaseNumberGenerator(db), new CreateCaseValidator(), new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());


    private static CreateCaseRequest Req(string name) => new()
    {
        DescriptiveName = name,
        Title = $"{name} case",
        Classification = Classification.Incident,
        Severity = Severity.Medium,
        Origin = CaseOrigin.InternalDetection
    };

    [Fact]
    public async Task Linking_two_cases_shows_from_both_sides_with_correct_direction_and_keeps_the_chain_valid()
    {
        Guid alpha, beta;
        await using (var db = NewContext())
        {
            var svc = NewService(db);
            alpha = (await svc.CreateAsync(Req("Alpha"))).Id;
            beta = (await svc.CreateAsync(Req("Beta"))).Id;

            await svc.LinkCaseAsync(alpha, beta, CaseLinkType.DuplicateOf, "same phishing kit");
        }

        await using (var db = NewContext())
        {
            var svc = NewService(db);

            var fromAlpha = await svc.GetCaseLinksAsync(alpha);
            fromAlpha.Should().ContainSingle();
            fromAlpha[0].OtherCaseId.Should().Be(beta);
            fromAlpha[0].Outgoing.Should().BeTrue();   // Alpha is the duplicate...
            fromAlpha[0].Type.Should().Be(CaseLinkType.DuplicateOf);
            fromAlpha[0].Description.Should().Be("same phishing kit");

            var fromBeta = await svc.GetCaseLinksAsync(beta);
            fromBeta.Should().ContainSingle();
            fromBeta[0].OtherCaseId.Should().Be(alpha);
            fromBeta[0].Outgoing.Should().BeFalse();   // ...seen from Beta as "duplicated by"

            var chain = await db.AuditLog.OrderBy(a => a.Sequence).ToListAsync();
            _hasher.VerifyChain(chain).IsValid.Should().BeTrue();
            chain.Should().Contain(a => a.EntityType == "CaseLink" && a.Action == AuditAction.Create);
        }
    }

    [Fact]
    public async Task A_pair_can_only_be_linked_once_in_either_direction()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var alpha = (await svc.CreateAsync(Req("Alpha"))).Id;
        var beta = (await svc.CreateAsync(Req("Beta"))).Id;

        var first = await svc.LinkCaseAsync(alpha, beta, CaseLinkType.RelatedTo, null);
        first.Should().NotBeNull();

        // Reverse direction, any type → rejected (returns null, no second row).
        var second = await svc.LinkCaseAsync(beta, alpha, CaseLinkType.PartOfCampaign, null);
        second.Should().BeNull();

        (await db.CaseLinks.CountAsync()).Should().Be(1);
    }

    [Fact]
    public async Task A_case_cannot_be_linked_to_itself()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var alpha = (await svc.CreateAsync(Req("Alpha"))).Id;

        var act = () => svc.LinkCaseAsync(alpha, alpha, CaseLinkType.RelatedTo, null);
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task Removing_a_link_clears_it_from_both_cases()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var alpha = (await svc.CreateAsync(Req("Alpha"))).Id;
        var beta = (await svc.CreateAsync(Req("Beta"))).Id;
        await svc.LinkCaseAsync(alpha, beta, CaseLinkType.RelatedTo, null);

        var link = (await svc.GetCaseLinksAsync(beta)).Single();
        await svc.RemoveCaseLinkAsync(beta, link.LinkId); // removed from the target side

        (await svc.GetCaseLinksAsync(alpha)).Should().BeEmpty();
        (await svc.GetCaseLinksAsync(beta)).Should().BeEmpty();
    }

    [Fact]
    public async Task A_link_to_a_restricted_case_the_caller_cannot_see_is_hidden_and_cannot_be_created()
    {
        Guid mine, restricted;
        await using (var db = NewContext())
        {
            // Manager creates both; one is restricted and owned by someone else.
            var svc = NewService(db);
            mine = (await svc.CreateAsync(Req("Mine"))).Id;
            var r = IncidentManager.Domain.Entities.Case.Open(2026, 99, "Restricted", "Restricted",
                Classification.Breach, Severity.High, CaseOrigin.InternalDetection, "someone-else", _clock.UtcNow);
            r.IsRestricted = true;
            db.Cases.Add(r);
            await db.SaveChangesAsync();
            restricted = r.Id;

            // A privileged user links them so there IS a link in the store.
            await svc.LinkCaseAsync(mine, restricted, CaseLinkType.RelatedTo, null);
        }

        // Now act as an analyst who is neither IC nor assigned on the restricted case.
        _user.UserId = "analyst-not-assigned";
        _user.RoleSet = [AppRole.Analyst];

        await using (var db = NewContext())
        {
            var svc = NewService(db);

            // The existing link to the restricted case is omitted from the visible case's view.
            (await svc.GetCaseLinksAsync(mine)).Should().BeEmpty();

            // And a fresh link to the invisible case is refused.
            var act = () => svc.LinkCaseAsync(mine, restricted, CaseLinkType.DuplicateOf, null);
            await act.Should().ThrowAsync<InvalidOperationException>();
        }
    }

    [Fact]
    public async Task The_picker_excludes_self_and_already_linked_cases()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var alpha = (await svc.CreateAsync(Req("Alpha"))).Id;
        var beta = (await svc.CreateAsync(Req("Beta"))).Id;
        var gamma = (await svc.CreateAsync(Req("Gamma"))).Id;
        await svc.LinkCaseAsync(alpha, beta, CaseLinkType.RelatedTo, null);

        var options = await svc.SearchLinkableCasesAsync(alpha, null);

        options.Select(o => o.Id).Should().ContainSingle().Which.Should().Be(gamma); // not self, not linked Beta
    }

    // BUG-525: holds the first save that adds a link, after its "already linked?" look and before its insert, so a second
    // link can be tried inside that window. Registered ahead of the audit interceptor, so it doesn't hold the chain gate.
    private sealed class HoldLinkSave : Microsoft.EntityFrameworkCore.Diagnostics.SaveChangesInterceptor
    {
        public readonly TaskCompletionSource Reached = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public readonly TaskCompletionSource Release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _held;

        public override async ValueTask<Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<int>> SavingChangesAsync(
            Microsoft.EntityFrameworkCore.Diagnostics.DbContextEventData eventData,
            Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (eventData.Context!.ChangeTracker.Entries<IncidentManager.Domain.Entities.CaseLink>().Any(e => e.State == EntityState.Added)
                && Interlocked.Exchange(ref _held, 1) == 0)
            {
                Reached.SetResult();
                await Release.Task;
            }
            return result;
        }
    }

    private CaseService HeldService(AppDbContext db, HoldLinkSave hold) =>
        new(new TestDbContextFactory(new DbContextOptionsBuilder<AppDbContext>()
                .UseSqlite(_connection)
                .AddInterceptors(hold, new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier()))
                .Options),
            _user, _clock, new CaseNumberGenerator(db), new CreateCaseValidator(), new NoOpCaseNotifications(),
            new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());

    // Runs the second link while the first is held; it must wait for the first instead of looking past it.
    private static async Task<T> SecondWhileFirstHeldAsync<T>(HoldLinkSave hold, Task first, Func<Task<T>> second)
    {
        await hold.Reached.Task.WaitAsync(TimeSpan.FromSeconds(10));
        var run = Task.Run(second);
        (await Task.WhenAny(run, Task.Delay(400))).Should().NotBe(run, "the second link waits while the first is saving");
        hold.Release.SetResult();
        await first;
        return await run;
    }

    [Theory]
    [InlineData(false)]   // the same direction (and type): the unique index would refuse the second with a raw error
    [InlineData(true)]    // the reverse direction: nothing in the schema stops a second row
    public async Task Two_people_linking_the_same_cases_at_once_make_one_link(bool reverse)
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var alpha = (await svc.CreateAsync(Req("Alpha"))).Id;
        var beta = (await svc.CreateAsync(Req("Beta"))).Id;
        var hold = new HoldLinkSave();

        var first = HeldService(db, hold).LinkCaseAsync(alpha, beta, CaseLinkType.RelatedTo, null);
        var second = await SecondWhileFirstHeldAsync(hold, first, () => reverse
            ? svc.LinkCaseAsync(beta, alpha, CaseLinkType.PartOfCampaign, null)
            : svc.LinkCaseAsync(alpha, beta, CaseLinkType.RelatedTo, null));

        (await first).Should().NotBeNull();
        second.Should().BeNull("the pair was already linked");
        (await db.CaseLinks.AsNoTracking().CountAsync()).Should().Be(1);
    }

    [Fact]
    public async Task A_follow_up_link_and_a_reverse_link_at_once_make_one_link()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var alpha = (await svc.CreateAsync(Req("Alpha"))).Id;
        var beta = (await svc.CreateAsync(Req("Beta"))).Id;
        var hold = new HoldLinkSave();

        var first = HeldService(db, hold).AddTimelineEntryAsync(alpha, TimelineKind.Investigation, TimelineEntryType.Other,
            _clock.UtcNow, "Same sender as Beta", null, followUps: new EntryFollowUps(LinkCaseId: beta));
        var second = await SecondWhileFirstHeldAsync(hold, first,
            () => svc.LinkCaseAsync(beta, alpha, CaseLinkType.RelatedTo, null));

        second.Should().BeNull("the follow-up linked the pair first");
        (await db.CaseLinks.AsNoTracking().CountAsync()).Should().Be(1);
    }

    [Fact]
    public async Task A_link_the_unique_index_refuses_because_it_was_just_made_elsewhere_reads_as_already_linked()
    {
        await using var db = NewContext();
        var svc = NewService(db);
        var alpha = (await svc.CreateAsync(Req("Alpha"))).Id;
        var beta = (await svc.CreateAsync(Req("Beta"))).Id;
        var hold = new HoldLinkSave();

        var first = HeldService(db, hold).LinkCaseAsync(alpha, beta, CaseLinkType.RelatedTo, null);
        await hold.Reached.Task.WaitAsync(TimeSpan.FromSeconds(10));
        // The same link, written past the gate (another server, say) while the first is between its look and its insert.
        await using (var other = NewContext())
        {
            other.CaseLinks.Add(new IncidentManager.Domain.Entities.CaseLink
            {
                CaseId = alpha, RelatedCaseId = beta, Type = CaseLinkType.RelatedTo, CreatedBy = "someone", CreatedAtUtc = _clock.UtcNow
            });
            await other.SaveChangesAsync();
        }
        hold.Release.SetResult();

        (await first).Should().BeNull();
        (await db.CaseLinks.AsNoTracking().CountAsync()).Should().Be(1);
    }

    public void Dispose() => _connection.Dispose();
}
