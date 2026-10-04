using FluentAssertions;
using IncidentManager.Application.Admin;
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

/// <summary>HR-01: a case closes with an outcome (admin-managed) and a closing brief.</summary>
public sealed class CaseOutcomeTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 1, 9, 0, 0, TimeSpan.Zero));
    private readonly TestCurrentUser _user = new();

    public CaseOutcomeTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _user.RoleSet = [AppRole.IncidentCommander, AppRole.SysAdmin];
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

    private CaseService Cases(AppDbContext db) => new(new TestDbContextFactory(Options()), _user, _clock,
        new CaseNumberGenerator(db), new CreateCaseValidator(), new NoOpCaseNotifications(),
        new IncidentManager.Application.StageGates.StageGateEvaluator(), new TestSlaTargets());

    private CaseOutcomeService Outcomes() => new(new TestDbContextFactory(Options()), _user, _clock);

    private async Task<(AppDbContext Db, CaseService Svc, Guid CaseId)> OpenCaseAsync()
    {
        var db = NewContext();
        await DevDataSeeder.SeedCaseOutcomesAsync(db, _clock);
        var svc = Cases(db);
        var c = await svc.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "Takeover", Title = "Impossible-travel sign-in", Classification = Classification.Incident,
            Severity = Severity.High, Origin = CaseOrigin.InternalDetection, Summary = "XSIAM flagged an impossible-travel sign-in."
        });
        await svc.ReviseBriefAsync(c.Id, (await svc.GetDetailAsync(c.Id))!.Briefs.Single(b => b.IsCurrent).Id,
            "XSIAM flagged an impossible-travel sign-in.", "Probably MFA fatigue.", "- Tor sign-in at 08:51", "- Any payment requested?");
        _clock.UtcNow = _clock.UtcNow.AddHours(2);
        return (db, svc, c.Id);
    }

    [Fact]
    public async Task Closing_needs_an_active_outcome_and_both_parts_of_the_closing_brief()
    {
        var (db, svc, id) = await OpenCaseAsync();
        await using var _ = db;

        await svc.Invoking(s => s.ChangePhaseAsync(id, CasePhase.Closed, "done"))
            .Should().ThrowAsync<ArgumentException>().WithMessage("*outcome*");
        await svc.Invoking(s => s.ChangePhaseAsync(id, CasePhase.Closed, null, closing: new("NoSuchOutcome", "a", "b")))
            .Should().ThrowAsync<ArgumentException>();
        await svc.Invoking(s => s.ChangePhaseAsync(id, CasePhase.Closed, null, closing: new(CaseOutcomeCatalog.Confirmed, "a", " ")))
            .Should().ThrowAsync<ArgumentException>().WithMessage("*concluded*");
        await svc.Invoking(s => s.ChangePhaseAsync(id, CasePhase.Containment, null, closing: TestOutcomes.Closing()))
            .Should().ThrowAsync<ArgumentException>("an outcome belongs to a close");

        var archived = (await Outcomes().ListAllAsync()).Single(o => o.Key == CaseOutcomeCatalog.Inconclusive);
        await Outcomes().SetArchivedAsync(archived.Id, true);
        await svc.Invoking(s => s.ChangePhaseAsync(id, CasePhase.Closed, null,
                closing: new(CaseOutcomeCatalog.Inconclusive, "a", "b")))
            .Should().ThrowAsync<ArgumentException>().WithMessage("*isn't available*");

        (await svc.GetDetailAsync(id))!.Phase.Should().NotBe(CasePhase.Closed);
    }

    [Fact]
    public async Task Closing_records_the_outcome_and_the_closing_brief_and_reopening_clears_only_the_current_outcome()
    {
        var (db, svc, id) = await OpenCaseAsync();
        await using var _ = db;

        await svc.ChangePhaseAsync(id, CasePhase.Closed, null, closing: new(CaseOutcomeCatalog.Confirmed,
            "Credential phishing and MFA fatigue gave an attacker the session.",
            "Account takeover; no payment was made."));

        var c = (await svc.GetDetailAsync(id))!;
        c.OutcomeKey.Should().Be(CaseOutcomeCatalog.Confirmed);
        c.Summary.Should().Be("Credential phishing and MFA fatigue gave an attacker the session.");
        var brief = c.Briefs.Single(b => b.IsCurrent);
        brief.Version.Should().Be(3);
        brief.WorkingAssessment.Should().Be("Account takeover; no payment was made.");
        brief.Known.Should().Be("- Tor sign-in at 08:51", "Known carries over into the closing brief");
        brief.OpenQuestions.Should().Be("- Any payment requested?");
        var close = c.StatusChanges.Single(s => s.To == CasePhase.Closed);
        close.OutcomeKey.Should().Be(CaseOutcomeCatalog.Confirmed);
        close.Reason.Should().Be("Account takeover; no payment was made.", "the conclusion stands in for the reason");

        var milestone = CaseMilestones.Project(c, new MilestoneLabels(x => "", s => "", p => p.ToString(), m => ""))
            .Single(m => m.Key == $"phase:{close.Id}");
        milestone.Title.Should().EndWith("· Confirmed");
        // Written with the close, at the same instant: the closing brief isn't "out of date" because of it.
        BriefFreshness.Since(c, brief, new MilestoneLabels(x => "", s => "", p => p.ToString(), m => "")).Count.Should().Be(0);

        await svc.ReopenAsync(id, "New sign-in from the same Tor node");
        var reopened = (await svc.GetDetailAsync(id))!;
        reopened.OutcomeKey.Should().BeNull();
        reopened.StatusChanges.Single(s => s.To == CasePhase.Closed).OutcomeKey.Should().Be(CaseOutcomeCatalog.Confirmed,
            "the earlier close keeps its outcome on record");

        var chain = await db.AuditLog.OrderBy(a => a.Sequence).ToListAsync();
        _hasher.VerifyChain(chain).IsValid.Should().BeTrue();
    }

    [Fact]
    public async Task An_unchanged_closing_brief_does_not_add_a_version_and_the_list_filters_by_outcome()
    {
        var (db, svc, id) = await OpenCaseAsync();
        await using var _ = db;
        var other = (await svc.CreateAsync(new CreateCaseRequest
        {
            DescriptiveName = "Other", Title = "Other", Classification = Classification.AdverseEvent,
            Severity = Severity.Low, Origin = CaseOrigin.InternalDetection
        })).Id;

        await svc.ChangePhaseAsync(id, CasePhase.Closed, "Closed after review",
            closing: new(CaseOutcomeCatalog.FalsePositive, "XSIAM flagged an impossible-travel sign-in.", "Probably MFA fatigue."));

        (await svc.GetDetailAsync(id))!.Briefs.Should().HaveCount(2, "the brief already said this");
        var list = await svc.ListAsync(new CaseFilter { OutcomeKey = CaseOutcomeCatalog.FalsePositive });
        list.Items.Select(i => i.Id).Should().Equal(id);
        (await svc.ListAsync(new CaseFilter())).Items.Select(i => i.Id).Should().Contain(other).And.NotContain(id);
    }

    [Fact]
    public async Task Admins_can_add_relabel_and_archive_outcomes_but_not_lose_recorded_or_built_in_ones()
    {
        var (db, svc, id) = await OpenCaseAsync();
        await using var _ = db;
        var admin = Outcomes();
        var all = await admin.ListAllAsync();
        all.Select(o => o.Label).Should().Equal("Confirmed", "Policy violation", "Benign or expected", "False positive", "Inconclusive", "Duplicate");

        var rows = all.Select(o => new CaseOutcomeRow(o.Id, o.Key == CaseOutcomeCatalog.Confirmed ? "Confirmed activity" : o.Label, o.Description))
            .Append(new CaseOutcomeRow(null, "Insider misuse", "A person with access misused it."))
            .ToList();
        await admin.SaveAsync(rows);

        var insider = (await admin.ListAllAsync()).Single(o => o.Label == "Insider misuse");
        insider.Key.Should().Be("InsiderMisuse");
        await svc.ChangePhaseAsync(id, CasePhase.Closed, null, closing: new("InsiderMisuse", "What happened.", "Concluded."));
        (await admin.LabelsAsync())["Confirmed"].Should().Be("Confirmed activity");

        await admin.Invoking(a => a.DeleteAsync(insider.Id)).Should().ThrowAsync<InvalidOperationException>().WithMessage("*Archive it instead*");
        var builtIn = (await admin.ListAllAsync()).Single(o => o.Key == CaseOutcomeCatalog.Duplicate);
        await admin.Invoking(a => a.DeleteAsync(builtIn.Id)).Should().ThrowAsync<InvalidOperationException>();

        await admin.SaveAsync([new CaseOutcomeRow(null, "Unused", null)]);   // archives nothing; adds one
        var unused = (await admin.ListAllAsync()).Single(o => o.Label == "Unused");
        await admin.DeleteAsync(unused.Id);
        (await admin.ListAllAsync()).Should().NotContain(o => o.Label == "Unused");

        foreach (var o in (await admin.ListAllAsync()).Where(o => o.IsActive).Skip(1))
            await admin.SetArchivedAsync(o.Id, true);
        var last = (await admin.ListActiveAsync()).Single();
        await admin.Invoking(a => a.SetArchivedAsync(last.Id, true)).Should().ThrowAsync<InvalidOperationException>().WithMessage("*at least one*");
    }

    public void Dispose() => _connection.Dispose();
}
