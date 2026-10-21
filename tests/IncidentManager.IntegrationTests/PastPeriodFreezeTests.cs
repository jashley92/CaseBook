using System.Reflection;
using FluentAssertions;
using IncidentManager.Application.Admin;
using IncidentManager.Application.Compliance;
using IncidentManager.Application.Dashboards;
using IncidentManager.Application.Mitre;
using IncidentManager.Application.Sla;
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
/// C11 (past-period stability): a figure for a closed period is computed only from values as they stood in it. Every
/// past-period figure (the Q2 program report, its ATT&amp;CK top techniques, the Program overview's windows and the
/// dashboard's trend months) is snapshotted, a later (Q3) change from the catalogue below is made, and nothing may move.
/// The reflection guard puts every public mutating method of <see cref="Case"/> (the record the figures read) either in
/// the catalogue or in a reasoned list of those that don't touch a period input, so a new mutator has to be judged.
/// </summary>
public sealed class PastPeriodFreezeTests : IDisposable
{
    private readonly SqliteConnection _connection = new("Data Source=:memory:");
    private readonly HashChainService _hasher = new();
    private readonly FixedClock _clock = new(Apr(1));
    private readonly TestCurrentUser _user = new() { UserId = "mgr", RoleSet = [AppRole.Manager] };
    private readonly Notify _notify = new();
    private static readonly ProgramPeriod Q2 = new(2026, 2);
    private static readonly DateTimeOffset Later = new(2026, 8, 10, 0, 0, 0, TimeSpan.Zero);   // in Q3
    private static readonly DateTimeOffset ReportedOn = new(2026, 9, 24, 0, 0, 0, TimeSpan.Zero);

    private static DateTimeOffset Apr(int d, int h = 0) => new(2026, 4, d, h, 0, 0, TimeSpan.Zero);
    private static DateTimeOffset Jul(int d) => new(2026, 7, d, 0, 0, 0, TimeSpan.Zero);

    private sealed class Notify : INotificationDeadlineSettingsProvider
    {
        public NotificationDeadlineSettings Current { get; set; } = new(true, NotificationStartBasis.Detection, 72, 80);
    }

    private sealed class NoServerValues : IncidentManager.Application.Abstractions.IServerSettingValues
    {
        public string? ValueOf(string key) => null;
    }

    public PastPeriodFreezeTests() => _connection.Open();

    private DbContextOptions<AppDbContext> Options() => new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_connection)
        .AddInterceptors(new AuditChainInterceptor(_hasher, _user, _clock, new CaseChangeNotifier())).Options;

    private AppDbContext Db() => new(Options());

    // Today's targets are the tightened ones; the trail says what held in Q2.
    private static readonly SlaTargets Today = new(new Dictionary<(SlaClock, Severity), int>
    {
        [(SlaClock.Containment, Severity.High)] = 1, [(SlaClock.Containment, Severity.Medium)] = 1,
        [(SlaClock.Resolution, Severity.High)] = 1, [(SlaClock.Detection, Severity.High)] = 1,
    }, 80);

    private ProgramReportService Program()
    {
        var f = new TestDbContextFactory(Options());
        return new ProgramReportService(f, _user, _clock, new TestSlaTargets(Today), new AttackCoverageService(f, _user, _clock),
            notify: _notify, rules: new NotificationRuleService(f, _user, _clock), server: new NoServerValues());
    }

    private DashboardService Dashboard()
    {
        var f = new TestDbContextFactory(Options());
        return new DashboardService(f, _user, _clock, new TestSlaTargets(Today), _notify, new NotificationRuleService(f, _user, _clock),
            server: new NoServerValues());
    }

    private sealed record Figures(ProgramSnapshot Quarter, IReadOnlyList<ProgramTechnique> Top, IReadOnlyList<ProgramSnapshot> Windows,
        IReadOnlyList<TrendPoint> Months);

    private async Task<Figures> FiguresAsync()
    {
        var saved = _clock.UtcNow;
        _clock.UtcNow = ReportedOn;
        var report = await Program().BuildAsync(Q2);
        var windows = await Program().SnapshotsAsync([new ProgramWindow(Apr(1), Jul(1), "Q2"), new ProgramWindow(Apr(1), Apr(8), "early April")]);
        var months = (await Dashboard().GetAsync()).Trend.Where(t => t is { Year: 2026, Month: >= 4 and <= 6 }).ToList();
        _clock.UtcNow = saved;
        return new Figures(report.Current, report.TopTechniques, windows, months);
    }

    private Guid _a, _b, _stepA1, _tagA;

    // Q2: A (High) is detected 6 h after it began, contained in 3 h, made a Breach, resolved, notified, reviewed, closed;
    // B (Medium) is contained and raised to High. Both carry ATT&CK steps or tags.
    private async Task SeedAsync()
    {
        await using var db = Db();
        await db.Database.EnsureCreatedAsync();
        _clock.UtcNow = new DateTimeOffset(2026, 3, 1, 0, 0, 0, TimeSpan.Zero);
        db.AppSettings.AddRange(
            new AppSetting { Key = "Sla:Containment:High", Value = "4", UpdatedAtUtc = _clock.UtcNow, UpdatedBy = "admin" },
            new AppSetting { Key = "Sla:Containment:Medium", Value = "24", UpdatedAtUtc = _clock.UtcNow, UpdatedBy = "admin" },
            new AppSetting { Key = "Sla:Resolution:High", Value = "168", UpdatedAtUtc = _clock.UtcNow, UpdatedBy = "admin" },
            new AppSetting { Key = "Sla:Detection:High", Value = "24", UpdatedAtUtc = _clock.UtcNow, UpdatedBy = "admin" });
        await db.SaveChangesAsync();

        _clock.UtcNow = Apr(2);
        var a = Case.Open(2026, 1, "A", "Phish", Classification.Incident, Severity.High, CaseOrigin.InternalDetection, "ic", Apr(2));
        a.DetectedAtUtc = Apr(2);
        a.OccurredAtUtc = Apr(1, 18);
        var step = a.AddEventStep(Apr(1, 18), [MitreTactic.InitialAccess], "T1566", null, null, "Phish opened", null, "ic", Apr(2));
        a.AddEventStep(Apr(2, 1), [MitreTactic.Discovery], "T1082", null, null, "Looked around", null, "ic", Apr(2));
        var tag = a.AddTechnique("T1078", "Valid Accounts", MitreTactic.InitialAccess, "ic", Apr(2));
        var b = Case.Open(2026, 2, "B", "Odd login", Classification.Incident, Severity.Medium, CaseOrigin.InternalDetection, "ic", Apr(2));
        b.DetectedAtUtc = Apr(2);
        b.AddTechnique("T1110", "Brute Force", MitreTactic.CredentialAccess, "ic", Apr(2));
        db.Cases.AddRange(a, b);
        await db.SaveChangesAsync();
        (_a, _b, _stepA1, _tagA) = (a.Id, b.Id, step.Id, tag.Id);

        async Task At(DateTimeOffset t, Action act) { _clock.UtcNow = t; act(); await db.SaveChangesAsync(); }
        // FR-51: A is contained as it enters Containment; B is still being contained (MarkContained, below, finishes it later).
        await At(Apr(2, 3), () =>
        {
            a.ChangePhase(CasePhase.Containment, null, "ic", Apr(2, 3));
            a.MarkContained("ic", Apr(2, 3));
            b.ChangePhase(CasePhase.Containment, null, "ic", Apr(2, 3));
        });
        await At(Apr(3), () => a.Reclassify(Classification.Breach, "PII in scope", "ic", Apr(3)));
        await At(Apr(4), () => { a.ChangePhase(CasePhase.Eradication, null, "ic", Apr(4)); b.ChangeSeverity(Severity.High, "Scope", "ic", Apr(4)); });
        await At(Apr(5), () => a.ChangePhase(CasePhase.Recovery, null, "ic", Apr(5)));
        await At(Apr(10), () =>
        {
            var n = a.RecordNotice("NY", Apr(9), "legal", Apr(10));
            n.DueAtUtc = Apr(12);
            a.ReportedFromNotices(["NY"], "legal", Apr(10));
        });
        await At(Apr(15), () =>
        {
            db.PostIncidentReviews.Add(new PostIncidentReview { CaseId = a.Id, WhatHappened = "A phish.", CreatedAtUtc = Apr(15), CreatedBy = "ic" });
            db.ImprovementActions.Add(new ImprovementAction { CaseId = a.Id, Title = "MFA", RelatedArea = "Identity", CreatedAtUtc = Apr(15),
                CreatedBy = "ic", Status = ImprovementActionStatus.Completed, ClosedAtUtc = Apr(25) });
        });
        await At(Apr(20, 1), () =>
        {
            a.ChangePhase(CasePhase.PostIncident, null, "ic", Apr(20));
            a.ChangePhase(CasePhase.Closed, "Done", "ic", Apr(20, 1), outcomeKey: "Confirmed");
        });
        _clock.UtcNow = Later;
    }

    // ---- The catalogue: each later change, by the Case method (or other input) it exercises ----

    private static readonly Dictionary<string, Func<PastPeriodFreezeTests, AppDbContext, Task>> Catalogue = new()
    {
        ["ChangePhase"] = (t, db) => t.OnCase(db, t._a, c => c.ChangePhase(CasePhase.Containment, "More found", "ic", Later)),
        ["MarkContained"] = (t, db) => t.OnCase(db, t._b, c => c.MarkContained("ic", Later, Jul(2))),   // FR-51
        ["Reopen"] = (t, db) => t.OnCase(db, t._a, c => c.Reopen("New evidence", "ic", Later)),
        ["Reclassify"] = (t, db) => t.OnCase(db, t._a, c => c.Reclassify(Classification.Incident, "Not a breach after all", "ic", Later)),
        ["ChangeSeverity"] = (t, db) => t.OnCase(db, t._b, c => c.ChangeSeverity(Severity.Low, "Smaller", "ic", Later)),
        ["CorrectTransitionTime"] = async (t, db) =>
        {
            await t.OnCase(db, t._a, c =>
            {
                c.CorrectTransitionTime(TransitionKind.Classification, c.ClassificationChanges.Single(x => x.To == Classification.Breach).Id,
                    Jul(2), "Dated wrongly", "ic", Later);
                c.CorrectTransitionTime(TransitionKind.Phase, c.StatusChanges.Single(x => x.To == CasePhase.Closed).Id,
                    Jul(3), "Dated wrongly", "ic", Later);
            });
            await t.OnCase(db, t._b, c => c.CorrectTransitionTime(TransitionKind.Severity,
                c.SeverityChanges.Single(x => x.From is not null).Id, Jul(4), "Dated wrongly", "ic", Later));
        },
        ["UpdateDetails"] = (t, db) => t.OnCase(db, t._a, c => c.UpdateDetails(c.Title, c.Summary, c.DetectionCaseId, c.DataTypesInvolved,
            c.ImpactedAssets, Apr(1, 20), Apr(1, 19), "ic", Later)),
        ["RecordNotice"] = (t, db) => t.OnCase(db, t._a, c => c.RecordNotice("NY", Jul(1), "legal", Later)),
        ["RemoveNotice"] = (t, db) => t.OnCase(db, t._a, c => { c.RemoveNotice("NY", "legal", Later); c.ReportedFromNotices(["NY"], "legal", Later); }),
        ["ReportedFromNotices"] = (t, db) => t.OnCase(db, t._a, c => c.ReportedFromNotices(["NY", "CA"], "legal", Later)),
        ["ClearReported"] = (t, db) => t.OnCase(db, t._a, c => c.ClearReported("legal", Later)),
        ["Unreport"] = (t, db) => t.OnCase(db, t._a, c => c.Unreport([], "legal", Later)),
        ["MarkReported"] = (t, db) => t.OnCase(db, t._a, c => c.MarkReported(Jul(2), "legal", Later)),
        ["SetImpactAssessment"] = (t, db) => t.OnCase(db, t._a, c => c.SetImpactAssessment(10, ["SSN"], "NY", "ic", Later)),
        ["EditEventStep"] = (t, db) => t.OnCase(db, t._a, c => c.EditEventStep(t._stepA1, Apr(1, 18), [MitreTactic.Execution], "T1059",
            null, null, "Ran a script", null, "ic", Later)),
        // BUG-583: the first step's time now stated as a day only, so the recorded start reads as approximate today.
        ["EditEventStep (time stated as a day)"] = (t, db) => t.OnCase(db, t._a, c => c.EditEventStep(t._stepA1, Apr(1, 18),
            [MitreTactic.InitialAccess], "T1566", null, null, "Phish opened", null, "ic", Later, timing: new StepTiming(TimePrecision.Day))),
        ["AddEventStep"] = (t, db) => t.OnCase(db, t._a, c => c.AddEventStep(Apr(3), [MitreTactic.Impact], "T1486", null, null,
            "Encrypted a share", null, "ic", Later)),
        ["RetractTimelineEntry"] = (t, db) => t.OnCase(db, t._a, c => c.RetractTimelineEntry(t._stepA1, "Wrong case", "ic", Later)),
        ["AddTechnique"] = (t, db) => t.OnCase(db, t._a, c =>
        {
            c.AddTechnique("T1486", "Data Encrypted for Impact", MitreTactic.Impact, "ic", Later);
            c.AddTechnique("T1078", "Valid Accounts", MitreTactic.Persistence, "ic", Later);   // re-tagged under another tactic
        }),
        ["RemoveTechnique"] = (t, db) => t.OnCase(db, t._a, c => c.RemoveTechnique(t._tagA, "ic", Later)),
        // Inputs that aren't Case methods.
        ["review cleared (BUG-586)"] = async (_, db) =>
        {
            (await db.PostIncidentReviews.SingleAsync()).WhatHappened = null;
            await db.SaveChangesAsync();
        },
        ["action reopened (WF-80)"] = async (_, db) =>
        {
            var x = await db.ImprovementActions.SingleAsync();
            (x.Status, x.ClosedAtUtc) = (ImprovementActionStatus.Open, null);
            await db.SaveChangesAsync();
        },
        ["targets tightened (BUG-322)"] = async (_, db) =>
        {
            foreach (var s in await db.AppSettings.ToListAsync()) s.Value = "1";
            await db.SaveChangesAsync();
        },
        ["deadline tracking switched off (BUG-585)"] = (t, _) => { t._notify.Current = NotificationDeadlineSettings.Off; return Task.CompletedTask; },
    };

    private async Task OnCase(AppDbContext db, Guid id, Action<Case> change)
    {
        var c = await db.Cases.AsSplitQuery()
            .Include(x => x.StatusChanges).Include(x => x.ClassificationChanges).Include(x => x.SeverityChanges)
            .Include(x => x.JurisdictionNotices).Include(x => x.DataElements).Include(x => x.Techniques)
            .Include(x => x.TimelineEntries).ThenInclude(e => e.Tactics)
            .SingleAsync(x => x.Id == id);
        change(c);
        await db.SaveChangesAsync();
    }

    public static TheoryData<string> Mutations => new(Catalogue.Keys);

    [Theory]
    [MemberData(nameof(Mutations))]
    public async Task A_later_change_moves_no_past_period_figure(string mutation)
    {
        await SeedAsync();
        var before = await FiguresAsync();
        await using (var db = Db()) await Catalogue[mutation](this, db);
        var after = await FiguresAsync();

        after.Should().BeEquivalentTo(before, o => o.WithStrictOrdering(), "{0} in Q3 mustn't move Q2", mutation);
    }

    [Fact]
    public async Task The_seed_gives_every_figure_the_catalogue_could_move_a_value()
    {
        await SeedAsync();
        var f = await FiguresAsync();
        (f.Quarter.Opened, f.Quarter.Closed, f.Quarter.BreachesOpened, f.Quarter.ReportedToRegulators).Should().Be((2, 1, 1, 1));
        (f.Quarter.NoticesMet, f.Quarter.ReviewsRecorded, f.Quarter.ClosedWithReview, f.Quarter.ActionsCompleted).Should().Be((1, 1, 1, 1));
        f.Quarter.TimeToDetect.Count.Should().Be(1);
        // FR-51: B is still being contained at the quarter's end, so only A counts toward the containment target.
        f.Quarter.Sla.Should().Equal(new SlaAttainment(SlaClock.Detection, 1, 0), new SlaAttainment(SlaClock.Containment, 1, 0),
            new SlaAttainment(SlaClock.Resolution, 1, 0));
        f.Quarter.OpenedBySeverity.Should().Equal(new CountBy<Severity>(Severity.High, 2));
        f.Top.Select(x => x.TechniqueId).Should().BeEquivalentTo("T1566", "T1082", "T1078", "T1110");
        f.Months.Single(m => m.Month == 4).ClosedBy.Should().Be(new ClassificationCounts(1, 0, 0, 0));
    }

    // ---- The guard: every public mutating Case method is catalogued above or reasoned here ----

    private static readonly Dictionary<string, string> DoesNotTouchPeriodInputs = new()
    {
        ["RenumberToIrp"] = "the case number; no figure reads it",
        // Removal takes a case out of every figure, past periods' too, on purpose: it was never a real case (opened by
        // mistake, a bad import), so a report regenerated after it is the truer one. Not a period input changing.
        ["Remove"] = "leaves the case out of every figure, past periods' too, by design: it was opened by mistake or imported badly",
        ["RestoreRemoved"] = "puts a removed case back into the figures it was in, as Remove takes it out",
        ["MarkPurged"] = "a removed case, already out of every figure, made a stub",
        ["SetComplexEventNumber"] = "the case number",
        ["AssignCustomNumber"] = "the case number",
        ["RecordGatePassage"] = "a stage-gate passage; no figure reads it",
        ["Assign"] = "assignments; visibility is today's by design (need-to-know applies to whoever reads the report now)",
        ["Unassign"] = "assignments, as Assign",
        ["ReferToLegal"] = "the legal referral; only the live dashboard reads it",
        ["RecordMateriality"] = "the notification trigger; a kept-deadline notice is judged on its own (BUG-375), and the rest through today's clock by design",
        ["AddEntity"] = "entities; no period figure reads them",
        ["AddParty"] = "CAP-34: outside parties; no period figure reads them",
        ["EditParty"] = "outside parties",
        ["RemoveParty"] = "outside parties",
        ["EditEntity"] = "entities",
        ["SetEntityPinned"] = "entities",
        ["SetEntityTlp"] = "entities",
        ["RemoveEntity"] = "entities (a step's actor/target link is rebuilt from the step's own trail)",
        ["LinkEntities"] = "entity relationships",
        ["EditRelationship"] = "entity relationships",
        ["Unlink"] = "entity relationships",
        ["EditInvestigationEntry"] = "investigation entries; the figures read event steps only",
        ["SetCitations"] = "evidence citations",
        ["PlaceNewEventStep"] = "places a step being added (AddEventStep's own rule, covered there)",
        ["MoveEventStep"] = "reorders steps through OccurredAtUtc/StepOrder, which EditEventStep's undo covers",
        ["EditNote"] = "analyst notes",
        ["SetNoticeDetails"] = "CAP-07: how a regulator was notified (method, reference, who, the file); no figure reads it, and the notice's time doesn't move",
        ["NoticesFromWholeReport"] = "only converts a whole-case report into notices dated at the reported time (no notice moves)",
        ["KeepElementsWhileReported"] = "adds elements to those a reported case had (BUG-618); the codes kept, notices and reported time don't move",
        ["Restrict"] = "visibility, as Assign",
        ["LiftRestriction"] = "visibility, as Assign",
        ["PlaceLegalHold"] = "legal hold",
        ["ReleaseLegalHold"] = "legal hold",
        ["RequestLegalHoldRelease"] = "legal hold",
        ["ApproveLegalHoldRelease"] = "legal hold",
        ["CancelLegalHoldReleaseRequest"] = "legal hold",
        ["SetReportProfile"] = "the case report's profile",
        ["SetTeam"] = "CAP-36: the owning team, which routes and filters; no period figure reads it (a team filter cuts by the team a case has now)",
        ["ChangeOrigin"] = "a correction of a case opened or imported as the wrong origin: a period's internal and third-party counts take the corrected origin, as they would have had it been right, which is the point of correcting it",
        ["Archive"] = "REV-59, the documented exception: a never-closed case archived later drops out of a past open-at-end count",
        ["Unarchive"] = "REV-59, as Archive",
        ["ReviseBrief"] = "the brief",
        ["ConfirmBrief"] = "the brief",
        ["SetInitialSummary"] = "the brief",
        ["RaiseTaskFromQuestion"] = "tasks; no period figure reads them",
    };

    private static readonly HashSet<string> Queries = ["FindEntity", "ReopenPhase", "RaisesClassification", "SkipsContainment",
        "LeavesContainmentUncontained", "SkipsRecovery", "TasksFollowingUp", "BuildCanonicalContent"];

    [Fact]
    public void Every_public_mutating_case_method_is_catalogued_or_reasoned()
    {
        var methods = typeof(Case).GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Where(m => !m.IsSpecialName && !Queries.Contains(m.Name) && !m.Name.EndsWith("ConcurrencyStamp", StringComparison.Ordinal))
            .Select(m => m.Name).ToHashSet();
        var catalogued = Catalogue.Keys.Select(k => k.Split(' ')[0]).ToHashSet();

        methods.Where(m => !catalogued.Contains(m) && !DoesNotTouchPeriodInputs.ContainsKey(m)).Should()
            .BeEmpty("a new Case mutator must be added to the freeze catalogue, or to the reasoned list with why it doesn't touch a period input");
        DoesNotTouchPeriodInputs.Keys.Where(k => !methods.Contains(k)).Should().BeEmpty("the reasoned list names only real methods");
        catalogued.Where(k => char.IsUpper(k[0]) && !methods.Contains(k)).Should().BeEmpty("the catalogue names only real methods");
        catalogued.Intersect(DoesNotTouchPeriodInputs.Keys).Should().BeEmpty();
    }

    public void Dispose() => _connection.Dispose();
}
