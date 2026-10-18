using System.Text.Json;
using FluentAssertions;
using IncidentManager.Application.Abstractions;
using IncidentManager.Application.Admin;
using IncidentManager.Application.Cases;
using IncidentManager.Application.Import;
using IncidentManager.Application.Security;
using IncidentManager.Domain.Entities;
using IncidentManager.Domain.Enums;
using IncidentManager.Infrastructure.Persistence;
using IncidentManager.Infrastructure.Persistence.Interceptors;
using IncidentManager.Infrastructure.Realtime;
using IncidentManager.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// CAP-35: historical and closed cases come in through schema v2 (a new case's phase history, outcome, conclusion,
/// incident commander and team), applied through the audited writes at their effective times, and a reviewer can confirm
/// a submitter's queue together, at most 25 at a time, each as its own confirm. A v1 document reads as it always did.
/// Runs on SQLite and, when a server is configured, on SQL Server.
/// </summary>
public sealed class CaseImportHistoryTests : IDisposable
{
    private TestDatabase? _db;
    private readonly FixedClock _clock = new(new DateTimeOffset(2026, 10, 18, 9, 0, 0, TimeSpan.Zero));
    private readonly HashChainService _hasher = new();
    private readonly CapturingSecurityEventSink _siem = new();
    private readonly TestCurrentUser _xsiam = new() { UserId = "apitoken:xsiam", RoleSet = [AppRole.Analyst] };
    private readonly TestCurrentUser _reviewer = new() { UserId = "analyst2", RoleSet = [AppRole.Analyst] };
    private readonly ListedUserDirectory _users = new(
        new UserSummary("ic-lee", "Dana Lee", "dana.lee@contoso.example", "dana.lee@contoso.example", "Analyst"),
        ListedUserDirectory.User("analyst9", "Analyst"));

    private readonly FailingRelease _releaseFails = new();

    public static TheoryData<string> Providers => TestDatabase.Providers;

    private void Open(string provider)
    {
        _db = TestDatabase.Open(provider, _releaseFails, new AuditChainInterceptor(_hasher, _reviewer, _clock, new CaseChangeNotifier()));
        using var db = _db.NewContext();
        DevDataSeeder.SeedCaseOutcomesAsync(db, _clock).GetAwaiter().GetResult();
    }

    private CaseImportService Import(TestCurrentUser user, ICaseNotifications? notifications = null, IUserDirectory? users = null,
        PendingImportSignal? signal = null) =>
        new(_db!.Factory(), user, _clock, new CaseService(_db.Factory(), user, _clock, new CaseNumberGenerator(_db.Factory()),
            new CreateCaseValidator(), notifications ?? new NoOpCaseNotifications(), new IncidentManager.Application.StageGates.StageGateEvaluator(),
            new TestSlaTargets(), siem: _siem, users: users ?? _users), users: users ?? _users, signal: signal, siem: _siem);

    // CAP-35 review: records who is told of an assignment; throws an exception no catch list names, the first N times.
    private sealed class AssignNotices(int throwFirst = 0) : ICaseNotifications
    {
        private int _throws = throwFirst;
        public List<string> Assigned { get; } = new();
        public Task OnAssignedAsync(Case c, string assigneeUserId, string assigneeDisplayName, CaseAssignmentRole role,
            string assignedByUserId, CancellationToken ct = default)
        {
            if (_throws-- > 0) throw new NotSupportedException("relay exploded");
            Assigned.Add(assigneeUserId);
            return Task.CompletedTask;
        }
        public Task OnActionItemsOverdueAsync(IReadOnlyList<OverdueActionItem> items, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnActionItemsDueSoonAsync(IReadOnlyList<DueSoonActionItem> items, int leadHours, CancellationToken ct = default) => Task.CompletedTask;
        public Task OnReclassifiedAsync(Case c, Classification? from, Classification to, CancellationToken ct = default) => Task.CompletedTask;
    }

    // The same case, still open: its history stops at PostIncident, with no outcome or conclusion.
    private CaseImportDocument StillOpen(string title = "Wire fraud attempt, still open")
    {
        var doc = Historical(title);
        var nc = doc.Target!.NewCase!;
        nc.History!.RemoveAt(nc.History.Count - 1);
        (nc.Outcome, nc.Conclusion) = (null, null);
        return doc;
    }

    // A new case detected ten days ago with just these steps.
    private CaseImportDocument WithSteps(CaseImportPhaseChange first, CaseImportPhaseChange? second = null,
        CaseImportPhaseChange? third = null, CaseImportPhaseChange? fourth = null)
    {
        var doc = Historical();
        var nc = doc.Target!.NewCase!;
        nc.History = new[] { first, second, third, fourth }.OfType<CaseImportPhaseChange>().ToList();
        (nc.Outcome, nc.Conclusion, nc.IncidentCommander, nc.Assignments) = (null, null, null, null);
        return doc;
    }

    private async Task AddCloseGateAsync(int commentaryMin, bool withRequirement)
    {
        await using var db = _db!.NewContext();
        var gate = new StageGate { Trigger = StageGateTrigger.CloseCase, Name = "Closure readiness", IsActive = true,
            CreatedBy = "system", CreatedAtUtc = _clock.UtcNow, CommentaryMinLength = commentaryMin };
        if (withRequirement)
            gate.Requirements.Add(new StageGateRequirement { GateId = gate.Id, Order = 0, Kind = GateRequirementKind.Attestation,
                Label = "Lessons review held", IsBlocking = true });
        db.StageGates.Add(gate);
        await db.SaveChangesAsync();
    }

    private async Task<int> CaseCountAsync()
    {
        await using var db = _db!.NewContext();
        return await db.Cases.CountAsync();
    }

    private DateTimeOffset Ago(int days) => _clock.UtcNow.AddDays(-days);

    // A case worked and closed before CaseBook: detected ten days ago, through every phase, closed four days ago.
    private CaseImportDocument Historical(string title = "Wire fraud attempt, March", int schemaVersion = 2) => new()
    {
        Format = CaseImportJson.FormatTag,
        SchemaVersion = schemaVersion,
        Origin = "Legacy tracker",
        Target = new CaseImportTarget
        {
            NewCase = new CaseImportNewCase
            {
                Title = title, Classification = "Incident", Severity = "High", DetectedAt = Ago(10), Summary = "A payment redirect was attempted.",
                History =
                [
                    new() { Phase = "Triage", At = Ago(9) },
                    new() { Phase = "Containment", At = Ago(8), Reason = "Mailbox rule removed" },
                    new() { Phase = "Eradication", At = Ago(7) },
                    new() { Phase = "Recovery", At = Ago(6) },
                    new() { Phase = "PostIncident", At = Ago(5) },
                    new() { Phase = "Closed", At = Ago(4) },
                ],
                Outcome = CaseOutcomeCatalog.Confirmed,
                Conclusion = "Stopped before any payment left.",
                IncidentCommander = "DANA.LEE@contoso.example",   // by UPN
                Assignments = [new() { User = "analyst9" }, new() { User = "ghost.user", Role = "Observer" }],
            },
        },
        Timeline = [new CaseImportTimelineEntry { OccurredAt = Ago(9), Description = "Finance reported the request." }],
    };

    private static string Json(CaseImportDocument doc) => JsonSerializer.Serialize(doc, CaseImportJson.Options);

    private static CaseImportDocument Parsed(CaseImportDocument doc) => CaseImportService.Parse(Json(doc)).Document!;

    private async Task<Guid> SubmitAs(TestCurrentUser who, CaseImportDocument doc) =>
        (await Import(who).SubmitAsync(Json(doc), Parsed(doc))).Id;

    private async Task<Case> LoadAsync(Guid id)
    {
        await using var db = _db!.NewContext();
        return await db.Cases.AsNoTracking().AsSplitQuery().Include(c => c.StatusChanges).Include(c => c.Assignments)
            .Include(c => c.GatePassages).SingleAsync(c => c.Id == id);
    }

    [Theory, MemberData(nameof(Providers))]
    public async Task A_v1_document_reads_as_it_always_did_and_v2_parts_in_one_are_ignored(string provider)
    {
        Open(provider);
        var plain = Historical(schemaVersion: 1);
        plain.Target!.NewCase!.History = null;
        plain.Target.NewCase.Outcome = plain.Target.NewCase.Conclusion = plain.Target.NewCase.IncidentCommander = null;
        plain.Target.NewCase.Assignments = null;
        var preview = await Import(_reviewer).BuildPreviewAsync(Parsed(plain));
        (preview.HasHistory, preview.HistoryProblem, preview.IncludedItemCount).Should().Be((false, (string?)null, 1));
        var result = await Import(_reviewer).ApplyAsync(preview);
        (await LoadAsync(result.CaseId)).Phase.Should().Be(CasePhase.New, "a v1 import lands open, as before");

        var mixed = await Import(_reviewer).BuildPreviewAsync(Parsed(Historical(schemaVersion: 1)));
        mixed.History.Should().BeEmpty();
        mixed.Warnings.Should().Contain(w => w.Contains("need \"schemaVersion\": 2"));
        CaseImportService.Parse(Json(Historical(schemaVersion: 3))).Error.Should().Contain("newer than this app supports (v2)");
    }

    [Theory, MemberData(nameof(Providers))]
    public async Task A_v2_history_closes_the_case_with_its_milestones_at_the_times_given(string provider)
    {
        Open(provider);
        var svc = Import(_reviewer);
        var preview = await svc.BuildPreviewAsync(Parsed(Historical()));
        preview.HistoryProblem.Should().BeNull();
        preview.IncidentCommander!.UserId.Should().Be("ic-lee");

        var result = await svc.ApplyAsync(preview);
        var c = await LoadAsync(result.CaseId);
        c.Phase.Should().Be(CasePhase.Closed);
        (c.ContainedAtUtc, c.ResolvedAtUtc, c.ClosedAtUtc).Should().Be((Ago(8), Ago(6), Ago(4)), "the milestones derive from the effective times");
        c.OutcomeKey.Should().Be(CaseOutcomeCatalog.Confirmed);
        c.StatusChanges.Where(s => s.From is not null).OrderBy(s => s.EffectiveAt).Select(s => (s.To, s.EffectiveAt)).Should().Equal(
            (CasePhase.Triage, Ago(9)), (CasePhase.Containment, Ago(8)), (CasePhase.Eradication, Ago(7)), (CasePhase.Recovery, Ago(6)),
            (CasePhase.PostIncident, Ago(5)), (CasePhase.Closed, Ago(4)));
        c.StatusChanges.Should().OnlyContain(s => s.ChangedBy == "analyst2", "the confirmer's name is on each write");
        c.StatusChanges.Single(s => s.To == CasePhase.Triage).Reason.Should().Be("imported record: Legacy tracker");
        c.StatusChanges.Single(s => s.To == CasePhase.Containment).Reason.Should().Be("Mailbox rule removed");
        c.IncidentCommander.Should().Be("ic-lee");
        c.Assignments.Select(a => a.UserId).Should().BeEquivalentTo(["ic-lee", "analyst9"]);
        var milestones = CaseMilestones.Project(c, new MilestoneLabels(x => "", s => "", p => "", m => ""));
        milestones.Should().Contain(m => m.Kind == MilestoneKind.Phase && m.AtUtc == Ago(4));
        _siem.Events.Where(e => e.Action == "ImportApplied").Should().ContainSingle();
    }

    [Theory, MemberData(nameof(Providers))]
    public async Task A_history_out_of_order_or_before_detection_is_refused_before_anything_is_written(string provider)
    {
        Open(provider);
        var svc = Import(_reviewer);
        var doc = Historical();
        doc.Target!.NewCase!.History![2].At = Ago(9).AddHours(-1);   // Eradication before Containment
        var preview = await svc.BuildPreviewAsync(Parsed(doc));
        preview.HistoryProblem.Should().Contain("History step 3").And.Contain("give the history in order");
        await svc.Invoking(s => s.ApplyAsync(preview)).Should().ThrowAsync<ArgumentException>().WithMessage("History step 3*");
        svc.CheckHistory(Parsed(doc)).Should().NotBeNull("the API refuses it before queueing");
        await using (var db = _db!.NewContext())
            (await db.Cases.CountAsync()).Should().Be(0, "nothing was written");

        var early = Historical();
        early.Target!.NewCase!.History![0].At = Ago(11);
        (await svc.BuildPreviewAsync(Parsed(early))).HistoryProblem.Should().Contain("before the case was detected");
        var future = Historical();
        future.Target!.NewCase!.History![5].At = _clock.UtcNow.AddHours(2);
        (await svc.BuildPreviewAsync(Parsed(future))).HistoryProblem.Should().Contain("in the future");
        var noOutcome = Historical();
        noOutcome.Target!.NewCase!.Outcome = null;
        (await svc.BuildPreviewAsync(Parsed(noOutcome))).HistoryProblem.Should().Contain("\"outcome\"");
        var unknownOutcome = Historical();
        unknownOutcome.Target!.NewCase!.Outcome = "made-up";
        (await svc.BuildPreviewAsync(Parsed(unknownOutcome))).HistoryProblem.Should().Contain("isn't an active outcome");
    }

    [Theory, MemberData(nameof(Providers))]
    public async Task A_close_whose_gate_checks_cant_be_met_is_overridden_as_an_imported_record(string provider)
    {
        Open(provider);
        await using (var db = _db!.NewContext())
        {
            var gate = new StageGate { Trigger = StageGateTrigger.CloseCase, Name = "Closure readiness", IsActive = true,
                CreatedBy = "system", CreatedAtUtc = _clock.UtcNow };
            gate.Requirements.Add(new StageGateRequirement { GateId = gate.Id, Order = 0, Kind = GateRequirementKind.Attestation,
                Label = "Lessons review held", IsBlocking = true });
            db.StageGates.Add(gate);
            await db.SaveChangesAsync();
        }
        var result = await Import(_reviewer).ApplyAsync(await Import(_reviewer).BuildPreviewAsync(Parsed(Historical())));

        var c = await LoadAsync(result.CaseId);
        c.Phase.Should().Be(CasePhase.Closed);
        var passage = c.GatePassages.Single(p => p.Trigger == StageGateTrigger.CloseCase);
        (passage.WasOverridden, passage.OverrideJustification, passage.PassedBy).Should().Be((true, "imported record: Legacy tracker", "analyst2"));
    }

    [Theory, MemberData(nameof(Providers))]
    public async Task Someone_the_directory_doesnt_know_is_a_warning_not_a_silent_drop(string provider)
    {
        Open(provider);
        var preview = await Import(_reviewer).BuildPreviewAsync(Parsed(Historical()));
        preview.Warnings.Should().Contain(w => w.Contains("\"ghost.user\"") && w.Contains("won't be added"));
        preview.Assignments.Single(a => a.Named == "ghost.user").UserId.Should().BeNull();
        var result = await Import(_reviewer).ApplyAsync(preview);
        (await LoadAsync(result.CaseId)).Assignments.Should().NotContain(a => a.UserId == "ghost.user");
    }

    [Theory, MemberData(nameof(Providers))]
    public async Task A_batch_confirm_applies_a_submitters_imports_each_on_its_own_and_reports_each(string provider)
    {
        Open(provider);
        // CAP-35 review: histories that stay open (one that closes is confirmed on its own; see below).
        var first = await SubmitAs(_xsiam, StillOpen("First"));
        _clock.UtcNow = _clock.UtcNow.AddSeconds(1);   // oldest first: submitted in turn, not in one instant
        var second = await SubmitAs(_xsiam, StillOpen("Second"));
        _clock.UtcNow = _clock.UtcNow.AddSeconds(1);
        var bad = StillOpen("Bad");
        bad.Target!.NewCase!.History![2].At = Ago(9).AddHours(-1);   // queued (SubmitAsync doesn't judge it), refused at review
        var third = await SubmitAs(_xsiam, bad);
        var other = await SubmitAs(new TestCurrentUser { UserId = "apitoken:other", RoleSet = [AppRole.Analyst] }, StillOpen("Other"));

        var svc = Import(_reviewer);
        (await svc.ListBatchFromSubmitterAsync(_xsiam.UserId)).Select(p => p.Id).Should().Equal(first, second, third);
        await svc.Invoking(s => s.ConfirmBatchAsync(_xsiam.UserId, Enumerable.Range(0, 26).Select(_ => Guid.NewGuid()).ToList()))
            .Should().ThrowAsync<ArgumentException>().WithMessage("Confirm up to 25*");

        var results = await svc.ConfirmBatchAsync(_xsiam.UserId, [first, second, third, other]);
        results.Select(r => (r.PendingImportId, r.Applied)).Should().Equal((first, true), (second, true), (third, false), (other, false));
        results[2].Message.Should().Contain("give the history in order");
        results[3].Message.Should().Contain("another submitter");
        foreach (var r in results.Where(r => r.Applied))
            (await LoadAsync(r.CaseId!.Value)).Phase.Should().Be(CasePhase.PostIncident);
        _siem.Events.Count(e => e.Action == "ImportApplied").Should().Be(2, "one per case applied");

        // CAP-13: the producer sees each as it stands; the one left needing review is still pending.
        var producer = Import(_xsiam);
        (await producer.GetSubmissionStatusAsync(first))!.Status.Should().Be("applied");
        (await producer.GetSubmissionStatusAsync(third))!.Status.Should().Be("pending");
        (await svc.ListBatchFromSubmitterAsync(_xsiam.UserId)).Select(p => p.Id).Should().Equal(third);

        // A second confirm of the same ones finds them decided.
        (await svc.ConfirmBatchAsync(_xsiam.UserId, [first])).Single().Message.Should().Contain("no longer waiting");
    }

    [Theory, MemberData(nameof(Providers))]
    public async Task A_history_aimed_at_an_existing_case_by_detection_id_is_left_out(string provider /* CAP-14 */)
    {
        Open(provider);
        await using (var db = _db!.NewContext())
        {
            var open = Case.Open(2026, 1, "open", "Open case", Classification.Incident, Severity.High, CaseOrigin.InternalDetection, "ic1", Ago(3));
            open.DetectionCaseId = "4812";
            db.Cases.Add(open);
            await db.SaveChangesAsync();
        }
        var doc = Historical();
        doc.Target!.DetectionCaseId = "4812";
        var preview = await Import(_reviewer).BuildPreviewAsync(Parsed(doc));
        preview.TargetKind.Should().Be(CaseImportTargetKind.ExistingCase);
        preview.Warnings.Should().Contain(w => w.Contains("aren't applied to an existing one"));
        var result = await Import(_reviewer).ApplyAsync(preview);
        (await LoadAsync(result.CaseId)).Phase.Should().Be(CasePhase.New);
    }

    public static TheoryData<string, string> RefusedSkips
    {
        get
        {
            var rows = new TheoryData<string, string>();
            foreach (var provider in TestDatabase.Providers)
                foreach (var shape in new[] { "contained-future", "contained-before-detection", "contained-after-move", "resolved-future",
                             "resolved-before-detection", "resolved-after-move", "resolved-before-contained", "rev11" })
                    rows.Add(provider, shape);
            return rows;
        }
    }

    // CAP-35 review (P1): every skip the domain refuses is refused in the preview, and apply writes nothing.
    [Theory, MemberData(nameof(RefusedSkips))]
    public async Task A_skip_the_domain_refuses_is_refused_before_anything_is_written(string provider, string shape)
    {
        Open(provider);
        var future = _clock.UtcNow.AddHours(1);
        var doc = shape switch
        {
            "contained-future" => WithSteps(new() { Phase = "Eradication", At = Ago(5), ContainedAt = future }),
            "contained-before-detection" => WithSteps(new() { Phase = "Eradication", At = Ago(5), ContainedAt = Ago(11) }),
            "contained-after-move" => WithSteps(new() { Phase = "Eradication", At = Ago(5), ContainedAt = Ago(4) }),
            "resolved-future" => WithSteps(new() { Phase = "Containment", At = Ago(8) }, new() { Phase = "PostIncident", At = Ago(5), ResolvedAt = future }),
            "resolved-before-detection" => WithSteps(new() { Phase = "Containment", At = Ago(8) }, new() { Phase = "PostIncident", At = Ago(5), ResolvedAt = Ago(11) }),
            "resolved-after-move" => WithSteps(new() { Phase = "Containment", At = Ago(8) }, new() { Phase = "PostIncident", At = Ago(5), ResolvedAt = Ago(4) }),
            "resolved-before-contained" => WithSteps(new() { Phase = "PostIncident", At = Ago(5), ContainedAt = Ago(7), ResolvedAt = Ago(8) }),
            // REV-11: "not needed", then Containment after all, takes back the resolution recorded on the way past.
            _ => WithSteps(new() { Phase = "Eradication", At = Ago(9), ContainmentNotNeeded = "Nothing to contain" },
                new() { Phase = "Recovery", At = Ago(8) }, new() { Phase = "Containment", At = Ago(7) }, new() { Phase = "PostIncident", At = Ago(6) }),
        };
        var svc = Import(_reviewer);
        var preview = await svc.BuildPreviewAsync(Parsed(doc));
        preview.HistoryProblem.Should().StartWith("History step");
        svc.CheckHistory(Parsed(doc)).Should().NotBeNull("the API refuses it before queueing");
        await svc.Invoking(s => s.ApplyAsync(preview)).Should().ThrowAsync<ArgumentException>();
        (await CaseCountAsync()).Should().Be(0, "nothing was written");
        if (shape == "rev11") preview.HistoryProblem.Should().Contain("give \"resolvedAt\"").And.Contain("took back the resolution");
    }

    [Theory, MemberData(nameof(Providers))]
    public async Task The_REV11_history_applies_when_it_says_when_it_was_resolved_again(string provider)
    {
        Open(provider);
        var doc = WithSteps(new() { Phase = "Eradication", At = Ago(9), ContainmentNotNeeded = "Nothing to contain" },
            new() { Phase = "Recovery", At = Ago(8) }, new() { Phase = "Containment", At = Ago(7) },
            new() { Phase = "PostIncident", At = Ago(5), ResolvedAt = Ago(6) });
        var preview = await Import(_reviewer).BuildPreviewAsync(Parsed(doc));
        preview.HistoryProblem.Should().BeNull("the preview takes what the domain takes");
        var c = await LoadAsync((await Import(_reviewer).ApplyAsync(preview)).CaseId);
        (c.Phase, c.ContainedAtUtc, c.ResolvedAtUtc).Should().Be((CasePhase.PostIncident, Ago(7), Ago(6)));
    }

    // CAP-35 review (P2): a close gate's commentary minimum is checked in the preview, against the close's own reason (or the
    // conclusion standing in for it), so a closing history doesn't fail at its last step.
    [Theory, MemberData(nameof(Providers))]
    public async Task A_close_gates_commentary_minimum_is_checked_before_anything_is_written(string provider)
    {
        Open(provider);
        await AddCloseGateAsync(commentaryMin: 40, withRequirement: true);
        var svc = Import(_reviewer);
        var preview = await svc.BuildPreviewAsync(Parsed(Historical()));   // no closing reason; the conclusion has 32 characters
        preview.HistoryProblem.Should().Contain("at least 40 characters");
        await svc.Invoking(s => s.ApplyAsync(preview)).Should().ThrowAsync<ArgumentException>();
        (await CaseCountAsync()).Should().Be(0, "refused before any write");

        var reasoned = Historical();
        const string why = "Closed on the legacy tracker after the finance review signed off.";
        reasoned.Target!.NewCase!.History![^1].Reason = why;
        var ok = await svc.BuildPreviewAsync(Parsed(reasoned));
        ok.HistoryProblem.Should().BeNull();
        var c = await LoadAsync((await svc.ApplyAsync(ok)).CaseId);
        c.Phase.Should().Be(CasePhase.Closed);
        c.StatusChanges.Single(s => s.To == CasePhase.Closed).Reason.Should().Be(why, "the close takes the step's own reason");
        var passage = c.GatePassages.Single(p => p.Trigger == StageGateTrigger.CloseCase);
        passage.WasOverridden.Should().BeTrue();
        passage.OverrideJustification.Should().StartWith("imported record: Legacy tracker").And.Contain(why);
        passage.OverrideJustification!.Length.Should().BeGreaterThanOrEqualTo(40);
    }

    [Theory, MemberData(nameof(Providers))]
    public async Task Without_its_own_reason_a_close_records_the_conclusion(string provider)
    {
        Open(provider);
        var c = await LoadAsync((await Import(_reviewer).ApplyAsync(await Import(_reviewer).BuildPreviewAsync(Parsed(Historical())))).CaseId);
        c.StatusChanges.Single(s => s.To == CasePhase.Closed).Reason.Should().Be("Stopped before any payment left.");
    }

    // CAP-35 review (P3): a batch confirm leaves a closing history for a person, whose close would override the gate.
    [Theory, MemberData(nameof(Providers))]
    public async Task A_batch_confirm_leaves_a_closing_history_for_review_on_its_own(string provider)
    {
        Open(provider);
        await AddCloseGateAsync(commentaryMin: 0, withRequirement: true);
        var closing = await SubmitAs(_xsiam, Historical("Closes"));
        var svc = Import(_reviewer);
        var result = (await svc.ConfirmBatchAsync(_xsiam.UserId, [closing])).Single();
        (result.Applied, result.CaseId).Should().Be((false, (Guid?)null));
        result.Message.Should().Contain("confirm it on its own");
        (await CaseCountAsync()).Should().Be(0, "nothing was written");
        (await Import(_xsiam).GetSubmissionStatusAsync(closing))!.Status.Should().Be("pending");

        // A single confirm still applies it, overriding the gate as an imported record.
        var preview = (await svc.BuildPreviewForPendingAsync(closing))!;
        var claim = await svc.ClaimPendingAsync(closing, preview);
        var applied = await svc.ApplyAsync(preview, closing);
        await svc.MarkPendingAppliedAsync(closing, applied, claim);
        (await LoadAsync(applied.CaseId)).GatePassages.Single(p => p.Trigger == StageGateTrigger.CloseCase).WasOverridden.Should().BeTrue();
    }

    // CAP-35 review (P4): an exception no catch list names releases that one and goes on to the next.
    [Theory, MemberData(nameof(Providers))]
    public async Task A_batch_confirm_releases_an_import_that_fails_unexpectedly_and_carries_on(string provider)
    {
        Open(provider);
        var first = await SubmitAs(_xsiam, StillOpen("First"));
        _clock.UtcNow = _clock.UtcNow.AddSeconds(1);
        var second = await SubmitAs(_xsiam, StillOpen("Second"));
        var notices = new AssignNotices(throwFirst: 1);
        var svc = Import(_reviewer, notices);

        var results = await svc.ConfirmBatchAsync(_xsiam.UserId, [first, second]);
        results.Select(r => (r.PendingImportId, r.Applied)).Should().Equal((first, false), (second, true));
        results[0].Message.Should().Contain("back in the queue");
        (await Import(_xsiam).GetSubmissionStatusAsync(first))!.Status.Should().Be("pending");
        await using (var db = _db!.NewContext())
        {
            var row = await db.PendingImports.AsNoTracking().SingleAsync(p => p.Id == first);
            (row.Status, row.DecidedBy, row.ResumeJson is null).Should().Be((PendingImportStatus.Pending, (string?)null, false),
                "released, with what it wrote kept to resume from");
        }
        // Reviewed on its own, it carries on into the case it created.
        var resumed = (await svc.BuildPreviewForPendingAsync(first))!;
        var claim = await svc.ClaimPendingAsync(first, resumed);
        claim.Should().NotBeNull();
        var done = await svc.ApplyAsync(resumed, first);
        await svc.MarkPendingAppliedAsync(first, done, claim);
        (await CaseCountAsync()).Should().Be(2, "one case each, none twice");
    }

    // CAP-35 review (P5): two directory rows with one UPN are ambiguous: a warning, and nobody is added.
    [Theory, MemberData(nameof(Providers))]
    public async Task A_UPN_two_users_share_is_a_warning_and_no_assignment(string provider)
    {
        Open(provider);
        var users = new ListedUserDirectory(
            new UserSummary("S-1-5-21-1", "Dana Lee", "dana.lee@contoso.example", "dana.lee@contoso.example", "Analyst"),
            new UserSummary("S-1-5-21-2", "Dana Lee (old)", "DANA.LEE@contoso.example", null, "Analyst"),
            ListedUserDirectory.User("analyst9", "Analyst"));
        var svc = Import(_reviewer, users: users);
        var preview = await svc.BuildPreviewAsync(Parsed(Historical()));
        preview.IncidentCommander!.UserId.Should().BeNull();
        preview.Warnings.Should().Contain(w => w.Contains("matches more than one CaseBook user") && w.Contains("S-1-5-21-1") && w.Contains("S-1-5-21-2"));
        var c = await LoadAsync((await svc.ApplyAsync(preview)).CaseId);
        c.IncidentCommander.Should().BeNull();
        c.Assignments.Select(a => a.UserId).Should().Equal("analyst9");
    }

    // CAP-35 review (P6): a closed historical case's team isn't emailed "assigned"; one that stays open is.
    [Theory, MemberData(nameof(Providers))]
    public async Task Importing_a_closed_history_sends_no_assignment_notices(string provider)
    {
        Open(provider);
        var closedNotices = new AssignNotices();
        var closed = await LoadAsync((await Import(_reviewer, closedNotices).ApplyAsync(
            await Import(_reviewer).BuildPreviewAsync(Parsed(Historical())))).CaseId);
        closed.Assignments.Select(a => a.UserId).Should().BeEquivalentTo(["ic-lee", "analyst9"]);
        closedNotices.Assigned.Should().BeEmpty("a closed historical case isn't work to act on");

        var openNotices = new AssignNotices();
        await Import(_reviewer, openNotices).ApplyAsync(await Import(_reviewer).BuildPreviewAsync(Parsed(StillOpen())));
        openNotices.Assigned.Should().BeEquivalentTo(["ic-lee", "analyst9"], "an open one is work in hand");
    }

    // CAP-35 review: a stale page can't claim after another reviewer's apply stopped part-way and was put back; it reopens.
    [Theory, MemberData(nameof(Providers))]
    public async Task A_stale_preview_cant_claim_over_a_partial_apply_and_a_reload_resumes_it(string provider)
    {
        Open(provider);
        var pid = await SubmitAs(_xsiam, StillOpen());
        var other = new TestCurrentUser { UserId = "analyst3", RoleSet = [AppRole.Analyst] };
        var stale = (await Import(other).BuildPreviewForPendingAsync(pid))!;   // analyst3 opens it, then looks away

        var failing = Import(_reviewer, new AssignNotices(throwFirst: 1));
        var mine = (await failing.BuildPreviewForPendingAsync(pid))!;
        var claim = await failing.ClaimPendingAsync(pid, mine);
        await failing.Invoking(s => s.ApplyAsync(mine, pid)).Should().ThrowAsync<NotSupportedException>();
        await failing.ReleaseClaimAsync(pid, mine, claim);
        (await CaseCountAsync()).Should().Be(1);

        await Import(other).Invoking(s => s.ClaimPendingAsync(pid, stale)).Should().ThrowAsync<StaleResumeException>();
        var reloaded = (await Import(other).BuildPreviewForPendingAsync(pid))!;
        var claim2 = await Import(other).ClaimPendingAsync(pid, reloaded);
        claim2.Should().NotBeNull("a reload carries the resume state");
        var result = await Import(other).ApplyAsync(reloaded, pid);
        await Import(other).MarkPendingAppliedAsync(pid, result, claim2);
        result.CaseId.Should().Be(mine.CreatedCaseId!.Value, "it resumed into the case already created");
        (await CaseCountAsync()).Should().Be(1, "not a second case");
    }

    // R2: a release whose save failed left the page's preview with a stamp the row never got, so once the claim went
    // stale the page's own retry was refused for good (StaleResumeException).
    [Theory, MemberData(nameof(Providers))]
    public async Task A_failed_release_leaves_the_preview_able_to_claim_again(string provider)
    {
        Open(provider);
        var pid = await SubmitAs(_xsiam, StillOpen());
        var svc = Import(_reviewer, new AssignNotices(throwFirst: 2));
        var mine = (await svc.BuildPreviewForPendingAsync(pid))!;

        var claim = await svc.ClaimPendingAsync(pid, mine);
        await svc.Invoking(s => s.ApplyAsync(mine, pid)).Should().ThrowAsync<NotSupportedException>();
        await svc.ReleaseClaimAsync(pid, mine, claim);
        mine.CreatedCaseId.Should().NotBeNull("the case was created before it stopped");

        claim = await svc.ClaimPendingAsync(pid, mine);
        claim.Should().NotBeNull();
        await svc.Invoking(s => s.ApplyAsync(mine, pid)).Should().ThrowAsync<NotSupportedException>();
        _releaseFails.Armed = true;
        await svc.Invoking(s => s.ReleaseClaimAsync(pid, mine, claim)).Should().ThrowAsync<InvalidOperationException>();
        _releaseFails.Armed = false;

        _clock.UtcNow = _clock.UtcNow.AddMinutes(31);
        var retry = await svc.ClaimPendingAsync(pid, mine);
        retry.Should().NotBeNull("the preview still carries the stamp the row has");
        var result = await svc.ApplyAsync(mine, pid);
        await svc.MarkPendingAppliedAsync(pid, result, retry);
        result.CaseId.Should().Be(mine.CreatedCaseId!.Value);
        (await CaseCountAsync()).Should().Be(1);
        await using var db = _db!.NewContext();
        var timeline = await db.TimelineEntries.AsNoTracking().Where(t => t.CaseId == result.CaseId)
            .Select(t => t.Description).ToListAsync();
        timeline.Should().OnlyHaveUniqueItems("nothing written twice");
        timeline.Should().ContainSingle(t => t == "Finance reported the request.");
    }

    // CAP-35 review: a preview that throws (unreadable resume state) or a claim that fails other than stale is that one's
    // failure: a claim taken is put back, and the batch carries on.
    [Theory, MemberData(nameof(Providers))]
    public async Task A_batch_confirm_carries_on_past_a_preview_or_claim_that_throws(string provider)
    {
        Open(provider);
        var unreadable = await SubmitAs(_xsiam, StillOpen("Unreadable"));
        _clock.UtcNow = _clock.UtcNow.AddSeconds(1);
        var unclaimable = await SubmitAs(_xsiam, StillOpen("Unclaimable"));
        _clock.UtcNow = _clock.UtcNow.AddSeconds(1);
        var fine = await SubmitAs(_xsiam, StillOpen("Fine"));
        await using (var db = _db!.NewContext())
        {
            (await db.PendingImports.SingleAsync(p => p.Id == unreadable)).ResumeJson = "{not json";
            await db.SaveChangesAsync();
        }
        // The claim of the second lands, then its call throws (a listener no catch names), once.
        var signal = new PendingImportSignal();
        var throws = 1;
        signal.Changed += () => { if (throws-- > 0) throw new NotSupportedException("listener exploded"); };

        var results = await Import(_reviewer, signal: signal).ConfirmBatchAsync(_xsiam.UserId, [unreadable, unclaimable, fine]);

        results.Select(r => (r.PendingImportId, r.Applied)).Should().Equal((unreadable, false), (unclaimable, false), (fine, true));
        results[0].Message.Should().Contain("couldn't be previewed");
        results[1].Message.Should().Contain("couldn't be claimed");
        await using (var db = _db!.NewContext())
        {
            var rows = await db.PendingImports.AsNoTracking().Where(p => p.Id == unreadable || p.Id == unclaimable).ToListAsync();
            rows.Should().OnlyContain(p => p.Status == PendingImportStatus.Pending && p.DecidedBy == null, "neither is left claimed");
        }
        (await CaseCountAsync()).Should().Be(1);
    }

    // R2: refuses a save that releases a claimed import, while armed.
    private sealed class FailingRelease : Microsoft.EntityFrameworkCore.Diagnostics.SaveChangesInterceptor
    {
        public bool Armed;

        public override ValueTask<Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<int>> SavingChangesAsync(
            Microsoft.EntityFrameworkCore.Diagnostics.DbContextEventData eventData,
            Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (Armed && eventData.Context!.ChangeTracker.Entries<PendingImport>()
                    .Any(e => e.State == EntityState.Modified && e.Entity.Status == PendingImportStatus.Pending))
                throw new InvalidOperationException("The database is down.");
            return ValueTask.FromResult(result);
        }
    }

    public void Dispose() => _db?.Dispose();
}
